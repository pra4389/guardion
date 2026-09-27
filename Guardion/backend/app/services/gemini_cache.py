"""
Guardion — Gemini API Cache & Rate Limiter
============================================
Saves API quota by:
  1. Caching responses (same/similar prompts don't re-call Gemini)
  2. Rate limiting (max N calls per minute)
  3. Cooldown after quota errors (back off automatically)

Uses an in-memory LRU cache with TTL expiry.
"""

import hashlib
import time
import logging
from collections import OrderedDict
from threading import Lock

logger = logging.getLogger("guardion.gemini_cache")

# ──────────────────── Configuration ────────────────────

MAX_CACHE_SIZE = 500          # Max cached responses
CACHE_TTL_SECONDS = 3600      # Cache entries live for 1 hour
MAX_CALLS_PER_MINUTE = 10     # Max Gemini API calls per minute (free tier: 15 RPM)
QUOTA_COOLDOWN_SECONDS = 60   # Back off this long after a quota error

# Circuit breaker: after N consecutive full-chain failures, stop calling the
# API entirely for a cooldown. Requests then fall back to the local pipeline
# instantly instead of hanging on a degraded/overloaded API.
CIRCUIT_FAILURE_THRESHOLD = 3
CIRCUIT_OPEN_SECONDS = 120


# ──────────────────── LRU Cache with TTL ────────────────────

class TTLCache:
    """Thread-safe LRU cache with time-to-live expiry."""

    def __init__(self, max_size: int = MAX_CACHE_SIZE, ttl: int = CACHE_TTL_SECONDS):
        self.max_size = max_size
        self.ttl = ttl
        self._cache: OrderedDict[str, tuple[float, dict]] = OrderedDict()
        self._lock = Lock()
        self._hits = 0
        self._misses = 0

    def _make_key(self, text: str, prefix: str = "") -> str:
        """Hash prompt text to create a cache key."""
        normalized = text.strip().lower()
        return prefix + hashlib.sha256(normalized.encode()).hexdigest()[:16]

    def get(self, text: str, prefix: str = "") -> dict | None:
        """Retrieve a cached response if it exists and hasn't expired."""
        key = self._make_key(text, prefix)
        with self._lock:
            if key in self._cache:
                timestamp, value = self._cache[key]
                if time.time() - timestamp < self.ttl:
                    # Move to end (most recently used)
                    self._cache.move_to_end(key)
                    self._hits += 1
                    logger.debug(f"Cache HIT: {key} (hits={self._hits})")
                    return value
                else:
                    # Expired
                    del self._cache[key]
            self._misses += 1
            return None

    def put(self, text: str, value: dict, prefix: str = ""):
        """Store a response in the cache."""
        key = self._make_key(text, prefix)
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = (time.time(), value)
            # Evict oldest if over capacity
            while len(self._cache) > self.max_size:
                self._cache.popitem(last=False)

    @property
    def stats(self) -> dict:
        """Return cache hit/miss statistics."""
        total = self._hits + self._misses
        return {
            "size": len(self._cache),
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": round(self._hits / total, 2) if total > 0 else 0,
        }


# ──────────────────── Rate Limiter ────────────────────

class RateLimiter:
    """Sliding-window rate limiter for API calls."""

    def __init__(self, max_calls: int = MAX_CALLS_PER_MINUTE, window: int = 60):
        self.max_calls = max_calls
        self.window = window
        self._timestamps: list[float] = []
        self._lock = Lock()
        self._quota_exhausted_until: float = 0  # Timestamp when cooldown ends
        self._consecutive_failures: int = 0
        self._circuit_open_until: float = 0.0

    def mark_quota_exhausted(self):
        """Called when we get a RESOURCE_EXHAUSTED error. Backs off."""
        self._quota_exhausted_until = time.time() + QUOTA_COOLDOWN_SECONDS
        logger.warning(f"Gemini quota exhausted — cooling down for {QUOTA_COOLDOWN_SECONDS}s")

    def record_success(self):
        """A chain succeeded — reset the failure streak."""
        self._consecutive_failures = 0

    def record_failure(self):
        """A full model chain failed — count it, maybe trip the circuit."""
        self._consecutive_failures += 1
        if self._consecutive_failures >= CIRCUIT_FAILURE_THRESHOLD:
            self._circuit_open_until = time.time() + CIRCUIT_OPEN_SECONDS
            self._consecutive_failures = 0
            logger.warning(
                f"Gemini circuit OPENED for {CIRCUIT_OPEN_SECONDS}s after "
                f"{CIRCUIT_FAILURE_THRESHOLD} consecutive failed chains — using local pipeline"
            )

    @property
    def circuit_open(self) -> bool:
        """True while the circuit breaker is tripped (API is failing consistently)."""
        return time.time() < self._circuit_open_until

    def can_call(self) -> bool:
        """Check if we're allowed to make an API call right now."""
        now = time.time()

        # Respect circuit breaker
        if now < self._circuit_open_until:
            logger.debug("Rate limiter: circuit open, using local fallback")
            return False

        # Respect quota cooldown
        if now < self._quota_exhausted_until:
            remaining = int(self._quota_exhausted_until - now)
            logger.debug(f"Rate limiter: in cooldown, {remaining}s remaining")
            return False

        with self._lock:
            # Remove timestamps outside the window
            self._timestamps = [t for t in self._timestamps if now - t < self.window]
            if len(self._timestamps) < self.max_calls:
                self._timestamps.append(now)
                return True
            return False

    @property
    def calls_remaining(self) -> int:
        """How many calls can still be made in the current window."""
        now = time.time()
        if now < self._quota_exhausted_until or now < self._circuit_open_until:
            return 0
        with self._lock:
            active = [t for t in self._timestamps if now - t < self.window]
            return max(0, self.max_calls - len(active))


# ──────────────────── Global Instances ────────────────────

# Shared across the entire app
gemini_cache = TTLCache()
gemini_rate_limiter = RateLimiter()
