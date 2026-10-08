/**
 * Guardion — Background Service Worker (Manifest V3)
 * Handles communication between content script and the Guardion backend API.
 * Includes JWT auth header forwarding and threat category tracking.
 *
 * Performance:
 *  - 3s AbortController timeout (fail-open, never hangs the composer)
 *  - Session LRU cache — identical prompts are answered in ~0ms
 *  - In-flight dedup — concurrent identical prompts share one request
 *  - Stats writes are fire-and-forget (never block the verdict)
 */

const API_BASE = "http://localhost:8000/api";
const FETCH_TIMEOUT_MS = 3000;
const CACHE_MAX = 50;
const CACHE_TTL_MS = 5 * 60 * 1000;

/** Session verdict cache: key → { result, at }. Best-effort (worker may sleep). */
const verdictCache = new Map();
/** In-flight requests: key → Promise, so identical concurrent prompts share one fetch. */
const pendingRequests = new Map();

function cacheKey(prompt) {
  // Truncate very long prompts to keep the key cheap; length keeps collisions unlikely.
  return prompt.length <= 512 ? prompt : `${prompt.slice(0, 256)}::${prompt.slice(-256)}::${prompt.length}`;
}

function cacheGet(key) {
  const hit = verdictCache.get(key);
  if (!hit) return undefined;
  if (Date.now() - hit.at > CACHE_TTL_MS) {
    verdictCache.delete(key);
    return undefined;
  }
  // LRU refresh
  verdictCache.delete(key);
  verdictCache.set(key, hit);
  return hit.result;
}

function cacheSet(key, result) {
  if (verdictCache.size >= CACHE_MAX) {
    verdictCache.delete(verdictCache.keys().next().value); // evict oldest
  }
  verdictCache.set(key, { result, at: Date.now() });
}

/**
 * Listen for messages from the content script.
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "analyzePrompt") {
    analyzePrompt(message.prompt, message.source)
      .then((result) => sendResponse(result))
      .catch((err) =>
        sendResponse({
          error: true,
          risk_score: 0,
          decision: "allow",
          detected_categories: [],
          message: err.message,
        })
      );
    return true;
  }

  if (message.action === "getStats") {
    getStats()
      .then((result) => sendResponse(result))
      .catch((err) => sendResponse({ error: true, message: err.message }));
    return true;
  }
});

/**
 * Get auth headers if user is logged in.
 */
async function getAuthHeaders() {
  const data = await chrome.storage.local.get("guardion_token");
  const headers = { "Content-Type": "application/json" };
  if (data.guardion_token) {
    headers["Authorization"] = `Bearer ${data.guardion_token}`;
  }
  return headers;
}

/**
 * Send prompt to Guardion backend for analysis.
 */
async function analyzePrompt(prompt, source) {
  const key = cacheKey(prompt);

  const cached = cacheGet(key);
  if (cached) return cached;

  const inflight = pendingRequests.get(key);
  if (inflight) return inflight;

  const request = doAnalyze(prompt, source).then((result) => {
    pendingRequests.delete(key);
    if (!result.error && result.decision) cacheSet(key, result);
    return result;
  }).catch((err) => {
    pendingRequests.delete(key);
    return {
      error: true,
      risk_score: 0,
      decision: "allow",
      detected_categories: [],
      message: err.message,
    };
  });

  pendingRequests.set(key, request);
  return request;
}

async function doAnalyze(prompt, source) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const headers = await getAuthHeaders();
    const response = await fetch(`${API_BASE}/analyze_prompt`, {
      method: "POST",
      headers,
      body: JSON.stringify({ prompt, source }),
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }

    const data = await response.json();
    // Fire-and-forget: stats must never delay the verdict reaching the composer.
    updateLocalStats(data.decision, data.detected_categories || []).catch(() => {});
    return data;
  } catch (error) {
    const timedOut = error.name === "AbortError";
    console.error("[Guardion] API call failed:", error);
    return {
      risk_score: 0,
      decision: "allow",
      detected_categories: [],
      error: true,
      message: timedOut
        ? "Backend timed out — prompt allowed by default"
        : "Backend unreachable — prompt allowed by default",
    };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Update local extension stats with category tracking.
 */
async function updateLocalStats(decision, categories) {
  const data = await chrome.storage.local.get("guardion_stats");
  const stats = data.guardion_stats || {
    total: 0,
    allowed: 0,
    warned: 0,
    blocked: 0,
    recentCategories: [],
  };

  stats.total++;
  if (decision === "allow") stats.allowed++;
  else if (decision === "warn") stats.warned++;
  else if (decision === "block") stats.blocked++;

  // Track recent threat categories (keep last 20 unique)
  if (categories && categories.length > 0) {
    const existing = new Set(stats.recentCategories || []);
    categories.forEach((c) => existing.add(c));
    stats.recentCategories = Array.from(existing).slice(-20);
  }

  await chrome.storage.local.set({ guardion_stats: stats });
}

/**
 * Get local stats for the popup.
 */
async function getStats() {
  const data = await chrome.storage.local.get("guardion_stats");
  return data.guardion_stats || {
    total: 0,
    allowed: 0,
    warned: 0,
    blocked: 0,
    recentCategories: [],
  };
}
