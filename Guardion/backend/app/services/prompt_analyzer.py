"""
Prompt Security Analysis Service
Detects sensitive information in AI prompts using regex pattern matching
and a local ML classifier (sentence-transformers + logistic regression).
Returns risk score, decision, and optionally sanitizes the prompt.
"""

import re
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# ──────────────────── Pattern Definitions ────────────────────
# Each pattern maps a category name to a compiled regex.
# These catch the most common sensitive data types developers accidentally paste.

SENSITIVE_PATTERNS: dict[str, re.Pattern] = {
    # AWS access keys
    "aws_key": re.compile(
        r"(?:AKIA|ASIA)[0-9A-Z]{16}", re.IGNORECASE
    ),
    # Generic API keys (sk-..., api_key=..., apikey:..., etc.)
    "api_key": re.compile(
        r"(?:sk-[a-zA-Z0-9]{20,})"
        r"|(?:(?:api[_\-\s]?key|apikey|access[_\-\s]?key)\s*[:=]{1,2}\s*['\"]?[a-zA-Z0-9\-_]{16,}['\"]?)",
        re.IGNORECASE,
    ),
    # Bearer / auth tokens
    "auth_token": re.compile(
        r"(?:bearer\s+[a-zA-Z0-9\-_\.]{20,})"
        r"|(?:(?:token|auth[_-]?token|access[_-]?token|secret[_-]?token)\s*[:=]\s*['\"]?[a-zA-Z0-9\-_\.]{20,}['\"]?)",
        re.IGNORECASE,
    ),
    # Passwords in assignments
    "password": re.compile(
        r"(?:password|passwd|pwd|pass)\s*[:=]\s*['\"]?[^\s'\"]{6,}['\"]?",
        re.IGNORECASE,
    ),
    # Private keys (PEM format)
    "private_key": re.compile(
        r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE\s+KEY-----",
        re.IGNORECASE,
    ),
    # Database connection strings
    "database_url": re.compile(
        r"(?:mongodb\+srv|postgres(?:ql)?|mysql|mssql|redis|amqp)://[^\s]{10,}",
        re.IGNORECASE,
    ),
    # Email addresses
    "email": re.compile(
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    ),
    # Credit card numbers (basic Luhn-eligible 13-19 digit sequences)
    "credit_card": re.compile(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
    ),
    # Phone numbers (US/international)
    "phone_number": re.compile(
        r"(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}",
    ),
    # Social Security Numbers
    "ssn": re.compile(
        r"\b\d{3}-\d{2}-\d{4}\b",
    ),
    # GitHub / GitLab personal access tokens
    "github_token": re.compile(
        r"(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}",
    ),
    # Slack tokens
    "slack_token": re.compile(
        r"xox[bpors]-[a-zA-Z0-9\-]{10,}",
    ),
    # JWT tokens
    "jwt": re.compile(
        r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_\-]{10,}",
    ),
    # Generic secrets in env-style assignments
    "generic_secret": re.compile(
        r"(?:secret|client_secret|app_secret|private|encryption_key)\s*[:=]\s*['\"]?[a-zA-Z0-9\-_]{10,}['\"]?",
        re.IGNORECASE,
    ),

    # ──────────────── Prompt Injection / Jailbreak Patterns ────────────────

    # System prompt extraction attempts
    "prompt_injection": re.compile(
        r"(?:reveal|show|display|print|output|leak|expose|tell\s+me|give\s+me|share)"
        r"\s+(?:the\s+|your\s+|all\s+|full\s+|hidden\s+|original\s+|internal\s+)*"
        r"(?:system\s*(?:prompt|instruction|message|config)|hidden\s*(?:prompt|instruction|rule|config)"
        r"|initial\s*(?:prompt|instruction)|secret\s*(?:prompt|instruction)"
        r"|instructions?\s*(?:used\s+to|that\s+|above|behind|configure|program))",
        re.IGNORECASE,
    ),

    # Role override / identity manipulation
    "role_manipulation": re.compile(
        r"(?:you\s+are\s+(?:now|actually|in)\s+(?:a\s+)?(?:debugging|developer|admin|root|sudo|unrestricted|unfiltered|jailbr(?:oken|eak)|dan|evil))"
        r"|(?:ignore\s+(?:all\s+)?(?:previous|prior|above|your|safety|ethical|content)\s*(?:instructions?|rules?|guidelines?|prompts?|constraints?|filters?|restrictions?))"
        r"|(?:forget\s+(?:all\s+)?(?:previous|prior|your)\s*(?:instructions?|rules?|programming|training))"
        r"|(?:disregard\s+(?:all\s+)?(?:previous|prior|your|safety)\s*(?:instructions?|rules?|guidelines?))"
        r"|(?:override\s+(?:your\s+)?(?:safety|content|ethical)\s*(?:settings?|filters?|guidelines?|rules?))"
        r"|(?:pretend\s+(?:you\s+(?:are|have)\s+(?:no|don'?t\s+have)\s*(?:restrictions?|rules?|filters?|guidelines?|limits?)))",
        re.IGNORECASE,
    ),

    # DAN / jailbreak keywords
    "jailbreak_attempt": re.compile(
        r"(?:(?:^|\W)DAN(?:$|\W))"
        r"|(?:do\s+anything\s+now)"
        r"|(?:jailbr(?:eak|oken)\s*(?:mode|prompt)?)"
        r"|(?:developer\s+mode\s*(?:enabled|on|activate))"
        r"|(?:act\s+as\s+(?:an?\s+)?(?:unrestricted|unfiltered|uncensored|evil|amoral))"
        r"|(?:no\s+(?:ethical|moral|safety|content)\s*(?:guidelines?|boundaries|constraints?|limitations?|restrictions?|filters?))"
        r"|(?:bypass\s+(?:your\s+)?(?:safety|content|ethical|security)\s*(?:filters?|measures?|protocols?|restrictions?))",
        re.IGNORECASE,
    ),
}

# Category weights — higher weight = more dangerous if leaked/detected
CATEGORY_WEIGHTS: dict[str, float] = {
    "aws_key": 1.0,
    "api_key": 0.9,
    "auth_token": 0.9,
    "password": 0.85,
    "private_key": 1.0,
    "database_url": 0.95,
    "github_token": 0.9,
    "slack_token": 0.8,
    "jwt": 0.85,
    "generic_secret": 0.75,
    "credit_card": 0.95,
    "ssn": 0.95,
    "email": 0.3,
    "phone_number": 0.3,
    # Prompt injection / manipulation
    "prompt_injection": 0.9,
    "role_manipulation": 0.95,
    "jailbreak_attempt": 1.0,
}

# Decision thresholds
BLOCK_THRESHOLD = 0.7
WARN_THRESHOLD = 0.3


@dataclass
class AnalysisResult:
    """Output of prompt security analysis."""
    risk_score: float
    decision: str
    detected_categories: list[str]
    sanitized_prompt: str | None
    gemini_reason: str = ""  # Contextual explanation from Gemini (empty if regex-only)
    ml_prediction: dict = field(default_factory=dict)  # ML model output: {prediction, confidence, all_scores}


# ── ML prediction → risk score mapping ──
ML_RISK_MAP: dict[str, float] = {
    "credential_leak": 0.9,
    "secret_code": 0.9,
    "financial_data": 0.95,
    "pii_leak": 0.6,
    "safe": 0.0,
}

# ML prediction → regex-style category mapping
ML_CATEGORY_MAP: dict[str, str] = {
    "credential_leak": "ml_credential_leak",
    "secret_code": "ml_secret_code",
    "financial_data": "ml_financial_data",
    "pii_leak": "ml_pii_leak",
}


def analyze_prompt(prompt_text: str, sanitize: bool = True) -> AnalysisResult:
    """
    Analyze a prompt for sensitive data.

    Steps:
      1. Run every regex pattern against the prompt text.
      2. Collect matched category names.
      3. Compute a risk score from the highest-weight match.
      4. Decide: allow / warn / block based on thresholds.
      5. Optionally sanitize (redact) matched values.

    Args:
        prompt_text: The raw prompt text from the user.
        sanitize: If True, generate a redacted version of the prompt.

    Returns:
        AnalysisResult with score, decision, categories, and optional sanitized text.
    """
    detected: list[str] = []
    max_weight = 0.0
    sanitized = prompt_text if sanitize else None

    for category, pattern in SENSITIVE_PATTERNS.items():
        matches = pattern.findall(prompt_text)
        if matches:
            detected.append(category)
            weight = CATEGORY_WEIGHTS.get(category, 0.5)
            max_weight = max(max_weight, weight)

            # Redact matched values in the sanitized version
            if sanitize and sanitized is not None:
                sanitized = pattern.sub(f"[REDACTED_{category.upper()}]", sanitized)

    # Risk score: use max weight, boosted slightly if multiple categories found
    if detected:
        category_boost = min(len(detected) * 0.05, 0.15)  # up to +0.15
        risk_score = round(min(max_weight + category_boost, 1.0), 2)
    else:
        risk_score = 0.0

    # Decision based on thresholds
    if risk_score >= BLOCK_THRESHOLD:
        decision = "block"
    elif risk_score >= WARN_THRESHOLD:
        decision = "warn"
    else:
        decision = "allow"

    return AnalysisResult(
        risk_score=risk_score,
        decision=decision,
        detected_categories=detected,
        sanitized_prompt=sanitized if detected else None,
    )


# ──────────────────── Combined Analysis (Regex + ML + Gemini) ────────────────────

async def analyze_prompt_combined(
    prompt_text: str, sanitize: bool = True, use_gemini: bool = False
) -> AnalysisResult:
    """
    Three-stage prompt analysis pipeline:
      Stage 1: Regex pattern matching (fast, deterministic)  — always runs
      Stage 2: Local ML model (sentence-transformers + logistic regression) — always runs
      Stage 3: Gemini contextual analysis (catches obfuscated/novel leaks)
               Only runs when use_gemini=True to conserve free-tier quota.

    The final result merges all stages:
      - Categories are unioned (regex + ML + Gemini)
      - Risk score takes the highest of the three
      - Decision follows the strictest of the three
      - Sanitized prompt comes from the regex stage
      - ML prediction dict is attached for frontend display

    If any stage fails, the pipeline continues with remaining stages.
    """
    from app.services.gemini_integration import analyze_prompt_with_gemini

    # Stage 1: regex-based analysis (always runs — free & fast)
    regex_result = analyze_prompt(prompt_text, sanitize=sanitize)

    # Stage 2: local ML model (always runs — fast, no API cost)
    # Runs in a worker thread so the event loop is never blocked during inference.
    ml_prediction = {}
    ml_risk_score = 0.0
    ml_decision = "allow"
    ml_categories: list[str] = []
    try:
        from guardion_ai_model.inference import analyze_prompt_async as ml_analyze_async
        ml_prediction = await ml_analyze_async(prompt_text)
        prediction = ml_prediction.get("prediction", "safe")
        confidence = ml_prediction.get("confidence", 0.0)

        # Only count ML prediction if confidence is above threshold
        if prediction != "safe" and confidence >= 0.6:
            base_risk = ML_RISK_MAP.get(prediction, 0.5)
            ml_risk_score = round(base_risk * confidence, 2)
            ml_categories = [ML_CATEGORY_MAP.get(prediction, f"ml_{prediction}")]

            if ml_risk_score >= BLOCK_THRESHOLD:
                ml_decision = "block"
            elif ml_risk_score >= WARN_THRESHOLD:
                ml_decision = "warn"
    except FileNotFoundError:
        logger.warning("ML model not trained yet — skipping ML stage")
    except Exception as e:
        logger.error(f"ML model error: {e}")

    # Stage 3: Gemini contextual analysis (only if explicitly requested)
    gemini_result = None
    if use_gemini:
        try:
            gemini_result = await analyze_prompt_with_gemini(prompt_text)
        except Exception:
            gemini_result = None

    # ── Merge all stages: take the strictest outcome ──
    merged_categories = list(set(regex_result.detected_categories + ml_categories))
    merged_score = round(max(regex_result.risk_score, ml_risk_score), 2)
    merged_decision = regex_result.decision
    gemini_reason = ""

    # Merge ML decision (take stricter)
    decision_rank = {"allow": 0, "warn": 1, "block": 2}
    if decision_rank.get(ml_decision, 0) > decision_rank.get(merged_decision, 0):
        merged_decision = ml_decision

    # Merge Gemini results if available
    if gemini_result is not None:
        gemini_score = gemini_result.get("risk_score", 0.0)
        gemini_decision = gemini_result.get("decision", "allow")
        gemini_categories = gemini_result.get("categories", [])
        gemini_reason = gemini_result.get("reason", "")

        merged_categories = list(set(merged_categories + gemini_categories))
        merged_score = round(max(merged_score, gemini_score), 2)

        if decision_rank.get(gemini_decision, 0) > decision_rank.get(merged_decision, 0):
            merged_decision = gemini_decision

    # Re-derive decision from merged score if it disagrees
    if merged_score >= BLOCK_THRESHOLD and merged_decision != "block":
        merged_decision = "block"
    elif merged_score >= WARN_THRESHOLD and merged_decision == "allow":
        merged_decision = "warn"

    return AnalysisResult(
        risk_score=merged_score,
        decision=merged_decision,
        detected_categories=merged_categories,
        sanitized_prompt=regex_result.sanitized_prompt,
        gemini_reason=gemini_reason,
        ml_prediction=ml_prediction,
    )
