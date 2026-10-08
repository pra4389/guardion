"""
Prompt Security API Routes
Handles prompt analysis requests from the Chrome extension.
Includes ML model + Gemini side-by-side comparison endpoint.
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends

from app.config import settings
from app.models.schemas import (
    PromptAnalysisRequest,
    PromptAnalysisResponse,
    MLCompareRequest,
    MLCompareResponse,
)
from app.services.prompt_analyzer import analyze_prompt, analyze_prompt_combined
from app.services.auth_service import get_current_user, get_optional_user
from app.db.mongodb import prompt_logs_collection

logger = logging.getLogger("guardion.prompt_routes")

router = APIRouter(prefix="/api", tags=["Prompt Security"])


def _insert_prompt_log(doc: dict) -> None:
    """Blocking pymongo insert, run inside a worker thread."""
    try:
        prompt_logs_collection().insert_one(doc)
    except Exception as e:
        logger.warning(f"MongoDB log failed: {e}")


# ──────────────────── Quota / Economy Status ────────────────────


@router.get("/quota_status")
async def quota_status():
    """
    Return current Gemini API quota usage so the frontend can show it.
    Helps users understand how much quota they have left.
    """
    from app.services.gemini_cache import gemini_cache, gemini_rate_limiter

    return {
        "economy_mode": settings.ECONOMY_MODE,
        "gemini_configured": bool(settings.GEMINI_API_KEY and settings.GEMINI_API_KEY != "your_gemini_api_key_here"),
        "rate_limiter": {
            "calls_remaining": gemini_rate_limiter.calls_remaining,
            "max_calls_per_minute": gemini_rate_limiter.max_calls,
            "in_cooldown": gemini_rate_limiter._quota_exhausted_until > __import__("time").time(),
            "circuit_open": gemini_rate_limiter.circuit_open,
        },
        "cache": gemini_cache.stats,
    }


@router.post("/analyze_prompt", response_model=PromptAnalysisResponse)
async def analyze_prompt_endpoint(
    request: PromptAnalysisRequest,
    current_user: Optional[dict] = Depends(get_optional_user),
):
    """
    Analyze a prompt for sensitive information.

    Pipeline:
      1. Regex pattern matching (fast, deterministic)
      2. Gemini contextual analysis (catches obfuscated/novel leaks)
      3. Merge: stricter decision wins, categories unioned

    Falls back to regex-only if Gemini is unavailable.
    Called by the Chrome extension before a prompt is sent to an AI chat tool.
    """
    # Combined analysis: regex-only by default, Gemini only when requested
    result = await analyze_prompt_combined(
        request.prompt, sanitize=True, use_gemini=request.use_gemini
    )

    # Log to MongoDB in a background thread — the sync pymongo driver would
    # otherwise block the event loop (and every concurrent request) for the
    # full Atlas round-trip. The response must not wait on audit logging.
    user_id = current_user["_id"] if current_user else "anonymous"
    doc = {
        "user_id": user_id,
        "prompt_text": request.prompt[:2000],
        "risk_score": result.risk_score,
        "decision": result.decision,
        "detected_categories": result.detected_categories,
        "source_site": request.source,
        "ml_prediction": result.ml_prediction,
        "result": {
            "is_threat": result.decision in ("block", "warn"),
            "risk_score": result.risk_score,
        },
        "created_at": datetime.now(timezone.utc),
    }
    loop = asyncio.get_running_loop()
    future = loop.run_in_executor(None, lambda: _insert_prompt_log(doc))
    future.add_done_callback(lambda f: f.exception() and logger.warning(f"MongoDB log failed: {f.exception()}"))

    return PromptAnalysisResponse(
        risk_score=result.risk_score,
        decision=result.decision,
        detected_categories=result.detected_categories,
        sanitized_prompt=result.sanitized_prompt,
        reason=result.gemini_reason,
        ml_prediction=result.ml_prediction if result.ml_prediction else None,
    )


# ──────────────────── ML + Gemini Comparison Endpoint ────────────────────


@router.post("/ml_compare", response_model=MLCompareResponse)
async def ml_compare_endpoint(request: MLCompareRequest):
    """
    Classify a prompt with BOTH the local ML model and Gemini API,
    returning a side-by-side comparison.

    Pipeline:
      1. Local ML model (sentence-transformers + logistic regression)
      2. Gemini API classification
      3. Combined decision (stricter of the two wins)
    """
    from guardion_ai_model.gemini_compare import compare_analysis
    from guardion_ai_model.inference import analyze_prompt as local_analyze

    try:
        if request.use_gemini:
            result = await compare_analysis(request.prompt, settings.GEMINI_API_KEY)
            return MLCompareResponse(
                prompt=result["prompt"],
                local_model=result["local_model"],
                gemini_analysis=result["gemini_analysis"],
                decision=result["decision"],
                agreement=result["agreement"],
            )
        else:
            # Local ML model only — no Gemini API call
            local_result = local_analyze(request.prompt)
            from guardion_ai_model.gemini_compare import DECISION_MAP
            decision = DECISION_MAP.get(local_result["prediction"], "WARN")
            return MLCompareResponse(
                prompt=request.prompt,
                local_model=local_result,
                gemini_analysis=None,
                decision=decision,
                agreement=None,
            )
    except FileNotFoundError:
        # Model not yet trained
        logger.warning("ML model not found. Run train_model.py first.")
        return MLCompareResponse(
            prompt=request.prompt,
            local_model={
                "prediction": "error",
                "confidence": 0.0,
                "all_scores": {},
                "error": "Model not trained. Run: python -m guardion_ai_model.train_model",
            },
            gemini_analysis={
                "prediction": "unknown",
                "confidence": 0.0,
                "explanation": "Skipped due to local model error",
            },
            decision="WARN",
            agreement=False,
        )
    except Exception as e:
        logger.error(f"ML compare error: {e}")
        return MLCompareResponse(
            prompt=request.prompt,
            local_model={"prediction": "error", "confidence": 0.0, "all_scores": {}, "error": str(e)},
            gemini_analysis={"prediction": "unknown", "confidence": 0.0, "explanation": str(e)},
            decision="WARN",
            agreement=False,
        )
