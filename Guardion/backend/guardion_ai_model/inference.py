"""
Guardion AI — Inference Pipeline
==================================
Loads the trained model and label encoder, then classifies new prompts.

Usage:
    from guardion_ai_model.inference import analyze_prompt
    result = analyze_prompt("My API key is sk-123456789")
    # → {"prediction": "credential_leak", "confidence": 0.92, "all_scores": {...}}
"""

import os
import threading
import numpy as np
import joblib
from sentence_transformers import SentenceTransformer

# ──────────────────── Constants ────────────────────

BASE_DIR = os.path.dirname(__file__)
MODEL_PATH = os.path.join(BASE_DIR, "model", "model.pkl")
ENCODER_PATH = os.path.join(BASE_DIR, "model", "label_encoder.pkl")
EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"

# ──────────────────── Lazy-loaded Globals ────────────────────
# Loaded once on first call to avoid startup cost if unused.

_embedding_model = None
_classifier = None
_label_encoder = None
_load_lock = threading.Lock()  # prevent concurrent double-loading (startup warmup + first request)


def _load_models():
    """Load the sentence-transformer, classifier, and label encoder into memory (once)."""
    global _embedding_model, _classifier, _label_encoder

    if _classifier is not None:
        return  # Already loaded

    with _load_lock:
        if _classifier is not None:  # re-check after acquiring the lock
            return

    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"Trained model not found at {MODEL_PATH}. "
            "Run `python -m guardion_ai_model.train_model` first."
        )

    _embedding_model = SentenceTransformer(EMBEDDING_MODEL_NAME)
    _classifier = joblib.load(MODEL_PATH)
    _label_encoder = joblib.load(ENCODER_PATH)


# ──────────────────── Public API ────────────────────

def analyze_prompt(prompt_text: str) -> dict:
    """
    Classify a single prompt using the local ML model.

    Steps:
      1. Generate sentence embedding (384-dim vector)
      2. Run logistic regression prediction
      3. Compute class probabilities

    Args:
        prompt_text: The raw prompt string to classify.

    Returns:
        {
            "prediction": "credential_leak",
            "confidence": 0.92,
            "all_scores": {
                "safe": 0.02,
                "pii_leak": 0.03,
                "credential_leak": 0.92,
                "financial_data": 0.01,
                "secret_code": 0.02
            }
        }
    """
    _load_models()

    # Step 1: Embed the prompt
    embedding = _embedding_model.encode([prompt_text])
    embedding = np.array(embedding)

    # Step 2: Predict class
    predicted_idx = _classifier.predict(embedding)[0]
    predicted_label = _label_encoder.inverse_transform([predicted_idx])[0]

    # Step 3: Get probability distribution across all classes
    probabilities = _classifier.predict_proba(embedding)[0]
    class_names = _label_encoder.classes_

    # Build score map: {label: probability}
    all_scores = {
        class_names[i]: round(float(probabilities[i]), 4)
        for i in range(len(class_names))
    }

    confidence = round(float(max(probabilities)), 4)

    return {
        "prediction": predicted_label,
        "confidence": confidence,
        "all_scores": all_scores,
    }


async def analyze_prompt_async(prompt_text: str) -> dict:
    """
    Async wrapper around analyze_prompt — runs the (CPU-bound) inference in a
    thread so the FastAPI event loop is never blocked.
    """
    import asyncio
    return await asyncio.get_event_loop().run_in_executor(None, analyze_prompt, prompt_text)


def analyze_prompt_batch(prompts: list[str]) -> list[dict]:
    """
    Classify multiple prompts efficiently in a single batch.

    Args:
        prompts: List of raw prompt strings.

    Returns:
        List of result dicts (same format as analyze_prompt).
    """
    _load_models()

    # Batch encode
    embeddings = _embedding_model.encode(prompts, batch_size=64)
    embeddings = np.array(embeddings)

    # Batch predict
    predicted_indices = _classifier.predict(embeddings)
    probabilities_batch = _classifier.predict_proba(embeddings)
    class_names = _label_encoder.classes_

    results = []
    for i, prompt in enumerate(prompts):
        predicted_label = _label_encoder.inverse_transform([predicted_indices[i]])[0]
        probs = probabilities_batch[i]
        all_scores = {
            class_names[j]: round(float(probs[j]), 4)
            for j in range(len(class_names))
        }
        results.append({
            "prediction": predicted_label,
            "confidence": round(float(max(probs)), 4),
            "all_scores": all_scores,
        })

    return results


# ──────────────────── CLI Test ────────────────────

if __name__ == "__main__":
    test_prompts = [
        "My API key is sk-123456789abcdef",
        "My email is john@gmail.com and phone is 9876543210",
        "My credit card is 4242 4242 4242 4242",
        "Explain recursion in Python",
        "Here is my private_key.pem file",
        "My password is admin123",
        "My AWS key is AKIA1234567890ABCDEF",
        "Write a bubble sort algorithm in JavaScript",
        "My SSN is 123-45-6789",
        "-----BEGIN RSA PRIVATE KEY-----",
    ]

    print("=" * 70)
    print("  Guardion Local ML — Prompt Classification")
    print("=" * 70)

    for prompt in test_prompts:
        result = analyze_prompt(prompt)
        print(f"\n📝 Prompt:     \"{prompt[:60]}...\"" if len(prompt) > 60 else f"\n📝 Prompt:     \"{prompt}\"")
        print(f"   Prediction: {result['prediction']}")
        print(f"   Confidence: {result['confidence']:.2%}")
