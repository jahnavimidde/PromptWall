"""Semantic Prompt Injection Layer using HuggingFace sequence classification.

Loads a fine-tuned prompt injection classification model (default:
fmops/distilbert-prompt-injection) to compute probability scores for indirect
instruction extraction, persona jailbreaks, and paraphrased attacks.
"""

from __future__ import annotations

import os
import threading
from typing import Any

DEFAULT_INJECTION_MODEL = "fmops/distilbert-prompt-injection"

_tokenizer: Any = None
_model: Any = None
_injection_label_idx: int = 1
_lock = threading.Lock()
_infer_lock = threading.Lock()


def _get_model_name() -> str:
    return (
        os.environ.get("DETECTOR_INJECTION_MODEL_PATH")
        or os.environ.get("DETECTOR_INJECTION_MODEL")
        or DEFAULT_INJECTION_MODEL
    )


def load_semantic_model() -> None:
    """Load the model and tokenizer once. Safe to call at startup or lazily."""
    global _tokenizer, _model, _injection_label_idx
    if _model is not None and _tokenizer is not None:
        return
    with _lock:
        if _model is not None and _tokenizer is not None:
            return

        model_name = _get_model_name()
        try:
            from transformers import AutoModelForSequenceClassification, AutoTokenizer

            try:
                _tokenizer = AutoTokenizer.from_pretrained(model_name, local_files_only=True)
                _model = AutoModelForSequenceClassification.from_pretrained(
                    model_name, local_files_only=True
                )
            except Exception:
                try:
                    _tokenizer = AutoTokenizer.from_pretrained(model_name)
                    _model = AutoModelForSequenceClassification.from_pretrained(model_name)
                except Exception as e:
                    print(f"Warning: Semantic injection model load deferred: {e}")
                    return

            _model.eval()

            # Determine injection class index dynamically from model config
            _injection_label_idx = 1
            if hasattr(_model.config, "id2label") and _model.config.id2label:
                for idx, label in _model.config.id2label.items():
                    lbl_upper = str(label).upper()
                    if "INJECT" in lbl_upper or "JAILBREAK" in lbl_upper or lbl_upper == "LABEL_1":
                        _injection_label_idx = int(idx)
                        break
        except Exception as e:
            print(f"Warning: Failed to initialize transformers: {e}")


def predict_injection(text: str) -> dict[str, Any]:
    """Compute prompt injection probability score for the given text.

    Returns:
        {
            "score": float in [0.0, 1.0],
            "label": "INJECTION" | "SAFE",
            "intent": "PROMPT_INJECTION"
        }
    """
    if not text or not text.strip():
        return {
            "score": 0.0,
            "label": "SAFE",
            "intent": "PROMPT_INJECTION",
        }

    load_semantic_model()

    if _model is None or _tokenizer is None:
        raise RuntimeError("Semantic injection model is not available")

    import torch

    with _infer_lock:
        inputs = _tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=512,
        )
        with torch.no_grad():
            outputs = _model(**inputs)
            probs = torch.softmax(outputs.logits, dim=-1)[0]
            score = float(probs[_injection_label_idx].item())

    score_rounded = round(score, 4)
    label = "INJECTION" if score_rounded >= 0.5 else "SAFE"

    return {
        "score": score_rounded,
        "label": label,
        "intent": "PROMPT_INJECTION",
    }
