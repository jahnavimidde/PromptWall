"""Unit tests for the GLiNER layer's precision calibration (no model load).

The role-noun suppressor labels and per-label floors are the precision layer; the
full model integration is covered by benchmarks/pii-accuracy.
"""

from unittest.mock import Mock

import pytest

from detector.gliner_layer import (
    _MAX_TOKENS,
    _SUPPRESS_LABELS,
    _TOKEN_RE,
    PER_LABEL_FLOOR,
    Span,
    _windows,
    detect_gliner,
)


def test_token_re_matches_gliner_splitter():
    # Windowing correctness depends on our token regex matching GLiNER's own
    # splitter exactly; pin it so a GLiNER change to the pattern fails here
    # instead of silently truncating long inputs past the token limit.
    try:
        from gliner.data_processing.tokenizer import WhitespaceTokenSplitter
    except Exception:
        pytest.skip("gliner WhitespaceTokenSplitter not importable")
    assert _TOKEN_RE.pattern == WhitespaceTokenSplitter().whitespace_pattern.pattern


def test_role_nouns_handled_by_suppressor_labels():
    # Generic role nouns are disambiguated language-agnostically by competing
    # suppressor labels rather than any hard-coded denylist.
    assert "customer" in _SUPPRESS_LABELS


def test_windows_single_for_short_text():
    text = "Mario Rossi lives in Rome."
    assert list(_windows(text)) == [(0, text)]


def test_windows_overlapping_and_cover_long_text():
    # > _MAX_TOKENS word-tokens -> multiple windows that slice the original text
    # correctly and reach the end (so trailing PII is never dropped).
    text = " ".join(f"word{i}" for i in range(_MAX_TOKENS * 4))
    wins = list(_windows(text))
    assert len(wins) > 1
    for off, sub in wins:
        assert text[off : off + len(sub)] == sub
    last_off, last_sub = wins[-1]
    assert last_off + len(last_sub) == len(text)


def test_per_label_floors_present_and_ordered():
    assert set(PER_LABEL_FLOOR) == {"person", "location", "address"}
    assert all(0.0 <= v <= 1.0 for v in PER_LABEL_FLOOR.values())
    # Person carries a stricter floor than location: higher volume and no
    # structural validator, so a higher floor curbs false positives.
    assert PER_LABEL_FLOOR["location"] <= PER_LABEL_FLOOR["person"]


def test_window_inference_cache(monkeypatch):
    repeated_text = "This is going to repeat, don't waste resources more than once!"
    cache_missed_text = "This appears for the first time, it will increase the model call count."

    mock_predictions = {
        repeated_text: [{"start": 0, "end": 1, "label": "person", "score": 1.0}],
        cache_missed_text: [{"start": 0, "end": 1, "label": "person", "score": 1.0}],
    }

    mock_gliner = Mock()
    mock_gliner.predict_entities.side_effect = lambda text, *_, **__: mock_predictions[text]
    monkeypatch.setattr("detector.gliner_layer._model", mock_gliner)

    expected = [
        Span(
            entity_type="PERSON",
            start=0,
            end=1,
            score=1.0,
        )
    ]

    assert detect_gliner(cache_missed_text, 0.0) == expected

    for _ in range(5):
        assert detect_gliner(repeated_text, 0.0) == expected

    # Hits once for the original cache miss, and only once more for the repeated content
    assert mock_gliner.predict_entities.call_count == 2
