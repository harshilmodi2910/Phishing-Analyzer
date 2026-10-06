import json

import pytest

from phishing_analyzer.scorer import DEFAULT_WEIGHTS, Scorer, load_weights_from_file
from phishing_analyzer.signals import SignalResult


def make_signal(key, triggered, severity, summary="test"):
    return SignalResult(key=key, triggered=triggered, severity=severity, summary=summary)


def test_no_signals_triggered_gives_zero_score():
    scorer = Scorer()
    results = [make_signal(key, False, 0.0) for key in DEFAULT_WEIGHTS]
    scored = scorer.score(results)
    assert scored.score == 0.0
    assert scored.risk_label == "low"


def test_all_signals_full_severity_caps_at_100():
    scorer = Scorer()
    results = [make_signal(key, True, 1.0) for key in DEFAULT_WEIGHTS]
    scored = scorer.score(results)
    assert scored.score == 100.0
    assert scored.risk_label == "high"


def test_partial_severity_scales_contribution():
    scorer = Scorer()
    results = [make_signal("authentication", True, 0.5)]
    scored = scorer.score(results)
    expected = round(DEFAULT_WEIGHTS["authentication"] * 0.5, 2)
    assert scored.contributions["authentication"] == expected
    assert scored.score == round(expected, 1)


def test_unknown_signal_key_contributes_nothing():
    scorer = Scorer()
    results = [make_signal("not_a_real_signal", True, 1.0)]
    scored = scorer.score(results)
    assert scored.score == 0.0


def test_custom_weights_override_defaults():
    scorer = Scorer(weights={"authentication": 100})
    results = [make_signal("authentication", True, 1.0)]
    scored = scorer.score(results)
    assert scored.score == 100.0


def test_custom_thresholds():
    scorer = Scorer(thresholds={"low": 0, "medium": 10, "high": 20})
    results = [make_signal("authentication", True, 0.5)]  # 22 * 0.5 = 11
    scored = scorer.score(results)
    assert scored.risk_label == "medium"


@pytest.mark.parametrize(
    "score,expected_label",
    [
        (0, "low"),
        (29, "low"),
        (30, "medium"),
        (59, "medium"),
        (60, "high"),
        (100, "high"),
    ],
)
def test_default_threshold_boundaries(score, expected_label):
    scorer = Scorer()
    label = scorer._label_for_score(score)
    assert label == expected_label


def test_load_weights_from_file(tmp_path):
    weights_file = tmp_path / "weights.json"
    weights_file.write_text(json.dumps({"authentication": 50, "urgency_language": 10}))

    weights = load_weights_from_file(str(weights_file))
    assert weights["authentication"] == 50.0
    assert weights["urgency_language"] == 10.0


def test_load_weights_from_file_rejects_non_object(tmp_path):
    weights_file = tmp_path / "bad_weights.json"
    weights_file.write_text(json.dumps([1, 2, 3]))

    with pytest.raises(ValueError):
        load_weights_from_file(str(weights_file))


def test_score_never_negative_even_with_bad_weights():
    scorer = Scorer(weights={"authentication": -50})
    results = [make_signal("authentication", True, 1.0)]
    scored = scorer.score(results)
    assert scored.score == 0.0
