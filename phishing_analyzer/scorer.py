"""
Turns a list of SignalResults into a single 0 to 100 score and a risk label.

The weights below are the point value each signal contributes when it fires
at full severity (severity 1.0). A signal that triggers at partial severity
contributes proportionally less. I picked these numbers based on gut feel
about which signals matter more, not from any dataset, see the README for
the reasoning. They are meant to be edited. Pass a different weights dict
into Scorer if the defaults do not match how you want to prioritize things.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from .signals import SignalResult

DEFAULT_WEIGHTS: Dict[str, float] = {
    "authentication": 22,
    "reply_to_mismatch": 8,
    "suspicious_links": 20,
    "urgency_language": 8,
    "spoofed_display_name": 17,
    "attachment_flags": 15,
    "newly_registered_domain": 10,
}

DEFAULT_THRESHOLDS = {
    "low": 0,
    "medium": 30,
    "high": 60,
}


@dataclass
class ScoredEmail:
    score: float
    risk_label: str
    contributions: Dict[str, float]
    signal_results: List[SignalResult] = field(default_factory=list)


class Scorer:
    def __init__(self, weights: Dict[str, float] = None, thresholds: Dict[str, int] = None):
        self.weights = dict(DEFAULT_WEIGHTS if weights is None else weights)
        self.thresholds = dict(DEFAULT_THRESHOLDS if thresholds is None else thresholds)

    def score(self, signal_results: List[SignalResult]) -> ScoredEmail:
        contributions: Dict[str, float] = {}
        raw_total = 0.0

        for result in signal_results:
            weight = self.weights.get(result.key, 0)
            contribution = round(weight * result.severity, 2)
            contributions[result.key] = contribution
            raw_total += contribution

        capped_score = max(0.0, min(raw_total, 100.0))
        label = self._label_for_score(capped_score)

        return ScoredEmail(
            score=round(capped_score, 1),
            risk_label=label,
            contributions=contributions,
            signal_results=signal_results,
        )

    def _label_for_score(self, score: float) -> str:
        if score >= self.thresholds["high"]:
            return "high"
        if score >= self.thresholds["medium"]:
            return "medium"
        return "low"


def load_weights_from_file(path: str) -> Dict[str, float]:
    """Load a custom weights config from a JSON file.

    The file should look like the DEFAULT_WEIGHTS dict above, keys are
    signal names, values are point contributions at full severity. You do
    not need to include every signal, anything left out just falls back to
    a weight of 0 for that signal, which effectively disables it.
    """
    import json

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError("weights config file must contain a JSON object")

    return {str(k): float(v) for k, v in data.items()}
