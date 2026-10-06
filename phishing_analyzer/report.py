"""
Formats a ScoredEmail into something a human can read on a terminal, or
into a JSON blob for piping into something else.
"""

from __future__ import annotations

import json
from typing import Optional

from .email_parser import ParsedEmail
from .scorer import ScoredEmail

RISK_LABEL_DISPLAY = {
    "low": "LOW",
    "medium": "MEDIUM",
    "high": "HIGH",
}


def build_report_dict(parsed: ParsedEmail, scored: ScoredEmail, source_file: str) -> dict:
    return {
        "file": source_file,
        "score": scored.score,
        "risk_label": scored.risk_label,
        "from": parsed.from_header,
        "from_address": parsed.from_address,
        "subject": parsed.subject,
        "signals": [
            {
                "key": r.key,
                "triggered": r.triggered,
                "severity": r.severity,
                "weight_contribution": scored.contributions.get(r.key, 0),
                "summary": r.summary,
                "details": r.details,
            }
            for r in scored.signal_results
        ],
        "parse_warnings": parsed.parse_warnings,
    }


def format_text_report(parsed: ParsedEmail, scored: ScoredEmail, source_file: str, verbose: bool = False) -> str:
    lines = []
    lines.append(f"file:      {source_file}")
    lines.append(f"from:      {parsed.from_header or '(missing)'}")
    lines.append(f"subject:   {parsed.subject or '(missing)'}")
    lines.append("")
    lines.append(f"score:     {scored.score} / 100")
    lines.append(f"risk:      {RISK_LABEL_DISPLAY.get(scored.risk_label, scored.risk_label.upper())}")
    lines.append("")
    lines.append("signals:")

    for result in scored.signal_results:
        contribution = scored.contributions.get(result.key, 0)
        mark = "[X]" if result.triggered else "[ ]"
        lines.append(f"  {mark} {result.key:<26} +{contribution:>5.1f}  {result.summary}")
        if verbose and result.details:
            for detail in result.details:
                lines.append(f"        - {detail}")

    if parsed.parse_warnings:
        lines.append("")
        lines.append("parse warnings:")
        for warning in parsed.parse_warnings:
            lines.append(f"  - {warning}")

    return "\n".join(lines)


def format_json_report(parsed: ParsedEmail, scored: ScoredEmail, source_file: str) -> str:
    return json.dumps(build_report_dict(parsed, scored, source_file), indent=2, default=str)


def format_batch_summary(reports: list) -> str:
    """reports is a list of (source_file, ScoredEmail or None, error or None) tuples."""
    lines = []
    lines.append(f"{'file':<40} {'score':>6}  {'risk':<8} status")
    lines.append("-" * 80)

    for source_file, scored, error in reports:
        if error is not None:
            lines.append(f"{source_file:<40} {'--':>6}  {'--':<8} error: {error}")
            continue
        lines.append(
            f"{source_file:<40} {scored.score:>6.1f}  {RISK_LABEL_DISPLAY.get(scored.risk_label, scored.risk_label):<8} ok"
        )

    return "\n".join(lines)
