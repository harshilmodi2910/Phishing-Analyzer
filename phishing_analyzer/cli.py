"""
Command line entry point.

Usage examples:
    python -m phishing_analyzer.cli --file sample.eml
    python -m phishing_analyzer.cli --file sample.eml --json-out result.json
    python -m phishing_analyzer.cli --batch tests/sample_emails/
    python -m phishing_analyzer.cli --file sample.eml --weights-config my_weights.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from .email_parser import EmailParseError, parse_eml_file
from .report import (
    build_report_dict,
    format_batch_summary,
    format_json_report,
    format_text_report,
)
from .scorer import Scorer, load_weights_from_file
from .signals import run_all_signals


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishnet",
        description="Scores a raw .eml file for how likely it is to be a phishing attempt.",
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--file", metavar="PATH", help="path to a single .eml file")
    input_group.add_argument(
        "--batch", metavar="DIR", help="path to a directory of .eml files to scan"
    )

    parser.add_argument(
        "--json-out", metavar="PATH", help="write the full JSON report to this path"
    )
    parser.add_argument(
        "--weights-config",
        metavar="PATH",
        help="path to a JSON file overriding the default signal weights",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="print per-signal detail lines in the text report",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress the text report, useful when you only care about --json-out",
    )

    return parser


def _build_scorer(weights_config: Optional[str]) -> Scorer:
    if weights_config:
        weights = load_weights_from_file(weights_config)
        return Scorer(weights=weights)
    return Scorer()


def _analyze_one(file_path: str, scorer: Scorer):
    parsed = parse_eml_file(file_path)
    signal_results = run_all_signals(parsed)
    scored = scorer.score(signal_results)
    return parsed, scored


def run_single(args: argparse.Namespace) -> int:
    scorer = _build_scorer(args.weights_config)

    try:
        parsed, scored = _analyze_one(args.file, scorer)
    except EmailParseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if not args.quiet:
        print(format_text_report(parsed, scored, args.file, verbose=args.verbose))

    if args.json_out:
        report_dict = build_report_dict(parsed, scored, args.file)
        Path(args.json_out).write_text(json.dumps(report_dict, indent=2, default=str))
        if not args.quiet:
            print(f"\nfull JSON report written to {args.json_out}")

    return 0


def run_batch(args: argparse.Namespace) -> int:
    scorer = _build_scorer(args.weights_config)
    batch_dir = Path(args.batch)

    if not batch_dir.is_dir():
        print(f"error: {args.batch} is not a directory", file=sys.stderr)
        return 1

    eml_files = sorted(batch_dir.glob("*.eml"))
    if not eml_files:
        print(f"error: no .eml files found in {args.batch}", file=sys.stderr)
        return 1

    results = []
    all_reports = []

    for eml_file in eml_files:
        try:
            parsed, scored = _analyze_one(str(eml_file), scorer)
            results.append((str(eml_file), scored, None))
            all_reports.append(build_report_dict(parsed, scored, str(eml_file)))
        except EmailParseError as exc:
            results.append((str(eml_file), None, str(exc)))

    if not args.quiet:
        print(format_batch_summary(results))

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(all_reports, indent=2, default=str))
        if not args.quiet:
            print(f"\nfull JSON report written to {args.json_out}")

    return 0


def main(argv=None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.file:
        return run_single(args)
    return run_batch(args)


if __name__ == "__main__":
    sys.exit(main())
