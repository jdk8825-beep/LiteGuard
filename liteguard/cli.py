"""Command line entry point:  liteguard scan [PATH] [--ai] [--format text|json|sarif]"""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .scanner import SEVERITY_ORDER, RULES, Finding, scan_path

COLORS = {"critical": "\033[95m", "high": "\033[91m", "medium": "\033[93m", "low": "\033[94m"}
RESET = "\033[0m"


def _text_report(findings: list[Finding], color: bool) -> str:
    if not findings:
        return "LiteGuard: no issues found."
    out = []
    for f in findings:
        sev = f.severity.upper()
        if color:
            sev = f"{COLORS[f.severity]}{sev}{RESET}"
        out.append(f"[{sev}] {f.rule_id} {f.title}\n    {f.file}:{f.line}  {f.snippet}")
        if f.ai_verdict:
            out.append(f"    AI: {f.ai_verdict} - {f.ai_note}")
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_ORDER}
    summary = ", ".join(f"{n} {s}" for s, n in sorted(counts.items(), key=lambda kv: -SEVERITY_ORDER[kv[0]]) if n)
    out.append(f"\nLiteGuard: {len(findings)} finding(s) - {summary}")
    return "\n".join(out)


def _sarif(findings: list[Finding]) -> dict:
    """SARIF 2.1.0 so results show up in GitHub's Security > Code scanning tab."""
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "LiteGuard", "version": __version__,
                "rules": [{"id": r.id, "shortDescription": {"text": r.title}} for r in RULES]
                + [{"id": "ENT001", "shortDescription": {"text": "High-entropy string (possible secret)"}}],
            }},
            "results": [{
                "ruleId": f.rule_id,
                "level": level[f.severity],
                "message": {"text": f.title + (f" (AI: {f.ai_verdict} - {f.ai_note})" if f.ai_verdict else "")},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": f.line},
                }}],
            } for f in findings],
        }],
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="liteguard", description="Lightweight AI-assisted security scanner.")
    p.add_argument("--version", action="version", version=f"liteguard {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan a file or directory")
    s.add_argument("path", nargs="?", default=".")
    s.add_argument("--ai", action="store_true", help="triage findings with Claude (needs anthropic SDK + API key)")
    s.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    s.add_argument("--output", "-o", help="write report to file instead of stdout")
    s.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default="high",
                   help="exit 1 if any finding is at or above this severity (default: high)")
    s.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                   help="skip matching paths (repeatable); also read from .liteguardignore")
    s.add_argument("--no-color", action="store_true")
    args = p.parse_args(argv)

    findings = scan_path(args.path, exclude=args.exclude)
    if args.ai and findings:
        from .ai import triage
        triage(findings, args.path)

    if args.format == "json":
        report = json.dumps([f.to_dict() for f in findings], indent=2)
    elif args.format == "sarif":
        report = json.dumps(_sarif(findings), indent=2)
    else:
        report = _text_report(findings, color=not args.no_color and not args.output and sys.stdout.isatty())

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
        print(f"LiteGuard: wrote {len(findings)} finding(s) to {args.output}")
    else:
        print(report)

    threshold = SEVERITY_ORDER[args.fail_on]
    blocking = [f for f in findings
                if SEVERITY_ORDER[f.severity] >= threshold and f.ai_verdict != "false_positive"]
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(main())
