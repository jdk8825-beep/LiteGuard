"""Optional AI triage: asks Claude to label each finding as a real issue or a
false positive and suggest a fix.

Only the *masked* snippet plus a few lines of surrounding code are sent -
raw secrets never leave your machine. Requires `pip install anthropic` and
credentials (ANTHROPIC_API_KEY or `ant auth login`).
"""
from __future__ import annotations

import json
from pathlib import Path

from .scanner import Finding

MODEL = "claude-opus-5-5"
BATCH_SIZE = 20

SYSTEM_PROMPT = (
    "You are a pragmatic application-security reviewer. You receive findings from a "
    "lightweight regex-based scanner. For each finding decide whether it is a real "
    "security issue ('true_positive'), a false positive ('false_positive'), or you "
    "cannot tell from the context ('needs_review'). Give a one-sentence reason and, "
    "for real issues, a concrete one-line fix. Secret values are masked with '*'; judge "
    "them by variable name and context (test fixtures and placeholders are usually false positives)."
)

RESULT_SCHEMA = {
    "type": "object",
    "properties": {
        "results": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "index": {"type": "integer"},
                    "verdict": {"type": "string", "enum": ["true_positive", "false_positive", "needs_review"]},
                    "note": {"type": "string"},
                },
                "required": ["index", "verdict", "note"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["results"],
    "additionalProperties": False,
}


def _context(base: Path, f: Finding, radius: int = 3) -> str:
    """Surrounding lines for the model. The flagged line stays masked."""
    try:
        lines = (base / f.file).read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return f.snippet
    lo, hi = max(0, f.line - 1 - radius), min(len(lines), f.line + radius)
    out = []
    for i in range(lo, hi):
        text = f.snippet if i == f.line - 1 else lines[i]
        if f.category == "secret" and i != f.line - 1 and "=" in text:
            text = text.split("=", 1)[0] + "= <redacted>"
        out.append(f"{i + 1:>5}: {text[:200]}")
    return "\n".join(out)


def triage(findings: list[Finding], base: str | Path) -> list[Finding]:
    try:
        import anthropic
    except ImportError as e:  # pragma: no cover
        raise SystemExit("AI triage needs the SDK: pip install anthropic") from e

    base = Path(base).resolve()
    if base.is_file():
        base = base.parent
    client = anthropic.Anthropic()

    for start in range(0, len(findings), BATCH_SIZE):
        batch = findings[start:start + BATCH_SIZE]
        payload = [
            {"index": i, "rule": f.rule_id, "title": f.title, "file": f.file,
             "line": f.line, "context": _context(base, f)}
            for i, f in enumerate(batch)
        ]
        response = client.beta.messages.create(
            model=MODEL,
            max_tokens=16000,
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",  # retry on another model if this one declines
            output_config={
                "effort": "medium",
                "format": {"type": "json_schema", "schema": RESULT_SCHEMA},
            },
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": json.dumps(payload, indent=1)}],
        )
        if response.stop_reason == "refusal":
            for f in batch:
                f.ai_verdict, f.ai_note = "needs_review", "AI declined to review this batch."
            continue
        text = next((b.text for b in response.content if b.type == "text"), "{}")
        try:
            results = json.loads(text).get("results", [])
        except json.JSONDecodeError:
            results = []
        for r in results:
            idx = r.get("index")
            if isinstance(idx, int) and 0 <= idx < len(batch):
                batch[idx].ai_verdict = r.get("verdict")
                batch[idx].ai_note = r.get("note")
    return findings
