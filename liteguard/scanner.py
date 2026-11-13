"""Lightweight, dependency-free security scanner.

The "lite" method: fast regex rules + Shannon-entropy checks, no network,
no heavy dependencies. Good enough to catch the common mistakes
(leaked keys, eval(), shell=True, weak hashes) before they reach GitHub.
"""
from __future__ import annotations

import fnmatch
import math
import os
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, Iterator

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    pattern: re.Pattern
    category: str  # "secret" or "code"
    extensions: tuple[str, ...] = ()  # empty = all text files


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str
    file: str
    line: int
    snippet: str
    ai_verdict: str | None = None
    ai_note: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def _r(p: str, flags: int = 0) -> re.Pattern:
    return re.compile(p, flags)


PY = (".py",)
JS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")

RULES: list[Rule] = [
    # ---- Secrets -------------------------------------------------------
    Rule("SEC001", "AWS access key ID", "critical", _r(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "secret"),
    Rule("SEC002", "GitHub token", "critical", _r(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "secret"),
    Rule("SEC003", "Anthropic API key", "critical", _r(r"\bsk-ant-[A-Za-z0-9_\-]{20,}"), "secret"),
    Rule("SEC004", "OpenAI-style API key", "high", _r(r"\bsk-(proj-)?[A-Za-z0-9]{32,}\b"), "secret"),
    Rule("SEC005", "Slack token", "high", _r(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), "secret"),
    Rule("SEC006", "Private key block", "critical", _r(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY"), "secret"),
    Rule("SEC007", "Google API key", "high", _r(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "secret"),
    Rule(
        "SEC008",
        "Hardcoded password/secret assignment",
        "medium",
        _r(r"""(?i)\b(password|passwd|pwd|secret|api_?key|token)\b\s*[:=]\s*['"][^'"\s]{6,}['"]"""),
        "secret",
    ),
    # ---- Risky code (Python) ------------------------------------------
    Rule("PY001", "Use of eval()/exec()", "high", _r(r"(?<![\w.])(eval|exec)\s*\("), "code", PY),
    Rule("PY002", "subprocess with shell=True", "high", _r(r"subprocess\.\w+\(.*shell\s*=\s*True"), "code", PY),
    Rule("PY003", "os.system call", "medium", _r(r"\bos\.system\s*\("), "code", PY),
    Rule("PY004", "Unsafe pickle load", "high", _r(r"\bpickle\.loads?\s*\("), "code", PY),
    Rule("PY005", "yaml.load without SafeLoader", "medium", _r(r"\byaml\.load\s*\((?!.*Safe)"), "code", PY),
    Rule("PY006", "Weak hash (MD5/SHA1)", "low", _r(r"\bhashlib\.(md5|sha1)\s*\("), "code", PY),
    Rule("PY007", "TLS verification disabled", "high", _r(r"verify\s*=\s*False"), "code", PY),
    Rule("PY008", "Possible SQL injection (string-built query)", "high",
         _r(r"""(?i)\.execute\s*\(\s*(f['"]|['"].*['"]\s*(%|\+|\.format))"""), "code", PY),
    Rule("PY009", "Flask debug mode on", "medium", _r(r"\.run\(.*debug\s*=\s*True"), "code", PY),
    # ---- Risky code (JavaScript/TypeScript) ---------------------------
    Rule("JS001", "Use of eval()", "high", _r(r"(?<![\w.])eval\s*\("), "code", JS),
    Rule("JS002", "innerHTML assignment (XSS risk)", "medium", _r(r"\.innerHTML\s*="), "code", JS),
    Rule("JS003", "child_process exec", "medium", _r(r"\bchild_process\b|\bexecSync\s*\("), "code", JS),
    Rule("JS004", "dangerouslySetInnerHTML", "medium", _r(r"dangerouslySetInnerHTML"), "code", JS),
]

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".tox", ".mypy_cache"}
TEXT_EXTS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json", ".yml", ".yaml", ".toml",
    ".ini", ".cfg", ".env", ".sh", ".ps1", ".rb", ".go", ".java", ".php", ".cs", ".tf",
    ".txt", ".md", ".xml", ".properties", ".conf",
}
MAX_FILE_BYTES = 1_000_000
IGNORE_MARKER = "liteguard: ignore"

# Long random-looking strings in quotes, e.g. "9fK2...". Flagged only if entropy is high.
_HIGH_ENTROPY_CANDIDATE = re.compile(r"""['"]([A-Za-z0-9+/=_\-]{24,})['"]""")
ENTROPY_THRESHOLD = 4.3


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def iter_files(root: Path) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            p = Path(dirpath) / name
            if p.suffix.lower() in TEXT_EXTS or name.startswith(".env"):
                yield p


def _read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None


def _mask(line: str, start: int, end: int) -> str:
    """Hide most of a secret so reports never re-leak it."""
    secret = line[start:end]
    keep = min(4, len(secret) // 4)
    masked = secret[:keep] + "*" * max(4, len(secret) - keep)
    return (line[:start] + masked + line[end:]).strip()[:200]


def scan_text(text: str, rel_path: str, rules: Iterable[Rule] = RULES) -> list[Finding]:
    suffix = Path(rel_path).suffix.lower()
    active = [r for r in rules if not r.extensions or suffix in r.extensions]
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if IGNORE_MARKER in line:
            continue
        hit_on_line = False
        for rule in active:
            m = rule.pattern.search(line)
            if not m:
                continue
            hit_on_line = True
            snippet = _mask(line, m.start(), m.end()) if rule.category == "secret" else line.strip()[:200]
            findings.append(Finding(rule.id, rule.title, rule.severity, rule.category, rel_path, lineno, snippet))
        if hit_on_line:
            continue
        for m in _HIGH_ENTROPY_CANDIDATE.finditer(line):
            token = m.group(1)
            if shannon_entropy(token) >= ENTROPY_THRESHOLD:
                findings.append(Finding(
                    "ENT001", "High-entropy string (possible secret)", "medium", "secret",
                    rel_path, lineno, _mask(line, m.start(1), m.end(1)),
                ))
                break
    return findings


def load_ignore(base: Path) -> list[str]:
    """Glob patterns from .liteguardignore (one per line, # for comments)."""
    p = base / ".liteguardignore"
    if not p.is_file():
        return []
    lines = (ln.strip() for ln in p.read_text(encoding="utf-8").splitlines())
    return [ln for ln in lines if ln and not ln.startswith("#")]


def _ignored(rel: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel, pat) or rel.startswith(pat.rstrip("/") + "/") for pat in patterns)


def scan_path(root: str | Path, exclude: Iterable[str] = ()) -> list[Finding]:
    root = Path(root).resolve()
    base = root if root.is_dir() else root.parent
    patterns = load_ignore(base) + list(exclude)
    results: list[Finding] = []
    for f in iter_files(root):
        rel = f.relative_to(base).as_posix()
        if _ignored(rel, patterns):
            continue
        text = _read_text(f)
        if text is None:
            continue
        results.extend(scan_text(text, rel))
    results.sort(key=lambda x: (-SEVERITY_ORDER[x.severity], x.file, x.line))
    return results
