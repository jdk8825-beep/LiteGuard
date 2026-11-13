# LiteGuard

**A lightweight, AI-assisted security scanner.** Catch leaked secrets and risky code before they reach GitHub.

LiteGuard works in two layers:

1. **Lite mode (default):** fast regex rules + Shannon-entropy checks. Zero dependencies, no network, runs in under a second on most repos.
2. **AI mode (`--ai`, optional):** sends each finding (with secrets masked) to Claude, which labels it `true_positive`, `false_positive` or `needs_review` and suggests a fix. Findings the AI marks as false positives don't fail the build.

## Watch how it works

A 3-minute narrated walkthrough: [docs/liteguard-explainer.mp4](docs/liteguard-explainer.mp4) (open it and choose **View raw** to download or play). The interactive version of the same explainer is [docs/explainer.html](docs/explainer.html).

## What it finds

| Category | Examples |
|---|---|
| Secrets | AWS / GitHub / Anthropic / OpenAI / Slack / Google keys, private key blocks, hardcoded passwords, high-entropy strings |
| Python | `eval`/`exec`, `shell=True`, `os.system`, `pickle.load`, unsafe `yaml.load`, `verify=False`, string-built SQL, MD5/SHA1, Flask `debug=True` |
| JavaScript / TypeScript | `eval`, `innerHTML =`, `dangerouslySetInnerHTML`, `child_process` |

Secrets are **masked** in every report and before anything is sent to the AI.

## Install

```bash
pip install -e .            # lite mode
pip install -e ".[ai]"      # + AI triage
```

## Use

```bash
liteguard scan .                          # human-readable report
liteguard scan src/ --format json         # machine-readable
liteguard scan . --format sarif -o out.sarif   # GitHub code scanning
liteguard scan . --ai                     # Claude triage (needs ANTHROPIC_API_KEY)
liteguard scan . --fail-on medium         # stricter CI gate
```

Exit code is `1` when a finding at or above `--fail-on` (default `high`) is present, so it works as a CI gate or pre-commit hook.

Silence a reviewed line with a comment: `# liteguard: ignore`.

## GitHub Actions

`.github/workflows/liteguard.yml` runs the tests and scans every push and pull request, uploading results to the repository's **Security → Code scanning** tab. To turn on AI triage in CI, add an `ANTHROPIC_API_KEY` repository secret and append `--ai` to the scan step.

## Pre-commit hook

```bash
echo 'liteguard scan . --fail-on high' > .git/hooks/pre-commit
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT
