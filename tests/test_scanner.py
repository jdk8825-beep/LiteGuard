"""Tests for the rule engine. Fake secrets are built by string concatenation so
this file never contains a real-looking key (and never trips GitHub push protection)."""
import json

from liteguard.cli import main
from liteguard.scanner import scan_text, shannon_entropy

FAKE_AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
FAKE_GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
FAKE_ANT = "sk-ant-" + "api03-" + "x" * 30


def ids(text, path="app.py"):
    return {f.rule_id for f in scan_text(text, path)}


def test_detects_cloud_and_api_keys():
    assert "SEC001" in ids(f'key = "{FAKE_AWS}"')
    assert "SEC002" in ids(f"token: {FAKE_GH}", "config.yml")
    assert "SEC003" in ids(f"ANTHROPIC_API_KEY={FAKE_ANT}", ".env")


def test_private_key_block():
    assert "SEC006" in ids("-----BEGIN " + "RSA PRIVATE KEY-----", "id_rsa.txt")


def test_secrets_are_masked_in_report():
    f = scan_text(f'key = "{FAKE_AWS}"', "app.py")[0]
    assert FAKE_AWS not in f.snippet
    assert "****" in f.snippet


def test_python_risky_code():
    assert "PY001" in ids("result = eval(user_input)")
    assert "PY002" in ids("subprocess.run(cmd, shell=True)")
    assert "PY004" in ids("obj = pickle.loads(data)")
    assert "PY007" in ids("requests.get(url, verify=False)")
    assert "PY008" in ids('cur.execute(f"SELECT * FROM users WHERE id={uid}")')


def test_safe_code_is_clean():
    assert ids("result = ast.literal_eval(user_input)") == set()
    assert ids("yaml.load(fh, Loader=yaml.SafeLoader)") == set()
    assert ids('cur.execute("SELECT * FROM users WHERE id=?", (uid,))') == set()


def test_js_rules_only_apply_to_js_files():
    assert "JS002" in ids("el.innerHTML = userInput;", "page.js")
    assert "JS002" not in ids("el.innerHTML = userInput;", "notes.md")


def test_ignore_marker():
    assert ids("x = eval(s)  # liteguard: ignore") == set()


def test_entropy():
    assert shannon_entropy("aaaaaaaa") == 0
    assert shannon_entropy("Zx9Qp2Lm7Rt4Vb8Nk3Wy6Hs1") > 4.3
    assert "ENT001" in ids('seed = "Zx9Qp2Lm7Rt4Vb8Nk3Wy6Hs1Jd5"')


def test_cli_exit_codes_and_json(tmp_path, capsys):
    (tmp_path / "bad.py").write_text("eval(x)\n")
    assert main(["scan", str(tmp_path), "--format", "json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data[0]["rule_id"] == "PY001"

    (tmp_path / "bad.py").write_text("print('hello')\n")
    assert main(["scan", str(tmp_path)]) == 0


def test_ignore_file_and_exclude(tmp_path, capsys):
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / "lib.py").write_text("eval(x)\n")
    assert main(["scan", str(tmp_path), "--exclude", "vendor/"]) == 0
    (tmp_path / ".liteguardignore").write_text("# comment\nvendor/\n")
    assert main(["scan", str(tmp_path)]) == 0


def test_cli_sarif(tmp_path, capsys):
    (tmp_path / "bad.py").write_text("eval(x)\n")
    main(["scan", str(tmp_path), "--format", "sarif"])
    sarif = json.loads(capsys.readouterr().out)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "PY001"
