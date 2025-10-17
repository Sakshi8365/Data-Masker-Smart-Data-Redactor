import json

from click.testing import CliRunner

from data_masker.cli import main


def test_scan_reports_columns(tmp_path):
    # create a small csv
    p = tmp_path / "data.csv"
    p.write_text("name,email\nAlice,alice@example.com\n")
    runner = CliRunner()
    res = runner.invoke(main, ["scan", str(p), "--as-json"])
    assert res.exit_code == 0
    data = json.loads(res.output)
    assert "email" in data["columns"]


def test_mask_writes_output(tmp_path):
    p = tmp_path / "data.csv"
    p.write_text("name,email\nAlice,alice@example.com\n")
    out = tmp_path / "out.csv"
    runner = CliRunner()
    res = runner.invoke(main, ["mask", str(p), "-o", str(out)])
    assert res.exit_code == 0
    assert out.exists()
    content = out.read_text()
    assert "[REDACTED]" in content or "TOK-" in content or "@" not in content
