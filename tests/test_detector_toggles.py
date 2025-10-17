import json
from pathlib import Path

from click.testing import CliRunner

from data_masker.cli import main


def test_scan_respects_disabled_email(tmp_path: Path) -> None:
    # Create CSV with an email value
    csv_path = tmp_path / "data.csv"
    csv_path.write_text("name,email\nAlice,alice@example.com\n", encoding="utf-8")
    # Rules disabling email detector
    rules_path = tmp_path / "rules.yml"
    rules_path.write_text(
        """
version: 1
detectors:
  enable_email: false
        """.strip(),
        encoding="utf-8",
    )
    runner = CliRunner()
    res = runner.invoke(main, [
        "scan",
        str(csv_path),
        "--as-json",
        "-r",
        str(rules_path),
    ])
    assert res.exit_code == 0
    data = json.loads(res.output)
    # With email disabled, there should be no PII detected
    assert data.get("columns") == {}


def test_mask_skips_disabled_email(tmp_path: Path) -> None:
    # Create CSV with an email value
    csv_path = tmp_path / "data.csv"
    csv_path.write_text("name,email\nAlice,alice@example.com\n", encoding="utf-8")
    out_path = tmp_path / "out.csv"
    # Rules disabling email detector
    rules_path = tmp_path / "rules.yml"
    rules_path.write_text(
        """
version: 1
detectors:
  enable_email: false
        """.strip(),
        encoding="utf-8",
    )
    runner = CliRunner()
    res = runner.invoke(main, [
        "mask",
        str(csv_path),
        "-o",
        str(out_path),
        "-r",
        str(rules_path),
    ])
    assert res.exit_code == 0
    content = out_path.read_text(encoding="utf-8")
    # Email should remain present (no masking) since email detector is disabled
    assert "alice@example.com" in content