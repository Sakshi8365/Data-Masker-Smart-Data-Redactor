from __future__ import annotations

import csv
import json
import os

import click

from .detectors import Detector
from .io_utils import iter_csv_chunks, read_table, write_table
from .masker import Masker
from .pii_patterns import DEFAULT_PATTERNS
from .rules import Rules
from .token_store import TokenStore


@click.group()
def main() -> None:
    """Data Masker – Smart Data Redactor"""
    pass


@main.command()
@click.argument("input_path", type=click.Path(exists=True))
@click.option(
    "--as-json",
    "as_json",
    is_flag=True,
    help="Output JSON report to stdout",
)
@click.option(
    "--export-json",
    type=click.Path(),
    help="Write scan report to a JSON file",
)
@click.option(
    "--export-csv",
    type=click.Path(),
    help="Write per-column/type counts to CSV",
)
@click.option(
    "--chunksize",
    type=int,
    default=0,
    help="Process CSV in row chunks to reduce memory usage",
)
@click.option(
    "-r",
    "--rules",
    "rules_path",
    type=click.Path(exists=True),
    required=False,
    help="Rules YAML file (supports strategies, columns, options, and detectors toggles)",
)
def scan(  # noqa: PLR0913, PLR0912
    input_path: str,
    as_json: bool,
    export_json: str | None,
    export_csv: str | None,
    chunksize: int,
    rules_path: str | None,
) -> None:
    """Scan a file and report PII presence per column."""
    df, kind = read_table(input_path)
    rules = Rules.load(rules_path)
    # Respect detector toggles in rules
    patterns = {k: v for k, v in DEFAULT_PATTERNS.items() if k in rules.enabled_detectors}
    det = Detector(patterns)
    results: dict[str, dict[str, int]] = {}
    if chunksize and kind == "csv":
        # Accumulate counts across chunks
        accum: dict[str, dict[str, int]] = {}
        for chunk in iter_csv_chunks(input_path, chunksize=chunksize):
            for col in chunk.columns:
                counts = det.detect_series(chunk[col])
                if col not in accum:
                    accum[col] = {t: 0 for t in patterns}
                for t, c in counts.items():
                    accum[col][t] = accum[col].get(t, 0) + c
        for col, counts in accum.items():
            total_hits = sum(counts.values())
            if total_hits:
                results[col] = {k: v for k, v in counts.items() if v}
    else:
        for col in df.columns:
            counts = det.detect_series(df[col])
            total_hits = sum(counts.values())
            if total_hits:
                results[col] = {k: v for k, v in counts.items() if v}
    report: dict[str, object] = {"file": input_path, "columns": results}
    if export_json:
        with open(export_json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
    if export_csv and results:
        # Flatten to rows: column,type,count
        with open(export_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["column", "type", "count"])
            for col, counts in results.items():
                for t, c in counts.items():
                    writer.writerow([col, t, c])
    if as_json:
        click.echo(json.dumps(report, indent=2))
    else:
        if not results:
            click.echo("No PII patterns detected.")
            return
        click.echo(f"PII detected in {len(results.keys())} column(s):")
        for col, counts in results.items():
            summary = ", ".join([f"{k}={v}" for k, v in counts.items()])
            click.echo(f"- {col}: {summary}")


@main.command()
@click.argument("input_path", type=click.Path(exists=True))
@click.option(
    "-o",
    "--output",
    "output_path",
    type=click.Path(),
    required=True,
    help="Output file path",
)
@click.option(
    "-r",
    "--rules",
    "rules_path",
    type=click.Path(exists=True),
    required=False,
    help="Rules YAML file",
)
@click.option(
    "--token-store",
    "token_store_path",
    type=click.Path(),
    required=False,
    help="Token store file path",
)
@click.option("--inplace", is_flag=True, help="Overwrite input file in place")
@click.option(
    "--chunksize",
    type=int,
    default=0,
    help="Process CSV in row chunks to reduce memory usage",
)
def mask(  # noqa: PLR0913
    input_path: str,
    output_path: str,
    rules_path: str | None,
    token_store_path: str | None,
    inplace: bool,
    chunksize: int,
) -> None:
    """Mask a file using rules or defaults and write to output."""
    df, kind = read_table(input_path)
    rules = Rules.load(rules_path)
    if token_store_path:
        rules.options["token_store"] = token_store_path
    masker = Masker(rules, token_store=TokenStore(rules.options.get("token_store")))
    # chunked CSV processing if requested
    target = input_path if inplace else output_path
    if chunksize and kind == "csv":
        # Remove existing target if present
        if os.path.exists(target):
            os.remove(target)
        header_written = False
        for chunk in iter_csv_chunks(input_path, chunksize=chunksize):
            for col in chunk.columns:
                chunk[col] = chunk[col].map(lambda v, c=col: masker.mask_cell(v, c))
            # append mode for subsequent chunks
            chunk.to_csv(target, index=False, mode="a", header=not header_written)
            header_written = True
        click.echo(f"Masked data written to {target} (chunked {chunksize})")
        return
    # non-chunked path
    for col in df.columns:
        df[col] = df[col].map(lambda v, c=col: masker.mask_cell(v, c))
    write_table(df, target, kind)
    click.echo(f"Masked data written to {target}")
