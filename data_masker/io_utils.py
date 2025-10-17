from __future__ import annotations

from collections.abc import Iterator

import pandas as pd

SUPPORTED = (".csv", ".json", ".xlsx")


def read_table(path: str) -> tuple[pd.DataFrame, str]:
    lower = path.lower()
    if lower.endswith(".csv"):
        return pd.read_csv(path), "csv"  # type: ignore[call-overload]
    if lower.endswith(".json"):
        return pd.read_json(path, orient="records"), "json"  # type: ignore[call-overload]
    if lower.endswith(".xlsx"):
        return pd.read_excel(path), "xlsx"  # type: ignore[call-overload]
    raise ValueError(f"Unsupported file type for {path}")


def iter_csv_chunks(path: str, chunksize: int = 10000) -> Iterator[pd.DataFrame]:
    """Yield DataFrame chunks for a CSV to support streaming."""
    yield from pd.read_csv(path, chunksize=chunksize)  # type: ignore[call-overload]


def write_table(df: pd.DataFrame, path: str, kind: str | None = None) -> None:
    lower = path.lower()
    if lower.endswith(".csv") or kind == "csv":
        df.to_csv(path, index=False)
    elif lower.endswith(".json") or kind == "json":
        df.to_json(path, orient="records", lines=False)  # type: ignore[call-overload]
    elif lower.endswith(".xlsx") or kind == "xlsx":
        df.to_excel(path, index=False)  # type: ignore[call-overload]
    else:
        raise ValueError(f"Unsupported file type for {path}")
