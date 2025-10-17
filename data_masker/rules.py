from __future__ import annotations

from dataclasses import dataclass
from typing import Any, cast

import yaml

from .pii_patterns import DEFAULT_PATTERNS

DEFAULT_STRATEGIES: dict[str, str] = {
    "default": "redact",
    "email": "redact",
    "phone": "redact",
    "credit_card": "tokenize",
    "ssn": "tokenize",
    "ipv4": "redact",
}

@dataclass
class Rules:
    strategies: dict[str, str]
    columns: dict[str, dict[str, Any]]
    options: dict[str, Any]
    enabled_detectors: set[str]

    @staticmethod
    def load(path: str | None) -> Rules:
            if not path:
                # All detectors enabled by default
                enabled_detectors = set(DEFAULT_PATTERNS.keys())
                return Rules(
                    DEFAULT_STRATEGIES.copy(),
                    {},
                    {"partial_keep_last": 4},
                    enabled_detectors,
                )
            with open(path, encoding="utf-8") as f:
                raw: Any = yaml.safe_load(f) or {}
            # Explicit type cast for mypy
            data: dict[str, Any] = cast(dict[str, Any], raw) if isinstance(raw, dict) else {}
            strategies = DEFAULT_STRATEGIES.copy()
            strat_in: dict[str, Any] = cast(
                dict[str, Any], data.get("strategies")
            ) if isinstance(data.get("strategies"), dict) else {}
            strategies.update({str(k): str(v) for k, v in strat_in.items()})
            columns_in: dict[str, Any] = cast(
                dict[str, Any], data.get("columns")
            ) if isinstance(data.get("columns"), dict) else {}
            columns: dict[str, dict[str, Any]] = {}
            for k, v in columns_in.items():
                columns[str(k)] = dict(cast(dict[str, Any], v)) if isinstance(v, dict) else {}
            options_in: dict[str, Any] = cast(
                dict[str, Any], data.get("options")
            ) if isinstance(data.get("options"), dict) else {}
            options: dict[str, Any] = dict(options_in)
            if "partial_keep_last" not in options:
                options["partial_keep_last"] = 4
            # Detector toggles
            detectors_in: dict[str, Any] = cast(
                dict[str, Any], data.get("detectors")
            ) if isinstance(data.get("detectors"), dict) else {}
            enabled_detectors = set(DEFAULT_PATTERNS.keys())
            for k, v in detectors_in.items():
                k_str = str(k)
                detector_name = k_str.replace("enable_", "")
                if isinstance(v, bool) and v:
                    enabled_detectors.add(detector_name)
                else:
                    enabled_detectors.discard(detector_name)
            return Rules(strategies, columns, options, enabled_detectors)
