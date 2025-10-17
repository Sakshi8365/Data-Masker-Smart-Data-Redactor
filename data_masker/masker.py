from __future__ import annotations

import hashlib
from typing import Any

from .detectors import Detector
from .pii_patterns import DEFAULT_PATTERNS
from .rules import Rules
from .token_store import TokenStore

MASK_REPLACEMENT = "[REDACTED]"

class Masker:
    def __init__(self, rules: Rules, token_store: TokenStore | None = None) -> None:
        self.rules = rules
        # Restrict detector patterns based on enabled detectors from rules
        patterns = {k: v for k, v in DEFAULT_PATTERNS.items() if k in self.rules.enabled_detectors}
        self.detector = Detector(patterns)
        token_path = self.rules.options.get("token_store") or ".tokens.json"
        self.tokens = token_store or TokenStore(token_path)

    def _hash(self, text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def _partial(self, text: str, keep_last: int) -> str:
        if len(text) <= keep_last:
            return "*" * len(text)
        return "*" * (len(text) - keep_last) + text[-keep_last:]

    def _apply_strategy(self, text: str, strategy: str) -> str:
        if strategy == "redact":
            return MASK_REPLACEMENT
        if strategy == "hash":
            return self._hash(text)
        if strategy == "tokenize":
            return self.tokens.tokenize(text)
        if strategy == "partial":
            keep = int(self.rules.options.get("partial_keep_last", 4))
            return self._partial(text, keep)
        if strategy == "null":
            return ""
        # fallback
        return MASK_REPLACEMENT

    def mask_cell(self, value: Any, column: str | None = None) -> Any:
        if value is None:
            return value
        text = str(value)
        # column-specific rule
        col_rule = (self.rules.columns.get(column or "") or {}) if column else {}
        if "strategy" in col_rule:
            return self._apply_strategy(text, col_rule["strategy"])
        # detect PII types and pick a strategy
        hits = self.detector.detect_cell(text)
        if not hits:
            # default strategy 'redact' shouldn't be applied to non-PII, so return original
            return value
        # choose strategy by first hit type-specific or default
        for hit in hits:
            strategy = self.rules.strategies.get(hit)
            if strategy:
                return self._apply_strategy(text, strategy)
        strategy = self.rules.strategies.get("default", "redact")
        return self._apply_strategy(text, strategy)
