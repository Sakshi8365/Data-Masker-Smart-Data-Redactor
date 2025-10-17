from __future__ import annotations

import hashlib
import json
import os


class TokenStore:
    def __init__(self, path: str | None = None) -> None:
        self.path = path or ".tokens.json"
        self._store: dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        if os.path.exists(self.path):
            try:
                with open(self.path, encoding="utf-8") as f:
                    self._store = json.load(f)
            except Exception:
                self._store = {}

    def save(self) -> None:
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self._store, f, indent=2)
        except Exception:
            pass

    def tokenize(self, value: str) -> str:
        key = f"tok::{value}"
        if key not in self._store:
            # stable short token (8 hex)
            digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
            self._store[key] = f"TOK-{digest}"
            self.save()
        return self._store[key]
