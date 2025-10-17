import ipaddress
import re
from re import Pattern
from typing import Any

import pandas as pd

from .pii_patterns import DEFAULT_PATTERNS


class Detector:
    def __init__(self, patterns: dict[str, Pattern[str]] | None = None) -> None:
        self.patterns = patterns or DEFAULT_PATTERNS

    def detect_cell(self, value: Any) -> list[str]:
        text = "" if value is None else str(value)
        hits: list[str] = []
        for name, pattern in self.patterns.items():
            if pattern.search(text):
                if name == "credit_card" and not self._passes_luhn(text):
                    continue
                if name == "ipv6" and not self._valid_ipv6(text):
                    continue
                if name == "iban" and not self._valid_iban(text):
                    continue
                hits.append(name)
        return hits

    def detect_series(self, series: pd.Series) -> dict[str, int]:
        # simple score: count cells with hits by type
        counts: dict[str, int] = {k: 0 for k in self.patterns}
        values: list[str] = ["" if pd.isna(x) else str(x) for x in series]
        for val in values:
            for name, pattern in self.patterns.items():
                if pattern.search(val):
                    if name == "credit_card" and not self._passes_luhn(val):
                        continue
                    if name == "ipv6" and not self._valid_ipv6(val):
                        continue
                    if name == "iban" and not self._valid_iban(val):
                        continue
                    counts[name] += 1
        return counts

    def _passes_luhn(self, text: str) -> bool:
        # strip non-digits
        digits = [int(ch) for ch in text if ch.isdigit()]
        MIN_CC_DIGITS = 13
        if len(digits) < MIN_CC_DIGITS:
            return False
        # Luhn algorithm
        checksum = 0
        parity = (len(digits) - 2) % 2
        for i, d in enumerate(digits[:-1]):
            if i % 2 == parity:
                d2 = d * 2
                LUHN_SUBTRACT = 9
                if d2 > LUHN_SUBTRACT:
                    d2 -= LUHN_SUBTRACT
                checksum += d2
            else:
                checksum += d
        check_digit = digits[-1]
        return (checksum + check_digit) % 10 == 0

    def _valid_ipv6(self, text: str) -> bool:
        try:
            # ipaddress will parse strict valid IPv6 tokens; split common separators to try tokens
            for token in text.replace(',', ' ').split():
                ipaddress.IPv6Address(token)
                return True
            return False
        except Exception:
            return False

    def _valid_iban(self, text: str) -> bool:
        # Extract uppercase alphanumerics only, simple tokenization by whitespace
        for token in re.findall(r"[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}", text.upper()):
            if self._iban_mod97(token):
                return True
        return False

    def _iban_mod97(self, iban: str) -> bool:
        # Move first 4 chars to end
        rearranged = (iban[4:] + iban[:4]).upper()
        # Replace letters with numbers A=10 ... Z=35
        digits: list[str] = []
        for ch in rearranged:
            if ch.isdigit():
                digits.append(ch)
            else:
                digits.append(str(ord(ch) - 55))
        # Compute mod 97 iteratively to avoid big ints
        remainder = 0
        for ch in ''.join(digits):
            remainder = (remainder * 10 + int(ch)) % 97
        return remainder == 1
