# Data Masker – Smart Data Redactor

A simple, extensible tool to detect and mask personally identifiable information (PII) in tabular data.

Features:

- Detect common PII with regex-based detectors (email, phone, credit card, SSN, IP)
- Detect common PII with regex-based detectors (email, phone, credit card, SSN, IPv4, IPv6, IBAN)
  - Credit card detection includes Luhn validation
  - IPv6 validated via Python's ipaddress
  - IBAN validated with MOD-97 checksum
- Apply masking strategies: redact, hash, tokenize, partial, null
- YAML rules to configure which columns or PII types to mask
- Supports CSV, JSON (records), and Excel (XLSX)
- CLI: scan (report PII), mask (apply)

## Install

Create a virtual environment and install requirements.

## Usage

To install the CLI entry point:

```
pip install .
```

This will provide a `data-masker` command. Alternatively, you can use `python -m data_masker`.

- Scan a CSV for PII:

```

```

- Mask a CSV with default rules:

```

```

- Mask using a rule file:

```

```

## Rules (YAML)

```
version: 1
  default: redact
  email: hash
  phone: partial
  credit_card: tokenize
columns:
  ssn:
    strategy: tokenize
  address:
    strategy: redact
options:
  token_store: .tokens.json
  partial_keep_last: 4
detectors:
  enable_email: true
  enable_ipv6: false  # disable IPv6 detection
  enable_iban: true
```

## Limitations

- Regex-based detection may have false positives/negatives.
- Token store is a local JSON file for demo purposes.

## Development

- Run tests with `pytest`.
