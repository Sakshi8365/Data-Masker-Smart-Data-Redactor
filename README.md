# Data Masker – Smart Data Redactor

Detect and mask PII in your datasets with a fast, configurable CLI. Supports CSV/JSON/XLSX, streaming for large files, validation-backed detectors, and flexible masking strategies.

<p>
  <a href="https://img.shields.io/badge/python-%3E%3D3.10-blue.svg"><img alt="Python" src="https://img.shields.io/badge/python-%3E%3D3.10-blue.svg"></a>
  <a href="https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey"><img alt="Platforms" src="https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey"></a>
  <a href="#tests"><img alt="Tests" src="https://img.shields.io/badge/tests-passing-brightgreen"></a>
</p>

---

## Highlights

- PII detection with validators:
  - Email, phone, credit card (Luhn), SSN, IPv4, IPv6 (validated via `ipaddress`), IBAN (MOD-97)
- Masking strategies: `redact`, `hash`, `tokenize` (stable), `partial`, `null`
- YAML rules: per-type defaults, per-column overrides, and detector toggles
- Streaming/Chunking: process huge CSVs with `--chunksize` to save memory
- CLI-first: `scan` to report PII, `mask` to apply rules

---

## Quick start

Install the CLI (in a virtual environment is recommended):

```
pip install .
```

Use either the installed command or the module runner:

```
data-masker --help
python -m data_masker --help
```

---

## Usage

Scan a CSV for PII and print JSON to stdout:

```
data-masker scan sample_data/people.csv --as-json
```

Export scan results:

```
data-masker scan sample_data/people.csv \
  --export-json report.json \
  --export-csv report.csv
```

Mask a file with defaults:

```
data-masker mask sample_data/people.csv -o masked.csv
```

Mask using a rules file:

```
data-masker mask sample_data/people.csv -r rules.yml -o masked.csv
```

Process very large CSVs in chunks:

```
data-masker scan big.csv --chunksize 50000 --export-json report.json
data-masker mask big.csv -o masked.csv --chunksize 50000
```

---

## Rules (YAML)

Configure strategies per PII type, per-column overrides, global options, and which detectors to enable.

```
version: 1
strategies:
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

Notes:
- `partial_keep_last` controls how many trailing characters are preserved in `partial` masking.
- `token_store` is a local JSON file used to keep `tokenize` mappings stable across runs.
- Detectors are enabled by name via `detectors:` using keys like `enable_email`, `enable_ipv6`, etc.

---

## Detectors and validation

- Credit cards: matched via regex and validated with the Luhn checksum to reduce false positives
- IPv6: validated using Python’s `ipaddress` module
- IBAN: validated using MOD-97 checksum
- Others: email, phone, SSN, IPv4 via robust regexes

---

## Performance

- Use `--chunksize` (e.g., 50k rows) to stream CSVs. Each chunk is scanned/masked independently and appended to the output.
- JSON and XLSX are loaded as a whole by default.

---

## Development

Set up and run tests:

```
pip install -r requirements.txt
pip install -r dev-requirements.txt
pytest -q
```

Lint/type check (if installed):

```
ruff check .
```

---

## Roadmap

- Optional sample-hit previews in scan reports
- Additional detectors (names, addresses, locale-specific IDs)
- Configurable output formats for masked data
- GitHub Actions CI (pytest + ruff) and release automation
- PyPI publishing

---

## Screenshots

Add screenshots or terminal recordings here to showcase scan and mask commands on real data.

---

## Acknowledgements

Built with Python, pandas, click, PyYAML, and a lot of regex.
