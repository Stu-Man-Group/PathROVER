# Changelog

All notable changes to PathROVER are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.0.0] — Initial public release

### Added
- Path traversal scanning engine with async HTTP/2 support (`pathrover/engine.py`)
- Baseline-diffing detection with variance band, binary magic bytes, text content signatures, and multi-line heuristics (`pathrover/detection.py`)
- Extractor producing typed findings: PEM keys, AWS credentials, shadow/passwd hashes, JWT tokens, Vault tokens, database URLs, generic secret variables, pg_hba trust entries, /proc/self/environ secrets, binary file previews, and 40+ additional file-type-specific extractors (`pathrover/extractor.py`)
- Raw HTTP request parser with ROVER placeholder substitution, percent-encoding detection, and Content-Length recalculation (`pathrover/request_parser.py`)
- Progress bar UX: baseline info printed before payload scan bar starts
- HTML, JSON, and CSV report output (`pathrover/reporter.py`)
- CLI with `--threads`, `--timeout`, `--output`, `--report-type`, and `--version` flags (`pathrover/cli.py`)
- Full unit test suite: 101 tests across detection, extraction, and request parsing (`tests/`)

### Security
- Switched XML parsing from `xml.etree.ElementTree` to `defusedxml` to prevent XML bomb / entity expansion attacks when parsing server responses
- SSL `verify=False` is intentional for testing environments with self-signed certificates; documented in README

### Changed
- Tightened `s.` Vault token pattern: now requires 28+ alphanumeric characters (up from 20) to reduce false positives on version strings and short identifiers
- Fixed `_RE_ENV_SECRET` to match variable names where the keyword appears at position 0 of the name (e.g. `SECRET_KEY`, `TOKEN`, `PASSWORD`) — previously these required at least one character prefix before the keyword
- `--threads` help text corrected to "concurrent async requests" (was misleadingly described as OS threads)

### Removed
- `anyio` dependency (was unused)
- Spurious `import re as _re` inside `extract()` body
- Duplicate `build_finding_records` call and dead `_print_summary` function in CLI
