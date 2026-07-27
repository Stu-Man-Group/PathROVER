# Contributing to PathROVER

## Prerequisites

- Python 3.10+
- `pip install -e .` (or install dependencies from `pyproject.toml` manually)
- `pip install defusedxml httpx[http2] pytest`

## Running the test suite

```bash
pytest tests/
```

All tests must pass before submitting a pull request.

## Code style

- Follow PEP 8.
- Keep lines under 120 characters where practical.
- New extractors belong in `pathrover/extractor.py` in the `extract()` function.
- New detection signatures belong in `pathrover/detection.py` in the appropriate `BINARY_SIGNATURES`, `TEXT_SIGNATURES`, or heuristic section.

## Adding an extractor

1. Add the regex constant near the top of `extractor.py` (alphabetical order within its section).
2. Add the extraction logic inside `extract()` in the appropriate section (ALWAYS-RUN vs file-type-specific).
3. Add a test class in `tests/test_extractor.py` covering at least: positive extraction, negative (non-matching) case, and any path-gating behavior.
4. Update `CHANGELOG.md`.

## Adding a detection signature

1. For binary magic bytes: add an entry to `BINARY_SIGNATURES` in `detection.py`.
2. For text content signatures: add an entry to `TEXT_SIGNATURES`.
3. For multi-line heuristics: add logic in `_check_content_heuristics()`.
4. Add a test in `tests/test_detection.py`.

## Pull request checklist

- [ ] All existing tests pass (`pytest tests/`)
- [ ] New functionality has tests
- [ ] `CHANGELOG.md` updated under `[Unreleased]`
- [ ] No credentials, API keys, or real target data included

## Reporting issues

Open an issue on GitHub. For false positives or missed detections, include an anonymized sample of the response body that triggered (or failed to trigger) the finding.
