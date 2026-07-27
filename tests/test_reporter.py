"""
tests/test_reporter.py

Unit tests for pathrover.reporter.build_finding_records():
  - Fix 2: JSON-envelope responses with empty data field produce
    body_preview == "[empty file]" rather than the raw envelope JSON.
"""

from __future__ import annotations

import json

from pathrover.detection import Confidence, ClassifiedResult
from pathrover.reporter import build_finding_records


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _confirmed(payload: str, body: bytes) -> ClassifiedResult:
    return ClassifiedResult(
        payload=payload,
        confidence=Confidence.CONFIRMED,
        status_code=200,
        body_bytes=body,
        response_length=len(body),
        elapsed_ms=5.0,
        is_binary=False,
        binary_type=None,
        matched_signature="test_sig",
        error=None,
    )


# ---------------------------------------------------------------------------
# Fix 2: Empty-file JSON envelope normalisation
# ---------------------------------------------------------------------------

class TestEmptyFileJsonEnvelope:
    """body_preview should be '[empty file]' when the JSON envelope data is ''."""

    def _build(self, envelope: dict) -> str:
        body = json.dumps(envelope).encode()
        result = _confirmed("etc/environment", body)
        records = build_finding_records([result], {})
        assert len(records) == 1
        return records[0].body_preview

    def test_data_empty_string_normalised(self):
        preview = self._build({"success": True, "message": None, "data": ""})
        assert preview == "[empty file]", f"Unexpected preview: {preview!r}"

    def test_content_empty_string_normalised(self):
        preview = self._build({"ok": True, "content": ""})
        assert preview == "[empty file]", f"Unexpected preview: {preview!r}"

    def test_result_empty_string_normalised(self):
        preview = self._build({"result": ""})
        assert preview == "[empty file]", f"Unexpected preview: {preview!r}"

    def test_non_empty_data_not_affected(self):
        """Responses with actual content must NOT be normalised."""
        envelope = {"success": True, "data": "root:x:0:0:root:/root:/bin/bash\n"}
        preview = self._build(envelope)
        assert preview != "[empty file]"
        assert "root" in preview

    def test_plain_text_response_not_affected(self):
        """Non-JSON responses must come through unchanged."""
        body = b"root:x:0:0:root:/root:/bin/bash\n"
        result = _confirmed("etc/passwd", body)
        records = build_finding_records([result], {})
        assert len(records) == 1
        assert "root" in records[0].body_preview
