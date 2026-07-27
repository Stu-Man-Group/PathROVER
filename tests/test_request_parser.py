"""
tests/test_request_parser.py

Unit tests for pathrover.request_parser:
  - parse_raw_request: URL path, query param, header, form body, JSON body injection points
  - ROVER location detection
  - separator encoding detection (_detect_sep_encoding)
  - build_request: payload substitution in URL / query / headers / body
  - Content-Length recalculation
  - Error cases: missing Host, missing ROVER, malformed request line
"""

from __future__ import annotations

import pytest

from pathrover.request_parser import (
    parse_raw_request,
    build_request,
    RequestParseError,
    _detect_sep_encoding,
    _encode_payload,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _req(method: str, path: str, host: str = "example.com", extra_headers: str = "",
         body: str = "", content_type: str = "") -> str:
    ct_line = f"\nContent-Type: {content_type}" if content_type else ""
    cl_line = f"\nContent-Length: {len(body)}" if body else ""
    return (
        f"{method} {path} HTTP/1.1\n"
        f"Host: {host}{ct_line}{cl_line}"
        f"{extra_headers}\n"
        f"\n{body}"
    )


# ---------------------------------------------------------------------------
# parse_raw_request — ROVER location detection
# ---------------------------------------------------------------------------

class TestRoverLocationDetection:
    def test_rover_in_url_path(self):
        raw = _req("GET", "/files/ROVER")
        parsed = parse_raw_request(raw)
        assert "url_path" in parsed.rover_locations

    def test_rover_in_query_param(self):
        raw = _req("GET", "/download?file=ROVER")
        parsed = parse_raw_request(raw)
        assert any("query_param:file" in loc for loc in parsed.rover_locations)

    def test_rover_in_header(self):
        raw = _req("GET", "/api", extra_headers="\nX-File-Path: ROVER")
        parsed = parse_raw_request(raw)
        assert any("header:X-File-Path" in loc for loc in parsed.rover_locations)

    def test_rover_in_form_body(self):
        raw = _req("POST", "/upload", body="path=ROVER&type=txt",
                   content_type="application/x-www-form-urlencoded")
        parsed = parse_raw_request(raw)
        assert any("body_form_param:path" in loc for loc in parsed.rover_locations)

    def test_rover_in_json_body(self):
        raw = _req("POST", "/api/fetch", body='{"path":"ROVER"}',
                   content_type="application/json")
        parsed = parse_raw_request(raw)
        assert any("body_json.path" in loc for loc in parsed.rover_locations)

    def test_rover_in_nested_json(self):
        raw = _req("POST", "/api", body='{"request":{"file":"ROVER"}}',
                   content_type="application/json")
        parsed = parse_raw_request(raw)
        assert any("body_json.request.file" in loc for loc in parsed.rover_locations)

    def test_rover_in_raw_body(self):
        raw = _req("POST", "/raw", body="ROVER")
        parsed = parse_raw_request(raw)
        assert "body_raw" in parsed.rover_locations


# ---------------------------------------------------------------------------
# parse_raw_request — scheme and host detection
# ---------------------------------------------------------------------------

class TestSchemeHostDetection:
    def test_http11_is_http(self):
        raw = _req("GET", "/path/ROVER")
        parsed = parse_raw_request(raw)
        assert parsed.scheme == "http"

    def test_http2_is_https(self):
        raw = "GET /path/ROVER HTTP/2\nHost: example.com\n\n"
        parsed = parse_raw_request(raw)
        assert parsed.scheme == "https"

    def test_host_port_parsed(self):
        raw = _req("GET", "/ROVER", host="example.com:8080")
        parsed = parse_raw_request(raw)
        assert parsed.host == "example.com"
        assert parsed.port == 8080


# ---------------------------------------------------------------------------
# parse_raw_request — error cases
# ---------------------------------------------------------------------------

class TestParseErrors:
    def test_missing_rover_raises(self):
        raw = _req("GET", "/api/files")
        with pytest.raises(RequestParseError, match="ROVER"):
            parse_raw_request(raw)

    def test_missing_host_raises(self):
        raw = "GET /ROVER HTTP/1.1\n\n"
        with pytest.raises(RequestParseError, match="Host"):
            parse_raw_request(raw)

    def test_malformed_request_line_raises(self):
        raw = "BADLINE\nHost: example.com\n\n"
        with pytest.raises(RequestParseError):
            parse_raw_request(raw)


# ---------------------------------------------------------------------------
# _detect_sep_encoding
# ---------------------------------------------------------------------------

class TestSepEncodingDetection:
    def test_bare_separators_returns_none(self):
        raw = _req("GET", "/files/../../../../ROVER")
        result = _detect_sep_encoding(raw)
        assert result == "none"

    def test_lowercase_percent_encoding_detected(self):
        raw = _req("GET", "/files/..%2f..%2fROVER")
        result = _detect_sep_encoding(raw)
        assert result == "lower"

    def test_uppercase_percent_encoding_detected(self):
        raw = _req("GET", "/files/..%2F..%2FROVER")
        result = _detect_sep_encoding(raw)
        assert result == "upper"

    def test_no_rover_returns_none(self):
        result = _detect_sep_encoding("some text with no marker")
        assert result == "none"


# ---------------------------------------------------------------------------
# _encode_payload
# ---------------------------------------------------------------------------

class TestEncodePayload:
    def test_none_encoding_leaves_payload_unchanged(self):
        p = "../../../../etc/passwd"
        assert _encode_payload(p, "none") == p

    def test_lower_encoding_converts_slashes(self):
        p = "../../../../etc/passwd"
        result = _encode_payload(p, "lower")
        assert "/" not in result
        assert "%2f" in result

    def test_upper_encoding_converts_slashes(self):
        p = "../../../../etc/passwd"
        result = _encode_payload(p, "upper")
        assert "/" not in result
        assert "%2F" in result

    def test_windows_backslashes_encoded(self):
        p = "..\\..\\Windows\\System32\\drivers\\etc\\hosts"
        result_lower = _encode_payload(p, "lower")
        assert "\\" not in result_lower
        assert "%5c" in result_lower
        result_upper = _encode_payload(p, "upper")
        assert "%5C" in result_upper


# ---------------------------------------------------------------------------
# build_request — payload substitution
# ---------------------------------------------------------------------------

class TestBuildRequest:
    def test_payload_substituted_in_url_path(self):
        raw = _req("GET", "/files/ROVER")
        parsed = parse_raw_request(raw)
        req = build_request(parsed, "../../../../etc/passwd")
        assert "../../../../etc/passwd" in req["url"]
        assert "ROVER" not in req["url"]

    def test_payload_substituted_in_query(self):
        raw = _req("GET", "/download?file=ROVER")
        parsed = parse_raw_request(raw)
        req = build_request(parsed, "../../../../etc/shadow")
        assert "../../../../etc/shadow" in req["url"]

    def test_payload_substituted_in_json_body(self):
        raw = _req("POST", "/api", body='{"path":"ROVER"}',
                   content_type="application/json")
        parsed = parse_raw_request(raw)
        req = build_request(parsed, "../../../../etc/passwd")
        content = req["content"] if isinstance(req["content"], str) else req["content"].decode()
        assert "../../../../etc/passwd" in content
        assert "ROVER" not in content

    def test_content_length_recalculated(self):
        original_body = "path=ROVER"
        raw = _req("POST", "/upload", body=original_body,
                   content_type="application/x-www-form-urlencoded")
        parsed = parse_raw_request(raw)
        payload = "../../../../etc/passwd"
        req = build_request(parsed, payload)
        expected_body = f"path={payload}"
        assert req["headers"]["Content-Length"] == str(len(expected_body))

    def test_encoded_payload_used_when_prefix_is_percent_encoded(self):
        raw = _req("GET", "/files/..%2f..%2fROVER")
        parsed = parse_raw_request(raw)
        req = build_request(parsed, "../../../../etc/passwd")
        # Separators in payload should also be percent-encoded (lowercase)
        assert "%2f" in req["url"]


# ---------------------------------------------------------------------------
# Scheme detection — HTTPS auto-detection from headers
# ---------------------------------------------------------------------------

class TestSchemeDetection:
    def test_http_request_line_defaults_to_http(self):
        raw = _req("GET", "/files/ROVER", host="target.com")
        parsed = parse_raw_request(raw)
        assert parsed.scheme == "http"

    def test_origin_header_upgrades_to_https(self):
        raw = _req("POST", "/api/ROVER", host="target.com:4201",
                   extra_headers="\nOrigin: https://target.com:4201",
                   body='{"file":"ROVER"}', content_type="application/json")
        parsed = parse_raw_request(raw)
        assert parsed.scheme == "https"

    def test_referer_header_upgrades_to_https(self):
        raw = _req("POST", "/api/ROVER", host="target.com",
                   extra_headers="\nReferer: https://target.com/dashboard")
        parsed = parse_raw_request(raw)
        assert parsed.scheme == "https"

    def test_http_origin_does_not_upgrade(self):
        raw = _req("GET", "/files/ROVER", host="target.com",
                   extra_headers="\nOrigin: http://target.com")
        parsed = parse_raw_request(raw)
        assert parsed.scheme == "http"

    def test_https_in_request_line_takes_precedence(self):
        raw = (
            "GET /files/ROVER HTTPS/1.1\n"
            "Host: target.com\n"
            "\n"
        )
        parsed = parse_raw_request(raw)
        assert parsed.scheme == "https"

    def test_port_preserved_when_https_auto_detected(self):
        raw = _req("POST", "/api/ROVER", host="localhost:4201",
                   extra_headers="\nOrigin: https://localhost:4201",
                   body='{"file":"ROVER"}', content_type="application/json")
        parsed = parse_raw_request(raw)
        assert parsed.scheme == "https"
        assert parsed.port == 4201
