"""
request_parser.py - Parses a raw Burp Suite HTTP request file.

Handles ROVER marker detection in URL path, query string, headers, and body.
Supports form-encoded, JSON, and raw body types.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse, urlencode, parse_qsl, quote


ROVER_MARKER = "ROVER"

# Encoding styles for path separators detected from the traversal prefix
# "none"  -> bare /  and \  (no percent-encoding)
# "lower" -> %2f and %5c
# "upper" -> %2F and %5C
# "mixed" -> %2f/%2F for slash, %5c/%5C for backslash — use the case found in the prefix
_ENCODING_NONE  = "none"
_ENCODING_LOWER = "lower"
_ENCODING_UPPER = "upper"


@dataclass
class ParsedRequest:
    method: str
    scheme: str
    host: str
    port: int
    path: str
    query: str
    headers: dict[str, str]
    body: str
    rover_locations: list[str] = field(default_factory=list)
    # raw body type detection
    body_type: str = "raw"  # "form", "json", "raw"
    # separator encoding style detected from the traversal prefix before ROVER
    sep_encoding: str = _ENCODING_NONE  # "none", "lower", "upper"


class RequestParseError(Exception):
    pass


def _detect_sep_encoding(text: str) -> str:
    """
    Inspect the characters immediately before the ROVER marker to determine
    how path separators (/ and \\) are encoded in the traversal prefix.

    Looks backwards from ROVER for the pattern  ..SEP  where SEP is one of:
        %2f  %2F  %5c  %5C  /  \\

    Returns one of: "none", "lower", "upper".
    If no traversal prefix is found the returned value is "none" (bare separators).
    """
    idx = text.find(ROVER_MARKER)
    if idx == -1:
        return _ENCODING_NONE

    prefix = text[:idx]

    # Check for percent-encoded separators in the prefix (last occurrence wins)
    # Order: look for the separator closest to ROVER, i.e. rightmost match.
    lower_pat = re.compile(r'(?:%2f|%5c)', re.IGNORECASE)
    matches = list(lower_pat.finditer(prefix))
    if not matches:
        return _ENCODING_NONE

    last = matches[-1].group(0)
    if last == last.upper():
        return _ENCODING_UPPER   # %2F or %5C
    return _ENCODING_LOWER       # %2f or %5c


def _encode_payload(payload: str, sep_encoding: str) -> str:
    """
    Encode the path separators in *payload* to match *sep_encoding*.

    Wordlist entries use bare /  (linux/macos) or \\  (windows).
    When the traversal prefix uses percent-encoded separators we must encode
    the payload separators too, otherwise the server receives a mix of
    encoded and bare separators and may reject or misparse the path.

      "none"  -> payload left as-is
      "lower" -> /  -> %2f,  \\  -> %5c
      "upper" -> /  -> %2F,  \\  -> %5C
    """
    if sep_encoding == _ENCODING_LOWER:
        return payload.replace("\\", "%5c").replace("/", "%2f")
    if sep_encoding == _ENCODING_UPPER:
        return payload.replace("\\", "%5C").replace("/", "%2F")
    return payload


def load_wordlist(os_name: str) -> list[str]:
    """Load and return paths from the OS-specific wordlist, stripping comments."""
    import importlib.resources as pkg_resources
    import pathrover.wordlists as wl_pkg

    filename = f"{os_name}.txt"
    try:
        ref = pkg_resources.files(wl_pkg).joinpath(filename)
        text = ref.read_text(encoding="utf-8")
    except Exception as exc:
        raise RequestParseError(f"Cannot load wordlist '{filename}': {exc}") from exc

    paths = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            paths.append(stripped)
    return paths


def parse_raw_request(raw_text: str) -> ParsedRequest:
    """
    Parse a raw HTTP request as captured from Burp Suite.

    Expects the format:
        METHOD /path?query HTTP/1.x
        Host: hostname
        Header-Name: value
        ...
        [blank line]
        [body]
    """
    raw_text = raw_text.replace("\r\n", "\n").replace("\r", "\n")

    # Split into head and body on first blank line
    if "\n\n" in raw_text:
        head, body = raw_text.split("\n\n", 1)
    else:
        head = raw_text
        body = ""

    lines = head.splitlines()
    if not lines:
        raise RequestParseError("Request file is empty.")

    # Parse request line
    request_line = lines[0].strip()
    parts = request_line.split(" ")
    if len(parts) < 2:
        raise RequestParseError(
            f"Cannot parse request line: '{request_line}'. "
            "Expected format: METHOD /path HTTP/1.x"
        )

    method = parts[0].upper()
    raw_path = parts[1]  # may include query string

    # Parse headers
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            key, _, val = line.partition(":")
            headers[key.strip()] = val.strip()

    # Determine scheme and host from Host header
    host_header = headers.get("Host", "")
    if not host_header:
        raise RequestParseError(
            "No 'Host' header found in request. "
            "Ensure the raw request includes a Host header."
        )

    # HTTP/2 (and HTTP/3) are always HTTPS. Also handle explicit HTTPS in the request line.
    _rl_upper = request_line.upper()
    scheme = "https" if ("HTTPS" in _rl_upper or "HTTP/2" in _rl_upper or "HTTP/3" in _rl_upper) else "http"
    # If host contains a port, use it
    if ":" in host_header:
        hostname, port_str = host_header.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            hostname = host_header
            port = 443 if scheme == "https" else 80
    else:
        hostname = host_header
        port = 443 if scheme == "https" else 80

    # Split path and query
    if "?" in raw_path:
        path, query = raw_path.split("?", 1)
    else:
        path = raw_path
        query = ""

    # Detect body type
    content_type = headers.get("Content-Type", "").lower()
    if "application/x-www-form-urlencoded" in content_type:
        body_type = "form"
    elif "application/json" in content_type:
        body_type = "json"
    else:
        body_type = "raw"

    # Detect ROVER locations
    rover_locations = _detect_rover_locations(path, query, headers, body, body_type)

    if not rover_locations:
        raise RequestParseError(
            f"ROVER marker not found in the request. "
            f"Embed '{ROVER_MARKER}' at the injection point in the request file."
        )

    # Detect separator encoding style from the full raw request text
    sep_encoding = _detect_sep_encoding(raw_text)

    return ParsedRequest(
        method=method,
        scheme=scheme,
        host=hostname,
        port=port,
        path=path,
        query=query,
        headers=headers,
        body=body,
        rover_locations=rover_locations,
        body_type=body_type,
        sep_encoding=sep_encoding,
    )


def _detect_rover_locations(
    path: str,
    query: str,
    headers: dict[str, str],
    body: str,
    body_type: str,
) -> list[str]:
    """Return a list of human-readable location strings where ROVER appears."""
    locations = []

    if ROVER_MARKER in path:
        locations.append("url_path")

    if ROVER_MARKER in query:
        # Identify which parameter(s) contain ROVER
        for key, val in parse_qsl(query, keep_blank_values=True):
            if ROVER_MARKER in val or ROVER_MARKER in key:
                locations.append(f"query_param:{key}")

    for name, val in headers.items():
        if ROVER_MARKER in val:
            locations.append(f"header:{name}")

    if body:
        if body_type == "form":
            for key, val in parse_qsl(body, keep_blank_values=True):
                if ROVER_MARKER in val or ROVER_MARKER in key:
                    locations.append(f"body_form_param:{key}")
        elif body_type == "json":
            _find_rover_in_json(body, locations)
        else:
            if ROVER_MARKER in body:
                locations.append("body_raw")

    return locations


def _find_rover_in_json(body: str, locations: list[str], prefix: str = "body_json") -> None:
    """Recursively find ROVER in JSON body, recording field paths."""
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        if ROVER_MARKER in body:
            locations.append("body_json_raw")
        return
    _walk_json(data, prefix, locations)


def _walk_json(obj: object, path: str, locations: list[str]) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            child_path = f"{path}.{k}"
            if isinstance(v, str) and ROVER_MARKER in v:
                locations.append(child_path)
            elif isinstance(v, (dict, list)):
                _walk_json(v, child_path, locations)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            _walk_json(item, f"{path}[{i}]", locations)


def build_request(parsed: ParsedRequest, payload: str) -> dict:
    """
    Substitute ROVER with payload and return a dict with keys:
        method, url, headers, content
    ready for httpx.

    The payload's path separators are percent-encoded to match the encoding
    style already used in the traversal prefix (detected at parse time).
    """
    encoded_payload = _encode_payload(payload, parsed.sep_encoding)

    path = parsed.path.replace(ROVER_MARKER, encoded_payload)
    query = parsed.query.replace(ROVER_MARKER, encoded_payload)

    # Rebuild URL
    if query:
        url = f"{parsed.scheme}://{parsed.host}:{parsed.port}{path}?{query}"
    else:
        url = f"{parsed.scheme}://{parsed.host}:{parsed.port}{path}"

    # Replace in headers (copy to avoid mutation)
    headers = {k: v.replace(ROVER_MARKER, encoded_payload) for k, v in parsed.headers.items()}
    # Remove the Host port if it's standard to avoid httpx double-encoding
    if parsed.port in (80, 443):
        headers["Host"] = parsed.host

    # Replace in body
    body = parsed.body.replace(ROVER_MARKER, encoded_payload) if parsed.body else None

    # Recalculate Content-Length if present — payload substitution changes body size
    if body is not None and "Content-Length" in headers:
        headers["Content-Length"] = str(len(body.encode()))

    return {
        "method": parsed.method,
        "url": url,
        "headers": headers,
        "content": body.encode() if body else None,
    }
