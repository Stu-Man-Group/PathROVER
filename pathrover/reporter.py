"""
reporter.py - Report generation in HTML, JSON, and CSV formats.

All three formats report CONFIRMED and CANDIDATE hits:
  - CONFIRMED hits have a matched content signature or heuristic.
  - CANDIDATE hits show structural divergence from baseline only
    (status or length delta) and require manual review.
  - Hits with extracted secrets are shown with their findings.
  - Hits with no extracted secrets are shown with a body preview.

HTML: self-contained single file, inline CSS, dark pentester theme.
JSON: structured for integration with vulnerability platforms.
CSV:  flat rows — one row per extracted sensitive item, plus one row per
      hit with no secrets (type="confirmed_hit" or "candidate_hit", value=body preview).
"""

from __future__ import annotations

import csv
import html
import io
import json
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathrover.detection import ClassifiedResult
    from pathrover.extractor import ExtractedFinding

from pathrover import __version__


# ---------------------------------------------------------------------------
# SHARED DATA STRUCTURES
# ---------------------------------------------------------------------------
@dataclass
class ScanMeta:
    target: str
    os_name: str
    date: str
    tool_version: str
    duration_seconds: float
    total_requests: int
    threads: int
    threshold: int
    proxy: str | None


@dataclass
class FindingRecord:
    path: str
    confidence: str
    status_code: int
    response_length: int
    elapsed_ms: float
    is_binary: bool
    binary_type: str | None
    matched_signature: str | None
    extracted: list["ExtractedFinding"]
    timestamp: str
    body_preview: str  # kept for internal use but not shown in reports


@dataclass
class AggregatedFinding:
    type: str
    value: str
    note: str
    source_paths: list[str]


_INDICATOR_TYPES = {
    "history_sensitive_command",
    "windows_log_credential_indicator",
}


def _aggregate_findings(records: list[FindingRecord]) -> list[AggregatedFinding]:
    """
    Flatten and deduplicate extracted findings across all records.

    Within a single path, extractor._dedupe() already removes same-path
    duplicates.  However, many traversal payload variants (e.g. different
    depths or encodings) can all resolve to the same underlying file, so the
    same secret may appear in multiple FindingRecords.

    Deduplication key: (type, value[:500]) — same type + same value is the
    same secret regardless of which path variant surfaced it.  The first
    occurrence (earliest in the results list) is kept; all later copies are
    silently discarded.
    """
    seen: dict[tuple[str, str], AggregatedFinding] = {}
    for record in records:
        for f in record.extracted:
            key = (f.type, f.value[:500])
            if key not in seen:
                seen[key] = AggregatedFinding(
                    type=f.type,
                    value=f.value,
                    note=f.note or "",
                    source_paths=[f.source_path],
                )
            elif f.source_path not in seen[key].source_paths:
                seen[key].source_paths.append(f.source_path)
    return list(seen.values())


def _split_findings(findings: list[AggregatedFinding]) -> tuple[list[AggregatedFinding], list[AggregatedFinding]]:
    secrets: list[AggregatedFinding] = []
    indicators: list[AggregatedFinding] = []
    for finding in findings:
        if finding.type in _INDICATOR_TYPES:
            indicators.append(finding)
        else:
            secrets.append(finding)
    return secrets, indicators


def build_finding_records(
    results: list["ClassifiedResult"],
    extracted_map: dict[str, list["ExtractedFinding"]],
    include_candidates: bool = False,
) -> list[FindingRecord]:
    """
    Build FindingRecord objects for CONFIRMED and CANDIDATE hits.
    Records with zero extracted findings are included — they represent
    traversal hits where no secrets were identified in the file content.
    CONFIRMED hits have a matched content signature or heuristic;
    CANDIDATE hits show structural divergence from baseline only and require
    manual review to confirm exploitation.
    Set include_candidates=False to restrict to CONFIRMED hits only.
    """
    records = []
    ts = datetime.now(timezone.utc).isoformat()
    for r in results:
        from pathrover.detection import Confidence
        if r.confidence not in (Confidence.CONFIRMED, Confidence.CANDIDATE):
            continue
        if r.confidence == Confidence.CANDIDATE and not include_candidates:
            continue

        extracted = extracted_map.get(r.payload, [])

        body_preview = ""
        if not r.is_binary:
            try:
                body_preview = r.body_bytes[:512].decode("utf-8", errors="replace")
            except Exception:
                pass
            # If the app wraps responses in a JSON envelope and the data value is
            # an empty string, the raw preview would show the envelope JSON rather
            # than meaningful content.  Normalise that to "[empty file]".
            if body_preview:
                try:
                    import json as _json
                    _parsed = _json.loads(body_preview)
                    if isinstance(_parsed, dict):
                        for _key in ("data", "content", "result", "body", "message"):
                            if _key in _parsed and _parsed[_key] == "":
                                body_preview = "[empty file]"
                                break
                except Exception:
                    pass

        records.append(FindingRecord(
            path=r.payload,
            confidence=r.confidence.value,
            status_code=r.status_code,
            response_length=r.response_length,
            elapsed_ms=r.elapsed_ms,
            is_binary=r.is_binary,
            binary_type=r.binary_type,
            matched_signature=r.matched_signature,
            extracted=extracted,
            timestamp=ts,
            body_preview=body_preview,
        ))
    return records


# ---------------------------------------------------------------------------
# JSON REPORTER
# ---------------------------------------------------------------------------
def render_json(meta: ScanMeta, records: list[FindingRecord]) -> str:
    """
    Output confirmed/candidate hits and any extracted sensitive findings.
    """
    all_findings = _aggregate_findings(records)
    sensitive_findings = [
        {
            "type": e.type,
            "value": e.value,
            "note": e.note or "",
            "source_paths": e.source_paths,
            "kind": "indicator" if e.type in _INDICATOR_TYPES else "secret",
        }
        for e in all_findings
    ]

    hits = [
        {
            "path": r.path,
            "confidence": r.confidence,
            "status_code": r.status_code,
            "response_length": r.response_length,
            "matched_signature": r.matched_signature,
            "body_preview": (
                r.body_preview
                if r.body_preview
                else (f"[binary: {r.binary_type}]" if r.is_binary else "")
            ),
        }
        for r in records
    ]

    output = {
        "scan_meta": {
            "target": meta.target,
            "os": meta.os_name,
            "date": meta.date,
            "tool_version": meta.tool_version,
            "duration_seconds": round(meta.duration_seconds, 2),
            "total_requests": meta.total_requests,
            "threads": meta.threads,
            "threshold_pct": meta.threshold,
            "proxy": meta.proxy,
        },
        "hits": hits,
        "sensitive_findings": sensitive_findings,
    }
    return json.dumps(output, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# CSV REPORTER
# ---------------------------------------------------------------------------
def render_csv(meta: ScanMeta, records: list[FindingRecord]) -> str:
    """
    One row per extracted sensitive item, plus one row per hit with no
    extracted secrets (type is "{confidence}_hit", e.g. "confirmed_hit" or
    "candidate_hit"; value is a body preview).
    """
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["type", "value", "note", "source_path"])
    for e in _aggregate_findings(records):
        writer.writerow([e.type, e.value, e.note or "", " | ".join(e.source_paths)])
    # Include hits that had no extracted secrets
    for r in records:
        if not r.extracted:
            writer.writerow([
                f"{r.confidence.lower()}_hit",
                r.body_preview[:500] if r.body_preview else f"[binary: {r.binary_type}]",
                f"status={r.status_code} len={r.response_length} sig={r.matched_signature}",
                r.path,
            ])
    return buf.getvalue()


# ---------------------------------------------------------------------------
# HTML REPORTER
# ---------------------------------------------------------------------------
_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    background: #0d1117;
    color: #c9d1d9;
    font-family: 'Courier New', Courier, monospace;
    font-size: 13px;
    line-height: 1.6;
}
.wrap { max-width: 1100px; margin: 0 auto; padding: 28px 20px; }

/* Header */
.header {
    border-bottom: 1px solid #21262d;
    padding-bottom: 14px;
    margin-bottom: 24px;
}
.header h1 { font-size: 1.4em; color: #f0f6fc; letter-spacing: 0.06em; }
.header .meta { color: #8b949e; font-size: 0.8em; margin-top: 4px; }

/* Section headings */
.section-heading {
    font-size: 0.9em;
    color: #f0f6fc;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    border-bottom: 1px solid #21262d;
    padding-bottom: 6px;
    margin: 24px 0 14px 0;
}

/* Finding type group */
.type-group { margin-bottom: 22px; }
.type-header {
    background: #1c2128;
    border: 1px solid #30363d;
    border-radius: 6px 6px 0 0;
    padding: 8px 14px;
    color: #388bfd;
    font-size: 0.82em;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    font-weight: bold;
}
.finding-card {
    background: #161b22;
    border: 1px solid #21262d;
    border-top: none;
    padding: 10px 14px;
}
.finding-card:last-child { border-radius: 0 0 6px 6px; }
.finding-source {
    color: #8b949e;
    font-size: 0.76em;
    margin-bottom: 5px;
    word-break: break-all;
}
.finding-source span { color: #58a6ff; }
.finding-value {
    background: #0d1117;
    border: 1px solid #21262d;
    border-radius: 4px;
    padding: 7px 10px;
}
.finding-value pre {
    color: #a5d6ff;
    white-space: pre-wrap;
    word-break: break-all;
    font-size: 0.87em;
    max-height: 260px;
    overflow-y: auto;
}
.finding-note {
    color: #8b949e;
    font-size: 0.74em;
    font-style: italic;
    margin-top: 5px;
}

/* Confirmed hit rows (no extracted secrets) */
.hit-table { width: 100%; border-collapse: collapse; margin-bottom: 22px; }
.hit-table th {
    background: #1c2128;
    border: 1px solid #30363d;
    padding: 7px 12px;
    text-align: left;
    color: #3fb950;
    font-size: 0.78em;
    text-transform: uppercase;
    letter-spacing: 0.08em;
}
.hit-table td {
    background: #161b22;
    border: 1px solid #21262d;
    padding: 7px 12px;
    font-size: 0.84em;
    vertical-align: top;
    word-break: break-all;
}
.hit-table td.path { color: #58a6ff; }
.hit-table td.preview {
    color: #8b949e;
    max-width: 500px;
    white-space: pre-wrap;
    overflow: hidden;
    max-height: 80px;
}
.badge {
    display: inline-block;
    padding: 1px 7px;
    border-radius: 3px;
    font-size: 0.75em;
    font-weight: bold;
}
.badge-confirmed { background: #1a4a1a; color: #3fb950; }
.badge-candidate { background: #3d2e00; color: #d29922; }

.no-findings { color: #8b949e; padding: 16px 0; }
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: #161b22; }
::-webkit-scrollbar-thumb { background: #30363d; border-radius: 3px; }
"""


def _e(text: str) -> str:
    """HTML-escape a string."""
    return html.escape(str(text), quote=True)


def render_html(
    meta: ScanMeta,
    records: list[FindingRecord],
    error_count: int,
    miss_count: int,
) -> str:
    from collections import defaultdict

    all_findings = _aggregate_findings(records)
    secret_findings, indicator_findings = _split_findings(all_findings)

    # Section 1: all confirmed/candidate hits table
    if records:
        rows_html = ""
        for r in records:
            badge_cls = "badge-confirmed" if r.confidence == "CONFIRMED" else "badge-candidate"
            preview = r.body_preview[:300].replace("\r\n", "\n") if r.body_preview else (f"[binary: {r.binary_type}]" if r.is_binary else "")
            rows_html += f"""
    <tr>
      <td class="path">{_e(r.path)}</td>
      <td><span class="badge {badge_cls}">{_e(r.confidence)}</span></td>
      <td>{_e(str(r.status_code))}</td>
      <td>{_e(str(r.response_length))}</td>
      <td class="preview">{_e(preview)}</td>
    </tr>"""
        hits_html = f"""
<div class="section-heading">Hits ({len(records)})</div>
<table class="hit-table">
  <thead><tr>
    <th>Path</th><th>Confidence</th><th>Status</th><th>Bytes</th><th>Preview</th>
  </tr></thead>
  <tbody>{rows_html}
  </tbody>
</table>"""
    else:
        hits_html = '<p class="no-findings">No traversal hits detected.</p>'

    def _render_grouped_findings(title: str, findings: list[AggregatedFinding], empty_text: str) -> str:
        by_type: dict[str, list[AggregatedFinding]] = defaultdict(list)
        for finding in findings:
            by_type[finding.type].append(finding)

        if not by_type:
            return f'<div class="section-heading">{_e(title)}</div><p class="no-findings">{_e(empty_text)}</p>'

        groups_html = f'<div class="section-heading">{_e(title)} ({len(findings)})</div>'
        for ftype, items in by_type.items():
            cards_html = ""
            for item in items:
                note_html = f'<div class="finding-note">{_e(item.note)}</div>' if item.note else ""
                source_list = "<br>".join(_e(path) for path in item.source_paths)
                cards_html += f"""
      <div class="finding-card">
        <div class="finding-source">from <span>{source_list}</span></div>
        <div class="finding-value"><pre>{_e(item.value)}</pre></div>
        {note_html}
      </div>"""
            groups_html += f"""
    <div class="type-group">
      <div class="type-header">{_e(ftype)}</div>
      {cards_html}
    </div>"""
        return groups_html

    # Section 2: extracted secrets grouped by type
    secrets_html = _render_grouped_findings(
        "Extracted Secrets",
        secret_findings,
        "No high-confidence secrets extracted from hits.",
    )
    indicators_html = _render_grouped_findings(
        "Sensitive Indicators",
        indicator_findings,
        "No additional indicators requiring manual review.",
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PathROVER — {_e(meta.target)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <h1>PathROVER &mdash; {_e(meta.target)}</h1>
    <div class="meta">{_e(meta.date)} &nbsp;|&nbsp; {len(records)} hit{'s' if len(records) != 1 else ''} &nbsp;|&nbsp; {len(secret_findings)} secret{'s' if len(secret_findings) != 1 else ''} &nbsp;|&nbsp; {len(indicator_findings)} indicator{'s' if len(indicator_findings) != 1 else ''}</div>
  </div>
  {hits_html}
  {secrets_html}
  {indicators_html}
</div>
</body>
</html>"""
