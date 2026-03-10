"""
cli.py - PathROVER command-line interface.

Entry point: main()
Orchestrates: argument parsing -> validation -> wordlist load ->
              scan -> classification -> extraction -> report write.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from pathrover import __version__


# ---------------------------------------------------------------------------
# ANSI colour helpers (no external deps)
# ---------------------------------------------------------------------------
_USE_COLOUR = sys.stdout.isatty()


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOUR else text


def _green(t: str) -> str:  return _c(t, "32")
def _yellow(t: str) -> str: return _c(t, "33")
def _red(t: str) -> str:    return _c(t, "31")
def _cyan(t: str) -> str:   return _c(t, "36")
def _bold(t: str) -> str:   return _c(t, "1")
def _dim(t: str) -> str:    return _c(t, "2")


def _format_injection_point(location: str) -> str:
    """Convert internal location strings to human-readable labels."""
    if location == "url_path":
        return "URL path"
    if location == "body_raw":
        return "Body (raw)"
    if location == "body_json_raw":
        return "JSON body (raw)"
    if location.startswith("body_json."):
        field = location[len("body_json."):]
        return f"JSON body \u2192 {field}"
    if location.startswith("query_param:"):
        param = location[len("query_param:"):]
        return f"Query param \u2192 {param}"
    if location.startswith("header:"):
        name = location[len("header:"):]
        return f"Header \u2192 {name}"
    if location.startswith("body_form_param:"):
        param = location[len("body_form_param:"):]
        return f"Form param \u2192 {param}"
    return location


_BANNER = (
    "██████╗  █████╗ ████████╗██╗  ██╗██████╗  ██████╗ ██╗   ██╗███████╗██████╗ \n"
    "██╔══██╗██╔══██╗╚══██╔══╝██║  ██║██╔══██╗██╔═══██╗██║   ██║██╔════╝██╔══██╗\n"
    "██████╔╝███████║   ██║   ███████║██████╔╝██║   ██║██║   ██║█████╗  ██████╔╝\n"
    "██╔═══╝ ██╔══██║   ██║   ██╔══██║██╔══██╗██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗\n"
    "██║     ██║  ██║   ██║   ██║  ██║██║  ██║╚██████╔╝ ╚████╔╝ ███████╗██║  ██║\n"
    "╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝"
)


# ---------------------------------------------------------------------------
# ARGUMENT PARSER
# ---------------------------------------------------------------------------
def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pathrover",
        description="Automated path traversal exploitation for confirmed vulnerabilities.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  pathrover -r req.txt --os linux --report-type html --output report.html\n"
            "  pathrover -r req.txt --os windows --report-type json --output out.json --threads 20\n"
            "  pathrover -r req.txt --os macos --report-type csv --output out.csv --proxy http://127.0.0.1:8080\n"
        ),
    )
    parser.add_argument(
        "-r", "--request",
        required=True,
        metavar="FILE",
        help="Raw HTTP request file (Burp Suite format). Must contain ROVER marker.",
    )
    parser.add_argument(
        "--os",
        required=True,
        choices=["linux", "windows", "macos"],
        dest="os_name",
        help="Target operating system. One of: linux, windows, macos.",
    )
    parser.add_argument(
        "--report-type",
        required=True,
        choices=["html", "json", "csv"],
        dest="report_type",
        help="Output report format.",
    )
    parser.add_argument(
        "--output",
        required=True,
        metavar="FILE",
        help="Output file path for the report.",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=10,
        metavar="N",
        help="Concurrent request threads (default: 10).",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        metavar="PCT",
        help="Response length delta %% to flag as CANDIDATE (default: 5).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        metavar="SEC",
        help="Per-request timeout in seconds (default: 10).",
    )
    parser.add_argument(
        "--proxy",
        default=None,
        metavar="URL",
        help="HTTP/HTTPS proxy URL (e.g. http://127.0.0.1:8080).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"PathROVER {__version__}",
    )
    return parser


# ---------------------------------------------------------------------------
# STARTUP VALIDATION
# ---------------------------------------------------------------------------
def _validate_inputs(args: argparse.Namespace) -> None:
    """Validate file accessibility and flag values. Exits on failure."""

    # 1. Request file exists and is readable
    req_path = Path(args.request)
    if not req_path.exists():
        print(_red(f"[ERROR] Request file not found: {args.request}"), file=sys.stderr)
        sys.exit(1)
    if not req_path.is_file():
        print(_red(f"[ERROR] Not a file: {args.request}"), file=sys.stderr)
        sys.exit(1)
    try:
        raw_text = req_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        print(_red(f"[ERROR] Cannot read request file: {exc}"), file=sys.stderr)
        sys.exit(1)

    # 2. ROVER marker present
    if "ROVER" not in raw_text:
        print(
            _red("[ERROR] ROVER marker not found in the request file.\n")
            + "        Embed 'ROVER' at the injection point, e.g.:\n"
            + "          GET /download?file=../../../../ROVER HTTP/1.1",
            file=sys.stderr,
        )
        sys.exit(1)

    # 3. Output path is writable
    out_path = Path(args.output)
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        # Touch to verify writability
        out_path.touch(exist_ok=True)
    except OSError as exc:
        print(_red(f"[ERROR] Cannot write to output path '{args.output}': {exc}"), file=sys.stderr)
        sys.exit(1)

    # 4. Sensible numeric ranges
    if args.threads < 1 or args.threads > 200:
        print(_red("[ERROR] --threads must be between 1 and 200."), file=sys.stderr)
        sys.exit(1)
    if args.threshold < 0 or args.threshold > 100:
        print(_red("[ERROR] --threshold must be between 0 and 100."), file=sys.stderr)
        sys.exit(1)
    if args.timeout < 1 or args.timeout > 300:
        print(_red("[ERROR] --timeout must be between 1 and 300 seconds."), file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# PROGRESS BAR
# ---------------------------------------------------------------------------
def _progress_bar(completed: int, total: int, width: int = 40) -> None:
    """Overwrite the current line with a progress bar."""
    if not _USE_COLOUR:
        return
    pct = completed / total if total else 1.0
    filled = int(width * pct)
    bar = "#" * filled + "-" * (width - filled)
    sys.stdout.write(f"\r  [{bar}] {completed}/{total} ({pct*100:.0f}%)")
    sys.stdout.flush()
    if completed == total:
        sys.stdout.write("\n")
        sys.stdout.flush()


# ---------------------------------------------------------------------------
# SCAN SUMMARY PRINTER
# ---------------------------------------------------------------------------
def _print_summary(records, error_count: int, miss_count: int, duration: float) -> None:
    from pathrover.reporter import FindingRecord
    confirmed = sum(1 for r in records if r.confidence == "CONFIRMED")
    candidates = sum(1 for r in records if r.confidence == "CANDIDATE")
    total_extracted = sum(len(r.extracted) for r in records if r.confidence == "CONFIRMED")

    print()
    print(_bold("  ---- Scan Summary ----"))
    print(f"  Duration        : {duration:.1f}s")
    print(f"  Confirmed hits  : {_green(str(confirmed))}")
    print(f"  Candidate hits  : {_yellow(str(candidates))}")
    print(f"  Misses          : {_dim(str(miss_count))}")
    print(f"  Errors          : {_dim(str(error_count))}")
    print(f"  Extracted items : {_cyan(str(total_extracted))}")
    print()


# ---------------------------------------------------------------------------
# ASYNC CORE
# ---------------------------------------------------------------------------
async def _async_main(args: argparse.Namespace) -> int:
    from pathrover.request_parser import parse_raw_request, load_wordlist, RequestParseError
    from pathrover.engine import ScanConfig, run_scan
    from pathrover.detection import build_baseline, classify_all, Confidence
    from pathrover.extractor import extract
    from pathrover.reporter import (
        ScanMeta, build_finding_records,
        render_html, render_json, render_csv,
    )

    # --- Parse request file ---
    req_path = Path(args.request)
    raw_text = req_path.read_text(encoding="utf-8", errors="replace")

    try:
        parsed = parse_raw_request(raw_text)
    except RequestParseError as exc:
        print(_red(f"[ERROR] {exc}"), file=sys.stderr)
        return 1

    # --- Load wordlist ---
    try:
        payloads = load_wordlist(args.os_name)
    except RequestParseError as exc:
        print(_red(f"[ERROR] {exc}"), file=sys.stderr)
        return 1

    # --- Print parsed request summary ---
    print()
    print(_bold("  Request Summary"))
    print(f"  Method          : {_cyan(parsed.method)}")
    print(f"  Host            : {_cyan(parsed.host)}")
    print(f"  Scheme          : {parsed.scheme}")
    print(f"  Injection point : {_yellow(', '.join(_format_injection_point(l) for l in parsed.rover_locations))}")
    print(f"  OS              : {args.os_name}")
    print(f"  Payloads        : {len(payloads)}")
    print(f"  Threads         : {args.threads}")
    print(f"  Threshold       : {args.threshold}%")
    print(f"  Timeout         : {args.timeout}s")
    if args.proxy:
        print(f"  Proxy           : {args.proxy}")
    print(f"  Output          : {args.output}")
    print(f"  Report type     : {args.report_type}")
    print()

    # --- Confirm before scan ---
    try:
        answer = input("  Proceed with scan? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        print(_yellow("  Aborted."))
        return 0

    if answer not in ("y", "yes"):
        print(_yellow("  Aborted."))
        return 0

    print()
    print(_bold("  [*] Sending baseline probes..."))

    # --- Run scan ---
    config = ScanConfig(
        threads=args.threads,
        timeout=args.timeout,
        proxy=args.proxy,
    )

    start_time = time.monotonic()

    def _on_progress(completed: int, total: int) -> None:
        _progress_bar(completed, total)

    scan_result = await run_scan(parsed, payloads, config, progress_callback=_on_progress)
    duration = time.monotonic() - start_time

    # --- Build baseline ---
    baseline = build_baseline(scan_result.baseline, scan_result.baseline_probes)
    print(f"  Baseline: status={baseline.status}  length={baseline.length:,}B  variance={baseline.length_min:,}–{baseline.length_max:,}B  binary={baseline.is_binary}")
    print()
    print(_bold(f"  [*] Scanning {len(payloads)} paths..."))

    # --- Classify ---
    classified = classify_all(scan_result.results, baseline, args.threshold)

    confirmed_results = [r for r in classified if r.confidence == Confidence.CONFIRMED]
    candidate_results = [r for r in classified if r.confidence == Confidence.CANDIDATE]
    miss_count = sum(1 for r in classified if r.confidence == Confidence.MISS)
    error_count = sum(1 for r in classified if r.confidence == Confidence.ERROR)

    # --- Extract from confirmed hits ---
    extracted_map: dict[str, list] = {}
    for r in confirmed_results:
        extracted_map[r.payload] = extract(r)

    # Print inline hit announcements
    for r in confirmed_results:
        extracted_count = len(extracted_map.get(r.payload, []))
        indicator = _green("[CONFIRMED]")
        extra = f" ({extracted_count} item{'s' if extracted_count != 1 else ''} extracted)" if extracted_count else ""
        print(f"  {indicator} {r.payload}{extra}")
    for r in candidate_results:
        print(f"  {_yellow('[CANDIDATE]')} {r.payload}  (status={r.status_code} len={r.response_length:,}B)")

    _print_summary(
        build_finding_records(classified, extracted_map),
        error_count,
        miss_count,
        duration,
    )

    # --- Build finding records (CONFIRMED + CANDIDATE) ---
    records = build_finding_records(classified, extracted_map, include_candidates=True)

    # --- Build scan meta ---
    meta = ScanMeta(
        target=f"{parsed.scheme}://{parsed.host}",
        os_name=args.os_name,
        date=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        tool_version=__version__,
        duration_seconds=duration,
        total_requests=len(payloads) + 1,  # +1 for baseline
        threads=args.threads,
        threshold=args.threshold,
        proxy=args.proxy,
    )

    # --- Render report ---
    print(_bold(f"  [*] Writing {args.report_type.upper()} report to {args.output} ..."))

    if args.report_type == "html":
        content = render_html(
            meta=meta,
            records=records,
            error_count=error_count,
            miss_count=miss_count,
        )
        Path(args.output).write_text(content, encoding="utf-8")
    elif args.report_type == "json":
        content = render_json(meta, records)
        Path(args.output).write_text(content, encoding="utf-8")
    elif args.report_type == "csv":
        content = render_csv(meta, records)
        Path(args.output).write_text(content, encoding="utf-8")

    confirmed_count = len(confirmed_results)
    candidate_count = len(candidate_results)
    print(_green(f"  [+] Report written: {args.output}"))
    print(_green(f"  [+] Done. {confirmed_count} confirmed, {candidate_count} candidates."))
    print()

    return 0


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------
def main() -> None:
    print(_bold(_BANNER))
    print(_dim(f"  v{__version__} — path traversal exploitation tool"))
    print()

    parser = _build_parser()
    args = parser.parse_args()

    _validate_inputs(args)

    try:
        rc = asyncio.run(_async_main(args))
    except KeyboardInterrupt:
        print()
        print(_yellow("  Interrupted."))
        rc = 1

    sys.exit(rc)


if __name__ == "__main__":
    main()
