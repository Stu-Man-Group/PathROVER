"""
engine.py - Async HTTP request engine using httpx.

Handles baseline fingerprinting and concurrent payload dispatch.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass

import httpx

from pathrover.request_parser import ParsedRequest, build_request


@dataclass
class ScanConfig:
    threads: int = 10
    timeout: int = 10
    proxy: str | None = None


@dataclass
class RawResult:
    payload: str
    status_code: int
    body_bytes: bytes
    headers: dict[str, str]
    elapsed_ms: float
    error: str | None = None


@dataclass
class ScanResult:
    baseline: RawResult
    baseline_probes: list[RawResult]
    results: list[RawResult]


async def _send_request(
    client: httpx.AsyncClient,
    parsed: ParsedRequest,
    payload: str,
    semaphore: asyncio.Semaphore,
    timeout: int,
) -> RawResult:
    """Send a single substituted request and return a RawResult."""
    request_kwargs = build_request(parsed, payload)
    async with semaphore:
        start = time.monotonic()
        try:
            response = await client.request(
                method=request_kwargs["method"],
                url=request_kwargs["url"],
                headers=request_kwargs["headers"],
                content=request_kwargs["content"],
                timeout=timeout,
                follow_redirects=False,
            )
            elapsed_ms = (time.monotonic() - start) * 1000
            return RawResult(
                payload=payload,
                status_code=response.status_code,
                body_bytes=response.content,
                headers=dict(response.headers),
                elapsed_ms=elapsed_ms,
            )
        except httpx.TimeoutException:
            elapsed_ms = (time.monotonic() - start) * 1000
            return RawResult(
                payload=payload,
                status_code=-1,
                body_bytes=b"",
                headers={},
                elapsed_ms=elapsed_ms,
                error="timeout",
            )
        except httpx.RequestError as exc:
            elapsed_ms = (time.monotonic() - start) * 1000
            return RawResult(
                payload=payload,
                status_code=-1,
                body_bytes=b"",
                headers={},
                elapsed_ms=elapsed_ms,
                error=f"request_error: {type(exc).__name__}: {exc}",
            )


async def run_scan(
    parsed: ParsedRequest,
    payloads: list[str],
    config: ScanConfig,
    progress_callback=None,
) -> ScanResult:
    """
    Run a full scan: baseline probes first, then all payloads concurrently.

    Three baseline probes are sent with distinct UUIDs to measure natural
    response variance (e.g. dynamic pages with timestamps or nonces).
    The min/max length range is stored so the classifier can ignore
    responses that fall within normal server variance.

    progress_callback: optional callable(completed: int, total: int) called after each result.
    """
    # httpx client: disable SSL verification for pentest targets (self-signed certs common)
    # proxy kwarg varies by httpx version: 0.27+ uses 'proxy', older uses 'proxies'
    client_kwargs: dict = {"verify": False, "http2": True}
    if config.proxy:
        client_kwargs["proxy"] = config.proxy

    async with httpx.AsyncClient(**client_kwargs) as client:
        # Three baseline probes with distinct UUIDs — establishes natural variance band
        baseline_sem = asyncio.Semaphore(1)
        baseline_probes = [
            await _send_request(
                client, parsed, f"PATHROVER_BASELINE_{uuid.uuid4().hex}",
                baseline_sem, config.timeout,
            )
            for _ in range(3)
        ]

        # Dispatch all payloads concurrently, capped by semaphore
        semaphore = asyncio.Semaphore(config.threads)
        total = len(payloads)
        completed = 0
        results: list[RawResult] = []

        tasks = [
            _send_request(client, parsed, payload, semaphore, config.timeout)
            for payload in payloads
        ]

        for coro in asyncio.as_completed(tasks):
            result = await coro
            results.append(result)
            completed += 1
            if progress_callback:
                progress_callback(completed, total)

    # Re-order results to match original payload order for deterministic output
    payload_order = {p: i for i, p in enumerate(payloads)}
    results.sort(key=lambda r: payload_order.get(r.payload, 9999))

    return ScanResult(baseline=baseline_probes[0], baseline_probes=baseline_probes, results=results)
