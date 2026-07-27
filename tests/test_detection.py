"""
tests/test_detection.py

Unit tests for pathrover.detection:
  - build_baseline / variance band
  - _unwrap_response JSON envelope handling
  - _looks_like_error_page suppression
  - classify() — CONFIRMED, CANDIDATE, MISS, ERROR tiers
  - classify() binary magic bytes
  - classify() text content signatures
  - classify() general content heuristics
  - classify() reflected-payload stripping
"""

from __future__ import annotations

import hashlib

import pytest

from pathrover.detection import (
    Baseline,
    Confidence,
    build_baseline,
    classify,
    classify_all,
    _unwrap_response,
    _looks_like_error_page,
    _check_binary_magic,
    _check_text_signatures,
    _check_content_heuristics,
)
from pathrover.engine import RawResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _raw(payload: str, status: int, body: bytes, error: str | None = None) -> RawResult:
    return RawResult(
        payload=payload,
        status_code=status,
        body_bytes=body,
        headers={},
        elapsed_ms=10.0,
        error=error,
    )


def _baseline_from_body(body: bytes) -> Baseline:
    """Build a minimal baseline from a single body."""
    r = _raw("PATHROVER_BASELINE_aaa", 200, body)
    return build_baseline(r, [r, r, r])


# ---------------------------------------------------------------------------
# build_baseline / variance band
# ---------------------------------------------------------------------------

class TestBuildBaseline:
    def test_basic_fields(self):
        body = b"hello world"
        bl = _baseline_from_body(body)
        assert bl.status == 200
        assert bl.length == len(body)
        assert bl.length_min == len(body)
        assert bl.length_max == len(body)
        assert bl.is_binary is False

    def test_variance_reflects_probe_spread(self):
        bodies = [b"x" * 100, b"x" * 120, b"x" * 110]
        probes = [_raw("b", 200, b) for b in bodies]
        bl = build_baseline(probes[0], probes)
        assert bl.length_min == 100
        assert bl.length_max == 120

    def test_binary_flag_set_for_null_bytes(self):
        body = b"\x00\x01\x02\x03binary content"
        bl = _baseline_from_body(body)
        assert bl.is_binary is True

    def test_json_envelope_unwrapped_for_baseline(self):
        """Baseline body wrapped in a JSON envelope should be unwrapped before measuring length."""
        # Use a value with no special JSON characters so json.loads succeeds
        inner = "root:x:0:0:root:/root:/bin/bash"
        wrapped = f'{{"data":"{inner}"}}'.encode()
        bl = _baseline_from_body(wrapped)
        # Length should reflect the unwrapped content, not the outer JSON
        assert bl.length == len(inner.encode())


# ---------------------------------------------------------------------------
# _unwrap_response
# ---------------------------------------------------------------------------

class TestUnwrapResponse:
    def test_plain_body_unchanged(self):
        body = b"hello world"
        assert _unwrap_response(body) == body

    def test_data_key_unwrapped(self):
        inner = "root:x:0:0"
        body = f'{{"data":"{inner}"}}'.encode()
        assert _unwrap_response(body) == inner.encode("utf-8")

    def test_result_key_unwrapped(self):
        inner = "somevalue"
        body = f'{{"result":"{inner}"}}'.encode()
        assert _unwrap_response(body) == inner.encode("utf-8")

    def test_content_key_unwrapped(self):
        inner = "file content"
        body = f'{{"content":"{inner}"}}'.encode()
        assert _unwrap_response(body) == inner.encode("utf-8")

    def test_non_string_value_not_unwrapped(self):
        body = b'{"data":{"nested":"obj"}}'
        assert _unwrap_response(body) == body

    def test_non_json_body_unchanged(self):
        body = b"not json at all"
        assert _unwrap_response(body) == body

    def test_empty_body_unchanged(self):
        assert _unwrap_response(b"") == b""

    def test_multiple_data_keys_first_match_used(self):
        """The first matching DATA_KEY wins."""
        inner_data = "data_value"
        body = f'{{"data":"{inner_data}","content":"other"}}'.encode()
        assert _unwrap_response(body) == inner_data.encode("utf-8")


# ---------------------------------------------------------------------------
# _looks_like_error_page
# ---------------------------------------------------------------------------

class TestErrorPageSuppression:
    def test_html_error_title_suppressed(self):
        body = "<html><head><title>404 Not Found</title></head></html>"
        assert _looks_like_error_page(body) is True

    def test_dotnet_exception_suppressed(self):
        body = "System.IO.FileNotFoundException: Could not find file 'C:\\path\\file.txt'"
        assert _looks_like_error_page(body) is True

    def test_iis_http_error_suppressed(self):
        body = "<h2>HTTP Error 404.0 - Not Found</h2>"
        assert _looks_like_error_page(body) is True

    def test_spring_boot_error_envelope_suppressed(self):
        body = '{"timestamp":"2024-01-01","path":"/api","status":404,"error":"Not Found"}'
        assert _looks_like_error_page(body) is True

    def test_aspnet_yellow_screen_suppressed(self):
        body = "<title>Server Error in '/' Application.</title>"
        assert _looks_like_error_page(body) is True

    def test_real_passwd_not_suppressed(self):
        body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        assert _looks_like_error_page(body) is False

    def test_real_config_not_suppressed(self):
        body = "[mysqld]\nbind-address = 0.0.0.0\nport = 3306\n"
        assert _looks_like_error_page(body) is False

    def test_aspnetcore_problem_details_suppressed(self):
        body = '{"type":"https://tools.ietf.org/html/rfc7231","title":"Not Found","status":404,"traceId":"abc123def456"}'
        assert _looks_like_error_page(body) is True


# ---------------------------------------------------------------------------
# classify() — ERROR tier
# ---------------------------------------------------------------------------

class TestClassifyError:
    def test_timeout_error(self):
        bl = _baseline_from_body(b"normal response")
        r = _raw("../../etc/passwd", -1, b"", error="timeout")
        result = classify(r, bl)
        assert result.confidence == Confidence.ERROR
        assert result.error == "timeout"

    def test_request_error(self):
        bl = _baseline_from_body(b"normal response")
        r = _raw("payload", -1, b"", error="request_error: ConnectError: ...")
        result = classify(r, bl)
        assert result.confidence == Confidence.ERROR


# ---------------------------------------------------------------------------
# classify() — MISS tier
# ---------------------------------------------------------------------------

class TestClassifyMiss:
    def test_exact_hash_match_is_miss(self):
        body = b"this is the normal page response"
        bl = _baseline_from_body(body)
        r = _raw("../../etc/passwd", 200, body)
        result = classify(r, bl)
        assert result.confidence == Confidence.MISS

    def test_error_page_response_is_miss(self):
        normal = b"normal page"
        bl = _baseline_from_body(normal)
        error_body = b"<html><title>404 Not Found</title></html>"
        r = _raw("../../etc/passwd", 404, error_body)
        result = classify(r, bl)
        assert result.confidence == Confidence.MISS

    def test_length_within_variance_band_is_miss(self):
        """Body that differs in hash but length is within natural variance should be MISS."""
        base = b"<html><body>normal page response here</body></html>"
        bodies = [base, base + b" ", base + b"  "]  # 50, 51, 52 bytes
        probes = [_raw("b", 200, b) for b in bodies]
        bl = build_baseline(probes[0], probes)
        # A 51-byte different body that falls within [50, 52] variance band
        r = _raw("payload", 200, b"<html><body>other page response here!</body></html>")
        result = classify(r, bl, threshold_pct=5)
        assert result.confidence == Confidence.MISS


# ---------------------------------------------------------------------------
# classify() — CANDIDATE tier
# ---------------------------------------------------------------------------

class TestClassifyCandidate:
    def test_status_code_change_is_candidate(self):
        bl = _baseline_from_body(b"normal")
        # Status changed from 200 to 403 — length same but status differs
        r = _raw("payload", 403, b"normal")
        result = classify(r, bl)
        # Hash also matches here, so it falls to MISS — let's make body different too
        r2 = _raw("payload", 403, b"different body but not a real file")
        result2 = classify(r2, bl)
        assert result2.confidence == Confidence.CANDIDATE

    def test_large_length_delta_is_candidate(self):
        bl = _baseline_from_body(b"short")
        # 10x larger body with no content signatures — use generic HTML-like content
        long_body = b"<html>" + b"<p>generic page content paragraph here</p>" * 10 + b"</html>"
        r = _raw("payload", 200, long_body)
        result = classify(r, bl)
        assert result.confidence == Confidence.CANDIDATE


# ---------------------------------------------------------------------------
# classify() — CONFIRMED via binary magic bytes
# ---------------------------------------------------------------------------

class TestClassifyBinaryMagic:
    def test_registry_hive_confirmed(self):
        body = b"regf" + b"\x00" * 100
        bl = _baseline_from_body(b"normal html page response body here")
        r = _raw("../../../../Windows/System32/config/SAM", 200, body)
        result = classify(r, bl)
        assert result.confidence == Confidence.CONFIRMED
        assert result.is_binary is True
        sig = result.matched_signature or ""
        assert "regf" in sig or "Registry" in sig

    def test_sqlite_confirmed(self):
        body = b"SQLite format 3\x00" + b"\x00" * 100
        bl = _baseline_from_body(b"normal html page response body here")
        r = _raw("../../../../var/db/something.db", 200, body)
        result = classify(r, bl)
        assert result.confidence == Confidence.CONFIRMED
        assert result.is_binary is True

    def test_evtx_confirmed(self):
        body = b"ELfL" + b"\x00" * 200
        bl = _baseline_from_body(b"normal html page response body here")
        r = _raw("../../../../Windows/System32/winevt/Logs/System.evtx", 200, body)
        result = classify(r, bl)
        assert result.confidence == Confidence.CONFIRMED

    def test_bplist_confirmed(self):
        body = b"bplist00" + b"\x00" * 50
        bl = _baseline_from_body(b"normal html page response body here")
        r = _raw("../../../../Library/Preferences/com.apple.airport.plist", 200, body)
        result = classify(r, bl)
        assert result.confidence == Confidence.CONFIRMED


# ---------------------------------------------------------------------------
# classify() — CONFIRMED via text content signatures
# ---------------------------------------------------------------------------

class TestClassifyTextSignatures:
    def _bl(self):
        return _baseline_from_body(b"<html><body>normal page content here</body></html>")

    def test_passwd_file_confirmed(self):
        body = b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        r = _raw("../../../../etc/passwd", 200, body)
        result = classify(r, self._bl())
        assert result.confidence == Confidence.CONFIRMED

    def test_shadow_file_confirmed(self):
        body = b"root:$6$salt$hash:18000:0:99999:7:::\ndaemon:*:18000:0:99999:7:::\n"
        r = _raw("../../../../etc/shadow", 200, body)
        result = classify(r, self._bl())
        assert result.confidence == Confidence.CONFIRMED

    def test_ssh_private_key_confirmed(self):
        body = b"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"
        r = _raw("../../../../root/.ssh/id_rsa", 200, body)
        result = classify(r, self._bl())
        assert result.confidence == Confidence.CONFIRMED

    def test_authorized_keys_confirmed(self):
        body = b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB user@host\n"
        r = _raw("../../../../root/.ssh/authorized_keys", 200, body)
        result = classify(r, self._bl())
        assert result.confidence == Confidence.CONFIRMED

    def test_nginx_config_confirmed(self):
        body = b"worker_processes auto;\nevents { worker_connections 1024; }\n"
        r = _raw("../../../../etc/nginx/nginx.conf", 200, body)
        result = classify(r, self._bl())
        assert result.confidence == Confidence.CONFIRMED

    def test_env_file_confirmed(self):
        body = b"DATABASE_URL=postgres://user:pass@localhost/db\nSECRET_KEY=abc123def456\nDEBUG=False\n"
        r = _raw("../../../../app/.env", 200, body)
        result = classify(r, self._bl())
        assert result.confidence == Confidence.CONFIRMED

    def test_aws_credentials_confirmed(self):
        body = b"[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI\n"
        r = _raw("../../../../home/user/.aws/credentials", 200, body)
        result = classify(r, self._bl())
        assert result.confidence == Confidence.CONFIRMED

    def test_kubeconfig_confirmed(self):
        body = b"apiVersion: v1\nclusters:\n- cluster:\n    server: https://k8s.example.com\n"
        r = _raw("../../../../home/user/.kube/config", 200, body)
        result = classify(r, self._bl())
        assert result.confidence == Confidence.CONFIRMED

    def test_pg_hba_confirmed(self):
        body = b"# TYPE  DATABASE        USER            ADDRESS                 METHOD\nlocal   all             all                                     peer\nhost    all             all             127.0.0.1/32            md5\n"
        r = _raw("../../../../etc/postgresql/14/main/pg_hba.conf", 200, body)
        result = classify(r, self._bl())
        assert result.confidence == Confidence.CONFIRMED

    def test_win_ini_confirmed(self):
        body = b"[fonts]\n[extensions]\n[mci extensions]\n[files]\n"
        r = _raw("../../../../Windows/win.ini", 200, body)
        result = classify(r, self._bl())
        assert result.confidence == Confidence.CONFIRMED

    def test_error_page_not_confirmed_even_if_length_differs(self):
        """An error page that somehow contains text matching a signature should still be MISS."""
        # A .NET exception page that happens to mention root:x:0:0 in a path
        body = (
            b"System.IO.FileNotFoundException: Could not find file "
            b"'root:x:0:0:/root:/bin/bash'"
        )
        r = _raw("../../../../etc/passwd", 500, body)
        result = classify(r, self._bl())
        assert result.confidence == Confidence.MISS


# ---------------------------------------------------------------------------
# classify() — CONFIRMED via general content heuristics
# ---------------------------------------------------------------------------

class TestClassifyHeuristics:
    def _bl(self):
        return _baseline_from_body(b"<html><body>normal page</body></html>")

    def test_syslog_entries_confirmed(self):
        body = (
            b"Jan  1 00:00:01 hostname sshd[1234]: Accepted password for user from 1.2.3.4\n"
            b"Jan  1 00:00:02 hostname sudo: user : TTY=pts/0 ; PWD=/home/user\n"
            b"Jan  1 00:00:03 hostname sshd[1235]: Disconnected from user 1.2.3.4\n"
        )
        r = _raw("../../../../var/log/syslog", 200, body)
        result = classify(r, self._bl())
        assert result.confidence == Confidence.CONFIRMED

    def test_hosts_file_confirmed(self):
        body = (
            b"127.0.0.1 localhost\n"
            b"127.0.1.1 myhostname\n"
            b"::1 localhost ip6-localhost ip6-loopback\n"
            b"192.168.1.10 internalserver.local\n"
        )
        r = _raw("../../../../etc/hosts", 200, body)
        result = classify(r, self._bl())
        assert result.confidence == Confidence.CONFIRMED

    def test_fstab_confirmed(self):
        body = (
            b"UUID=abc-123 / ext4 errors=remount-ro 0 1\n"
            b"UUID=def-456 /boot ext2 defaults 0 2\n"
            b"tmpfs /tmp tmpfs defaults,noatime 0 0\n"
        )
        r = _raw("../../../../etc/fstab", 200, body)
        result = classify(r, self._bl())
        assert result.confidence == Confidence.CONFIRMED

    def test_proc_net_tcp_confirmed(self):
        body = (
            b"  sl  local_address rem_address   st tx_queue rx_queue\n"
            b"   0: 00000000:0016 00000000:0000 0A 00000000:00000000\n"
            b"   1: 0F02000A:0035 00000000:0000 0A 00000000:00000000\n"
        )
        r = _raw("../../../../proc/net/tcp", 200, body)
        result = classify(r, self._bl())
        assert result.confidence == Confidence.CONFIRMED

    def test_dotnet_error_page_not_heuristic_confirmed(self):
        """A .NET stack trace with INI-like lines should NOT be confirmed."""
        body = (
            b"System.IO.DirectoryNotFoundException: Could not find path.\n"
            b"   at System.IO.File.InternalCopy(String src)\n"
            b"   at MyApp.Controllers.FileController.Download(String path)\n"
        )
        r = _raw("payload", 500, body)
        result = classify(r, self._bl())
        assert result.confidence != Confidence.CONFIRMED


# ---------------------------------------------------------------------------
# classify() — reflected-payload stripping
# ---------------------------------------------------------------------------

class TestReflectedPayloadStripping:
    def test_reflected_payload_not_inflated_to_candidate(self):
        """
        When a server echoes the payload back in an error body, the inflated
        length delta should not produce a false CANDIDATE. The stripped length
        should fall within the baseline variance band.
        """
        baseline_body = b"File not found: "
        bl = _baseline_from_body(baseline_body)
        payload = "../../../../etc/passwd"
        # Server echoes the payload, making body larger — but content is just the echo
        echo_body = (baseline_body + payload.encode()).ljust(len(baseline_body), b" ")
        r = _raw(payload, 200, echo_body)
        result = classify(r, bl, threshold_pct=5)
        # Should NOT be CANDIDATE because the delta after stripping the payload is tiny
        assert result.confidence != Confidence.CANDIDATE


# ---------------------------------------------------------------------------
# classify_all()
# ---------------------------------------------------------------------------

class TestClassifyAll:
    def test_mixed_results(self):
        bl = _baseline_from_body(b"<html>normal page response</html>")
        results = [
            _raw("p1", 200, b"<html>normal page response</html>"),  # MISS (hash match)
            _raw("p2", -1, b"", error="timeout"),                    # ERROR
            _raw("p3", 200, b"root:x:0:0:root:/root:/bin/bash\n"),  # CONFIRMED
            _raw("p4", 403, b"totally different content here"),      # CANDIDATE
        ]
        classified = classify_all(results, bl)
        confidences = {r.payload: r.confidence for r in classified}
        assert confidences["p1"] == Confidence.MISS
        assert confidences["p2"] == Confidence.ERROR
        assert confidences["p3"] == Confidence.CONFIRMED
        assert confidences["p4"] == Confidence.CANDIDATE
