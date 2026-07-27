"""
tests/test_extractor.py

Unit tests for pathrover.extractor.extract():
  - PEM private key / certificate extraction
  - AWS credentials
  - Shadow hash extraction
  - Unix passwd extraction
  - JWT token extraction
  - Vault token extraction (including s. false-positive avoidance)
  - SSH authorized_keys
  - Database URL
  - Generic secret variables
  - /proc/self/environ processing
  - pg_hba.conf trust entries
  - _prune_overlapping_findings deduplication
  - Binary body handling (hex preview returned)
"""

from __future__ import annotations

import pytest

from pathrover.detection import Confidence, ClassifiedResult
from pathrover.engine import RawResult
from pathrover.extractor import extract, ExtractedFinding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _confirmed(payload: str, body: bytes, binary_type: str | None = None) -> ClassifiedResult:
    return ClassifiedResult(
        payload=payload,
        confidence=Confidence.CONFIRMED,
        status_code=200,
        body_bytes=body,
        response_length=len(body),
        elapsed_ms=5.0,
        is_binary=binary_type is not None,
        binary_type=binary_type,
        matched_signature="test_sig",
        error=None,
    )


def _types(findings: list[ExtractedFinding]) -> list[str]:
    return [f.type for f in findings]


def _values(findings: list[ExtractedFinding]) -> list[str]:
    return [f.value for f in findings]


# ---------------------------------------------------------------------------
# PEM private key
# ---------------------------------------------------------------------------

class TestPemExtraction:
    def test_rsa_private_key_extracted(self):
        body = (
            b"-----BEGIN RSA PRIVATE KEY-----\n"
            b"MIIEpAIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4RosXKDqB\n"
            b"-----END RSA PRIVATE KEY-----\n"
        )
        findings = extract(_confirmed("id_rsa", body))
        assert any(f.type == "private_key" for f in findings)

    def test_openssh_private_key_extracted(self):
        body = (
            b"-----BEGIN OPENSSH PRIVATE KEY-----\n"
            b"b3BlbnNzaC1rZXktdjEAAAA=\n"
            b"-----END OPENSSH PRIVATE KEY-----\n"
        )
        findings = extract(_confirmed("id_ed25519", body))
        assert any(f.type == "private_key" for f in findings)

    def test_certificate_extracted(self):
        body = (
            b"-----BEGIN CERTIFICATE-----\n"
            b"MIIDXTCCAkWgAwIBAgIJAMV6xJsM\n"
            b"-----END CERTIFICATE-----\n"
        )
        findings = extract(_confirmed("server.crt", body))
        assert any(f.type == "certificate" for f in findings)


# ---------------------------------------------------------------------------
# AWS credentials
# ---------------------------------------------------------------------------

class TestAwsCredentials:
    def test_access_key_and_secret_extracted(self):
        body = (
            b"[default]\n"
            b"aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
            b"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        )
        findings = extract(_confirmed("credentials", body))
        types = _types(findings)
        assert "aws_access_key_id" in types
        assert "aws_secret_access_key" in types

    def test_session_token_extracted(self):
        body = (
            b"aws_session_token = AQoDYXdzEJr//////////wEaoAK\n"
        )
        findings = extract(_confirmed("credentials", body))
        assert any(f.type == "aws_session_token" for f in findings)


# ---------------------------------------------------------------------------
# Shadow hashes
# ---------------------------------------------------------------------------

class TestShadowExtraction:
    def test_sha512_hash_extracted(self):
        body = b"root:$6$salt$longhashvalue:18000:0:99999:7:::\n"
        findings = extract(_confirmed("shadow", body))
        shadow_findings = [f for f in findings if f.type == "unix_password_hash"]
        assert len(shadow_findings) >= 1
        assert "root" in shadow_findings[0].value
        assert "$6$" in shadow_findings[0].value

    def test_md5_hash_extracted(self):
        body = b"user:$1$salt$hashvalue:18000:0:99999:7:::\n"
        findings = extract(_confirmed("shadow", body))
        assert any(f.type == "unix_password_hash" for f in findings)

    def test_locked_account_not_extracted(self):
        """Accounts with * or ! have no crackable hash — should not appear."""
        body = b"daemon:*:18000:0:99999:7:::\nnobody:!:18000:::::::\n"
        findings = extract(_confirmed("shadow", body))
        assert not any(f.type == "unix_password_hash" for f in findings)


# ---------------------------------------------------------------------------
# Unix passwd
# ---------------------------------------------------------------------------

class TestPasswdExtraction:
    def test_root_entry_extracted(self):
        body = b"root:x:0:0:root:/root:/bin/bash\n"
        findings = extract(_confirmed("passwd", body))
        assert any(f.type == "unix_user" for f in findings)
        entry = next(f for f in findings if f.type == "unix_user")
        assert "root" in entry.value

    def test_multiple_entries(self):
        body = (
            b"root:x:0:0:root:/root:/bin/bash\n"
            b"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            b"mysql:x:110:118:MySQL Server:/nonexistent:/bin/false\n"
        )
        findings = extract(_confirmed("passwd", body))
        passwd_findings = [f for f in findings if f.type == "unix_user"]
        assert len(passwd_findings) == 3


# ---------------------------------------------------------------------------
# JWT tokens
# ---------------------------------------------------------------------------

class TestJwtExtraction:
    def test_jwt_extracted(self):
        # A syntactically valid JWT structure (not a real signed token)
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        body = f"Authorization: Bearer {jwt}\n".encode()
        findings = extract(_confirmed("some_config", body))
        assert any(f.type == "jwt_token" for f in findings)

    def test_jwt_note_includes_decode_hint(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        body = f"token: {jwt}\n".encode()
        findings = extract(_confirmed("token_file", body))
        jwt_findings = [f for f in findings if f.type == "jwt_token"]
        if jwt_findings:
            assert "jwt.io" in jwt_findings[0].note.lower() or "decode" in jwt_findings[0].note.lower()


# ---------------------------------------------------------------------------
# Vault tokens
# ---------------------------------------------------------------------------

class TestVaultTokenExtraction:
    def test_hvs_token_extracted(self):
        token = "hvs." + "A" * 24
        body = f"VAULT_TOKEN={token}\n".encode()
        findings = extract(_confirmed("config", body))
        assert any(f.type == "vault_token" for f in findings)

    def test_hvb_token_extracted(self):
        token = "hvb." + "B" * 24
        body = f"vault_token = {token}\n".encode()
        findings = extract(_confirmed("config", body))
        assert any(f.type == "vault_token" for f in findings)

    def test_legacy_s_token_extracted(self):
        """Legacy s. token requires 28+ chars to avoid false positives."""
        token = "s." + "C" * 28
        body = f"VAULT_TOKEN={token}\n".encode()
        findings = extract(_confirmed("config", body))
        assert any(f.type == "vault_token" for f in findings)

    def test_short_s_prefix_not_extracted(self):
        """s. with only 20 chars should NOT match (tightened pattern)."""
        token = "s." + "X" * 20
        body = f"version={token}\n".encode()
        findings = extract(_confirmed("config", body))
        vault_findings = [f for f in findings if f.type == "vault_token" and token in f.value]
        assert len(vault_findings) == 0


# ---------------------------------------------------------------------------
# Database URL
# ---------------------------------------------------------------------------

class TestDatabaseUrlExtraction:
    def test_postgres_url_extracted(self):
        body = b"DATABASE_URL=postgres://admin:s3cr3t@db.internal:5432/mydb\n"
        findings = extract(_confirmed(".env", body))
        assert any(f.type == "database_url" for f in findings)

    def test_mysql_url_extracted(self):
        body = b"DB_URL=mysql://root:rootpass@127.0.0.1:3306/app\n"
        findings = extract(_confirmed(".env", body))
        assert any(f.type == "database_url" for f in findings)


# ---------------------------------------------------------------------------
# Generic secret variables
# ---------------------------------------------------------------------------

class TestGenericSecretExtraction:
    def test_api_key_extracted(self):
        # Use a variable name that isn't handled by a more specific extractor
        body = b"APP_API_KEY=abcdefghijklmnopqrstuvwxyz\n"
        findings = extract(_confirmed(".env", body))
        assert any(f.type == "secret_variable" for f in findings)

    def test_benign_variable_not_extracted(self):
        """Variables like AUTH_TYPE, PRIVATE_DIR should not be flagged."""
        body = b"AUTH_TYPE=oauth2\nPRIVATE_DIR=/var/private\n"
        findings = extract(_confirmed(".env", body))
        # AUTH_TYPE and PRIVATE_DIR should not produce secret_variable hits
        secret_vars = [f for f in findings if f.type == "secret_variable"]
        values = [f.value for f in secret_vars]
        assert not any("AUTH_TYPE" in v for v in values)
        assert not any("PRIVATE_DIR" in v for v in values)


# ---------------------------------------------------------------------------
# pg_hba.conf trust entries
# ---------------------------------------------------------------------------

class TestPgHbaExtraction:
    def test_trust_entry_flagged(self):
        body = (
            b"local   all             all                                     peer\n"
            b"host    all             all             0.0.0.0/0               trust\n"
        )
        findings = extract(_confirmed("pg_hba.conf", body))
        trust_findings = [f for f in findings if f.type == "pg_hba_trust_entry"]
        assert len(trust_findings) >= 1

    def test_md5_entry_not_flagged(self):
        body = b"host    all             all             127.0.0.1/32            md5\n"
        findings = extract(_confirmed("pg_hba.conf", body))
        assert not any(f.type == "pg_hba_trust_entry" for f in findings)


# ---------------------------------------------------------------------------
# /proc/self/environ
# ---------------------------------------------------------------------------

class TestProcEnvironExtraction:
    def test_null_separated_environ_extracted(self):
        body = b"PATH=/usr/bin\x00SECRET_KEY=mysecretvalue123\x00HOME=/root\x00"
        findings = extract(_confirmed("../../../../proc/self/environ", body))
        assert any(f.type == "process_env_secret" for f in findings)
        secret = next(f for f in findings if f.type == "process_env_secret")
        assert "SECRET_KEY" in secret.value


# ---------------------------------------------------------------------------
# Binary body — hex preview
# ---------------------------------------------------------------------------

class TestBinaryExtraction:
    def test_registry_hive_gives_hex_preview(self):
        body = b"regf" + b"\x00\x01\x02\x03" * 64
        findings = extract(_confirmed(
            "../../../../Windows/System32/config/SAM",
            body,
            binary_type="Windows Registry Hive (regf)",
        ))
        assert any(f.type == "binary_file" for f in findings)
        binary_finding = next(f for f in findings if f.type == "binary_file")
        assert "regf" in binary_finding.value.lower() or "hex" in binary_finding.note.lower()

    def test_sqlite_gives_hex_preview(self):
        body = b"SQLite format 3\x00" + b"\x00" * 200
        findings = extract(_confirmed(
            "../../../../var/db/creds.db",
            body,
            binary_type="SQLite Database",
        ))
        assert any(f.type == "binary_file" for f in findings)


# ---------------------------------------------------------------------------
# Deduplication / pruning
# ---------------------------------------------------------------------------

class TestPruning:
    def test_specific_extractor_wins_over_generic_secret_variable(self):
        """
        When a database URL is found, a generic secret_variable finding for
        the same value should be pruned.
        """
        body = b"DATABASE_URL=postgres://admin:s3cr3t@db.internal/mydb\n"
        findings = extract(_confirmed(".env", body))
        # Should have database_url; secret_variable for the same value should be removed
        db_findings = [f for f in findings if f.type == "database_url"]
        assert len(db_findings) >= 1
        # If a secret_variable was also produced for DATABASE_URL, verify pruning worked
        secret_vars = [f for f in findings if f.type == "secret_variable"]
        db_url_value = db_findings[0].value
        # Pruned: no secret_variable should contain the same exact value as the database_url
        for sv in secret_vars:
            assert sv.value not in db_url_value


# ---------------------------------------------------------------------------
# Fix 1: config_password false positive — NSS service names (nsswitch.conf)
# ---------------------------------------------------------------------------

class TestNsswitchFalsePositive:
    """NSS service names in nsswitch.conf must NOT trigger config_password."""

    _NSSWITCH_BODY = (
        b"passwd:         files compat\n"
        b"group:          files compat\n"
        b"shadow:         files\n"
        b"hosts:          files mdns4_minimal [NOTFOUND=return] dns\n"
        b"networks:       files\n"
        b"protocols:      db files\n"
        b"services:       db files\n"
        b"ethers:         db files\n"
        b"rpc:            db files\n"
        b"netgroup:       nis\n"
    )

    def test_nsswitch_produces_no_config_password(self):
        findings = extract(_confirmed("etc/nsswitch.conf", self._NSSWITCH_BODY))
        config_pw = [f for f in findings if f.type == "config_password"]
        assert config_pw == [], (
            f"Expected no config_password findings from nsswitch.conf, got: {config_pw}"
        )

    def test_real_password_in_config_still_extracted(self):
        """A genuine password value in a config file should still be flagged."""
        body = b"password=VHealth_SA_2024!\n"
        findings = extract(_confirmed("app.conf", body))
        assert any(f.type == "config_password" for f in findings)


# ---------------------------------------------------------------------------
# Fix 3: Shadow entries must NOT be labelled as unix_user / unix_password_hash
# ---------------------------------------------------------------------------

class TestShadowNotMislabelledAsUnixUser:
    """Shadow file lines must not be parsed as passwd entries."""

    # Typical /etc/shadow line format:
    # username:hashed_or_locked_pw:last_changed:min:max:warn:inactive:expire:reserved
    _SHADOW_BODY = (
        b"root:*:20549:0:99999:7:::\n"
        b"daemon:*:20549:0:99999:7:::\n"
        b"nobody:*:20549:0:99999:7:::\n"
        b"appuser:$6$salt$hashedpassword:20549:0:99999:7:::\n"
    )

    def test_shadow_lines_not_extracted_as_unix_user(self):
        findings = extract(_confirmed("etc/shadow", self._SHADOW_BODY))
        unix_user = [f for f in findings if f.type == "unix_user"]
        assert unix_user == [], (
            f"Shadow lines incorrectly labelled as unix_user: {unix_user}"
        )

    def test_shadow_lines_not_extracted_as_unix_password_hash(self):
        # Only the lines with locked/no password (*, !) are tested here.
        # The appuser line has a real $6$ hash so _RE_SHADOW_HASH correctly
        # extracts it as unix_password_hash — that is intentional behaviour.
        # We check that the locked-account lines (root, daemon, nobody) do NOT
        # produce a unix_password_hash finding (their pw field is *, not a hash).
        findings = extract(_confirmed("etc/shadow", self._SHADOW_BODY))
        pw_hash = [f for f in findings if f.type == "unix_password_hash"]
        locked_as_hash = [f for f in pw_hash if any(
            name in f.value for name in ("root", "daemon", "nobody")
        )]
        assert locked_as_hash == [], (
            f"Locked-account shadow lines incorrectly labelled as unix_password_hash: {locked_as_hash}"
        )

    def test_real_passwd_line_still_extracted(self):
        """A genuine /etc/passwd line must still produce a unix_user finding."""
        body = b"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        findings = extract(_confirmed("etc/passwd", body))
        assert any(f.type == "unix_user" for f in findings)
