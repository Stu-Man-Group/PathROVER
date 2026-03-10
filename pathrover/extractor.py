"""
extractor.py - Passive sensitive data extraction from confirmed hits.

Runs only on CONFIRMED ClassifiedResults. Makes no additional HTTP requests.
For binary files, returns a hex preview and offline analysis instructions.

All text extractors run against every confirmed body — filename gating has
been removed so that files confirmed via heuristics still get extraction.
"""

from __future__ import annotations

import base64
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathrover.detection import ClassifiedResult


@dataclass
class ExtractedFinding:
    type: str
    value: str
    source_path: str
    note: str = ""


# ---------------------------------------------------------------------------
# EXTRACTION PATTERNS
# ---------------------------------------------------------------------------

_RE_UNIX_PASSWD_LINE = re.compile(
    r"^([^:\n]+):([^:\n]*):(\d+):(\d+):([^:\n]*):([^:\n]*):([^\n]*)$", re.MULTILINE
)
_RE_SHADOW_HASH = re.compile(
    r"^([^:]+):(\$(?:[1-6]|y|gy|sha512|md5)\$[^\s:]+):", re.MULTILINE
)
_RE_PEM_BLOCK = re.compile(
    r"(-----BEGIN [A-Z ]+-----[\s\S]+?-----END [A-Z ]+-----)", re.MULTILINE
)
_RE_AWS_KEY_ID = re.compile(r"aws_access_key_id\s*[=:]\s*([A-Z0-9]{16,32})", re.IGNORECASE)
_RE_AWS_SECRET = re.compile(r"aws_secret_access_key\s*[=:]\s*([A-Za-z0-9+/=]{30,60})", re.IGNORECASE)
_RE_DATABASE_URL = re.compile(
    r"(?:DATABASE_URL|DB_URL|CONNECTION_STRING|DB_HOST)\s*[=:]\s*['\"]?([^\s'\"]{8,})", re.IGNORECASE
)
_RE_CONNECTION_STRING_XML = re.compile(
    r'connectionString\s*=\s*["\']([^"\']{10,})["\']', re.IGNORECASE
)
# Generic secret variable patterns — KEY=value / KEY: value (YAML/config too)
# Matches both UPPER_CASE and lower_case / mixed_case secret variable names.
_RE_ENV_SECRET = re.compile(
    r'^([A-Za-z_][A-Za-z0-9_]*(?:key|token|secret|password|passwd|api_?key|private|credential|auth)[A-Za-z0-9_]*)\s*[=:]\s*(.{4,})$',
    re.IGNORECASE | re.MULTILINE,
)
# Broader env var capture (for /proc/self/environ and .env)
_RE_ENV_ALL_VARS = re.compile(
    r"^([A-Z_][A-Z0-9_]{2,})\s*=\s*(.+)$",
    re.IGNORECASE | re.MULTILINE,
)
_RE_UNATTEND_PASSWORD = re.compile(
    r"<Password>\s*<Value>([^<]+)</Value>", re.IGNORECASE
)
_RE_UNATTEND_USERNAME = re.compile(
    r"<Username>([^<]+)</Username>", re.IGNORECASE
)
_RE_UNATTEND_PRODUCT_KEY = re.compile(
    r"<ProductKey>([^<]+)</ProductKey>", re.IGNORECASE
)
_RE_JENKINS_MASTER_KEY = re.compile(r"^([a-f0-9]{64})$", re.MULTILINE)
_RE_PG_TRUST = re.compile(
    r"^(host[^\n]*\btrust\b|local[^\n]*\btrust\b)", re.MULTILINE
)
_RE_SHELL_NOTABLE = re.compile(
    r"^.*(?:password|passwd|token|secret|key|curl\s+-H|export\s+[A-Z_]+=|ssh\s+-i|"
    r"mysql\s+-p|psql\s+.*password|--password|--secret|Authorization:).*$",
    re.IGNORECASE | re.MULTILINE,
)
_RE_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
_RE_GCP_CREDS = re.compile(
    r'"(client_id|client_secret|refresh_token|private_key_id|private_key)"\s*:\s*"([^"]+)"'
)
_RE_AZURE_TOKEN = re.compile(
    r'"(accessToken|secret|clientSecret|password|refreshToken)"\s*:\s*"([^"]{8,})"', re.IGNORECASE
)
_RE_KUBE_TOKEN = re.compile(r"token:\s+([A-Za-z0-9_\-\.]{20,})")
_RE_KUBE_CERT = re.compile(
    r"(certificate-authority-data|client-certificate-data|client-key-data):\s+([A-Za-z0-9+/=]{20,})"
)
_RE_NPMRC_TOKEN = re.compile(r"//[^:]+:_authToken=([^\s]+)")
_RE_DOCKER_AUTH = re.compile(r'"auth"\s*:\s*"([A-Za-z0-9+/=]{8,})"')
# Generic password patterns in config files  password = secret123
_RE_GENERIC_PASSWORD = re.compile(
    r'^[ \t]*(?:password|passwd|pass|pwd|db_?pass(?:word)?|secret|auth_?(?:key|token|secret))'
    r'\s*[=:]\s*["\']?([^\s"\'#;]{4,})["\']?\s*(?:#.*)?$',
    re.IGNORECASE | re.MULTILINE,
)
# SSH authorized_keys lines
_RE_AUTHORIZED_KEY = re.compile(
    r'^(ssh-(?:rsa|ed25519|ecdsa)|ecdsa-sha2-nistp\d+)\s+(AAAA[A-Za-z0-9+/=]{20,})(?:\s+(.*))?$',
    re.MULTILINE,
)
# /proc/self/status — PID leak
_RE_PROC_PID = re.compile(r"^Pid:\s+(\d+)$", re.MULTILINE)
_RE_PROC_NAME = re.compile(r"^Name:\s+(\S+)$", re.MULTILINE)
# cgroup container ID detection  (useful for pivot)
_RE_CGROUP_CONTAINER = re.compile(
    r"(?:docker|kubepods|lxc)/(?:[a-z0-9\-]+/)*([a-f0-9]{12,64})"
)
# IP addresses in network/config files
_RE_PRIVATE_IP = re.compile(
    r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"
)
# Samba workgroup/password backend lines
_RE_SAMBA_PASS = re.compile(r"^(?:workgroup|passdb backend|security)\s*=\s*(.+)$", re.IGNORECASE | re.MULTILINE)
# MySQL / MariaDB bind-address + credentials
_RE_MYSQL_CONFIG = re.compile(r"^(?:bind-address|user|password|datadir)\s*=\s*(.+)$", re.IGNORECASE | re.MULTILINE)
# Kubernetes service account token (JWT in file)
_RE_SA_TOKEN = re.compile(r"^(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$", re.MULTILINE)
# Redis requirepass line
_RE_REDIS_PASS = re.compile(r"^requirepass\s+(\S+)", re.IGNORECASE | re.MULTILINE)
# Apache htpasswd
_RE_HTPASSWD = re.compile(r"^([^:]+):(\$apr1\$[^\s]+|\{SHA\}[^\s]+|[a-zA-Z0-9./]{13})\s*$", re.MULTILINE)
# Vault token (s.xxxxxxxx or hvs.xxxxxxxx)
_RE_VAULT_TOKEN = re.compile(r"\b((?:s|hvs|hvb)\.[A-Za-z0-9]{20,})\b")
# Generic bearer / API tokens in config lines
_RE_BEARER_TOKEN = re.compile(
    r'(?:Authorization|Bearer|X-Auth-Token|X-API-Key)\s*[=:]\s*["\']?([A-Za-z0-9\-_\.]{20,})["\']?',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# NEW PATTERNS — high-impact extraction gaps
# ---------------------------------------------------------------------------

# PowerShell history notable lines (ConsoleHost_history.txt)
_RE_PS_NOTABLE = re.compile(
    r"^.*(?:-[Pp]assword\s|ConvertTo-SecureString|Get-Credential|net\s+user\s|"
    r"Set-ADAccountPassword|Invoke-Expression|IEX\s*[\(\$]|"
    r"-[Cc]redential\s|\btoken\b|\bsecret\b|Authorization:|"
    r"[Aa][Ww][Ss]_|AZURE_|GOOGLE_|api[_\-]?key).*$",
    re.MULTILINE,
)

# .netrc — handles both single-line and multi-line formats
# Single-line:  machine host login user password pass
# Multi-line across 2-3 lines starting with machine
_RE_NETRC_ENTRY = re.compile(
    r"machine\s+(\S+)\s+login\s+(\S+)\s+password\s+(\S+)",
    re.IGNORECASE,
)
# Multi-line .netrc: machine on one line, login/password on subsequent lines
_RE_NETRC_MACHINE = re.compile(r"^machine\s+(\S+)", re.IGNORECASE | re.MULTILINE)
_RE_NETRC_LOGIN   = re.compile(r"^login\s+(\S+)",   re.IGNORECASE | re.MULTILINE)
_RE_NETRC_PASS    = re.compile(r"^password\s+(\S+)", re.IGNORECASE | re.MULTILINE)

# Django SECRET_KEY and Rails secret_key_base
_RE_FRAMEWORK_SECRET = re.compile(
    r"(?:SECRET_KEY|SECRET_KEY_BASE|secret_key_base)\s*[=:]\s*['\"]?([A-Za-z0-9+/\-_@#$!%^&*()]{20,})['\"]?",
    re.IGNORECASE,
)

# Jenkins credentials.xml — encrypted blobs and plaintext passwords
_RE_JENKINS_CRED_BLOB = re.compile(
    r"<(?:secret|password|privateKey|passphrase|apiToken|secretBytes)>"
    r"\s*(\{?[A-Za-z0-9+/=]{10,}\}?)\s*"
    r"</(?:secret|password|privateKey|passphrase|apiToken|secretBytes)>",
    re.IGNORECASE,
)
# Jenkins username entries for context
_RE_JENKINS_CRED_USER = re.compile(
    r"<username>\s*([^<]{1,100})\s*</username>",
    re.IGNORECASE,
)

# Maven settings.xml — <password> and <username> inside <server> blocks
_RE_MAVEN_SERVER = re.compile(
    r"<server>.*?<id>\s*([^<]+)\s*</id>.*?</server>",
    re.IGNORECASE | re.DOTALL,
)
_RE_MAVEN_PASSWORD = re.compile(
    r"<password>\s*([^<]{1,200})\s*</password>",
    re.IGNORECASE,
)
_RE_MAVEN_USERNAME = re.compile(
    r"<username>\s*([^<]{1,200})\s*</username>",
    re.IGNORECASE,
)

# .gem/credentials — RubyGems and GitHub tokens
_RE_GEM_TOKEN = re.compile(
    r"^:([a-zA-Z0-9_]+):\s*([A-Za-z0-9\-_]{8,})\s*$",
    re.MULTILINE,
)

# ~/.config/gh/hosts.yml — GitHub CLI oauth token
_RE_GH_CLI_TOKEN = re.compile(
    r"oauth_token:\s*([A-Za-z0-9_\-]{10,})",
    re.IGNORECASE,
)

# Rails config/master.key — 32-char hex string, one per line
# (Jenkins master.key is 64-char; this is explicitly 32-char to avoid collision)
_RE_RAILS_MASTER_KEY = re.compile(r"^([a-f0-9]{32})$", re.MULTILINE)

# Azure MSAL token cache — snake_case keys used by msal/azure-identity libraries
# (The existing _RE_AZURE_TOKEN only covers camelCase; MSAL uses snake_case)
_RE_MSAL_TOKEN = re.compile(
    r'"(access_token|refresh_token|id_token)"\s*:\s*"([A-Za-z0-9._\-]{20,})"',
    re.IGNORECASE,
)

# GitLab Runner config.toml — indented TOML token/url lines
# _RE_ENV_SECRET misses these because it anchors on ^[A-Za-z_] with no leading whitespace
_RE_TOML_TOKEN = re.compile(
    r'^[ \t]*(token|registration_token|url)\s*=\s*"([^"]{8,})"',
    re.IGNORECASE | re.MULTILINE,
)

# WinSCP INI — XOR-obfuscated Password= / ProxyPassword= hex blobs
_RE_WINSCP_PASSWORD = re.compile(
    r'^(Password|ProxyPassword)\s*=\s*([A-Fa-f0-9]{6,})\s*$',
    re.MULTILINE | re.IGNORECASE,
)
# WinSCP session context fields
_RE_WINSCP_HOST = re.compile(r'^HostName\s*=\s*(\S+)', re.MULTILINE | re.IGNORECASE)
_RE_WINSCP_USER = re.compile(r'^UserName\s*=\s*(\S+)', re.MULTILINE | re.IGNORECASE)

# ~/.git-credentials — plaintext https://user:token@host lines
_RE_GIT_CREDENTIALS = re.compile(
    r"https?://([^:@\s]+):([^@\s]{4,})@([^\s/]+)",
)

# Postfix sasl_passwd — [relay]:port user:password lines
_RE_POSTFIX_SASL = re.compile(
    r"^\s*(\[[^\]]+\](?::\d+)?|[a-zA-Z0-9.\-]+(?::\d+)?)\s+([^\s:]+):(\S+)\s*$",
    re.MULTILINE,
)

# RDCMan .rdg — server names and DPAPI-encrypted password blobs in XML
_RE_RDCMAN_SERVER = re.compile(r"<name>([^<]{3,})</name>", re.IGNORECASE)
_RE_RDCMAN_PASSWORD = re.compile(
    r"<password[^>]*>\s*(AQA[A-Za-z0-9+/=]{10,})\s*</password>",
    re.IGNORECASE,
)
_RE_RDCMAN_USER = re.compile(r"<userName>([^<]+)</userName>", re.IGNORECASE)

# ---------------------------------------------------------------------------
# IIS / ASP.NET — web.config / applicationHost.config
# ---------------------------------------------------------------------------

# machineKey — validationKey and decryptionKey (used for ViewState/auth cookie forgery)
_RE_MACHINE_KEY = re.compile(
    r'<machineKey\s[^>]*(?:validationKey|decryptionKey)\s*=\s*"([A-Fa-f0-9]{16,})"[^>]*/?>',
    re.IGNORECASE,
)
_RE_MACHINE_KEY_ATTR = re.compile(
    r'(?:validationKey|decryptionKey)\s*=\s*"([A-Fa-f0-9]{16,})"',
    re.IGNORECASE,
)
# <credentials password="..."> — Forms auth plaintext password
_RE_IIS_CREDENTIALS = re.compile(
    r'<credentials\b[^>]*\bpassword\s*=\s*"([^"]{4,})"',
    re.IGNORECASE,
)
# <user name="..." password="..."> inside <credentials>
_RE_IIS_USER_PASS = re.compile(
    r'<user\s[^>]*\bname\s*=\s*"([^"]+)"[^>]*\bpassword\s*=\s*"([^"]{4,})"',
    re.IGNORECASE,
)
# <smtp> deliveryMethod + network credentials
_RE_IIS_SMTP_PASS = re.compile(
    r'<network\b[^>]*\bpassword\s*=\s*"([^"]{4,})"[^>]*(?:\buserName\s*=\s*"([^"]*)")?',
    re.IGNORECASE,
)
_RE_IIS_SMTP_USER = re.compile(
    r'<network\b[^>]*\buserName\s*=\s*"([^"]+)"',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# sudoers — passwordless sudo rules
# ---------------------------------------------------------------------------

_RE_SUDOERS_NOPASSWD = re.compile(
    r"^[^#\n]*NOPASSWD\s*:[^#\n]*$", re.IGNORECASE | re.MULTILINE
)

# ---------------------------------------------------------------------------
# SSH client config (~/.ssh/config)
# ---------------------------------------------------------------------------

_RE_SSH_CONFIG_ENTRY = re.compile(
    r"^\s*(Host|HostName|User|IdentityFile|ProxyJump|ProxyCommand|IdentityAgent"
    r"|Port|ForwardAgent|LocalForward|RemoteForward)\s+(.+)$",
    re.IGNORECASE | re.MULTILINE,
)

# ---------------------------------------------------------------------------
# Log files — accidentally-logged credentials
# ---------------------------------------------------------------------------

# HTTP Basic auth header value in logs: "Authorization: Basic <b64>"
_RE_LOG_BASIC_AUTH = re.compile(
    r'Authorization:\s*Basic\s+([A-Za-z0-9+/=]{8,})',
    re.IGNORECASE,
)
# Password/token in query string: ?password=foo&  or  ?pass=foo&  etc.
_RE_LOG_QUERY_CRED = re.compile(
    r'[?&](?:password|passwd|pass|pwd|token|secret|api[_\-]?key|auth)\s*=\s*([^&\s"\']{4,})',
    re.IGNORECASE,
)
# SMTP AUTH PLAIN / LOGIN base64 blobs in mail logs (Postfix, Exim, sendmail)
_RE_LOG_SMTP_AUTH = re.compile(
    r'(?:AUTH\s+(?:PLAIN|LOGIN)|sasl_username|sasl_password)\s+([A-Za-z0-9+/=]{8,})',
    re.IGNORECASE,
)
# curl -u user:pass or wget --password= appearing in logged commands
_RE_LOG_CURL_CREDS = re.compile(
    r'(?:curl\s+.*-u\s+["\']?(\S+:\S+)|wget\s+.*--password[=\s]+(\S+))',
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# PHP define() credential syntax
# ---------------------------------------------------------------------------

_RE_PHP_DEFINE = re.compile(
    r"define\s*\(\s*['\"]([^'\"]*(?:password|passwd|secret|key|token|auth|api)[^'\"]*)['\"]"
    r"\s*,\s*['\"]([^'\"]{4,})['\"]",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# BINARY OFFLINE NOTES
# ---------------------------------------------------------------------------
BINARY_OFFLINE_NOTES: dict[str, str] = {
    "Windows Registry Hive (regf)": (
        "Binary Windows registry hive. Offline analysis required. "
        "Recommended: impacket-secretsdump (SAM+SYSTEM for NTLM hashes, "
        "SECURITY for LSA secrets/cached creds). "
        "Command: impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL"
    ),
    "Windows Event Log (.evtx)": (
        "Binary Windows Event Log. Offline analysis required. "
        "Recommended: python-evtx (pip install python-evtx) or Windows Event Viewer. "
        "Command: evtx_dump.py Security.evtx | grep -i password"
    ),
    "SQL Server Data File (.mdf/.ldf)": (
        "Binary SQL Server data/log file. Offline analysis required. "
        "Recommended: attach to a local SQL Server instance or use mdf-parser tools."
    ),
    "Apple Binary Plist (bplist)": (
        "Apple binary property list. Offline analysis required. "
        "Recommended: plutil -convert xml1 file.plist -o output.xml  "
        "OR: python3 -c \"import plistlib,sys; print(plistlib.load(open(sys.argv[1],'rb')))\" file.plist"
    ),
    "macOS Keychain Database": (
        "macOS Keychain database. Offline analysis required. "
        "Recommended: chainbreaker (https://github.com/n0fate/chainbreaker) "
        "or keychain-dumper. Requires user password or unlocked keychain."
    ),
    "SQLite Database": (
        "SQLite database. Offline analysis required. "
        "Recommended: sqlite3 file.db .dump  "
        "For Chrome Login Data: sqlite3 'Login Data' \"SELECT origin_url,username_value,password_value FROM logins;\""
        " (passwords are AES-encrypted with OS keychain key on macOS/Windows)."
    ),
    "MySQL InnoDB Data File": (
        "Binary MySQL InnoDB data file. Offline analysis required. "
        "Recommended: attach to a local MySQL instance or use innodb-parser tools."
    ),
    "Rails Encrypted Credentials": (
        "Rails AES-256-GCM encrypted credentials file (credentials.yml.enc). "
        "Offline decryption requires config/master.key or RAILS_MASTER_KEY env var. "
        "Decrypt with: RAILS_MASTER_KEY=<key> rails credentials:edit --environment production  "
        "OR: ruby -e \"require 'active_support'; "
        "puts ActiveSupport::EncryptedFile.new(content_path: 'credentials.yml.enc', "
        "key_path: 'master.key', env_key: 'RAILS_MASTER_KEY', raise_if_missing_key: true).read\""
    ),
    "Jenkins hudson.util.Secret": (
        "Binary Jenkins AES key file (hudson.util.Secret). "
        "Used together with secrets/master.key to decrypt credentials.xml blobs. "
        "Offline decrypt with: https://github.com/tweksteen/jenkins-decrypt  "
        "Command: python3 jenkins_decrypt.py master.key hudson.util.Secret credentials.xml"
    ),
}


def _hex_preview(data: bytes, max_bytes: int = 256) -> str:
    """Return a formatted hex dump of the first max_bytes bytes."""
    chunk = data[:max_bytes]
    lines = []
    for i in range(0, len(chunk), 16):
        row = chunk[i: i + 16]
        hex_part = " ".join(f"{b:02x}" for b in row)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append(f"{i:04x}  {hex_part:<47}  {ascii_part}")
    return "\n".join(lines)


def _dedupe(findings: list[ExtractedFinding]) -> list[ExtractedFinding]:
    """Remove duplicate (type, value) pairs while preserving order."""
    seen: set[tuple[str, str]] = set()
    out: list[ExtractedFinding] = []
    for f in findings:
        key = (f.type, f.value[:200])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def extract(result: "ClassifiedResult") -> list[ExtractedFinding]:
    """Extract sensitive data from a CONFIRMED ClassifiedResult."""
    findings: list[ExtractedFinding] = []
    path = result.payload

    # Binary handling
    if result.is_binary:
        _extract_binary(result, findings)
        return findings

    # Text extraction
    try:
        body = result.body_bytes.decode("utf-8", errors="replace")
    except Exception:
        return findings

    # Normalise path hints for optional gating (used only for context, not as gates)
    filename = path.replace("\\", "/").split("/")[-1].lower()
    path_lower = path.lower().replace("\\", "/")

    # -----------------------------------------------------------------------
    # ALWAYS-RUN extractors (no filename gate)
    # -----------------------------------------------------------------------

    # PEM blocks (private keys, certificates) — high value, always extract
    for m in _RE_PEM_BLOCK.finditer(body):
        key_type = "private_key" if "PRIVATE KEY" in m.group(1) else "certificate"
        findings.append(ExtractedFinding(
            type=key_type,
            value=m.group(1),
            source_path=path,
            note="PEM block extracted",
        ))

    # SSH public keys / authorized_keys lines
    for m in _RE_AUTHORIZED_KEY.finditer(body):
        comment = m.group(3) or ""
        findings.append(ExtractedFinding(
            type="ssh_public_key",
            value=f"{m.group(1)} {m.group(2)[:40]}... {comment}".strip(),
            source_path=path,
            note="SSH public key / authorized_keys entry",
        ))

    # AWS credentials
    for m in _RE_AWS_KEY_ID.finditer(body):
        findings.append(ExtractedFinding(
            type="aws_access_key_id",
            value=m.group(1),
            source_path=path,
        ))
    for m in _RE_AWS_SECRET.finditer(body):
        findings.append(ExtractedFinding(
            type="aws_secret_access_key",
            value=m.group(1),
            source_path=path,
        ))

    # JWT tokens
    for m in _RE_JWT.finditer(body):
        findings.append(ExtractedFinding(
            type="jwt_token",
            value=m.group(0),
            source_path=path,
            note="JWT — decode at jwt.io to inspect claims",
        ))

    # Kubernetes service account token (raw JWT in token file)
    for m in _RE_SA_TOKEN.finditer(body):
        findings.append(ExtractedFinding(
            type="kubernetes_sa_token",
            value=m.group(1),
            source_path=path,
            note="Kubernetes service account JWT token",
        ))

    # Vault tokens
    for m in _RE_VAULT_TOKEN.finditer(body):
        findings.append(ExtractedFinding(
            type="vault_token",
            value=m.group(1),
            source_path=path,
        ))

    # Bearer / API key tokens in config lines
    for m in _RE_BEARER_TOKEN.finditer(body):
        findings.append(ExtractedFinding(
            type="api_token",
            value=m.group(1),
            source_path=path,
            note=f"Token type hint: {m.group(0).split('=')[0].split(':')[0].strip()}",
        ))

    # Database URLs / connection strings
    for m in _RE_DATABASE_URL.finditer(body):
        findings.append(ExtractedFinding(
            type="database_url",
            value=m.group(1),
            source_path=path,
        ))
    for m in _RE_CONNECTION_STRING_XML.finditer(body):
        findings.append(ExtractedFinding(
            type="connection_string",
            value=m.group(1),
            source_path=path,
        ))

    # Generic secret variable patterns (KEY=value / KEY: value)
    for m in _RE_ENV_SECRET.finditer(body):
        val = m.group(2).strip().strip("'\"")
        if len(val) >= 4:
            findings.append(ExtractedFinding(
                type="secret_variable",
                value=f"{m.group(1)}={val}",
                source_path=path,
            ))

    # Generic password assignments in config files
    for m in _RE_GENERIC_PASSWORD.finditer(body):
        val = m.group(1).strip()
        if val and val not in ("''", '""', "changeme", "password", "secret", "xxx"):
            findings.append(ExtractedFinding(
                type="config_password",
                value=val,
                source_path=path,
                note=f"Matched line: {m.group(0).strip()[:120]}",
            ))

    # GCP credentials
    for m in _RE_GCP_CREDS.finditer(body):
        findings.append(ExtractedFinding(
            type="gcp_credential",
            value=f"{m.group(1)}: {m.group(2)[:80]}",
            source_path=path,
        ))

    # Azure tokens
    for m in _RE_AZURE_TOKEN.finditer(body):
        if len(m.group(2)) > 8:
            findings.append(ExtractedFinding(
                type="azure_token",
                value=f"{m.group(1)}: {m.group(2)[:80]}",
                source_path=path,
            ))

    # Kubeconfig tokens and cert data
    for m in _RE_KUBE_TOKEN.finditer(body):
        findings.append(ExtractedFinding(
            type="kubernetes_token",
            value=m.group(1),
            source_path=path,
            note="Kubernetes service account or user token",
        ))
    for m in _RE_KUBE_CERT.finditer(body):
        findings.append(ExtractedFinding(
            type="kubernetes_cert_data",
            value=f"{m.group(1)}: {m.group(2)[:40]}...",
            source_path=path,
        ))

    # Container ID from cgroup file (pivot indicator)
    for m in _RE_CGROUP_CONTAINER.finditer(body):
        findings.append(ExtractedFinding(
            type="container_id",
            value=m.group(1),
            source_path=path,
            note="Container ID from cgroup — confirms running inside Docker/k8s",
        ))

    # Internal/private IP addresses
    ips = list(dict.fromkeys(_RE_PRIVATE_IP.findall(body)))  # dedupe preserving order
    if ips:
        findings.append(ExtractedFinding(
            type="internal_ip_addresses",
            value=", ".join(ips[:20]),
            source_path=path,
            note="Private IP addresses found in file — useful for network mapping",
        ))

    # -----------------------------------------------------------------------
    # FILE-TYPE-SPECIFIC extractors (still run via regex, no hard filename gate)
    # -----------------------------------------------------------------------

    # PowerShell history (ConsoleHost_history.txt)
    is_ps_history = (
        "consolehost_history" in filename
        or "consolehost_history" in path_lower
        or "psreadline" in path_lower
    )
    if is_ps_history:
        ps_notable = _RE_PS_NOTABLE.findall(body)
        for line in ps_notable[:30]:
            findings.append(ExtractedFinding(
                type="powershell_history_notable",
                value=line.strip(),
                source_path=path,
                note="PowerShell history — sensitive command",
            ))
    else:
        # Still extract if body looks like PS history (multiple PS-style lines)
        ps_notable = _RE_PS_NOTABLE.findall(body)
        if len(ps_notable) >= 2:
            for line in ps_notable[:15]:
                findings.append(ExtractedFinding(
                    type="powershell_history_notable",
                    value=line.strip(),
                    source_path=path,
                    note="PowerShell history — sensitive command",
                ))

    # .netrc credentials
    if "netrc" in filename or "netrc" in path_lower or (
        "machine " in body.lower() and "password " in body.lower()
    ):
        # Try single-line format first
        for m in _RE_NETRC_ENTRY.finditer(body):
            findings.append(ExtractedFinding(
                type="netrc_credential",
                value=f"machine={m.group(1)} login={m.group(2)} password={m.group(3)}",
                source_path=path,
                note=".netrc cleartext credential",
            ))
        # Multi-line format: pair up machines with logins and passwords
        if not _RE_NETRC_ENTRY.search(body):
            machines = _RE_NETRC_MACHINE.findall(body)
            logins   = _RE_NETRC_LOGIN.findall(body)
            passwords = _RE_NETRC_PASS.findall(body)
            for i, machine in enumerate(machines):
                login = logins[i] if i < len(logins) else "?"
                pw    = passwords[i] if i < len(passwords) else "?"
                findings.append(ExtractedFinding(
                    type="netrc_credential",
                    value=f"machine={machine} login={login} password={pw}",
                    source_path=path,
                    note=".netrc cleartext credential",
                ))

    # Django SECRET_KEY / Rails secret_key_base
    for m in _RE_FRAMEWORK_SECRET.finditer(body):
        findings.append(ExtractedFinding(
            type="framework_secret_key",
            value=m.group(1),
            source_path=path,
            note=f"Django/Rails secret key (matched: {m.group(0).split('=')[0].split(':')[0].strip()})",
        ))

    # Jenkins credentials.xml encrypted blobs
    if "credentials" in filename or "credentials" in path_lower or "jenkins" in path_lower:
        usernames = _RE_JENKINS_CRED_USER.findall(body)
        for i, m in enumerate(_RE_JENKINS_CRED_BLOB.finditer(body)):
            user_hint = usernames[i] if i < len(usernames) else ""
            findings.append(ExtractedFinding(
                type="jenkins_encrypted_credential",
                value=m.group(1),
                source_path=path,
                note=(
                    f"{'User: ' + user_hint + ' — ' if user_hint else ''}"
                    "Jenkins encrypted credential blob. "
                    "Decrypt with: master.key + hudson.util.Secret via jenkins-decrypt or "
                    "impacket's jenkins_decrypt.py"
                ),
            ))

    # Maven settings.xml
    if "settings" in filename and (".xml" in filename or ".xml" in path_lower):
        for m in _RE_MAVEN_PASSWORD.finditer(body):
            val = m.group(1).strip()
            if val:
                # Try to find a nearby username for context
                user_m = _RE_MAVEN_USERNAME.search(body)
                user_hint = user_m.group(1).strip() if user_m else ""
                findings.append(ExtractedFinding(
                    type="maven_server_password",
                    value=val,
                    source_path=path,
                    note=f"Maven settings.xml server password{' (user: ' + user_hint + ')' if user_hint else ''}",
                ))
    elif "settings.xml" in path_lower or ("maven" in path_lower and ".xml" in path_lower):
        for m in _RE_MAVEN_PASSWORD.finditer(body):
            val = m.group(1).strip()
            if val:
                findings.append(ExtractedFinding(
                    type="maven_server_password",
                    value=val,
                    source_path=path,
                    note="Maven settings.xml server password",
                ))

    # .gem/credentials — RubyGems / GitHub tokens
    if ".gem" in path_lower or "gem/credentials" in path_lower or (
        body.lstrip().startswith("---") and ":rubygems" in body
    ):
        for m in _RE_GEM_TOKEN.finditer(body):
            findings.append(ExtractedFinding(
                type="rubygems_token",
                value=f":{m.group(1)}: {m.group(2)}",
                source_path=path,
                note="RubyGems / GitHub gem credential",
            ))

    # GitHub CLI hosts.yml
    if "gh" in path_lower and ("hosts.yml" in filename or "hosts.yml" in path_lower):
        for m in _RE_GH_CLI_TOKEN.finditer(body):
            findings.append(ExtractedFinding(
                type="github_cli_token",
                value=m.group(1),
                source_path=path,
                note="GitHub CLI oauth_token from ~/.config/gh/hosts.yml",
            ))
    elif "oauth_token:" in body.lower():
        for m in _RE_GH_CLI_TOKEN.finditer(body):
            findings.append(ExtractedFinding(
                type="github_cli_token",
                value=m.group(1),
                source_path=path,
                note="GitHub CLI oauth_token",
            ))

    # Rails config/master.key — 32-char hex (Jenkins is 64-char; different pattern)
    if "master.key" in filename or (
        "master.key" in path_lower and "rails" not in path_lower.split("master.key")[0][-20:]
    ) or path_lower.endswith("master.key"):
        for m in _RE_RAILS_MASTER_KEY.finditer(body):
            findings.append(ExtractedFinding(
                type="rails_master_key",
                value=m.group(1),
                source_path=path,
                note=(
                    "Rails master key (32-char hex). "
                    "Decrypts config/credentials.yml.enc via: "
                    "RAILS_MASTER_KEY=<key> rails credentials:edit"
                ),
            ))

    # Azure MSAL token cache — snake_case access_token/refresh_token
    if "msal" in path_lower or "msal_token_cache" in filename or (
        '"access_token"' in body or '"refresh_token"' in body
    ):
        for m in _RE_MSAL_TOKEN.finditer(body):
            token_val = m.group(2)
            findings.append(ExtractedFinding(
                type="azure_msal_token",
                value=f"{m.group(1)}: {token_val[:80]}{'...' if len(token_val) > 80 else ''}",
                source_path=path,
                note=(
                    f"Azure MSAL {m.group(1)} — live OAuth token, "
                    "usable directly with az CLI or MSAL libraries. No decryption needed."
                ),
            ))

    # Ansible vault password file — bare single-line secret
    if any(hint in path_lower for hint in (
        "ansible_vault_pass", "vault_pass", "vault_pass.txt", ".ansible_vault"
    )):
        stripped = body.strip()
        # Only fire if it looks like a bare password (no key=value, no yaml structure)
        if stripped and "\n" not in stripped and "=" not in stripped and ":" not in stripped[:20]:
            findings.append(ExtractedFinding(
                type="ansible_vault_password",
                value=stripped[:500],
                source_path=path,
                note=(
                    "Ansible Vault plaintext decryption password. "
                    "Decrypt vaults with: ansible-vault decrypt --vault-password-file <this_file> vault.yml"
                ),
            ))
        elif stripped:
            # Multi-line or key:value vault pass file — emit first non-comment line
            for line in stripped.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    findings.append(ExtractedFinding(
                        type="ansible_vault_password",
                        value=line[:500],
                        source_path=path,
                        note="Ansible Vault password file",
                    ))
                    break

    # GitLab Runner config.toml — indented token/url fields
    if "config.toml" in filename or (
        "gitlab" in path_lower and ".toml" in path_lower
    ) or (
        "[[runners]]" in body and "token" in body.lower()
    ):
        runner_urls: list[str] = []
        for m in _RE_TOML_TOKEN.finditer(body):
            field = m.group(1).lower()
            val = m.group(2)
            if field == "url":
                runner_urls.append(val)
            else:
                findings.append(ExtractedFinding(
                    type="gitlab_runner_token",
                    value=val,
                    source_path=path,
                    note=(
                        f"GitLab Runner {'registration ' if val.startswith('glrt-') else ''}token"
                        f"{' (url: ' + runner_urls[-1] + ')' if runner_urls else ''}. "
                        "Register a new runner or access the GitLab API with this token."
                    ),
                ))

    # WinSCP INI — XOR-obfuscated passwords
    body_lower = body.lower()
    if "winscp" in path_lower or "winscp" in filename or (
        "[sessions\\" in body_lower
        and "hostname" in body_lower
        and "password" in body_lower
        and "winscp" in body_lower
    ):
        host_m = _RE_WINSCP_HOST.search(body)
        user_m = _RE_WINSCP_USER.search(body)
        host_hint = host_m.group(1) if host_m else ""
        user_hint = user_m.group(1) if user_m else ""
        for m in _RE_WINSCP_PASSWORD.finditer(body):
            findings.append(ExtractedFinding(
                type="winscp_obfuscated_password",
                value=m.group(2),
                source_path=path,
                note=(
                    f"WinSCP XOR-obfuscated password (field: {m.group(1)})"
                    f"{', host: ' + host_hint if host_hint else ''}"
                    f"{', user: ' + user_hint if user_hint else ''}. "
                    "Recover with: https://github.com/bhavesh-davda/winscp-password-decryptor  "
                    "OR one-liner: python3 -c \""
                    "h='<hex>'; k=ord('A'); r=''.join(chr(int(h[i:i+2],16)^k^(i//2)) "
                    "for i in range(0,len(h),2))[1:]; print(r)\""
                ),
            ))

    # ~/.git-credentials — plaintext https://user:token@host
    if ".git-credentials" in filename or ".git-credentials" in path_lower or (
        "https://" in body and "@" in body and ("github" in body or "gitlab" in body or "bitbucket" in body)
    ):
        for m in _RE_GIT_CREDENTIALS.finditer(body):
            findings.append(ExtractedFinding(
                type="git_credential",
                value=f"{m.group(1)}:{m.group(2)}@{m.group(3)}",
                source_path=path,
                note=(
                    f"Git plaintext credential for {m.group(3)}. "
                    "Use directly: git clone https://<user>:<token>@<host>/repo.git"
                ),
            ))

    # Postfix sasl_passwd — [relay]:port user:password
    if "sasl_passwd" in filename or "sasl_passwd" in path_lower or (
        "postfix" in path_lower and "passwd" in path_lower
    ):
        for m in _RE_POSTFIX_SASL.finditer(body):
            relay, user, pw = m.group(1), m.group(2), m.group(3)
            findings.append(ExtractedFinding(
                type="postfix_sasl_credential",
                value=f"relay={relay} user={user} password={pw}",
                source_path=path,
                note=(
                    "Postfix SMTP relay credential (sasl_passwd). "
                    "May be a SendGrid API key, Mailgun token, SES SMTP password, or Gmail app password."
                ),
            ))

    # RDCMan .rdg — DPAPI-encrypted RDP session passwords
    if ".rdg" in filename or ".rdg" in path_lower or (
        "rdcman" in path_lower or (
            "<RDCMan" in body or "<remoteDesktop" in body.lower() or
            ("<server>" in body.lower() and "<logonCredentials>" in body.lower())
        )
    ):
        servers = _RE_RDCMAN_SERVER.findall(body)
        users = _RE_RDCMAN_USER.findall(body)
        for i, m in enumerate(_RE_RDCMAN_PASSWORD.finditer(body)):
            server_hint = servers[i] if i < len(servers) else ""
            user_hint = users[i] if i < len(users) else ""
            findings.append(ExtractedFinding(
                type="rdcman_dpapi_password",
                value=m.group(1)[:80],
                source_path=path,
                note=(
                    f"RDCMan DPAPI-encrypted RDP password"
                    f"{' for ' + server_hint if server_hint else ''}"
                    f"{' (user: ' + user_hint + ')' if user_hint else ''}. "
                    "Decrypt offline with: mimikatz 'dpapi::rdg /in:<file>.rdg /unprotect'  "
                    "OR: https://github.com/nettitude/PoshC2/blob/master/resources/modules/Decrypt-RDCMan.ps1"
                ),
            ))

    # Unix passwd-format lines (root:x:0:0:...)
    passwd_matches = _RE_UNIX_PASSWD_LINE.findall(body)
    if passwd_matches:
        for m in passwd_matches:
            username, pw_field, uid, gid, gecos, home, shell = m
            # Filter noise — skip lines that don't look like real accounts
            if not uid.isdigit():
                continue
            if pw_field not in ("x", "*", "!!", "!", ""):
                findings.append(ExtractedFinding(
                    type="unix_password_hash",
                    value=f"{username}:{pw_field}:{uid}:{gid}:{gecos}:{home}:{shell}",
                    source_path=path,
                    note=f"User: {username} — hash may be crackable",
                ))
            else:
                findings.append(ExtractedFinding(
                    type="unix_user",
                    value=f"{username}:{uid}:{home}:{shell}",
                    source_path=path,
                    note="username:uid:home:shell",
                ))

    # Shadow / gshadow hashes
    _SHADOW_ALGO_MAP = {
        "$1$":  "MD5 (hashcat -m 500)",
        "$2$":  "Blowfish/bcrypt (hashcat -m 3200)",
        "$2a$": "bcrypt (hashcat -m 3200)",
        "$2b$": "bcrypt (hashcat -m 3200)",
        "$5$":  "SHA-256 (hashcat -m 7400)",
        "$6$":  "SHA-512 (hashcat -m 1800)",
        "$y$":  "yescrypt (hashcat -m 7900)",
        "$gy$": "gost-yescrypt (hashcat -m 23900)",
        "$7$":  "scrypt (hashcat -m 8900)",
    }
    for m in _RE_SHADOW_HASH.finditer(body):
        hash_val = m.group(2)
        algo_note = next(
            (label for prefix, label in _SHADOW_ALGO_MAP.items() if hash_val.startswith(prefix)),
            "unknown algorithm",
        )
        findings.append(ExtractedFinding(
            type="unix_password_hash",
            value=f"{m.group(1)}:{hash_val}",
            source_path=path,
            note=f"User: {m.group(1)} — {algo_note} — crackable with hashcat/john",
        ))

    # /proc/self/environ null-separated variables
    # Servers may strip/replace null bytes, so we try both: null-delimited and
    # heuristic splitting on uppercase KEY= boundaries as a fallback.
    if "\x00" in body or ("environ" in filename and "proc" in path_lower):
        if "\x00" in body:
            # Properly null-delimited: replace nulls with newlines before matching
            environ_text = body.replace("\x00", "\n")
        else:
            # Null bytes stripped by the server: attempt to split on KEY= boundaries
            # by inserting newlines before any run of UPPER_CASE= that looks like an
            # env var name (must start at a word boundary after the previous value).
            import re as _re
            environ_text = _re.sub(r'(?<=[^\n])([A-Z_][A-Z0-9_]{2,}=)', r'\n\1', body)
        for m in _RE_ENV_SECRET.finditer(environ_text):
            val = m.group(2).strip()
            findings.append(ExtractedFinding(
                type="process_env_secret",
                value=f"{m.group(1)}={val}",
                source_path=path,
                note="Leaked via /proc/self/environ",
            ))

    # /proc/self/status — process name and PID
    pid_m = _RE_PROC_PID.search(body)
    name_m = _RE_PROC_NAME.search(body)
    if pid_m and name_m:
        findings.append(ExtractedFinding(
            type="process_info",
            value=f"Name={name_m.group(1)} PID={pid_m.group(1)}",
            source_path=path,
            note="Process name and PID from /proc/self/status",
        ))

    # Unattend.xml credentials
    if "unattend" in filename or "unattend" in path_lower or "sysprep" in path_lower:
        for m in _RE_UNATTEND_PASSWORD.finditer(body):
            findings.append(ExtractedFinding(
                type="unattend_password",
                value=m.group(1),
                source_path=path,
                note="Windows provisioning/unattend password",
            ))
        for m in _RE_UNATTEND_USERNAME.finditer(body):
            findings.append(ExtractedFinding(
                type="unattend_username",
                value=m.group(1),
                source_path=path,
            ))
        for m in _RE_UNATTEND_PRODUCT_KEY.finditer(body):
            findings.append(ExtractedFinding(
                type="windows_product_key",
                value=m.group(1),
                source_path=path,
            ))

    # Jenkins master.key — 64-char hex string, gated to Jenkins-related paths only.
    # Without the gate this fires on any file containing a 64-char hex string
    # (e.g. PostgreSQL configs, Rails files, git hashes), producing false positives.
    is_jenkins_key_path = (
        "master.key" in filename
        or "jenkins" in path_lower
        or "hudson" in path_lower
    )
    if is_jenkins_key_path:
        for m in _RE_JENKINS_MASTER_KEY.finditer(body):
            findings.append(ExtractedFinding(
                type="jenkins_master_key",
                value=m.group(1),
                source_path=path,
                note="Use with hudson.util.Secret to decrypt Jenkins credentials.xml",
            ))

    # pg_hba.conf trust entries
    for m in _RE_PG_TRUST.finditer(body):
        findings.append(ExtractedFinding(
            type="pg_hba_trust_entry",
            value=m.group(1),
            source_path=path,
            note="CRITICAL: trust auth allows password-less PostgreSQL access",
        ))

    # Shell history notable lines
    if any(hist in filename for hist in ["history", "_hist"]) or any(hist in path_lower for hist in ["bash_history", "zsh_history", "sh_history", "fish_history", "psql_history", "mysql_history", "python_history"]):
        notable = _RE_SHELL_NOTABLE.findall(body)
        for line in notable[:20]:
            findings.append(ExtractedFinding(
                type="shell_history_notable",
                value=line.strip(),
                source_path=path,
            ))
    else:
        # Still extract shell history notable lines even without filename gate
        # if body looks like shell history (multiple command lines)
        notable = _RE_SHELL_NOTABLE.findall(body)
        if len(notable) >= 2:
            for line in notable[:10]:
                findings.append(ExtractedFinding(
                    type="shell_history_notable",
                    value=line.strip(),
                    source_path=path,
                ))

    # npm auth token
    for m in _RE_NPMRC_TOKEN.finditer(body):
        findings.append(ExtractedFinding(
            type="npm_auth_token",
            value=m.group(1),
            source_path=path,
        ))

    # Docker registry auth
    for m in _RE_DOCKER_AUTH.finditer(body):
        try:
            decoded = base64.b64decode(m.group(1)).decode("utf-8", errors="replace")
            findings.append(ExtractedFinding(
                type="docker_registry_auth",
                value=decoded,
                source_path=path,
                note="Base64-decoded Docker registry credentials",
            ))
        except Exception:
            findings.append(ExtractedFinding(
                type="docker_registry_auth_b64",
                value=m.group(1),
                source_path=path,
            ))

    # Redis requirepass
    for m in _RE_REDIS_PASS.finditer(body):
        findings.append(ExtractedFinding(
            type="redis_password",
            value=m.group(1),
            source_path=path,
        ))

    # Apache htpasswd entries
    for m in _RE_HTPASSWD.finditer(body):
        findings.append(ExtractedFinding(
            type="htpasswd_entry",
            value=f"{m.group(1)}:{m.group(2)}",
            source_path=path,
            note="Apache htpasswd credential — crackable with hashcat/john",
        ))

    # MySQL config interesting values
    for m in _RE_MYSQL_CONFIG.finditer(body):
        findings.append(ExtractedFinding(
            type="mysql_config_value",
            value=f"{m.group(0).strip()}",
            source_path=path,
        ))

    # Samba config
    for m in _RE_SAMBA_PASS.finditer(body):
        findings.append(ExtractedFinding(
            type="samba_config_value",
            value=m.group(0).strip(),
            source_path=path,
        ))

    # -----------------------------------------------------------------------
    # IIS / ASP.NET — web.config / applicationHost.config
    # -----------------------------------------------------------------------
    is_iis_config = any(hint in path_lower for hint in (
        "web.config", "applicationhost.config", "connectionstrings.config",
        "appsettings.config", "machine.config",
    )) or (
        "<configuration>" in body.lower() and (
            "<system.web>" in body.lower()
            or "<connectionstrings>" in body.lower()
            or "machinekey" in body.lower()
        )
    )
    if is_iis_config:
        # machineKey — validationKey / decryptionKey attributes
        for m in _RE_MACHINE_KEY_ATTR.finditer(body):
            findings.append(ExtractedFinding(
                type="iis_machine_key",
                value=m.group(1),
                source_path=path,
                note=(
                    "ASP.NET machineKey attribute. "
                    "Use to forge ViewState payloads or auth cookies. "
                    "Attack with: https://github.com/pwntester/ysoserial.net"
                ),
            ))
        # Forms auth <credentials password="...">
        for m in _RE_IIS_CREDENTIALS.finditer(body):
            findings.append(ExtractedFinding(
                type="iis_forms_auth_password",
                value=m.group(1),
                source_path=path,
                note="ASP.NET Forms authentication credential (plaintext)",
            ))
        # <user name="..." password="...">
        for m in _RE_IIS_USER_PASS.finditer(body):
            findings.append(ExtractedFinding(
                type="iis_user_credential",
                value=f"{m.group(1)}:{m.group(2)}",
                source_path=path,
                note="ASP.NET Forms auth user credential",
            ))
        # SMTP <network password="..." userName="...">
        smtp_users = _RE_IIS_SMTP_USER.findall(body)
        for i, m in enumerate(_RE_IIS_SMTP_PASS.finditer(body)):
            user_hint = smtp_users[i] if i < len(smtp_users) else (m.group(2) or "")
            findings.append(ExtractedFinding(
                type="iis_smtp_credential",
                value=f"password={m.group(1)}" + (f" user={user_hint}" if user_hint else ""),
                source_path=path,
                note="ASP.NET SMTP relay credential from <mailSettings>",
            ))

    # -----------------------------------------------------------------------
    # sudoers — passwordless sudo rules
    # -----------------------------------------------------------------------
    is_sudoers = (
        "sudoers" in filename
        or "sudoers" in path_lower
        or (
            "nopasswd" in body.lower()
            and ("all=" in body.lower() or "all =(" in body.lower())
        )
    )
    if is_sudoers:
        for m in _RE_SUDOERS_NOPASSWD.finditer(body):
            line = m.group(0).strip()
            findings.append(ExtractedFinding(
                type="sudoers_nopasswd",
                value=line,
                source_path=path,
                note=(
                    "Passwordless sudo rule — user/command can be run as root without a password. "
                    "Check for GTFOBins: https://gtfobins.github.io"
                ),
            ))

    # -----------------------------------------------------------------------
    # SSH client config (~/.ssh/config)
    # -----------------------------------------------------------------------
    is_ssh_config = (
        filename == "config"
        and (".ssh" in path_lower or "ssh" in path_lower)
    ) or (
        # Heuristic: looks like an SSH config (Host + HostName blocks)
        re.search(r"^\s*Host\s+\S", body, re.MULTILINE | re.IGNORECASE) is not None
        and re.search(r"^\s*HostName\s+\S", body, re.MULTILINE | re.IGNORECASE) is not None
    )
    if is_ssh_config:
        entries: dict[str, list[str]] = {}
        current_host = "*"
        for m in _RE_SSH_CONFIG_ENTRY.finditer(body):
            key, val = m.group(1).strip(), m.group(2).strip()
            if key.lower() == "host":
                current_host = val
                entries.setdefault(current_host, [])
            else:
                entries.setdefault(current_host, []).append(f"{key} {val}")
        for host, fields in entries.items():
            if not fields:
                continue
            findings.append(ExtractedFinding(
                type="ssh_config_host",
                value=f"Host {host}\n  " + "\n  ".join(fields),
                source_path=path,
                note=(
                    "SSH client config block — may reveal internal hostnames, "
                    "jump hosts, identity files, and forwarding rules"
                ),
            ))

    # -----------------------------------------------------------------------
    # Log files — accidentally-logged credentials
    # -----------------------------------------------------------------------
    is_log_file = (
        filename.endswith(".log") or filename.endswith(".log.gz")
        or "_log" in filename or "access" in filename or "error" in filename
        or "/log/" in path_lower or "/logs/" in path_lower
        or "auth.log" in path_lower or "secure" in filename
    )
    if is_log_file:
        # HTTP Basic auth header values
        for m in _RE_LOG_BASIC_AUTH.finditer(body):
            b64_val = m.group(1)
            try:
                decoded = base64.b64decode(b64_val).decode("utf-8", errors="replace")
            except Exception:
                decoded = b64_val
            findings.append(ExtractedFinding(
                type="log_basic_auth_credential",
                value=decoded,
                source_path=path,
                note="HTTP Basic auth credential found in log file (base64-decoded)",
            ))
        # Passwords / tokens in query strings
        seen_log_creds: set[str] = set()
        for m in _RE_LOG_QUERY_CRED.finditer(body):
            val = m.group(1)
            if val not in seen_log_creds:
                seen_log_creds.add(val)
                findings.append(ExtractedFinding(
                    type="log_query_string_credential",
                    value=f"{m.group(0).split('=')[0].lstrip('?&')}={val}",
                    source_path=path,
                    note="Credential/token leaked in HTTP query string (logged in access log)",
                ))
        # SMTP AUTH blobs
        for m in _RE_LOG_SMTP_AUTH.finditer(body):
            blob = m.group(1)
            try:
                decoded = base64.b64decode(blob).decode("utf-8", errors="replace")
            except Exception:
                decoded = blob
            findings.append(ExtractedFinding(
                type="log_smtp_auth_credential",
                value=decoded,
                source_path=path,
                note="SMTP AUTH credential found in mail log (base64-decoded if applicable)",
            ))
        # curl/wget credentials in logged commands
        for m in _RE_LOG_CURL_CREDS.finditer(body):
            val = m.group(1) or m.group(2)
            if val:
                findings.append(ExtractedFinding(
                    type="log_curl_credential",
                    value=val,
                    source_path=path,
                    note="Credential passed via curl -u or wget --password, captured in log",
                ))

    # -----------------------------------------------------------------------
    # PHP define() credential syntax (wp-config.php, config.php, etc.)
    # -----------------------------------------------------------------------
    is_php = (
        filename.endswith(".php")
        or "php" in filename
        or "wp-config" in path_lower
        or "config.php" in path_lower
        or "<?php" in body[:512]
    )
    if is_php:
        for m in _RE_PHP_DEFINE.finditer(body):
            const_name = m.group(1)
            val = m.group(2)
            # Skip obvious placeholders
            if val.lower() in ("changeme", "password", "secret", "xxx", "your_password_here", ""):
                continue
            findings.append(ExtractedFinding(
                type="php_define_credential",
                value=f"{const_name}={val}",
                source_path=path,
                note="PHP define() constant with credential — common in wp-config.php and framework configs",
            ))

    return _dedupe(findings)


def _extract_binary(result: "ClassifiedResult", findings: list[ExtractedFinding]) -> None:
    """Handle binary confirmed hits — hex preview + offline analysis note."""
    binary_type = result.binary_type or "Unknown binary file"
    offline_note = BINARY_OFFLINE_NOTES.get(binary_type, "Binary file — offline analysis required.")
    hex_preview = _hex_preview(result.body_bytes, max_bytes=256)

    findings.append(ExtractedFinding(
        type="binary_file",
        value=hex_preview,
        source_path=result.payload,
        note=f"Type: {binary_type}\n{offline_note}",
    ))
