"""
detection.py - Baseline fingerprinting and hit classification.

Classification tiers:
    CONFIRMED  - content signature regex matched OR binary magic bytes matched
    CANDIDATE  - structural divergence from baseline (status and/or length delta)
    MISS       - matches baseline fingerprint
    ERROR      - request failed (timeout or network error)
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath, PureWindowsPath

from pathrover.engine import RawResult


class Confidence(str, Enum):
    CONFIRMED = "CONFIRMED"
    CANDIDATE = "CANDIDATE"
    MISS = "MISS"
    ERROR = "ERROR"


# ---------------------------------------------------------------------------
# BINARY MAGIC BYTES
# Each entry: (label, magic_bytes, offset, path_patterns)
# path_patterns are hints only — magic match alone is sufficient to CONFIRM.
# ---------------------------------------------------------------------------
BINARY_SIGNATURES: list[tuple[str, bytes, int, list[str]]] = [
    (
        "Windows Registry Hive (regf)",
        b"regf",
        0,
        ["SAM", "SYSTEM", "SECURITY", "SOFTWARE", "DEFAULT", "NTUSER.DAT"],
    ),
    (
        "Windows Event Log (.evtx)",
        b"ELfL",
        0,
        [".evtx"],
    ),
    (
        "SQL Server Data File (.mdf/.ldf)",
        bytes([0x01, 0x0F, 0x00, 0x00]),
        0,
        [".mdf", ".ldf"],
    ),
    (
        "Apple Binary Plist (bplist)",
        b"bplist",
        0,
        [".plist"],
    ),
    (
        "macOS Keychain Database",
        b"kych",
        0,
        ["login.keychain-db", "login.keychain", "System.keychain"],
    ),
    (
        "SQLite Database",
        b"SQLite format 3",
        0,
        ["Login Data", "TCC.db", "History.db", "cookies.sqlite", "key4.db", "ibdata1"],
    ),
    (
        "MySQL InnoDB Data File",
        bytes([0xFE, 0xFE, 0x00, 0x00]),
        0,
        ["ibdata1", "user.MYD"],
    ),
]

# ---------------------------------------------------------------------------
# TEXT CONTENT SIGNATURES
# Each entry: (path_pattern_hints, compiled_regex, require_count)
#
# IMPORTANT: path_pattern_hints are used ONLY as hints for labelling.
# The regex is ALWAYS evaluated against the response body regardless of
# whether the payload path matches a hint.  This ensures we catch files
# even when the payload format is unexpected or the path matching fails.
#
# require_count: minimum number of regex matches required to CONFIRM.
# ---------------------------------------------------------------------------
_TEXT_SIGS_RAW: list[tuple[str | list[str], str, int]] = [
    # -----------------------------------------------------------------------
    # SYSTEM CREDENTIALS
    # -----------------------------------------------------------------------
    # Unix password files — root entry is almost always present
    (["passwd", "master.passwd"], r"root[:*]", 1),
    # Shadow files — password hash pattern
    (["shadow", "gshadow"], r"\$[1-6y]\$[A-Za-z0-9./]+\$", 1),
    # /etc/group
    (["group"], r"^(root|sudo|wheel|admin):x?:\d+:", 1),
    # sudoers
    (["sudoers"], r"^(root|%sudo|%wheel)\s+ALL=", 1),

    # -----------------------------------------------------------------------
    # SSH KEYS AND CONFIG
    # -----------------------------------------------------------------------
    # SSH private keys (OpenSSH, RSA, EC, DSA)
    (
        ["id_rsa", "id_ecdsa", "id_ed25519", "id_dsa", "ssh_host_rsa_key",
         "ssh_host_ecdsa_key", "ssh_host_ed25519_key", "ssh_host_dsa_key",
         "ssl-cert-snakeoil.key"],
        r"-----BEGIN (OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----",
        1,
    ),
    # Authorized keys
    (["authorized_keys"], r"ssh-(rsa|ed25519|ecdsa|dss) AAAA", 1),
    # Known hosts
    (["known_hosts"], r"^[^\s]+ ssh-(rsa|ed25519|ecdsa)", 1),
    # SSH public keys
    (["id_rsa.pub", "id_ecdsa.pub", "id_ed25519.pub", "id_dsa.pub",
      "ssh_host_rsa_key.pub", "ssh_host_ecdsa_key.pub",
      "ssh_host_ed25519_key.pub", "ssh_host_dsa_key.pub"],
     r"^ssh-(rsa|ecdsa|ed25519|dss) AAAA", 1),
    # SSHD config
    (["sshd_config"], r"^(Port|PermitRootLogin|PasswordAuthentication)\s+", 1),
    # SSH client config
    (["ssh_config"], r"^Host\s+", 1),

    # -----------------------------------------------------------------------
    # NETWORK / HOST CONFIG
    # -----------------------------------------------------------------------
    # /etc/hosts
    (["hosts"], r"127\.0\.0\.1\s+localhost", 1),
    # /etc/hostname
    (["hostname"], r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$", 1),
    # /etc/resolv.conf
    (["resolv.conf"], r"^(nameserver|search|domain)\s+", 1),
    # /etc/fstab
    (["fstab"], r"^(UUID=|/dev/|tmpfs)\s+", 1),
    # /etc/exports (NFS)
    (["exports"], r"^/[^\s]+\s+", 1),
    # /etc/environment
    (["environment"], r"^[A-Z_][A-Z0-9_]*=", 1),
    # /etc/nsswitch.conf
    (["nsswitch.conf"], r"^(passwd|shadow|group|hosts):\s+", 1),

    # -----------------------------------------------------------------------
    # WEB SERVER CONFIGS
    # -----------------------------------------------------------------------
    # Nginx
    (["nginx.conf"], r"worker_processes", 1),
    # Apache
    (["httpd.conf", "apache2.conf"], r"^(ServerRoot|DocumentRoot|Listen)\s+", 1),
    # Apache .htpasswd
    ([".htpasswd"], r"^[^:]+:\$apr1\$|^[^:]+:\{SHA\}", 1),
    # Apache envvars
    (["envvars"], r"^export\s+APACHE_", 1),
    # Apache ports.conf
    (["ports.conf"], r"^Listen\s+\d+", 1),
    # Windows web.config
    (["web.config"], r"<(connectionStrings|appSettings|configuration)", 1),
    # IIS applicationHost.config
    (["applicationHost.config"], r"<system\.webServer|<sites>", 1),

    # -----------------------------------------------------------------------
    # PHP
    # -----------------------------------------------------------------------
    (["php.ini"], r"\[PHP\]", 1),
    # PHP config files with DB passwords
    (["config.php", "configuration.php", "database.php"], r"\$db(pass|password|_password)|DB_PASS", 1),
    # WordPress config
    (["wp-config.php"], r"DB_PASSWORD", 1),
    # phpMyAdmin config
    (["config.inc.php", "config-db.php"], r"\$cfg\['Servers'\]|\$dbpass", 1),

    # -----------------------------------------------------------------------
    # DATABASE CONFIGS
    # -----------------------------------------------------------------------
    # MySQL / MariaDB config
    (["my.cnf", "my.ini", "mysqld.cnf"], r"\[mysqld\]", 1),
    # PostgreSQL hba
    (["pg_hba.conf"], r"^(local|host)\s+", 1),
    # PostgreSQL config
    (["postgresql.conf"], r"^(listen_addresses|port|max_connections)\s*=", 1),
    # Redis config
    (["redis.conf"], r"^(port|bind|requirepass)\s+", 1),
    # Tomcat users
    (["tomcat-users.xml"], r"<tomcat-users", 1),

    # -----------------------------------------------------------------------
    # ENV / SECRET FILES
    # -----------------------------------------------------------------------
    # .env files — require 3+ VAR=value lines
    ([".env", ".env.local", ".env.production", ".env.staging"],
     r"^[A-Z_][A-Z0-9_]*=.+", 3),
    # .netrc (contains login/password pairs)
    ([".netrc"], r"^(machine|login|password)\s+", 1),
    # .npmrc (auth tokens)
    ([".npmrc"], r"//registry\.npmjs\.org/:_authToken|_authToken\s*=", 1),
    # .pypirc
    ([".pypirc"], r"\[pypi\]", 1),
    # AWS credentials
    (["credentials"], r"aws_access_key_id\s*=", 1),
    # Azure tokens
    (["accessTokens.json", "msal_token_cache.json"], r'"accessToken"|"secret"', 1),
    # GCP application default credentials
    (["application_default_credentials.json"], r'"client_id"|"refresh_token"', 1),
    # Terraform credentials
    (["credentials.tfrc.json"], r'"credentials"', 1),
    # Terraform tfvars
    (["terraform.tfvars", ".tfvars"], r'^\w+\s*=\s*"', 1),
    # Vault token
    ([".vault-token"], r"^[a-zA-Z0-9]{24,}$", 1),

    # -----------------------------------------------------------------------
    # SHELL HISTORY AND RC FILES
    # -----------------------------------------------------------------------
    # Shell history — commands are strong evidence
    (["bash_history", "zsh_history", "sh_history", "fish_history",
      "mysql_history", "psql_history", "python_history"],
     r"^(sudo|ssh|curl|export|wget|mysql|psql|kubectl|git|pip|apt|docker|python|ruby|node)\s",
     1),
    # Shell RC / profile files — look for export statements or PS1 / alias
    (["bashrc", "bash_profile", "zshrc", "profile", "bash.bashrc"],
     r"^(export\s+[A-Z_]+=|alias\s+\w+=|PS1=)", 1),

    # -----------------------------------------------------------------------
    # CI/CD
    # -----------------------------------------------------------------------
    # Jenkins config.xml / credentials.xml
    (["credentials.xml"], r"<com\.cloudbees", 1),
    (["config.xml"], r"<hudson>|<jenkins>|<com\.cloudbees", 1),
    # Jenkins master.key (64 char hex)
    (["master.key"], r"^[a-f0-9]{64}$", 1),
    # GitLab runner config
    (["config.toml"], r"\[runners\]", 1),
    # GitLab secrets
    (["gitlab.rb"], r"^(gitlab_rails|postgresql|redis)\[", 1),
    (["gitlab-secrets.json"], r'"gitlab_rails_secret_key_base"', 1),
    # Ansible vault password file
    ([".ansible_vault_pass", "ansible_vault_pass"], r"^[^\s]{8,}$", 1),
    # Ansible config
    (["ansible.cfg"], r"^\[defaults\]", 1),

    # -----------------------------------------------------------------------
    # CLOUD / CONTAINER
    # -----------------------------------------------------------------------
    # kubeconfig
    ([".kube/config", "admin.conf", "scheduler.conf", "controller-manager.conf",
      "kubelet.conf"],
     r"apiVersion: v1", 1),
    # Kubernetes service account token (JWT)
    (["token"], r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$", 1),
    # Docker daemon config
    (["daemon.json"], r'"(runtimes|storage-driver|log-driver|insecure-registries)"', 1),
    # Docker config.json (registry auth)
    (["config.json"], r'"auths"', 1),
    # GCP credentials db (SQLite)
    (["credentials.db"], r"SQLite format 3|access_token", 1),

    # -----------------------------------------------------------------------
    # /proc FILESYSTEM
    # -----------------------------------------------------------------------
    # /proc/self/environ — null-separated NAME=VALUE pairs
    (["environ"], r"[A-Z_]+=", 3),
     # /proc/self/cmdline — null-byte separated arguments (exclude \r\n so Windows line endings don't trigger this)
     (["cmdline"], r"[\x00-\x08\x0e-\x1f]", 1),
    # /proc/self/status
    (["status"], r"^(Name|Pid|PPid|Uid|Gid):\s+\S+", 2),
    # /proc/version
    (["version"], r"Linux version \d+\.\d+", 1),
    # /proc/cpuinfo
    (["cpuinfo"], r"^(processor|model name|cpu MHz)\s*:", 2),
    # /proc/mounts or /proc/self/mounts
    (["mounts"], r"^(rootfs|sysfs|proc|devtmpfs|tmpfs|/dev/)\s+", 1),
    # /proc/net/arp
    (["arp"], r"IP address\s+HW type|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+0x", 1),
    # /proc/net/tcp
    (["tcp", "udp"], r"^\s+\d+:\s+[0-9A-F]{8}:[0-9A-F]{4}", 1),
    # /proc/self/cgroup
    (["cgroup"], r"^[0-9]+:[^:]*:/", 1),
    # /proc/net/route
    (["route"], r"^(Iface|[a-z]+\s+[0-9A-F]{8})", 1),

    # -----------------------------------------------------------------------
    # LOG FILES
    # -----------------------------------------------------------------------
    # syslog / messages / kern.log
    (["syslog", "messages", "kern.log", "dmesg", "boot.log"],
     r"^[A-Z][a-z]{2}\s+\d+ \d{2}:\d{2}:\d{2}|kernel:|systemd\[", 1),
    # auth.log / secure
    (["auth.log", "secure"], r"sshd\[|PAM|sudo:|Accepted password|Failed password", 1),
    # Apache / Nginx access log
    (["access.log", "access_log", "other_vhosts_access.log"],
     r'^\S+ \S+ \S+ \[[\d/A-Za-z: +]+\] "(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)', 1),
    # Apache / Nginx error log
    (["error.log", "error_log"],
     r"\[(error|warn|notice|info|crit|alert|emerg)\]|\[client ", 1),
    # MySQL error log
    (["mysql.log", "mysqld.log", "mysql-slow.log"],
     r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}|\[ERROR\] mysqld|Query_time:", 1),
    # PostgreSQL log
    (["postgresql.log", "postgresql-12-main.log", "postgresql-13-main.log",
      "postgresql-14-main.log", "postgresql-15-main.log", "postgresql-16-main.log"],
     r"LOG:|FATAL:|ERROR:|HINT:\s+\S|UTC \[\d+\]", 1),
    # dpkg / apt log
    (["dpkg.log", "history.log"], r"^20\d{2}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+(install|upgrade|remove|status)", 1),
    # cloud-init log
    (["cloud-init.log", "cloud-init-output.log"],
     r"cloud-init|Cloud-init v\.", 1),

    # -----------------------------------------------------------------------
    # WINDOWS SPECIFIC
    # -----------------------------------------------------------------------
    (["win.ini"], r"\[fonts\]", 1),
    (["system.ini"], r"\[386Enh\]", 1),
    (["Unattend.xml", "Unattended.xml", "unattend.xml"], r"<Password>|<AutoLogon>", 1),
    # SAM / SYSTEM / SECURITY hives handled by binary magic above
    # Windows hosts file (same pattern as Linux)
    # Hosts is already in the "hosts" entry above

    # -----------------------------------------------------------------------
    # SAMBA
    # -----------------------------------------------------------------------
    (["smb.conf"], r"^\[global\]|workgroup\s*=", 1),

    # -----------------------------------------------------------------------
    # MISC CONFIG FILES
    # -----------------------------------------------------------------------
    (["grub.cfg"], r"^(menuentry|set root=|linux\s+/)", 1),
    (["crontab", "root"], r"^(@(reboot|hourly|daily|weekly|monthly|annually)|(\*|\d+)\s)", 1),
    # .gitconfig
    ([".gitconfig"], r"^\[user\]", 1),
    # macOS airport plist (XML plist)
    (["airport.preferences.plist"], r"<plist", 1),
    # Kubernetes PKI keys (PEM)
    (["ca.key", "sa.key"], r"-----BEGIN (RSA |EC )?PRIVATE KEY-----|-----BEGIN PRIVATE KEY-----", 1),
    # Kubernetes CA cert
    (["ca.crt"], r"-----BEGIN CERTIFICATE-----", 1),
]


def _build_text_signatures() -> list[tuple[list[str], re.Pattern, int]]:
    compiled = []
    for patterns, regex_str, count in _TEXT_SIGS_RAW:
        if isinstance(patterns, str):
            patterns = [patterns]
        compiled.append((patterns, re.compile(regex_str, re.MULTILINE), count))
    return compiled


TEXT_SIGNATURES = _build_text_signatures()


@dataclass
class Baseline:
    status: int
    length: int
    length_min: int   # minimum body length across all baseline probes
    length_max: int   # maximum body length across all baseline probes
    body_hash: str
    head_bytes: bytes
    tail_bytes: bytes
    is_binary: bool


@dataclass
class ClassifiedResult:
    payload: str
    confidence: Confidence
    status_code: int
    body_bytes: bytes
    response_length: int
    elapsed_ms: float
    is_binary: bool
    binary_type: str | None
    matched_signature: str | None
    error: str | None


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_binary(data: bytes) -> bool:
    """Heuristic: attempt UTF-8 decode; presence of null bytes is a strong indicator."""
    if b"\x00" in data:
        return True
    try:
        data.decode("utf-8")
        return False
    except UnicodeDecodeError:
        return True


def build_baseline(result: RawResult, all_probes: list[RawResult] | None = None) -> Baseline:
    body = result.body_bytes
    probe_lengths = [len(p.body_bytes) for p in all_probes] if all_probes else [len(body)]
    return Baseline(
        status=result.status_code,
        length=len(body),
        length_min=min(probe_lengths),
        length_max=max(probe_lengths),
        body_hash=_sha256(body),
        head_bytes=body[:64],
        tail_bytes=body[-64:] if len(body) >= 64 else body,
        is_binary=_is_binary(body),
    )


def _unwrap_response(body_bytes: bytes) -> bytes:
    """
    Detect and unwrap common API JSON envelope patterns so that content
    signatures and heuristics operate on the actual file content rather
    than the surrounding JSON structure.

    Handles patterns like:
        {"success":true,"message":null,"data":"<file content>"}
        {"status":"ok","result":"<file content>"}
        {"data":"<file content>","error":null}
        {"content":"<file content>"}
        {"file":"<file content>"}
        {"output":"<file content>"}
        {"body":"<file content>"}

    If the body is not a JSON envelope wrapping a string, the original bytes
    are returned unchanged.  The unwrapped content is re-encoded as UTF-8
    so multi-line regex anchors work correctly.
    """
    if not body_bytes or body_bytes[0:1] != b"{":
        return body_bytes
    try:
        obj = json.loads(body_bytes)
    except (json.JSONDecodeError, ValueError):
        return body_bytes

    if not isinstance(obj, dict):
        return body_bytes

    # Common field names that carry the actual file content as a string
    _DATA_KEYS = ("data", "content", "result", "body", "file", "output",
                  "text", "response", "value", "payload", "fileContent",
                  "file_content", "fileData", "file_data")

    for key in _DATA_KEYS:
        val = obj.get(key)
        if isinstance(val, str) and len(val) > 0:
            return val.encode("utf-8", errors="replace")

    return body_bytes


def _check_binary_magic(body_bytes: bytes, payload: str) -> tuple[bool, str | None]:
    """Check binary magic bytes against known signatures."""
    for label, magic, offset, _path_patterns in BINARY_SIGNATURES:
        chunk = body_bytes[offset: offset + len(magic)]
        if chunk == magic:
            return True, label
    return False, None


# ---------------------------------------------------------------------------
# GENERAL CONTENT HEURISTICS
# These run after TEXT_SIGNATURES fail. They are intentionally broader —
# they look for patterns that are characteristic of real file content
# regardless of filename. Each entry: (label, compiled_regex, require_count)
# require_count is the minimum number of matches needed across the whole body.
# ---------------------------------------------------------------------------
_CONTENT_HEURISTICS: list[tuple[str, re.Pattern, int]] = [
    # Unix colon-delimited account files (passwd / group / shadow-like)
    ("unix_account_file",     re.compile(r"^[^:]+:[^:]+:\d+:\d+", re.MULTILINE), 3),
    # INI-style section headers  [SectionName]
    ("ini_config_file",       re.compile(r"^\[[A-Za-z][A-Za-z0-9 _\-]{1,40}\]", re.MULTILINE), 2),
    # Shell/env export statements
    ("shell_env_exports",     re.compile(r"^export\s+[A-Z_][A-Z0-9_]+=\S", re.MULTILINE), 2),
    # KEY=VALUE env-style pairs (e.g. /etc/environment, .env, /proc/self/environ decoded)
    ("env_key_value_file",    re.compile(r"^[A-Z_][A-Z0-9_]{2,}=\S", re.MULTILINE), 4),
    # Apache/Nginx/sshd-style  directive  value
    ("daemon_config_file",    re.compile(r"^[A-Za-z][A-Za-z0-9_]{2,}\s+\S", re.MULTILINE), 5),
    # Syslog-style timestamps  Jan 01 00:00:00 hostname
    ("syslog_entries",        re.compile(r"^[A-Z][a-z]{2}\s{1,2}\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S", re.MULTILINE), 3),
    # ISO-8601 / RFC3339 log timestamps  2024-01-01T00:00:00
    ("iso_log_entries",       re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", re.MULTILINE), 3),
    # Apache/Nginx combined access log  "GET /path HTTP/1.1" 200
    ("web_access_log",        re.compile(r'"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+/[^\s"]*\s+HTTP/\d\.\d"\s+\d{3}', re.MULTILINE), 2),
    # XML/HTML config files with attributes  key="value"
    ("xml_config_file",       re.compile(r'<[A-Za-z][A-Za-z0-9_]{1,30}\s+[A-Za-z]+="[^"]{1,200}"', re.MULTILINE), 3),
    # YAML key: value (kubeconfig, docker-compose, etc.)
    ("yaml_config_file",      re.compile(r"^[A-Za-z][A-Za-z0-9_\-]{1,30}:\s+\S", re.MULTILINE), 4),
    # crontab entries   * * * * * command
    ("crontab_entries",       re.compile(r"^(\*|[0-9,\-/]+)\s+(\*|[0-9,\-/]+)\s+(\*|[0-9,\-/]+)\s+(\*|[0-9,\-/]+)\s+(\*|[0-9,\-/]+)\s+\S", re.MULTILINE), 1),
    # /proc/net/tcp socket table  00000000:0016
    ("proc_net_table",        re.compile(r"^\s*\d+:\s+[0-9A-F]{8}:[0-9A-F]{4}\s+[0-9A-F]{8}:[0-9A-F]{4}", re.MULTILINE), 2),
    # /proc/self/status  Name:   nginx
    ("proc_status_file",      re.compile(r"^(Name|Pid|PPid|Uid|Gid|VmRSS|Threads):\s+\S", re.MULTILINE), 3),
    # /proc/cpuinfo  processor : 0 / model name
    ("proc_cpuinfo_file",     re.compile(r"^(processor|model name|cpu MHz|cache size)\s*:\s+\S", re.MULTILINE), 2),
    # /proc/mounts  devtmpfs /dev devtmpfs rw
    ("proc_mounts_file",      re.compile(r"^(rootfs|sysfs|proc|devtmpfs|tmpfs|/dev/\w+|overlay)\s+/\S*\s+\w+\s+\w", re.MULTILINE), 2),
    # Shell history — any recognisable command lines
    ("shell_history_file",    re.compile(r"^(sudo|ssh|curl|wget|git|docker|kubectl|mysql|psql|python|pip|apt|yum|systemctl|export|cd\s+/)\s+", re.MULTILINE), 3),
    # PEM certificate blocks
    ("pem_certificate",       re.compile(r"-----BEGIN CERTIFICATE-----", re.MULTILINE), 1),
    # SSH public key lines
    ("ssh_public_key",        re.compile(r"^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp\d+|ssh-dss) AAAA[A-Za-z0-9+/]", re.MULTILINE), 1),
    # /etc/fstab — device mountpoint fstype options
    ("fstab_entries",         re.compile(r"^(UUID=[a-f0-9\-]{36}|/dev/\w+|tmpfs|none)\s+/\S*\s+\w+\s+\w", re.MULTILINE), 1),
    # /etc/hosts — IP  hostname
    ("hosts_file_entries",    re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\S", re.MULTILINE), 2),
    # /etc/resolv.conf
    ("resolv_conf_entries",   re.compile(r"^(nameserver|search|domain)\s+\S", re.MULTILINE), 1),
    # MySQL error log timestamps
    ("mysql_log_entries",     re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z\s+\d+\s+\[", re.MULTILINE), 2),
    # Generic password/secret assignment patterns in config files
    ("config_secret_assignment", re.compile(r"^[A-Za-z_][A-Za-z0-9_\-\.]{2,40}\s*[=:]\s*['\"]?[A-Za-z0-9+/\-_@#$!]{8,}['\"]?\s*$", re.MULTILINE), 3),
]


def _check_content_heuristics(body_bytes: bytes) -> str | None:
    """
    Filename-agnostic content heuristics.  Run when TEXT_SIGNATURES produce no match.
    Returns a label string if the body looks like real file content, else None.
    Helps promote CANDIDATEs to CONFIRMED for files with no specific signature.
    """
    try:
        body_text = body_bytes.decode("utf-8", errors="replace")
    except Exception:
        return None

    # -----------------------------------------------------------------------
    # .NET / IIS exception guard — bail out before running any heuristic.
    # A response containing a .NET exception name, a stack frame line, or the
    # ASP.NET yellow-screen header is a server error, not a real file, even if
    # its structure (XML tags, key=value lines from the stack trace) would
    # otherwise satisfy one of the heuristic patterns below.
    # -----------------------------------------------------------------------
    _DOTNET_EXCEPTION_RE = re.compile(
        r'System\.[A-Za-z.]*Exception\s*:'           # e.g. System.IO.DirectoryNotFoundException:
        r'|^\s+at\s+[A-Za-z][\w.]+\.[A-Za-z]\w+\('  # stack frame:  at Namespace.Class.Method(
        r"|Server Error in '",                        # yellow screen header
        re.MULTILINE,
    )
    if _DOTNET_EXCEPTION_RE.search(body_text):
        return None

    for label, pattern, required in _CONTENT_HEURISTICS:
        if len(pattern.findall(body_text)) >= required:
            return label

    return None


def _check_text_signatures(body_bytes: bytes, payload: str) -> str | None:
    """
    Return the first matching signature label, or None.

    Strategy:
    1. Run EVERY regex against the body regardless of path hints.
    2. If a regex matches the required number of times, return a label.
    3. Path hints are used only to build a human-readable label string;
       they do NOT gate whether the regex is tried.

    This ensures we catch files even when path matching is unreliable
    (e.g. encoded payloads, unusual traversal prefixes, etc.).
    """
    try:
        body_text = body_bytes.decode("utf-8", errors="replace")
    except Exception:
        return None

    # Normalise the payload for hint matching (label generation only)
    payload_lower = payload.replace("\\", "/").lower()
    filename_lower = payload_lower.split("/")[-1]

    for path_hints, regex, require_count in TEXT_SIGNATURES:
        matches = regex.findall(body_text)
        if len(matches) >= require_count:
            # Build a label: prefer a hint that matches the payload, else use the regex
            hint_label = next(
                (h for h in path_hints if h.lower() in filename_lower or h.lower() in payload_lower),
                None,
            )
            label = hint_label if hint_label else regex.pattern
            return label

    return None


def _length_delta_pct(baseline_len: int, response_len: int) -> float:
    """Return the percentage difference in length relative to the baseline."""
    if baseline_len == 0:
        return 100.0 if response_len > 0 else 0.0
    return abs(response_len - baseline_len) / baseline_len * 100


# ---------------------------------------------------------------------------
# ERROR-PAGE SUPPRESSION
# Patterns that identify common server error / rejection responses.
# If the body matches any of these, a length or status divergence is NOT
# treated as evidence of traversal — the server is just complaining.
#
# IMPORTANT: These patterns must be NARROW and specific. Overly broad
# patterns (e.g. matching any JSON with a "status" key) will suppress
# legitimate file hits such as config JSON files.
# ---------------------------------------------------------------------------
_ERROR_PAGE_PATTERNS: list[re.Pattern] = [
    # HTML pages with error-indicating titles
    re.compile(
        r'<title[^>]*>[^<]*(error|not\s+found|forbidden|denied|invalid|bad\s+request|'
        r'unauthorized|access\s+denied)[^<]*</title>',
        re.IGNORECASE,
    ),
    # Plain-text HTTP-style status lines as the ENTIRE body (e.g. "404 Not Found")
    re.compile(
        r'^\s*(400|401|403|404|405|410|422|429|500|502|503)\s+'
        r'(bad request|unauthorized|forbidden|not found|method not allowed|'
        r'gone|unprocessable|too many requests|internal server error|'
        r'bad gateway|service unavailable)\s*$',
        re.IGNORECASE | re.MULTILINE,
    ),
    # Spring Boot / Django REST Framework error envelopes — require MULTIPLE
    # error-specific fields so we don't suppress config JSON files that happen
    # to have a "status" or "message" field.
    # Only match when the body contains at least two of: timestamp, path, exception, trace, status+error together
    re.compile(r'"timestamp"\s*:.*"(path|exception|trace|status)"', re.IGNORECASE | re.DOTALL),
    re.compile(r'"status"\s*:\s*[45]\d\d.*"(error|message|path)"', re.IGNORECASE | re.DOTALL),

    # -----------------------------------------------------------------------
    # .NET / IIS ERROR RESPONSES
    # -----------------------------------------------------------------------
    # Any .NET exception class name followed by a colon+message, e.g.:
    #   System.IO.DirectoryNotFoundException: Could not find a part of the path ...
    #   System.IO.FileNotFoundException: Could not find file ...
    #   System.UnauthorizedAccessException: Access to the path ... is denied.
    #   System.Security.SecurityException: ...
    re.compile(
        r'System\.[A-Za-z.]*Exception\s*:',
        re.IGNORECASE,
    ),
    # .NET yellow screen of death — classic ASP.NET error page title
    re.compile(
        r'<title[^>]*>\s*(Server Error in|Runtime Error|ASP\.NET|Unhandled Exception)',
        re.IGNORECASE,
    ),
    # IIS detailed error pages (7+) — contain HTTP Error <code> in an h2/h3
    re.compile(
        r'HTTP Error\s+[45]\d\d\s*[\.\-–]',
        re.IGNORECASE,
    ),
    # IIS machine-generated XML error response — contains MajorVersion/ErrorCode fields
    re.compile(
        r'<MajorVersion>|<MinorVersion>|<ErrorCode>',
        re.IGNORECASE,
    ),
    # ASP.NET Core ProblemDetails JSON envelope:
    #   {"type":"...","title":"...","status":4xx,"traceId":"..."}
    # Require "traceId" alongside "status" to avoid suppressing legitimate config JSON.
    re.compile(
        r'"traceId"\s*:\s*"[^"]{4,}".*"status"\s*:\s*[45]\d\d'
        r'|"status"\s*:\s*[45]\d\d.*"traceId"\s*:\s*"[^"]{4,}"',
        re.IGNORECASE | re.DOTALL,
    ),
]


def _looks_like_error_page(body_text: str) -> bool:
    """Return True if the body looks like a generic server error / rejection response."""
    for pattern in _ERROR_PAGE_PATTERNS:
        if pattern.search(body_text):
            return True
    return False


def _strip_payload(text: str, payload: str) -> str:
    """Remove all occurrences of the payload from text for reflection-neutral comparison."""
    if not payload:
        return text
    return text.replace(payload, "")


def classify(
    result: RawResult,
    baseline: Baseline,
    threshold_pct: int = 5,
) -> ClassifiedResult:
    """Classify a single RawResult against the baseline."""

    # Error results
    if result.error or result.status_code == -1:
        return ClassifiedResult(
            payload=result.payload,
            confidence=Confidence.ERROR,
            status_code=result.status_code,
            body_bytes=result.body_bytes,
            response_length=len(result.body_bytes),
            elapsed_ms=result.elapsed_ms,
            is_binary=False,
            binary_type=None,
            matched_signature=None,
            error=result.error,
        )

    body = result.body_bytes
    response_len = len(body)

    # Unwrap JSON envelope responses — many APIs return file content as a
    # string value inside a JSON wrapper (e.g. {"success":true,"data":"..."}).
    # All content matching and extraction must operate on the unwrapped bytes.
    body = _unwrap_response(body)
    is_bin = _is_binary(body)

    # -----------------------------------------------------------------------
    # ERROR-PAGE SUPPRESSION — runs FIRST, before any content matching.
    # A .NET/IIS exception body, HTML error page, or framework error envelope
    # is never a real file hit even if its text happens to match a content
    # signature (e.g. a reflected Linux path in the exception message contains
    # "authorized_keys" which could coincidentally satisfy a pattern).
    # Binary magic check is intentionally exempt — no error page has regf/ELfL
    # magic bytes, so binary hits can never be false-positived this way.
    # -----------------------------------------------------------------------
    if not is_bin:
        body_text_for_error_check = body.decode("utf-8", errors="replace")
        if _looks_like_error_page(body_text_for_error_check):
            # Treat as MISS regardless of length/status delta.
            return ClassifiedResult(
                payload=result.payload,
                confidence=Confidence.MISS,
                status_code=result.status_code,
                body_bytes=body,
                response_length=response_len,
                elapsed_ms=result.elapsed_ms,
                is_binary=False,
                binary_type=None,
                matched_signature=None,
                error=None,
            )

    binary_matched, binary_label = _check_binary_magic(body, result.payload)

    if binary_matched:
        return ClassifiedResult(
            payload=result.payload,
            confidence=Confidence.CONFIRMED,
            status_code=result.status_code,
            body_bytes=body,
            response_length=response_len,
            elapsed_ms=result.elapsed_ms,
            is_binary=True,
            binary_type=binary_label,
            matched_signature=f"binary_magic:{binary_label}",
            error=None,
        )

    # Check text content signatures — path-pattern gating has been removed.
    # Every regex is evaluated against every response body.
    sig_match = _check_text_signatures(body, result.payload)
    if sig_match:
        return ClassifiedResult(
            payload=result.payload,
            confidence=Confidence.CONFIRMED,
            status_code=result.status_code,
            body_bytes=body,
            response_length=response_len,
            elapsed_ms=result.elapsed_ms,
            is_binary=False,
            binary_type=None,
            matched_signature=sig_match,
            error=None,
        )

    # General content heuristics — filename-agnostic patterns that indicate real
    # file content (log timestamps, ini sections, key=value pairs, etc.).
    # Runs when no specific signature matched but the body looks like a real file.
    heuristic_match = _check_content_heuristics(body)
    if heuristic_match:
        return ClassifiedResult(
            payload=result.payload,
            confidence=Confidence.CONFIRMED,
            status_code=result.status_code,
            body_bytes=body,
            response_length=response_len,
            elapsed_ms=result.elapsed_ms,
            is_binary=False,
            binary_type=None,
            matched_signature=f"heuristic:{heuristic_match}",
            error=None,
        )

    # Structural divergence check
    body_text = body.decode("utf-8", errors="replace")

    # --- Reflected-payload stripping ---
    # Measure length after removing the payload from both bodies so that
    # servers that echo the path back in an error message don't inflate the delta.
    stripped_body_len = len(_strip_payload(body_text, result.payload).encode("utf-8", errors="replace"))
    length_delta = _length_delta_pct(baseline.length, stripped_body_len)
    length_differs = length_delta > threshold_pct

    # --- Variance-band check ---
    # If the stripped length still falls within the natural range seen across
    # baseline probes (with threshold margin), it's indistinguishable from
    # normal server variance.
    variance_band_low  = baseline.length_min * (1 - threshold_pct / 100)
    variance_band_high = baseline.length_max * (1 + threshold_pct / 100)
    within_variance_band = variance_band_low <= stripped_body_len <= variance_band_high

    # --- Status-code change detection ---
    # Any change in the response status code is treated as a signal.
    # We no longer require baseline_is_error — if the server returns a different
    # status for a real file vs. a garbage baseline probe, that's informative
    # regardless of the baseline status.
    status_changed = result.status_code != baseline.status

    hash_matches = _sha256(body) == baseline.body_hash

    if hash_matches:
        # Exact body match to baseline — definitive miss
        return ClassifiedResult(
            payload=result.payload,
            confidence=Confidence.MISS,
            status_code=result.status_code,
            body_bytes=body,
            response_length=response_len,
            elapsed_ms=result.elapsed_ms,
            is_binary=is_bin,
            binary_type=None,
            matched_signature=None,
            error=None,
        )

    if status_changed or (length_differs and not within_variance_band):
        return ClassifiedResult(
            payload=result.payload,
            confidence=Confidence.CANDIDATE,
            status_code=result.status_code,
            body_bytes=body,
            response_length=response_len,
            elapsed_ms=result.elapsed_ms,
            is_binary=is_bin,
            binary_type=None,
            matched_signature=None,
            error=None,
        )

    # Body hash differs but length/status is indistinguishable from baseline variance
    return ClassifiedResult(
        payload=result.payload,
        confidence=Confidence.MISS,
        status_code=result.status_code,
        body_bytes=body,
        response_length=response_len,
        elapsed_ms=result.elapsed_ms,
        is_binary=is_bin,
        binary_type=None,
        matched_signature=None,
        error=None,
    )


def classify_all(
    results: list[RawResult],
    baseline: Baseline,
    threshold_pct: int = 5,
) -> list[ClassifiedResult]:
    return [classify(r, baseline, threshold_pct) for r in results]
