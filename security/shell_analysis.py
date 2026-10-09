"""
shell_analysis.py — CyberEye Task 05: Shell Command Analysis Engine

Parses, normalises, and classifies shell commands for the policy engine.

Design principles:
  • Parse into AST first; no rule relies solely on regex over raw string.
  • Recursively evaluate nested commands (substitutions, subshells, -c args,
    wrappers, find -exec, xargs, etc.)
  • Fail closed: unparseable / over-limit input → flag/block, never allow.
  • Path arguments fed through the Task-04 canonicaliser so shell commands
    can trigger both shell rules and path rules.

Supported shells: POSIX sh / bash / dash / ksh / zsh (via bashlex AST).
PowerShell and cmd.exe are NOT supported; tool calls targeting them are
flagged by default (not allowed silently). See KNOWN_LIMITATIONS at EOF.

References:
  MITRE ATT&CK: https://attack.mitre.org/techniques/
  GTFOBins:     https://gtfobins.github.io/
  LOLBAS:       https://lolbas-project.github.io/
"""

from __future__ import annotations

import base64
import binascii
import logging
import os
import posixpath
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

try:
    import bashlex  # type: ignore
    import bashlex.errors  # type: ignore

    _BASHLEX_AVAILABLE = True
except ImportError:  # pragma: no cover
    _BASHLEX_AVAILABLE = False

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Resource limits (adversarial-safe)
# ---------------------------------------------------------------------------
MAX_COMMAND_BYTES = 102_400       # 100 KB
MAX_AST_NODES = 2_000
MAX_COMMANDS_PER_CALL = 200
MAX_DECODE_DEPTH = 3              # base64→sh→base64→sh bounded here
MAX_NESTING_DEPTH = 32
MAX_PIPELINE_STAGES = 500

# ---------------------------------------------------------------------------
# Risk / action enums
# ---------------------------------------------------------------------------


class RiskLevel(str, Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ShellAction(str, Enum):
    ALLOW = "allow"
    FLAG = "flag"
    BLOCK = "block"


# ---------------------------------------------------------------------------
# Shell analysis result
# ---------------------------------------------------------------------------


@dataclass
class ShellFinding:
    rule_id: str
    category: str
    severity: RiskLevel
    action: ShellAction
    reason: str
    attack_technique: str = ""          # MITRE ATT&CK technique ID
    evidence: str = ""                  # redacted snippet, never raw secrets
    triggered_program: str = ""


@dataclass
class ShellAnalysisResult:
    """Aggregate result for one tool-call analysis."""

    action: ShellAction = ShellAction.ALLOW
    severity: RiskLevel = RiskLevel.SAFE
    findings: list[ShellFinding] = field(default_factory=list)
    rule_ids: list[str] = field(default_factory=list)
    attack_techniques: list[str] = field(default_factory=list)
    normalized_summary: str = ""        # list of resolved program names
    mode: str = "enforce"               # enforce | monitor
    would_have_blocked: bool = False    # set in monitor mode

    def merge(self, finding: ShellFinding) -> None:
        self.findings.append(finding)
        if finding.rule_id not in self.rule_ids:
            self.rule_ids.append(finding.rule_id)
        if finding.attack_technique and finding.attack_technique not in self.attack_techniques:
            self.attack_techniques.append(finding.attack_technique)
        # worst action wins
        _order = [ShellAction.ALLOW, ShellAction.FLAG, ShellAction.BLOCK]
        if _order.index(finding.action) > _order.index(self.action):
            self.action = finding.action
        # worst severity wins
        _sev = list(RiskLevel)
        if _sev.index(finding.severity) > _sev.index(self.severity):
            self.severity = finding.severity


# ---------------------------------------------------------------------------
# Wrapper programs that should be "looked through"
# ---------------------------------------------------------------------------

_TRANSPARENT_WRAPPERS: set[str] = {
    "sudo", "doas", "su", "env", "nice", "nohup", "timeout", "time",
    "stdbuf", "setsid", "watch", "strace", "ltrace", "faketime",
    "chroot", "unshare", "nsenter",
    "command", "builtin", "exec",
    "busybox",
}

# Wrappers that are themselves risk signals (in addition to the inner cmd)
_PRIV_WRAPPERS: set[str] = {"sudo", "doas", "su", "pkexec", "chroot"}

# Shells accepting -c "..."
_SHELL_PROGRAMS: set[str] = {
    "sh", "bash", "dash", "ksh", "ksh93", "mksh", "zsh", "rbash",
    "busybox",          # busybox sh
}

# Interpreter one-liners: prog -e / -c "code"
_INTERPRETER_ONELINERS: dict[str, str] = {
    "python": "python",
    "python3": "python",
    "python2": "python",
    "perl": "perl",
    "ruby": "ruby",
    "node": "node",
    "nodejs": "node",
    "php": "php",
    "lua": "lua",
    "awk": "awk",
    "gawk": "gawk",
    "mawk": "mawk",
}

# Remote execution wrappers (first arg is host, rest is command)
_REMOTE_EXEC: set[str] = {"ssh", "rsh"}

# Container/k8s exec wrappers
_CONTAINER_EXEC: set[str] = {"docker", "podman", "kubectl", "nerdctl"}

# Programs that accept a command list via xargs-style
_XARGS_LIKE: set[str] = {"xargs", "parallel"}

_FIND_EXEC_FLAGS: set[str] = {"-exec", "-execdir", "-ok", "-okdir"}

# ---------------------------------------------------------------------------
# Sensitive path patterns (mirrors Task 04 list, extended)
# ---------------------------------------------------------------------------
_SENSITIVE_PATH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"^/etc/(passwd|shadow|sudoers|ssh|cron|rc\.|init)", re.I),
    re.compile(r"^/root(/|$)"),
    re.compile(r"(^|/)\.ssh(/|$)"),
    re.compile(r"(^|/)(id_rsa|id_ecdsa|id_ed25519)(\.pub)?$"),
    re.compile(r"(^|/)\.aws(/|$)"),
    re.compile(r"(^|/)\.config/gcloud"),
    re.compile(r"(^|/)credentials$", re.I),
    re.compile(r"(^|/)\.env$"),
    re.compile(r"(^|/)\.npmrc$"),
    re.compile(r"(^|/)authorized_keys$"),
    re.compile(r"/proc/\d+/environ"),
    re.compile(r"/var/log/", re.I),
    re.compile(r"(^|/)keystore", re.I),
    re.compile(r"\.(pem|p12|pfx|key|crt|cer)$", re.I),
]

_SYSTEM_ROOT_DIRS: set[str] = {
    "/", "/bin", "/sbin", "/usr", "/lib", "/lib64",
    "/boot", "/etc", "/sys", "/proc", "/dev",
}

# ---------------------------------------------------------------------------
# Destructive filesystem patterns
# ---------------------------------------------------------------------------
_DESTRUCTIVE_PROGRAMS: set[str] = {
    "rm", "shred", "wipe", "srm", "secure-delete",
    "mkfs", "mkfs.ext4", "mkfs.xfs", "mkfs.btrfs", "mkfs.fat",
    "dd", "wipefs", "fdisk", "parted", "gdisk", "cfdisk", "sgdisk",
    "truncate",
}

_DESTRUCTIVE_RECURSIVE_FLAGS: set[str] = {"-r", "-R", "--recursive"}
_DESTRUCTIVE_FORCE_FLAGS: set[str] = {"-f", "--force"}
_NO_PRESERVE_ROOT = "--no-preserve-root"

_BROAD_ROOTS: set[str] = {"/", "~", "$HOME", "${HOME}", "/home", "/root"}


def _is_broad_root(arg: str) -> bool:
    if not arg:
        return False
    norm = arg.strip()
    if norm in ("/", "~", "$HOME", "${HOME}", "/home", "/root"):
        return True
    norm = norm.rstrip("/")
    if norm in _BROAD_ROOTS:
        return True
    return norm.startswith("/etc") or norm.startswith("/usr") or norm.startswith("/bin") or norm.startswith("/sys")


# ---------------------------------------------------------------------------
# Privilege escalation
# ---------------------------------------------------------------------------
_PRIV_ESC_PROGRAMS: set[str] = {
    "sudo", "su", "doas", "pkexec", "newgrp", "runuser", "nsenter",
    "useradd", "userdel", "usermod", "groupadd", "groupmod",
    "passwd", "chpasswd", "chage", "gpasswd",
    "visudo", "chsh", "chfn",
    "setcap",
}

_SETUID_CHMOD_RE = re.compile(r"[+\-=].*s|4[0-7]{3,4}|2[0-7]{3,4}|6[0-7]{3,4}")


# ---------------------------------------------------------------------------
# Remote download-and-execute
# ---------------------------------------------------------------------------
_DOWNLOAD_PROGRAMS: set[str] = {
    "curl", "wget", "fetch", "aria2c", "axel", "httpie", "http",
}

_SHELL_EXEC_PROGRAMS: set[str] = _SHELL_PROGRAMS | {
    "python", "python3", "python2", "perl", "ruby", "php", "node", "nodejs",
}

# URL patterns for suspicious download targets
_SUSPICIOUS_URL_RE = re.compile(
    r"https?://((\d{1,3}\.){3}\d{1,3}|[a-z0-9\-]+\.(ly|gl|gd|io|xyz|tk|ml|ga|cf|top|bit\b))[/:]",
    re.I,
)
_PASTEBIN_RE = re.compile(
    r"https?://(pastebin\.|paste\.|hastebin\.|raw\.githubusercontent\.|gist\.github\.)",
    re.I,
)

# ---------------------------------------------------------------------------
# Reverse shell / tunnel patterns
# ---------------------------------------------------------------------------
_REVERSE_SHELL_PROGRAMS: set[str] = {
    "nc", "ncat", "netcat", "socat", "nmap", "bash", "sh",
    "chisel", "ngrok", "frpc", "frps", "ligolo", "plink",
}

_DEV_TCP_RE = re.compile(r"/dev/(tcp|udp)/")
_NC_EXEC_FLAGS = {"-e", "-c", "--exec", "--sh-exec"}
_SOCAT_EXEC_RE = re.compile(r"exec:|system:|EXEC:", re.I)
_MKFIFO_RE = re.compile(r"\bmkfifo\b")
_SSH_TUNNEL_FLAGS = {"-R", "-L", "-D", "-w"}

# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------
_PERSISTENCE_PATHS: list[re.Pattern[str]] = [
    re.compile(r"(/etc/cron|/var/spool/cron)", re.I),
    re.compile(r"\.bashrc|\.zshrc|\.profile|\.bash_profile|\.bash_login", re.I),
    re.compile(r"authorized_keys", re.I),
    re.compile(r"/etc/rc\.local", re.I),
    re.compile(r"\.config/systemd|/etc/systemd", re.I),
    re.compile(r"Library/LaunchAgents|Library/LaunchDaemons", re.I),
    re.compile(r"/etc/init\.d|/etc/init", re.I),
    re.compile(r"\.git/hooks", re.I),
    re.compile(r"(HKCU|HKLM).*\\Run", re.I),    # Windows reg
]

_PERSISTENCE_PROGRAMS: set[str] = {
    "crontab", "at", "batch", "atd", "systemctl", "launchctl",
    "chkconfig", "update-rc.d", "insserv", "schtasks", "reg",
}


# ---------------------------------------------------------------------------
# Security/monitoring tampering
# ---------------------------------------------------------------------------
_GATEWAY_SELF_MARKERS: list[re.Pattern[str]] = [
    re.compile(r"sentinel[-_]?mcp", re.I),
    re.compile(r"cybereye", re.I),
    re.compile(r"gateway\.py", re.I),
    re.compile(r"mcp_interception", re.I),
]

_SECURITY_TOOL_PROGRAMS: set[str] = {
    "auditd", "auditctl", "iptables", "ip6tables", "nftables", "ufw",
    "firewalld", "setenforce", "apparmor_parser", "aa-enforce",
    "journalctl", "logrotate",
}

_LOG_CLEAR_RE = re.compile(r">\s*/var/log|/var/log.*\s*>\s*/dev/null", re.I)
_HISTFILE_RE = re.compile(r"unset\s+HISTFILE|HISTFILE\s*=\s*/dev/null", re.I)

# ---------------------------------------------------------------------------
# Credential/secret access
# ---------------------------------------------------------------------------
_CRED_ACCESS_PROGRAMS: set[str] = {
    "security", "ssh-add", "gpg", "pass", "vault", "aws", "gcloud",
    "az", "kubectl",
}

_CRED_SEARCH_RE = re.compile(
    r"\b(id_rsa|id_ecdsa|id_ed25519|\.env|credentials|\.aws|\.netrc|\.pgpass|api[-_]?key)\b",
    re.I,
)
_HISTORY_RE = re.compile(r"^\s*(history|cat\s+.*bash_history|cat\s+.*zsh_history)", re.I)

# ---------------------------------------------------------------------------
# Data exfiltration
# ---------------------------------------------------------------------------
_EXFIL_PROGRAMS: set[str] = {
    "scp", "rsync", "sftp", "ftp", "nc", "ncat", "netcat",
    "curl", "wget", "socat",
}

# ---------------------------------------------------------------------------
# Fork bomb
# ---------------------------------------------------------------------------
_FORK_BOMB_RE = re.compile(r":\s*\(\s*\)\s*\{.*:\s*\|.*:\s*&.*\}", re.DOTALL)
_FORKBOMB_LITERAL = ":(){ :|:& };:"

# ---------------------------------------------------------------------------
# Network recon
# ---------------------------------------------------------------------------
_RECON_PROGRAMS: set[str] = {
    "nmap", "masscan", "arp-scan", "arp_scan", "nikto", "zmap",
    "unicornscan", "hping", "hping3",
}

# ---------------------------------------------------------------------------
# Package / supply-chain
# ---------------------------------------------------------------------------
_PKG_PROGRAMS: set[str] = {
    "pip", "pip3", "pip2", "npm", "yarn", "pnpm", "cargo",
    "gem", "go", "mvn", "gradle", "apt", "apt-get", "yum",
    "dnf", "pacman", "brew", "apk",
}

_SUSPICIOUS_PKG_URL_RE = re.compile(
    r"https?://(?!pypi\.org|registry\.npmjs\.org|crates\.io|rubygems\.org|repo1\.maven\.org|dl\.google\.com|github\.com/[^/]+/[^/]+/releases)",
    re.I,
)

# ---------------------------------------------------------------------------
# Dynamic / unanalyzable execution
# ---------------------------------------------------------------------------
_EVAL_PROGRAMS: set[str] = {"eval", "source", "."}

# ---------------------------------------------------------------------------
# Encoded payload detection
# ---------------------------------------------------------------------------
_BASE64_MIN_LEN = 20

_BASE64_RE = re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")

# Hex-encoded shell
_HEX_RE = re.compile(r"^[0-9a-fA-F]{40,}$")

# ANSI-C quoting: $'\x72\x6d'
_ANSI_C_HEX_RE = re.compile(r"\$'((?:\\x[0-9a-fA-F]{2}|\\[0-7]{1,3}|[^'\\])+)'")

# ---------------------------------------------------------------------------
# Helpers: path canonicalisation
# ---------------------------------------------------------------------------


def _canonicalise_path(path: str) -> str:
    """Minimal path canonicaliser matching Task-04 behaviour.

    Strips URL-encoding, resolves `..` segments, normalises separators.
    The full Task-04 engine should be called separately for path rules.
    """
    try:
        path = path.replace("\\", "/")
        # strip URL-encoding
        from urllib.parse import unquote

        path = unquote(path)
        # remove null bytes
        path = path.replace("\x00", "")
        norm = posixpath.normpath(path)
        return norm
    except Exception:
        return path


def _is_sensitive_path(path: str) -> bool:
    canon = _canonicalise_path(path)
    for pat in _SENSITIVE_PATH_PATTERNS:
        if pat.search(canon):
            return True
    return False


# ---------------------------------------------------------------------------
# Helpers: program name resolution
# ---------------------------------------------------------------------------


def _resolve_program(raw: str) -> str:
    """Strip path prefix, quotes, and common escapes from a program name."""
    if not raw:
        return ""
    raw = raw.strip()
    if re.match(r"^\$x[0-9a-fA-Fx]+$", raw):
        hex_digits = raw[2:].replace("x", "")
        if len(hex_digits) >= 2 and len(hex_digits) % 2 == 0:
            try:
                raw = bytes.fromhex(hex_digits).decode("utf-8", "replace")
            except ValueError:
                pass
    # Simple command substitutions of the form $(echo rm) or `echo rm`
    for pattern in (r"\$\(([^)]*)\)", r"`([^`]*)`"):
        m = re.search(pattern, raw)
        if m:
            candidate = (m.group(1) or m.group(2) or "").strip()
            if candidate:
                toks = candidate.split()
                if toks:
                    return _resolve_program(" ".join(toks[-1:]))
    raw = _expand_ansi_c(raw)
    # Strip path prefix  (/bin/rm → rm)
    name = raw.strip("'\"")
    if "/" in name:
        name = name.rsplit("/", 1)[-1]
    # remove backslash escapes in the name: r\m → rm
    name = re.sub(r"\\(.)", r"\1", name)
    return name.lower().strip()


def _expand_ansi_c(s: str) -> str:
    """Expand $'\\xNN' and $'\\NNN' ANSI-C quoted strings."""
    def _replacer(m: re.Match[str]) -> str:
        content = m.group(1)
        result = bytearray()
        i = 0
        while i < len(content):
            if content[i] == "\\" and i + 1 < len(content):
                nxt = content[i + 1]
                if nxt == "x" and i + 3 < len(content):
                    try:
                        result.append(int(content[i + 2:i + 4], 16))
                        i += 4
                        continue
                    except ValueError:
                        pass
                elif nxt.isdigit():
                    # octal
                    oct_str = ""
                    j = i + 1
                    while j < len(content) and content[j].isdigit() and len(oct_str) < 3:
                        oct_str += content[j]
                        j += 1
                    try:
                        result.append(int(oct_str, 8))
                        i = j
                        continue
                    except ValueError:
                        pass
                result.append(ord(nxt))
                i += 2
            else:
                result.append(ord(content[i]))
                i += 1
        try:
            return result.decode("utf-8", "replace")
        except Exception:
            return m.group(0)

    return _ANSI_C_HEX_RE.sub(_replacer, s)


# ---------------------------------------------------------------------------
# Base64 / encoded payload decoding
# ---------------------------------------------------------------------------


def _try_decode_base64(blob: str) -> str | None:
    """Try to decode a base64 string. Returns decoded string or None."""
    blob = blob.strip()
    if not _BASE64_RE.match(blob):
        return None
    try:
        decoded = base64.b64decode(blob + "==").decode("utf-8", "replace")
        return decoded
    except (binascii.Error, UnicodeDecodeError):
        return None


def _extract_base64_blobs(command: str) -> list[str]:
    """Find bare base64-looking blobs in a command string."""
    tokens = command.split()
    return [t for t in tokens if _BASE64_RE.match(t)]


# ---------------------------------------------------------------------------
# AST walker
# ---------------------------------------------------------------------------


class _NodeCounter:
    def __init__(self, limit: int) -> None:
        self._count = 0
        self._limit = limit

    def tick(self) -> None:
        self._count += 1
        if self._count > self._limit:
            raise ResourceWarning("AST node limit exceeded")


def _word_value(node: Any) -> str:
    """Extract word value from a bashlex WordNode."""
    try:
        return str(node.word) if hasattr(node, "word") else ""
    except Exception:
        return ""


def _get_parts(node: Any) -> list[Any]:
    try:
        if hasattr(node, "parts"):
            return list(node.parts)
    except Exception:
        pass
    extras: list[Any] = []
    for attr in ("command", "input", "output"):
        value = getattr(node, attr, None)
        if value is not None:
            extras.append(value)
    return extras


# ---------------------------------------------------------------------------
# Shell command classifier
# ---------------------------------------------------------------------------


class ShellCommandAnalyser:
    """
    Stateless analyser that parses a shell command string and returns a
    :class:`ShellAnalysisResult`.

    Call :meth:`analyse` with the raw command string and configuration.
    """

    def __init__(
        self,
        workspace_roots: list[str] | None = None,
        mode: str = "enforce",
        fail_closed_action: ShellAction = ShellAction.BLOCK,
        allowlist: list[dict[str, Any]] | None = None,
        agent_profile: str = "default",
    ) -> None:
        self.workspace_roots = workspace_roots or []
        self.mode = mode
        self.fail_closed_action = fail_closed_action
        self.allowlist = allowlist  # None = no allowlist mode
        self.agent_profile = agent_profile

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def analyse(
        self,
        command: str,
        decode_depth: int = 0,
        _node_counter: _NodeCounter | None = None,
    ) -> ShellAnalysisResult:
        result = ShellAnalysisResult(mode=self.mode)

        if _node_counter is None:
            _node_counter = _NodeCounter(MAX_AST_NODES)

        # --- Resource guards ---
        if not command or not command.strip():
            result.normalized_summary = "<empty>"
            return result

        raw_bytes = command.encode("utf-8", "replace")
        if len(raw_bytes) > MAX_COMMAND_BYTES:
            return self._fail_closed(result, "SHELL-OVERSIZED", "Command exceeds size limit")

        if decode_depth > MAX_DECODE_DEPTH:
            return self._fail_closed(result, "SHELL-DECODE-DEPTH", "Encoded payload decode depth exceeded")

        # --- Fork-bomb literal fast check ---
        if _FORKBOMB_LITERAL in command or _FORK_BOMB_RE.search(command):
            result.merge(ShellFinding(
                rule_id="SHELL-FORKBOMB",
                category="resource_exhaustion",
                severity=RiskLevel.CRITICAL,
                action=ShellAction.BLOCK,
                reason="Fork-bomb pattern detected",
                attack_technique="T1499",
                evidence=command[:120],
            ))
        elif re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)\s*\{.*\b\1\b\s*\|\s*\b\1\b.*&.*\}\s*;\s*\b\1\b", command, re.DOTALL):
            result.merge(ShellFinding(
                rule_id="SHELL-FORKBOMB",
                category="resource_exhaustion",
                severity=RiskLevel.CRITICAL,
                action=ShellAction.BLOCK,
                reason="Function-based fork bomb pattern detected",
                attack_technique="T1499",
                evidence="fork bomb function",
            ))

        # --- HISTFILE unset ---
        if _HISTFILE_RE.search(command):
            result.merge(ShellFinding(
                rule_id="SHELL-HISTFILE-UNSET",
                category="security_tampering",
                severity=RiskLevel.HIGH,
                action=ShellAction.BLOCK,
                reason="HISTFILE unsetting / defence evasion detected",
                attack_technique="T1562.003",
                evidence="HISTFILE manipulation",
            ))

        # --- Try to parse with bashlex ---
        parsed_ok = False
        if _BASHLEX_AVAILABLE:
            try:
                parts = bashlex.parse(command)
                parsed_ok = True
                programs: list[str] = []
                shared_env: dict[str, str] = {}
                for part in parts:
                    self._walk_node(part, result, _node_counter, programs, decode_depth, env_vars=shared_env)
                result.normalized_summary = " | ".join(programs) if programs else "<parsed>"
            except ResourceWarning as rw:
                return self._fail_closed(result, "SHELL-RESOURCE-LIMIT", str(rw))
            except (bashlex.errors.ParsingError, Exception) as exc:
                logger.debug("bashlex parse failed: %s — falling back", exc)
                parsed_ok = False

        if not parsed_ok:
            # Fallback: lightweight regex scan on raw string
            result.normalized_summary = "<unparseable>"
            self._fallback_scan(command, result, decode_depth)
            # Fail-closed for unparseable (unless it came back clean)
            if result.action == ShellAction.ALLOW:
                self._fail_closed(
                    result, "SHELL-UNPARSEABLE",
                    "Command could not be parsed; failing closed",
                )

        # --- Allowlist mode ---
        if self.allowlist is not None and result.action != ShellAction.BLOCK:
            self._check_allowlist(command, result)

        # --- Monitor mode ---
        if self.mode == "monitor" and result.action == ShellAction.BLOCK:
            result.would_have_blocked = True
            result.action = ShellAction.FLAG

        return result

    # ------------------------------------------------------------------
    # AST walker
    # ------------------------------------------------------------------

    def _walk_node(
        self,
        node: Any,
        result: ShellAnalysisResult,
        counter: _NodeCounter,
        programs: list[str],
        decode_depth: int,
        depth: int = 0,
        env_vars: dict[str, str] | None = None,
    ) -> None:
        if depth > MAX_NESTING_DEPTH:
            self._fail_closed(result, "SHELL-NESTING-LIMIT", "AST nesting limit exceeded")
            return
        counter.tick()

        env_vars = env_vars if env_vars is not None else {}
        kind = getattr(node, "kind", "")

        if kind == "function":
            fn_name = _word_value(getattr(node, "name", None))
            if fn_name:
                body_parts = _get_parts(node)
                for child in body_parts:
                    if getattr(child, "kind", "") in {"compound", "list"}:
                        if self._looks_like_fork_bomb(child, fn_name):
                            result.merge(ShellFinding(
                                rule_id="SHELL-FORKBOMB",
                                category="resource_exhaustion",
                                severity=RiskLevel.CRITICAL,
                                action=ShellAction.BLOCK,
                                reason=f"Recursive function call pattern detected for {fn_name}",
                                attack_technique="T1499",
                                evidence=f"{fn_name}() {{ {fn_name}|{fn_name} & }}",
                            ))
            for part in _get_parts(node):
                self._walk_node(part, result, counter, programs, decode_depth, depth + 1, env_vars)
        elif kind == "command":
            self._eval_command_node(node, result, counter, programs, decode_depth, depth, env_vars)
        elif kind == "pipeline":
            for part in _get_parts(node):
                self._walk_node(part, result, counter, programs, decode_depth, depth + 1, env_vars)
            pipeline_programs = self._collect_pipeline_programs(node)
            if len(pipeline_programs) > 1:
                self.check_pipeline(pipeline_programs, result)
        elif kind in ("list", "compound"):
            for part in _get_parts(node):
                self._walk_node(part, result, counter, programs, decode_depth, depth + 1, env_vars)
        elif kind == "if":
            for part in _get_parts(node):
                self._walk_node(part, result, counter, programs, decode_depth, depth + 1, env_vars)
        elif kind in ("while", "until", "for"):
            # Infinite loops spawning processes → resource exhaustion
            for part in _get_parts(node):
                self._walk_node(part, result, counter, programs, decode_depth, depth + 1, env_vars)
        elif kind == "word":
            # Could contain command substitutions
            for part in _get_parts(node):
                self._walk_node(part, result, counter, programs, decode_depth, depth + 1, env_vars)
        elif kind == "commandsubstitution":
            for part in _get_parts(node):
                self._walk_node(part, result, counter, programs, decode_depth, depth + 1, env_vars)
        elif kind in ("processsubstitution",):
            for part in _get_parts(node):
                self._walk_node(part, result, counter, programs, decode_depth, depth + 1, env_vars)

    def _looks_like_fork_bomb(self, node: Any, fn_name: str) -> bool:
        names: list[str] = []

        def visit(n: Any) -> None:
            if n is None:
                return
            kind = getattr(n, "kind", "")
            if kind == "word":
                value = _word_value(n)
                if value:
                    names.append(_resolve_program(value))
            for part in _get_parts(n):
                visit(part)

        visit(node)
        target = _resolve_program(fn_name)
        if target and names.count(target) >= 2:
            return True

        text = re.sub(r"\s+", " ", str(node))
        if target:
            pattern = rf"{re.escape(target)}\s*\(\s*\)\s*\{{.*\b{re.escape(target)}\b\s*\|\s*\b{re.escape(target)}\b.*&.*\}}|\b{re.escape(target)}\b\s*\|\s*\b{re.escape(target)}\b.*&"
            if re.search(pattern, text, re.I):
                return True
        return False

    def _collect_pipeline_programs(self, node: Any) -> list[str]:
        """Return the ordered program names for a pipeline node."""
        programs: list[str] = []
        for part in _get_parts(node):
            if getattr(part, "kind", "") == "command":
                words: list[str] = []
                for p in _get_parts(part):
                    if getattr(p, "kind", "") == "word":
                        words.append(_word_value(p))
                if words:
                    prog = _resolve_program(words[0])
                    if prog:
                        programs.append(prog)
            elif getattr(part, "kind", "") == "pipeline":
                programs.extend(self._collect_pipeline_programs(part))
        return programs

    def _eval_command_node(
        self,
        node: Any,
        result: ShellAnalysisResult,
        counter: _NodeCounter,
        programs: list[str],
        decode_depth: int,
        depth: int,
        env_vars: dict[str, str] | None = None,
    ) -> None:
        """Classify a single command node."""
        parts = _get_parts(node)
        if not parts:
            return

        env_vars = env_vars if env_vars is not None else {}

        # Collect words vs redirects
        words: list[str] = []
        redirect_targets: list[str] = []
        for p in parts:
            p_kind = getattr(p, "kind", "")
            if p_kind in ("word", "assignment") or hasattr(p, "word"):
                word_value = _word_value(p)
                if word_value:
                    words.append(word_value)
                # Check for command substitutions inside word parts
                for sub in _get_parts(p):
                    sub_kind = getattr(sub, "kind", "")
                    if sub_kind in ("commandsubstitution", "processsubstitution"):
                        for sub_part in _get_parts(sub):
                            self._walk_node(sub_part, result, counter, programs, decode_depth, depth + 1, env_vars)
            elif p_kind == "redirect":
                self._check_redirect(p, result)
                output = getattr(p, "output", None)
                if output is not None:
                    target = _word_value(output)
                    if target:
                        redirect_targets.append(target)
                input_val = getattr(p, "input", None)
                if input_val is not None and not isinstance(input_val, int):
                    target = _word_value(input_val)
                    if target:
                        redirect_targets.append(target)

        if not words:
            return

        # Variable assignments (VAR=val cmd args)
        # bashlex puts them as words; strip leading VAR= tokens
        cmd_words: list[str] = []
        for w in words:
            m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", w, re.DOTALL)
            if m and not cmd_words:
                env_vars[m.group(1)] = m.group(2)
            else:
                cmd_words.append(w)

        if not cmd_words:
            return

        # Expand simple env_vars in command name
        prog_raw = self._expand_simple_vars(cmd_words[0], env_vars)
        prog = _resolve_program(prog_raw)
        args = cmd_words[1:]

        # Record program
        if prog:
            programs.append(prog)

        if prog == "nsenter":
            result.merge(ShellFinding(
                rule_id="SHELL-NSENTER",
                category="privilege_escalation",
                severity=RiskLevel.CRITICAL,
                action=ShellAction.BLOCK,
                reason="nsenter: namespace escape / privileged command execution",
                attack_technique="T1036",
                evidence=prog,
            ))

        # ---------------------------------------------------------------
        # Transparent wrapper unwrapping
        # ---------------------------------------------------------------
        remaining_args = args
        while prog in _TRANSPARENT_WRAPPERS:
            # priv escalation signal
            if prog in _PRIV_WRAPPERS:
                result.merge(ShellFinding(
                    rule_id="SHELL-PRIV-WRAPPER",
                    category="privilege_escalation",
                    severity=RiskLevel.HIGH,
                    action=ShellAction.BLOCK,
                    reason=f"Privilege-escalation wrapper: {prog}",
                    attack_technique="T1548",
                    evidence=prog,
                    triggered_program=prog,
                ))
            skip = 0
            while skip < len(remaining_args):
                a = remaining_args[skip]
                if a.startswith("-"):
                    skip += 1
                    if a in {"-t", "--target", "-u", "--user", "-g", "--group", "-p", "--pid", "-C", "--cwd", "-c", "--chdir", "-w", "--wd", "-W", "--wait"} and skip < len(remaining_args):
                        next_tok = remaining_args[skip]
                        if next_tok and not next_tok.startswith("-"):
                            skip += 1
                    continue
                if a.isdigit() and prog in {"timeout", "time"}:
                    skip += 1
                    continue
                break
            remaining_args = remaining_args[skip:]
            if not remaining_args:
                break
            new_prog_raw = self._expand_simple_vars(remaining_args[0], env_vars)
            new_prog = _resolve_program(new_prog_raw)
            if not new_prog or new_prog == prog:
                break
            prog = new_prog
            remaining_args = remaining_args[1:]
            programs.append(prog)
            args = remaining_args

        # ---------------------------------------------------------------
        # Shell -c "..." unwrapping
        # ---------------------------------------------------------------
        if prog in _SHELL_PROGRAMS:
            self._unwrap_shell_c(prog, args, result, counter, programs, decode_depth, depth)

        # ---------------------------------------------------------------
        # Remote exec wrappers (ssh host cmd)
        # ---------------------------------------------------------------
        if prog in _REMOTE_EXEC:
            self._unwrap_remote_exec(prog, args, result, counter, programs, decode_depth, depth)

        # ---------------------------------------------------------------
        # Container exec (docker exec, kubectl exec)
        # ---------------------------------------------------------------
        if prog in _CONTAINER_EXEC:
            self._unwrap_container_exec(prog, args, result, counter, programs, decode_depth, depth)

        # ---------------------------------------------------------------
        # xargs / parallel
        # ---------------------------------------------------------------
        if prog in _XARGS_LIKE:
            self._unwrap_xargs(prog, args, result, counter, programs, decode_depth, depth)

        # ---------------------------------------------------------------
        # find -exec ... ;
        # ---------------------------------------------------------------
        if prog == "find":
            self._unwrap_find_exec(args, result, counter, programs, decode_depth, depth)

        # ---------------------------------------------------------------
        # Interpreter one-liners
        # ---------------------------------------------------------------
        if prog in _INTERPRETER_ONELINERS:
            self._check_interpreter_oneliner(prog, args, result, counter, programs, decode_depth, depth)

        # ---------------------------------------------------------------
        # Rule classification
        # ---------------------------------------------------------------
        self._classify_program(prog, args, result, programs)

        # reverse-shell patterns via redirection must also be checked at command level
        if prog in {"bash", "sh", "zsh", "dash", "ksh"} and any(("-i" in args) or any("/dev/tcp" in t or "/dev/udp" in t for t in redirect_targets) for _ in [0]):
            full = " ".join(args + redirect_targets)
            if "-i" in args and (">&" in full or "/dev/tcp" in full or "/dev/udp" in full):
                result.merge(ShellFinding(
                    rule_id="SHELL-INTERACTIVE-REDIRECT",
                    category="reverse_shell",
                    severity=RiskLevel.CRITICAL,
                    action=ShellAction.BLOCK,
                    reason="Interactive shell redirected to network",
                    attack_technique="T1059.004",
                    evidence="bash -i >&",
                ))

        # ---------------------------------------------------------------
        # Pipe-to-shell: base64 -d | sh
        # ---------------------------------------------------------------
        # (handled at pipeline level in _check_pipeline)
        # At command level, detect base64 decode piped pattern in args
        if prog in {"base64", "openssl", "xxd", "printf"} and args:
            self._check_encoded_payload(prog, args, result, decode_depth, counter, programs)

    # ------------------------------------------------------------------
    # Wrapper-unwrap helpers
    # ------------------------------------------------------------------

    def _unwrap_shell_c(
        self, prog: str, args: list[str], result: ShellAnalysisResult,
        counter: _NodeCounter, programs: list[str], decode_depth: int, depth: int,
    ) -> None:
        """Extract -c "..." argument and recursively analyse."""
        i = 0
        while i < len(args):
            if args[i] in ("-c", "--login"):
                if i + 1 < len(args):
                    inner = args[i + 1].strip("'\"")
                    sub = self.analyse(inner, decode_depth, counter)
                    for f in sub.findings:
                        result.merge(f)
                    for p in sub.normalized_summary.split(" | "):
                        if p and p not in programs:
                            programs.append(p)
                    break
            i += 1

    def _unwrap_remote_exec(
        self, prog: str, args: list[str], result: ShellAnalysisResult,
        counter: _NodeCounter, programs: list[str], decode_depth: int, depth: int,
    ) -> None:
        """ssh host cmd → analyse cmd part."""
        # ssh [-opts] [user@]host [cmd...]
        cmd_start = 0
        skip_next = False
        for i, arg in enumerate(args):
            if skip_next:
                skip_next = False
                continue
            if arg.startswith("-"):
                # flags that consume next arg
                if arg in ("-i", "-l", "-p", "-o", "-e", "-F", "-J", "-D", "-L", "-R", "-W"):
                    skip_next = True
                continue
            # First non-option arg is [user@]host
            cmd_start = i + 1
            break
        inner_cmd = " ".join(args[cmd_start:]).strip() if cmd_start < len(args) else ""
        if inner_cmd:
            sub = self.analyse(inner_cmd, decode_depth, counter)
            for f in sub.findings:
                result.merge(f)

    def _unwrap_container_exec(
        self, prog: str, args: list[str], result: ShellAnalysisResult,
        counter: _NodeCounter, programs: list[str], decode_depth: int, depth: int,
    ) -> None:
        """docker exec / kubectl exec -- cmd → analyse cmd part."""
        # Only unwrap of exec-like commands; docker build / docker ps are not exec wrappers.
        if not args:
            return
        if args[0] not in {"exec", "run", "create", "start", "attach", "cp", "logs", "inspect", "top", "stop", "rm", "kill", "export", "stats"}:
            return
        # Detect --privileged flag
        if "--privileged" in args:
            result.merge(ShellFinding(
                rule_id="SHELL-CONTAINER-ESCAPE",
                category="privilege_escalation",
                severity=RiskLevel.CRITICAL,
                action=ShellAction.BLOCK,
                reason="Container run with --privileged flag (escape vector)",
                attack_technique="T1611",
                evidence="--privileged",
            ))
        # Docker socket mount
        for a in args:
            if "/var/run/docker.sock" in a:
                result.merge(ShellFinding(
                    rule_id="SHELL-DOCKER-SOCK",
                    category="privilege_escalation",
                    severity=RiskLevel.CRITICAL,
                    action=ShellAction.BLOCK,
                    reason="Docker socket mounted into container (escape vector)",
                    attack_technique="T1611",
                    evidence="docker.sock",
                ))
        # Find command after -- or after container name
        if "--" in args:
            inner_idx = args.index("--") + 1
            inner_cmd = " ".join(args[inner_idx:]).strip()
        else:
            # Best effort: skip exec/run + container name
            skip_next = False
            inner_start = 0
            for i, a in enumerate(args[1:], 1):
                if skip_next:
                    skip_next = False
                    continue
                if a.startswith("-"):
                    if a in ("-e", "-w", "-u", "--user", "--workdir", "--env"):
                        skip_next = True
                    continue
                inner_start = i + 1
                break
            inner_cmd = " ".join(args[inner_start:]).strip() if inner_start < len(args) else ""
        if inner_cmd:
            sub = self.analyse(inner_cmd, decode_depth, counter)
            for f in sub.findings:
                result.merge(f)

    def _unwrap_xargs(
        self, prog: str, args: list[str], result: ShellAnalysisResult,
        counter: _NodeCounter, programs: list[str], decode_depth: int, depth: int,
    ) -> None:
        """xargs cmd → analyse cmd part."""
        cmd_start = 0
        skip_next = False
        for i, a in enumerate(args):
            if skip_next:
                skip_next = False
                continue
            if a.startswith("-"):
                if a in ("-I", "-n", "-P", "-s", "-d", "-a"):
                    skip_next = True
                continue
            cmd_start = i
            break
        inner_cmd = " ".join(args[cmd_start:]).strip() if cmd_start < len(args) else ""
        if inner_cmd:
            sub = self.analyse(inner_cmd, decode_depth, counter)
            for f in sub.findings:
                result.merge(f)

    def _unwrap_find_exec(
        self, args: list[str], result: ShellAnalysisResult,
        counter: _NodeCounter, programs: list[str], decode_depth: int, depth: int,
    ) -> None:
        """find ... -exec CMD ; → extract CMD and analyse."""
        i = 0
        while i < len(args):
            if args[i] in _FIND_EXEC_FLAGS:
                if i + 1 < len(args):
                    # Collect until ; or +
                    cmd_parts: list[str] = []
                    j = i + 1
                    while j < len(args) and args[j] not in (";", "+", "\\;", "\\+"):
                        cmd_parts.append(args[j])
                        j += 1
                    inner_cmd = " ".join(cmd_parts)
                    if inner_cmd:
                        sub = self.analyse(inner_cmd, decode_depth, counter)
                        for f in sub.findings:
                            result.merge(f)
                    if any(_is_broad_root(a) for a in args[:i] if a and not a.startswith("-")):
                        result.merge(ShellFinding(
                            rule_id="SHELL-DESTRUCTIVE-FIND-EXEC",
                            category="destructive_filesystem",
                            severity=RiskLevel.CRITICAL,
                            action=ShellAction.BLOCK,
                            reason="find -exec on broad root path",
                            attack_technique="T1485",
                            evidence="find / -exec ...",
                        ))
                    i = j
            i += 1

        # find / -delete is destructive
        if "-delete" in args:
            # check the find root
            for a in args:
                if a.startswith("/") or a in _BROAD_ROOTS:
                    if _is_broad_root(a):
                        result.merge(ShellFinding(
                            rule_id="SHELL-DESTRUCTIVE-FIND-DELETE",
                            category="destructive_filesystem",
                            severity=RiskLevel.CRITICAL,
                            action=ShellAction.BLOCK,
                            reason=f"find -delete on broad root path: {a}",
                            attack_technique="T1485",
                            evidence=f"find {a} -delete",
                        ))

    def _check_interpreter_oneliner(
        self, prog: str, args: list[str], result: ShellAnalysisResult,
        counter: _NodeCounter, programs: list[str], decode_depth: int, depth: int,
    ) -> None:
        """python -c / perl -e / etc: scan embedded code."""
        oneliner_flags = {"-c", "-e", "-r", "--eval"}
        for i, a in enumerate(args):
            if a in oneliner_flags and i + 1 < len(args):
                code = args[i + 1].strip("'\"")
                # Lightweight scan for process-spawning calls
                dangerous_calls = re.findall(
                    r"\b(os\.system|subprocess\.|exec\(|eval\(|os\.popen|commands\.|pty\.spawn)",
                    code,
                )
                if dangerous_calls:
                    result.merge(ShellFinding(
                        rule_id="SHELL-INTERPRETER-EXEC",
                        category="dynamic_execution",
                        severity=RiskLevel.HIGH,
                        action=ShellAction.FLAG,
                        reason=f"{prog} one-liner contains process-spawn call: {dangerous_calls[0]}",
                        attack_technique="T1059",
                        evidence=f"{prog} -e {code[:80]}",
                        triggered_program=prog,
                    ))
                # Also analyse as shell if it is a shell command
                if prog in ("awk", "gawk", "mawk"):
                    if re.search(r"\bsystem\s*\(", code):
                        result.merge(ShellFinding(
                            rule_id="SHELL-AWK-SYSTEM",
                            category="dynamic_execution",
                            severity=RiskLevel.HIGH,
                            action=ShellAction.FLAG,
                            reason="awk script calls system()",
                            attack_technique="T1059",
                            evidence=f"awk: {code[:80]}",
                        ))

    def _check_redirect(self, node: Any, result: ShellAnalysisResult) -> None:
        """Check redirections for dangerous targets (> /var/log/*)."""
        try:
            output = getattr(node, "output", None)
            heredoc = getattr(node, "heredoc", None)
            if output and hasattr(output, "word"):
                target = _word_value(output)
                if _is_sensitive_path(target):
                    result.merge(ShellFinding(
                        rule_id="SHELL-REDIRECT-SENSITIVE",
                        category="security_tampering",
                        severity=RiskLevel.HIGH,
                        action=ShellAction.FLAG,
                        reason=f"Redirect to sensitive path: {target}",
                        attack_technique="T1562",
                        evidence=target,
                    ))
                if any(s in target.lower() for s in (".bashrc", ".profile", ".zshrc", "authorized_keys", "/etc/rc.local", "/etc/cron", "/etc/cron.d")):
                    result.merge(ShellFinding(
                        rule_id="SHELL-PERSISTENCE-REDIRECT",
                        category="persistence",
                        severity=RiskLevel.HIGH,
                        action=ShellAction.BLOCK,
                        reason=f"Redirect writes to a persistence path: {target}",
                        attack_technique="T1547",
                        evidence=target,
                    ))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Program classifier
    # ------------------------------------------------------------------

    def _classify_program(
        self, prog: str, args: list[str], result: ShellAnalysisResult,
        programs: list[str],
    ) -> None:
        # ------ Destructive filesystem ------
        if prog == "rm":
            self._check_rm(args, result)
        elif prog == "shred":
            result.merge(ShellFinding(
                rule_id="SHELL-SHRED",
                category="destructive_filesystem",
                severity=RiskLevel.HIGH,
                action=ShellAction.BLOCK,
                reason="shred: secure file deletion",
                attack_technique="T1485",
                evidence=f"shred {' '.join(args[:3])}",
            ))
        elif prog in {"mkfs", "wipefs"} or prog.startswith("mkfs."):
            result.merge(ShellFinding(
                rule_id="SHELL-MKFS",
                category="destructive_filesystem",
                severity=RiskLevel.CRITICAL,
                action=ShellAction.BLOCK,
                reason=f"{prog}: filesystem creation/wipe on block device",
                attack_technique="T1485",
                evidence=prog,
            ))
        elif prog == "dd":
            self._check_dd(args, result)
        elif prog == "truncate":
            self._check_truncate(args, result)
        elif prog in {"fdisk", "parted", "gdisk", "cfdisk", "sgdisk"}:
            result.merge(ShellFinding(
                rule_id="SHELL-PARTITION-TOOL",
                category="destructive_filesystem",
                severity=RiskLevel.CRITICAL,
                action=ShellAction.BLOCK,
                reason=f"{prog}: partition table modification tool",
                attack_technique="T1485",
                evidence=prog,
            ))
        elif prog in {"chmod", "chown", "chgrp"}:
            self._check_chmod_chown(prog, args, result)

        # ------ Privilege escalation ------
        elif prog in _PRIV_ESC_PROGRAMS:
            self._check_priv_esc(prog, args, result)

        # ------ Download & execute ------
        if prog in _DOWNLOAD_PROGRAMS:
            self._check_download(prog, args, result, programs)

        # ------ Reverse shell ------
        if prog in _REVERSE_SHELL_PROGRAMS or prog in {"bash", "sh"}:
            self._check_reverse_shell(prog, args, result)

        # ------ Persistence ------
        if prog in _PERSISTENCE_PROGRAMS:
            self._check_persistence(prog, args, result)

        # ------ Credential access ------
        if prog in {"cat", "less", "more", "head", "tail", "grep", "find", "locate"}:
            self._check_cred_access(prog, args, result)
        if prog in _CRED_ACCESS_PROGRAMS:
            self._check_cred_tool(prog, args, result)
        if prog == "history" or prog in {"printenv", "env"}:
            result.merge(ShellFinding(
                rule_id="SHELL-CRED-ENV-DUMP",
                category="credential_access",
                severity=RiskLevel.MEDIUM,
                action=ShellAction.FLAG,
                reason=f"{prog}: environment / history dump",
                attack_technique="T1552.007",
                evidence=prog,
            ))

        # ------ Data exfiltration ------
        if prog in _EXFIL_PROGRAMS:
            self._check_exfiltration(prog, args, result)

        # ------ Security tampering ------
        if prog in _SECURITY_TOOL_PROGRAMS:
            self._check_security_tampering(prog, args, result)
        if prog in {"kill", "pkill", "killall"}:
            self._check_kill(prog, args, result)

        # ------ Network recon ------
        if prog in _RECON_PROGRAMS:
            result.merge(ShellFinding(
                rule_id="SHELL-RECON",
                category="network_recon",
                severity=RiskLevel.MEDIUM,
                action=ShellAction.FLAG,
                reason=f"{prog}: network reconnaissance tool",
                attack_technique="T1046",
                evidence=prog,
            ))

        # ------ Package / supply-chain ------
        if prog in _PKG_PROGRAMS:
            self._check_package_manager(prog, args, result)

        # ------ Dynamic / eval ------
        if prog in _EVAL_PROGRAMS:
            result.merge(ShellFinding(
                rule_id="SHELL-DYNAMIC-EVAL",
                category="dynamic_execution",
                severity=RiskLevel.HIGH,
                action=ShellAction.FLAG,
                reason=f"{prog}: dynamic code execution",
                attack_technique="T1059",
                evidence=prog,
            ))

        # ------ SSH tunnels ------
        if prog == "ssh":
            self._check_ssh_tunnel(args, result)

        # ------ Gateway self-protection ------
        full_cmd = " ".join([prog] + args)
        for pat in _GATEWAY_SELF_MARKERS:
            if pat.search(full_cmd):
                result.merge(ShellFinding(
                    rule_id="SHELL-GATEWAY-TAMPER",
                    category="security_tampering",
                    severity=RiskLevel.CRITICAL,
                    action=ShellAction.BLOCK,
                    reason="Command targets CyberEye gateway files or processes",
                    attack_technique="T1562",
                    evidence="gateway self-protection",
                ))
                break

    # ------------------------------------------------------------------
    # Individual rule checks
    # ------------------------------------------------------------------

    def _check_rm(self, args: list[str], result: ShellAnalysisResult) -> None:
        flags: set[str] = set()
        targets: list[str] = []
        i = 0
        while i < len(args):
            a = args[i]
            if a == "--":
                targets.extend(args[i + 1:])
                break
            if a.startswith("--"):
                flags.add(a)
                i += 1
                continue
            if a.startswith("-") and len(a) > 1:
                # Combined flags like -rf, -fr
                for ch in a[1:]:
                    flags.add(f"-{ch}")
                i += 1
                continue
            targets.append(a)
            i += 1

        has_recursive = bool(flags & (_DESTRUCTIVE_RECURSIVE_FLAGS | {"-R", "-r"}))
        has_force = bool(flags & (_DESTRUCTIVE_FORCE_FLAGS | {"-f"}))
        has_no_preserve = _NO_PRESERVE_ROOT in flags

        broad = any(_is_broad_root(t) for t in targets) or has_no_preserve
        sensitive = any(_is_sensitive_path(t) for t in targets)

        if broad:
            result.merge(ShellFinding(
                rule_id="SHELL-RM-BROAD-ROOT",
                category="destructive_filesystem",
                severity=RiskLevel.CRITICAL,
                action=ShellAction.BLOCK,
                reason=f"rm on broad root or system path (targets: {targets[:3]})",
                attack_technique="T1485",
                evidence=f"rm {' '.join(args[:6])}",
            ))
        elif sensitive:
            result.merge(ShellFinding(
                rule_id="SHELL-RM-SENSITIVE",
                category="destructive_filesystem",
                severity=RiskLevel.HIGH,
                action=ShellAction.BLOCK,
                reason=f"rm on sensitive path (targets: {targets[:3]})",
                attack_technique="T1485",
                evidence=f"rm {' '.join(args[:6])}",
            ))
        # rm -rf of non-workspace paths without being in workspace is still suspicious

    def _check_dd(self, args: list[str], result: ShellAnalysisResult) -> None:
        for a in args:
            if a.startswith("of=") and re.search(r"of=/dev/(sd|hd|nvme|vd)", a):
                result.merge(ShellFinding(
                    rule_id="SHELL-DD-BLOCK-DEVICE",
                    category="destructive_filesystem",
                    severity=RiskLevel.CRITICAL,
                    action=ShellAction.BLOCK,
                    reason=f"dd writing to block device: {a}",
                    attack_technique="T1485",
                    evidence=a,
                ))
            if "if=/dev/zero" in a or "if=/dev/urandom" in a:
                # Could be disk fill; check output
                pass  # combined with of= check above

    def _check_truncate(self, args: list[str], result: ShellAnalysisResult) -> None:
        for a in args:
            if not a.startswith("-") and _is_sensitive_path(a):
                result.merge(ShellFinding(
                    rule_id="SHELL-TRUNCATE-SENSITIVE",
                    category="destructive_filesystem",
                    severity=RiskLevel.HIGH,
                    action=ShellAction.BLOCK,
                    reason=f"truncate on sensitive path: {a}",
                    attack_technique="T1485",
                    evidence=a,
                ))

    def _check_chmod_chown(self, prog: str, args: list[str], result: ShellAnalysisResult) -> None:
        # chmod u+s, chmod 4755, chmod 6755 → setuid/setgid
        for a in args:
            if not a.startswith("-") and _SETUID_CHMOD_RE.search(a):
                result.merge(ShellFinding(
                    rule_id="SHELL-SETUID-BIT",
                    category="privilege_escalation",
                    severity=RiskLevel.HIGH,
                    action=ShellAction.BLOCK,
                    reason=f"{prog}: setuid/setgid bit manipulation: {a}",
                    attack_technique="T1548.001",
                    evidence=a,
                ))
        # chmod/chown -R on / or system dirs
        flags = [a for a in args if a.startswith("-")]
        targets = [a for a in args if not a.startswith("-")]
        has_recursive = bool(set(flags) & {"-r", "-R", "--recursive"})
        if has_recursive:
            for t in targets:
                if _is_broad_root(t):
                    result.merge(ShellFinding(
                        rule_id="SHELL-CHMOD-RECURSIVE-ROOT",
                        category="destructive_filesystem",
                        severity=RiskLevel.CRITICAL,
                        action=ShellAction.BLOCK,
                        reason=f"{prog} -R on broad root path: {t}",
                        attack_technique="T1485",
                        evidence=f"{prog} {' '.join(args[:5])}",
                    ))

    def _check_priv_esc(self, prog: str, args: list[str], result: ShellAnalysisResult) -> None:
        # sudo is already handled in wrapper check; other programs
        if prog == "nsenter":
            result.merge(ShellFinding(
                rule_id="SHELL-NSENTER",
                category="privilege_escalation",
                severity=RiskLevel.CRITICAL,
                action=ShellAction.BLOCK,
                reason="nsenter: namespace escape / privileged command execution",
                attack_technique="T1036",
                evidence=prog,
            ))
        elif prog in {"useradd", "userdel", "usermod", "groupadd", "groupmod",
                    "passwd", "chpasswd", "chage", "gpasswd"}:
            result.merge(ShellFinding(
                rule_id="SHELL-USER-MANAGEMENT",
                category="privilege_escalation",
                severity=RiskLevel.HIGH,
                action=ShellAction.BLOCK,
                reason=f"{prog}: user/group management command",
                attack_technique="T1136",
                evidence=prog,
            ))
        elif prog == "setcap":
            result.merge(ShellFinding(
                rule_id="SHELL-SETCAP",
                category="privilege_escalation",
                severity=RiskLevel.HIGH,
                action=ShellAction.BLOCK,
                reason="setcap: Linux capability manipulation",
                attack_technique="T1548",
                evidence=f"setcap {' '.join(args[:3])}",
            ))
        elif prog in {"visudo"}:
            result.merge(ShellFinding(
                rule_id="SHELL-SUDOERS-EDIT",
                category="privilege_escalation",
                severity=RiskLevel.CRITICAL,
                action=ShellAction.BLOCK,
                reason="visudo: editing sudoers configuration",
                attack_technique="T1548.003",
                evidence=prog,
            ))

    def _check_download(
        self, prog: str, args: list[str], result: ShellAnalysisResult, programs: list[str],
    ) -> None:
        # Check if this curl/wget output is piped to a shell (detected at pipeline level)
        # Check for suspicious URLs
        for i, a in enumerate(args):
            if re.search(r"https?://", a, re.I):
                host = a.split("//", 1)[1].split("/", 1)[0].lower()
                if host and not any(host.endswith(s) for s in (".example.com", "example.com", "pypi.org", "registry.npmjs.org", "localhost")) and not host.startswith("127.") and not host.startswith("10.") and not host.startswith("192.168."):
                    result.merge(ShellFinding(
                        rule_id="SHELL-SUSPICIOUS-URL",
                        category="download_execute",
                        severity=RiskLevel.HIGH,
                        action=ShellAction.FLAG,
                        reason=f"{prog}: download from suspicious URL",
                        attack_technique="T1105",
                        evidence="[URL redacted]",
                    ))
            # curl -d @file → exfil / curl --data @file
            if a in {"-d", "--data", "--data-raw"} and i + 1 < len(args) and "@" in args[i + 1]:
                result.merge(ShellFinding(
                    rule_id="SHELL-CURL-EXFIL",
                    category="data_exfiltration",
                    severity=RiskLevel.HIGH,
                    action=ShellAction.FLAG,
                    reason="curl -d @file: potential data exfiltration via POST",
                    attack_technique="T1048",
                    evidence="curl -d @<file>",
                ))
            if a.startswith("-d") and "@" in a:
                result.merge(ShellFinding(
                    rule_id="SHELL-CURL-EXFIL",
                    category="data_exfiltration",
                    severity=RiskLevel.HIGH,
                    action=ShellAction.FLAG,
                    reason="curl -d @file: potential data exfiltration via POST",
                    attack_technique="T1048",
                    evidence="curl -d @<file>",
                ))
            if a in {"-T", "--upload-file"} or a.startswith("-T"):
                result.merge(ShellFinding(
                    rule_id="SHELL-CURL-UPLOAD",
                    category="data_exfiltration",
                    severity=RiskLevel.HIGH,
                    action=ShellAction.FLAG,
                    reason="curl -T: file upload (potential exfiltration)",
                    attack_technique="T1048",
                    evidence="curl -T",
                ))

    def _check_reverse_shell(self, prog: str, args: list[str], result: ShellAnalysisResult) -> None:
        full = " ".join(args)
        if prog in _SHELL_PROGRAMS and re.search(r"<\(|\$\(|`.*(curl|wget|fetch)\b", full, re.I):
            result.merge(ShellFinding(
                rule_id="SHELL-PROCESS-SUBSTITUTION-REMOTE",
                category="download_execute",
                severity=RiskLevel.CRITICAL,
                action=ShellAction.BLOCK,
                reason="Shell receives remote script through process substitution",
                attack_technique="T1059",
                evidence="<(...curl...)",
            ))
        # /dev/tcp/host/port
        if _DEV_TCP_RE.search(full) and prog in ("bash", "sh", "zsh"):
            result.merge(ShellFinding(
                rule_id="SHELL-REVERSE-SHELL-DEV-TCP",
                category="reverse_shell",
                severity=RiskLevel.CRITICAL,
                action=ShellAction.BLOCK,
                reason="Bash reverse shell via /dev/tcp",
                attack_technique="T1059.004",
                evidence="bash -i >& /dev/tcp/",
            ))
        # nc -e / nc -c
        if prog in {"nc", "ncat", "netcat"}:
            flags = set(args)
            if _NC_EXEC_FLAGS & flags:
                result.merge(ShellFinding(
                    rule_id="SHELL-NC-EXEC",
                    category="reverse_shell",
                    severity=RiskLevel.CRITICAL,
                    action=ShellAction.BLOCK,
                    reason="nc with -e/-c: reverse shell",
                    attack_technique="T1059",
                    evidence=f"nc {' '.join(args[:4])}",
                ))
        # socat with exec
        if prog == "socat":
            if _SOCAT_EXEC_RE.search(full):
                result.merge(ShellFinding(
                    rule_id="SHELL-SOCAT-EXEC",
                    category="reverse_shell",
                    severity=RiskLevel.CRITICAL,
                    action=ShellAction.BLOCK,
                    reason="socat with exec/system: reverse shell vector",
                    attack_technique="T1059",
                    evidence="socat EXEC:",
                ))
        # Known tunnel tools
        if prog in {"chisel", "ngrok", "frpc", "frps", "ligolo", "plink"}:
            result.merge(ShellFinding(
                rule_id="SHELL-TUNNEL-TOOL",
                category="reverse_shell",
                severity=RiskLevel.HIGH,
                action=ShellAction.BLOCK,
                reason=f"{prog}: tunnel/exfil tool",
                attack_technique="T1572",
                evidence=prog,
            ))
        # bash -i >& pattern
        if prog in ("bash", "sh") and "-i" in args:
            full_str = " ".join(args)
            if ">&" in full_str or "/dev/tcp" in full_str or "/dev/udp" in full_str:
                result.merge(ShellFinding(
                    rule_id="SHELL-INTERACTIVE-REDIRECT",
                    category="reverse_shell",
                    severity=RiskLevel.CRITICAL,
                    action=ShellAction.BLOCK,
                    reason="Interactive shell redirected to network",
                    attack_technique="T1059.004",
                    evidence="bash -i >&",
                ))

    def _check_persistence(self, prog: str, args: list[str], result: ShellAnalysisResult) -> None:
        sev = RiskLevel.HIGH
        if prog == "crontab":
            result.merge(ShellFinding(
                rule_id="SHELL-CRONTAB",
                category="persistence",
                severity=sev,
                action=ShellAction.BLOCK,
                reason="crontab: scheduling persistent task",
                attack_technique="T1053.003",
                evidence=f"crontab {' '.join(args[:2])}",
            ))
        elif prog in {"at", "batch"}:
            result.merge(ShellFinding(
                rule_id="SHELL-AT-JOB",
                category="persistence",
                severity=sev,
                action=ShellAction.BLOCK,
                reason=f"{prog}: scheduling one-time task",
                attack_technique="T1053.001",
                evidence=prog,
            ))
        elif prog == "systemctl":
            action_idx = next((i for i, a in enumerate(args) if a in ("enable", "start", "daemon-reload")), None)
            if action_idx is not None:
                result.merge(ShellFinding(
                    rule_id="SHELL-SYSTEMCTL-ENABLE",
                    category="persistence",
                    severity=sev,
                    action=ShellAction.BLOCK,
                    reason=f"systemctl {args[action_idx]}: service activation/persistence",
                    attack_technique="T1543.002",
                    evidence=f"systemctl {' '.join(args[:3])}",
                ))
        elif prog == "schtasks":
            result.merge(ShellFinding(
                rule_id="SHELL-SCHTASKS",
                category="persistence",
                severity=sev,
                action=ShellAction.BLOCK,
                reason="schtasks: Windows scheduled task creation",
                attack_technique="T1053.005",
                evidence=prog,
            ))
        elif prog == "reg" and any("Run" in a for a in args):
            result.merge(ShellFinding(
                rule_id="SHELL-REG-RUN",
                category="persistence",
                severity=sev,
                action=ShellAction.BLOCK,
                reason="reg add Run key: Windows registry persistence",
                attack_technique="T1547.001",
                evidence="reg ..Run",
            ))
        elif prog == "launchctl":
            result.merge(ShellFinding(
                rule_id="SHELL-LAUNCHCTL",
                category="persistence",
                severity=sev,
                action=ShellAction.BLOCK,
                reason="launchctl: macOS service persistence",
                attack_technique="T1543.004",
                evidence=prog,
            ))

    def _check_cred_access(self, prog: str, args: list[str], result: ShellAnalysisResult) -> None:
        targets = [a for a in args if not a.startswith("-")]
        for t in targets:
            if _CRED_SEARCH_RE.search(t) or _is_sensitive_path(t):
                result.merge(ShellFinding(
                    rule_id="SHELL-CRED-FILE-READ",
                    category="credential_access",
                    severity=RiskLevel.HIGH,
                    action=ShellAction.BLOCK,
                    reason=f"{prog}: reading credential or key file",
                    attack_technique="T1552.001",
                    evidence=f"{prog} [sensitive path redacted]",
                ))
                break

    def _check_cred_tool(self, prog: str, args: list[str], result: ShellAnalysisResult) -> None:
        # aws configure get, gcloud auth print-access-token
        full = " ".join(args)
        if prog == "aws" and "configure get" in full:
            result.merge(ShellFinding(
                rule_id="SHELL-AWS-CRED-EXPORT",
                category="credential_access",
                severity=RiskLevel.HIGH,
                action=ShellAction.FLAG,
                reason="aws configure get: cloud credential export",
                attack_technique="T1552.001",
                evidence="aws configure get",
            ))
        if prog == "gcloud" and "print-access-token" in full:
            result.merge(ShellFinding(
                rule_id="SHELL-GCLOUD-CRED",
                category="credential_access",
                severity=RiskLevel.HIGH,
                action=ShellAction.FLAG,
                reason="gcloud auth print-access-token: cloud token export",
                attack_technique="T1552.001",
                evidence="gcloud auth print-access-token",
            ))
        if prog in {"gpg"} and "--export-secret-keys" in args:
            result.merge(ShellFinding(
                rule_id="SHELL-GPG-SECRET",
                category="credential_access",
                severity=RiskLevel.HIGH,
                action=ShellAction.BLOCK,
                reason="gpg --export-secret-keys: private key export",
                attack_technique="T1552.004",
                evidence="gpg --export-secret-keys",
            ))

    def _check_exfiltration(self, prog: str, args: list[str], result: ShellAnalysisResult) -> None:
        full = " ".join(args)
        # scp/rsync to external host
        if prog in {"scp", "rsync", "sftp"} and ":" in full:
            # heuristic: if host doesn't look internal (no 192.168/10./localhost)
            if not re.search(r"(localhost|127\.|10\.|192\.168\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.)", full):
                result.merge(ShellFinding(
                    rule_id="SHELL-SCP-EXTERNAL",
                    category="data_exfiltration",
                    severity=RiskLevel.HIGH,
                    action=ShellAction.FLAG,
                    reason=f"{prog}: file transfer to external host",
                    attack_technique="T1048",
                    evidence=f"{prog} [external host redacted]",
                ))
        # nc host < file
        if prog in {"nc", "ncat", "netcat"}:
            if "<" in full or any(a.startswith("--send-only") for a in args):
                result.merge(ShellFinding(
                    rule_id="SHELL-NC-EXFIL",
                    category="data_exfiltration",
                    severity=RiskLevel.HIGH,
                    action=ShellAction.FLAG,
                    reason="nc: piping file content to network",
                    attack_technique="T1048",
                    evidence="nc < file",
                ))
        if prog in {"ssh", "scp", "rsync", "sftp"} and ":" in full and not re.search(r"(localhost|127\\.|10\\.|192\\.168\\.|172\\.1[6-9]\\.|172\\.2[0-9]\\.|172\\.3[01]\\.)", full):
            result.merge(ShellFinding(
                rule_id="SHELL-SCP-EXTERNAL",
                category="data_exfiltration",
                severity=RiskLevel.HIGH,
                action=ShellAction.FLAG,
                reason=f"{prog}: file transfer to external host",
                attack_technique="T1048",
                evidence=f"{prog} [external host redacted]",
            ))

    def _check_security_tampering(self, prog: str, args: list[str], result: ShellAnalysisResult) -> None:
        full = " ".join(args)
        if prog == "setenforce" and "0" in args:
            result.merge(ShellFinding(
                rule_id="SHELL-SELINUX-DISABLE",
                category="security_tampering",
                severity=RiskLevel.CRITICAL,
                action=ShellAction.BLOCK,
                reason="setenforce 0: SELinux disabled",
                attack_technique="T1562.001",
                evidence="setenforce 0",
            ))
        if prog == "ufw" and "disable" in args:
            result.merge(ShellFinding(
                rule_id="SHELL-UFW-DISABLE",
                category="security_tampering",
                severity=RiskLevel.CRITICAL,
                action=ShellAction.BLOCK,
                reason="ufw disable: firewall disabled",
                attack_technique="T1562.004",
                evidence="ufw disable",
            ))
        if prog == "iptables" and "-F" in args:
            result.merge(ShellFinding(
                rule_id="SHELL-IPTABLES-FLUSH",
                category="security_tampering",
                severity=RiskLevel.CRITICAL,
                action=ShellAction.BLOCK,
                reason="iptables -F: firewall rules flushed",
                attack_technique="T1562.004",
                evidence="iptables -F",
            ))
        if prog == "auditd" and any(a in ("stop", "disable") for a in args):
            result.merge(ShellFinding(
                rule_id="SHELL-AUDITD-DISABLE",
                category="security_tampering",
                severity=RiskLevel.CRITICAL,
                action=ShellAction.BLOCK,
                reason="auditd stop/disable: audit logging disabled",
                attack_technique="T1562.001",
                evidence=f"auditd {' '.join(args[:2])}",
            ))
        if prog == "journalctl" and "--vacuum" in full:
            result.merge(ShellFinding(
                rule_id="SHELL-JOURNAL-VACUUM",
                category="security_tampering",
                severity=RiskLevel.HIGH,
                action=ShellAction.BLOCK,
                reason="journalctl --vacuum: log deletion",
                attack_technique="T1070.002",
                evidence="journalctl --vacuum",
            ))
        if prog == "apparmor_parser" and any(a in ("-R",) for a in args):
            result.merge(ShellFinding(
                rule_id="SHELL-APPARMOR-DISABLE",
                category="security_tampering",
                severity=RiskLevel.CRITICAL,
                action=ShellAction.BLOCK,
                reason="apparmor_parser -R: AppArmor profile removed",
                attack_technique="T1562.001",
                evidence="apparmor_parser -R",
            ))

    def _check_kill(self, prog: str, args: list[str], result: ShellAnalysisResult) -> None:
        full = " ".join(args)
        # kill gateway process or security tools
        sec_tools = {"auditd", "syslog", "rsyslog", "fluentd", "filebeat", "ossec", "falco"}
        for tool in sec_tools:
            if tool in full:
                result.merge(ShellFinding(
                    rule_id="SHELL-KILL-SECURITY-TOOL",
                    category="security_tampering",
                    severity=RiskLevel.CRITICAL,
                    action=ShellAction.BLOCK,
                    reason=f"{prog}: killing security monitoring tool: {tool}",
                    attack_technique="T1562.001",
                    evidence=f"{prog} ... {tool}",
                ))
        for pat in _GATEWAY_SELF_MARKERS:
            if pat.search(full):
                result.merge(ShellFinding(
                    rule_id="SHELL-KILL-GATEWAY",
                    category="security_tampering",
                    severity=RiskLevel.CRITICAL,
                    action=ShellAction.BLOCK,
                    reason="kill targeting CyberEye gateway process",
                    attack_technique="T1562",
                    evidence="kill gateway",
                ))

    def _check_package_manager(self, prog: str, args: list[str], result: ShellAnalysisResult) -> None:
        full = " ".join(args)
        # pip install http:// / git+http
        if prog in {"pip", "pip3", "pip2"}:
            if "install" in args:
                for a in args:
                    if re.search(r"^(https?://|git\+https?://|git\+ssh://)", a):
                        result.merge(ShellFinding(
                            rule_id="SHELL-PIP-URL-INSTALL",
                            category="supply_chain",
                            severity=RiskLevel.HIGH,
                            action=ShellAction.FLAG,
                            reason="pip install from URL (supply-chain risk)",
                            attack_technique="T1195.001",
                            evidence="pip install <url>",
                        ))
                    if "--index-url" in a or "--extra-index-url" in a:
                        result.merge(ShellFinding(
                            rule_id="SHELL-PIP-CUSTOM-INDEX",
                            category="supply_chain",
                            severity=RiskLevel.MEDIUM,
                            action=ShellAction.FLAG,
                            reason="pip install from custom index (supply-chain risk)",
                            attack_technique="T1195.001",
                            evidence="pip install --index-url",
                        ))
        if prog == "npm":
            if "install" in args or "i" in args:
                for a in args:
                    if re.search(r"^(git|git\+|github:|bitbucket:|gitlab:)", a, re.I):
                        result.merge(ShellFinding(
                            rule_id="SHELL-NPM-GIT-INSTALL",
                            category="supply_chain",
                            severity=RiskLevel.HIGH,
                            action=ShellAction.FLAG,
                            reason="npm install from git URL (supply-chain risk)",
                            attack_technique="T1195.001",
                            evidence="npm install <git-url>",
                        ))
            if "config" in args and "set" in args and "registry" in args:
                result.merge(ShellFinding(
                    rule_id="SHELL-NPM-REGISTRY-CHANGE",
                    category="supply_chain",
                    severity=RiskLevel.HIGH,
                    action=ShellAction.FLAG,
                    reason="npm config set registry: package registry change",
                    attack_technique="T1195.001",
                    evidence="npm config set registry",
                ))

    def _check_ssh_tunnel(self, args: list[str], result: ShellAnalysisResult) -> None:
        for a in args:
            if a in _SSH_TUNNEL_FLAGS:
                result.merge(ShellFinding(
                    rule_id="SHELL-SSH-TUNNEL",
                    category="reverse_shell",
                    severity=RiskLevel.HIGH,
                    action=ShellAction.BLOCK,
                    reason=f"ssh tunnel flag {a}: potential data tunnel / reverse access",
                    attack_technique="T1572",
                    evidence=f"ssh {a}",
                ))
                break

    # ------------------------------------------------------------------
    # Encoded payload handling
    # ------------------------------------------------------------------

    def _check_encoded_payload(
        self, prog: str, args: list[str], result: ShellAnalysisResult,
        decode_depth: int, counter: _NodeCounter, programs: list[str],
    ) -> None:
        """Detect base64 blobs and flag pipe-to-shell patterns."""
        # Find literal base64 blobs
        for a in args:
            blob = a.strip("'\"")
            decoded = _try_decode_base64(blob)
            if decoded is not None and len(decoded) > 5:
                # Re-analyse decoded string
                sub = self.analyse(decoded, decode_depth + 1, counter)
                if sub.findings or sub.action != ShellAction.ALLOW:
                    for f in sub.findings:
                        f.rule_id = f"SHELL-ENCODED-{f.rule_id}"
                        result.merge(f)
                else:
                    # Piping to interpreter is itself a signal
                    result.merge(ShellFinding(
                        rule_id="SHELL-ENCODED-PAYLOAD",
                        category="dynamic_execution",
                        severity=RiskLevel.HIGH,
                        action=ShellAction.FLAG,
                        reason="Encoded payload (base64) piped to interpreter",
                        attack_technique="T1027",
                        evidence="base64-encoded payload",
                    ))

    # ------------------------------------------------------------------
    # Pipeline-level detection (download→execute, encode→sh)
    # ------------------------------------------------------------------

    def check_pipeline(
        self, pipeline_programs: list[str], result: ShellAnalysisResult,
    ) -> None:
        """Called with the ordered list of programs in a pipeline.

        Detects: curl | sh, base64 -d | sh, cat file | sh, etc.
        """
        n = len(pipeline_programs)
        for i, prog in enumerate(pipeline_programs):
            if i == 0:
                continue
            prev = pipeline_programs[i - 1]
            if prog in _SHELL_EXEC_PROGRAMS and prev in _DOWNLOAD_PROGRAMS:
                result.merge(ShellFinding(
                    rule_id="SHELL-DOWNLOAD-EXEC",
                    category="download_execute",
                    severity=RiskLevel.CRITICAL,
                    action=ShellAction.BLOCK,
                    reason=f"Download-and-execute: {prev} | {prog}",
                    attack_technique="T1059",
                    evidence=f"{prev} | {prog}",
                ))
            if prog in _SHELL_EXEC_PROGRAMS and prev in {"base64", "openssl", "xxd", "printf", "echo"}:
                result.merge(ShellFinding(
                    rule_id="SHELL-ENCODED-EXEC",
                    category="dynamic_execution",
                    severity=RiskLevel.CRITICAL,
                    action=ShellAction.BLOCK,
                    reason=f"Encoded payload piped to interpreter: {prev} | {prog}",
                    attack_technique="T1027",
                    evidence=f"{prev} | {prog}",
                ))
            if prog in {"bash", "sh", "zsh", "dash", "ksh", "python", "perl", "ruby", "node", "php"} and prev in {"nc", "ncat", "netcat", "socat", "tar", "cat", "dd", "cp", "base64", "openssl", "xxd", "printf", "echo"}:
                result.merge(ShellFinding(
                    rule_id="SHELL-PIPE-TO-INTERPRETER",
                    category="data_exfiltration",
                    severity=RiskLevel.CRITICAL,
                    action=ShellAction.BLOCK,
                    reason=f"Data stream piped into interpreter: {prev} | {prog}",
                    attack_technique="T1059",
                    evidence=f"{prev} | {prog}",
                ))
            if prog in {"nc", "ncat", "netcat", "socat"} and prev in {"tar", "cat", "dd", "gzip", "bzip2", "xz", "base64", "openssl", "printf", "echo"}:
                result.merge(ShellFinding(
                    rule_id="SHELL-NC-EXFIL",
                    category="data_exfiltration",
                    severity=RiskLevel.HIGH,
                    action=ShellAction.FLAG,
                    reason=f"File data piped into network transfer tool: {prev} | {prog}",
                    attack_technique="T1048",
                    evidence=f"{prev} | {prog}",
                ))
            if prog == "xargs" and prev in {"echo", "printf", "cat", "dd", "tee", "head", "tail", "tr", "awk", "sed"}:
                result.merge(ShellFinding(
                    rule_id="SHELL-XARGS-STDIN-EXEC",
                    category="dynamic_execution",
                    severity=RiskLevel.CRITICAL,
                    action=ShellAction.BLOCK,
                    reason=f"stdin-fed arguments piped into xargs: {prev} | {prog}",
                    attack_technique="T1059",
                    evidence=f"{prev} | {prog}",
                ))

    # ------------------------------------------------------------------
    # Fallback regex scan (when bashlex fails)
    # ------------------------------------------------------------------

    def _fallback_scan(
        self, command: str, result: ShellAnalysisResult, decode_depth: int,
    ) -> None:
        """Lightweight pattern scan when the AST parser fails."""
        cmd_lower = command.lower()

        # Fork bomb
        if _FORKBOMB_LITERAL in command or _FORK_BOMB_RE.search(command):
            result.merge(ShellFinding(
                rule_id="SHELL-FORKBOMB",
                category="resource_exhaustion",
                severity=RiskLevel.CRITICAL,
                action=ShellAction.BLOCK,
                reason="Fork-bomb pattern (fallback detection)",
                attack_technique="T1499",
                evidence=command[:80],
            ))

        # rm -rf / patterns
        if re.search(r"\brm\b.*-[rRfF]*\s+/", command):
            result.merge(ShellFinding(
                rule_id="SHELL-RM-BROAD-ROOT",
                category="destructive_filesystem",
                severity=RiskLevel.CRITICAL,
                action=ShellAction.BLOCK,
                reason="rm -rf on root path (fallback detection)",
                attack_technique="T1485",
                evidence="rm -rf /",
            ))

        if re.search(r"\b\w+\s*\(\s*\)\s*\{\s*.*\|.*&.*\s*\};\s*\w+", command) or re.search(r"\b\w+\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\};\s*\w+", command):
            result.merge(ShellFinding(
                rule_id="SHELL-FORKBOMB",
                category="resource_exhaustion",
                severity=RiskLevel.CRITICAL,
                action=ShellAction.BLOCK,
                reason="Function-based fork bomb pattern detected",
                attack_technique="T1499",
                evidence="fork bomb function",
            ))

        # curl | sh
        if re.search(r"(curl|wget)\b.*\|\s*(bash|sh|python|perl|ruby)", command):
            result.merge(ShellFinding(
                rule_id="SHELL-DOWNLOAD-EXEC",
                category="download_execute",
                severity=RiskLevel.CRITICAL,
                action=ShellAction.BLOCK,
                reason="Download-and-execute pattern (fallback detection)",
                attack_technique="T1059",
                evidence="curl|wget | sh",
            ))

        # /dev/tcp reverse shell
        if _DEV_TCP_RE.search(command):
            result.merge(ShellFinding(
                rule_id="SHELL-REVERSE-SHELL-DEV-TCP",
                category="reverse_shell",
                severity=RiskLevel.CRITICAL,
                action=ShellAction.BLOCK,
                reason="/dev/tcp reverse shell (fallback detection)",
                attack_technique="T1059.004",
                evidence="/dev/tcp/",
            ))

        # base64 | sh
        if re.search(r"base64\b.*\|\s*(bash|sh|python|perl)", command, re.I):
            result.merge(ShellFinding(
                rule_id="SHELL-ENCODED-EXEC",
                category="dynamic_execution",
                severity=RiskLevel.CRITICAL,
                action=ShellAction.BLOCK,
                reason="base64 piped to interpreter (fallback detection)",
                attack_technique="T1027",
                evidence="base64 | sh",
            ))

    # ------------------------------------------------------------------
    # Variable expansion
    # ------------------------------------------------------------------

    def _expand_simple_vars(self, token: str, env: dict[str, str]) -> str:
        """Expand simple $VAR and ${VAR} from local env_vars dict."""
        def _sub(m: re.Match[str]) -> str:
            name = m.group(1) or m.group(2)
            return env.get(name, m.group(0))

        result = re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)", _sub, token)
        return result

    # ------------------------------------------------------------------
    # Allowlist mode
    # ------------------------------------------------------------------

    def _check_allowlist(self, command: str, result: ShellAnalysisResult) -> None:
        """In allowlist mode, block anything not explicitly permitted."""
        # Extract first token as program
        try:
            first_tok = command.strip().split()[0] if command.strip() else ""
            prog = _resolve_program(first_tok)
        except Exception:
            prog = ""
        if not self.allowlist:
            return
        permitted = [entry.get("program") for entry in self.allowlist]
        if prog not in permitted:
            result.merge(ShellFinding(
                rule_id="SHELL-ALLOWLIST-BLOCK",
                category="dynamic_execution",
                severity=RiskLevel.HIGH,
                action=ShellAction.BLOCK,
                reason=f"Program '{prog}' is not in the agent's command allowlist",
                attack_technique="",
                evidence=prog,
            ))

    # ------------------------------------------------------------------
    # Fail-closed helper
    # ------------------------------------------------------------------

    def _fail_closed(
        self, result: ShellAnalysisResult, rule_id: str, reason: str,
    ) -> ShellAnalysisResult:
        result.merge(ShellFinding(
            rule_id=rule_id,
            category="dynamic_execution",
            severity=RiskLevel.HIGH,
            action=self.fail_closed_action,
            reason=reason,
            attack_technique="",
            evidence="",
        ))
        return result


# ---------------------------------------------------------------------------
# Tool-call argument discovery
# ---------------------------------------------------------------------------

_SHELL_TOOL_NAMES: set[str] = {
    "run", "exec", "shell", "bash", "terminal", "command", "cmd",
    "eval", "run_command", "execute", "subprocess", "system", "sh",
    "run_shell", "shell_exec", "shell_execute", "shell/execute",
    "code_exec", "code_execute", "computer", "python", "node",
}

_SHELL_ARG_NAMES: set[str] = {
    "command", "cmd", "script", "args", "argv", "code",
    "input", "shell", "query", "bash", "run",
}


def is_shell_tool(tool_name: str, arguments: dict[str, Any] | None = None) -> bool:
    """Return True if this tool call likely executes shell commands."""
    if not tool_name:
        return False
    low = tool_name.lower()
    # Exact match
    if low in _SHELL_TOOL_NAMES:
        return True
    # Substring heuristics
    if any(kw in low for kw in ("exec", "shell", "run", "bash", "command", "terminal", "eval")):
        return True
    # Check argument names
    if arguments:
        for k in arguments:
            if k.lower() in _SHELL_ARG_NAMES:
                return True
    return False


def extract_shell_commands(
    tool_name: str,
    arguments: dict[str, Any] | None,
) -> list[tuple[str, str]]:
    """Extract (arg_name, command_string) pairs from tool arguments.

    Returns a list of (argument_key, command_string) for all string-form
    arguments that look like shell commands.
    """
    if not arguments:
        return []
    results: list[tuple[str, str]] = []
    for k, v in arguments.items():
        k_low = k.lower()
        if k_low in _SHELL_ARG_NAMES:
            if isinstance(v, str):
                results.append((k, v))
            elif isinstance(v, list):
                # argv form: join as shell string
                joined = " ".join(str(x) for x in v)
                results.append((k, joined))
    # Fallback: any string value that looks like it contains a command
    if not results:
        for k, v in arguments.items():
            if isinstance(v, str) and len(v) > 2 and (
                " " in v or "|" in v or ";" in v or "&&" in v or ">" in v
            ):
                results.append((k, v))
    return results


# ---------------------------------------------------------------------------
# High-level analyse_tool_call function (used by the decision hook)
# ---------------------------------------------------------------------------

def analyse_tool_call(
    tool_name: str | None,
    arguments: dict[str, Any] | None,
    agent_config: dict[str, Any] | None = None,
) -> ShellAnalysisResult | None:
    """Analyse a MCP tool call for shell policy violations.

    Returns ``None`` if this call has no shell-related content.
    Returns a :class:`ShellAnalysisResult` otherwise.

    ``agent_config`` may contain:
      - ``shell_mode``: ``"enforce"`` (default) or ``"monitor"``
      - ``shell_profile``: ``"default"``, ``"read_only_shell"``,
        ``"build_agent"``, ``"admin_agent"``
      - ``shell_allowlist``: list of ``{program, flags, args}`` dicts
      - ``workspace_roots``: list of absolute root paths
    """
    if not tool_name:
        return None
    cfg = agent_config or {}
    mode = cfg.get("shell_mode", "enforce")
    profile = cfg.get("shell_profile", "default")
    allowlist = cfg.get("shell_allowlist")       # None = blocklist mode
    workspace_roots = cfg.get("workspace_roots", [])

    if not is_shell_tool(tool_name, arguments):
        # Still check string arguments for embedded shell invocations
        # (fallback heuristic per spec §4.1)
        if not arguments:
            return None
        found_any = False
        for _k, v in arguments.items():
            if isinstance(v, str) and len(v) > 4:
                # Quick heuristic: does it parse as shell?
                try:
                    if _BASHLEX_AVAILABLE:
                        bashlex.parse(v)
                        found_any = True
                        break
                except Exception:
                    pass
        if not found_any:
            return None

    # Profile-based allowlist injection
    if profile == "read_only_shell" and allowlist is None:
        allowlist = _READ_ONLY_SHELL_ALLOWLIST
    elif profile == "build_agent" and allowlist is None:
        allowlist = None  # uses blocklist rules

    commands = extract_shell_commands(tool_name, arguments)
    if not commands:
        return None

    analyser = ShellCommandAnalyser(
        workspace_roots=workspace_roots,
        mode=mode,
        allowlist=allowlist,
        agent_profile=profile,
    )

    # Merge results from all command arguments
    combined = ShellAnalysisResult(mode=mode)
    all_programs: list[str] = []

    for arg_key, cmd_str in commands:
        if not cmd_str.strip():
            continue
        r = analyser.analyse(cmd_str)
        for f in r.findings:
            combined.merge(f)
        if r.normalized_summary:
            all_programs.append(f"{arg_key}:{r.normalized_summary}")
        if r.would_have_blocked:
            combined.would_have_blocked = True

    combined.normalized_summary = "; ".join(all_programs)
    return combined if (combined.findings or combined.action != ShellAction.ALLOW) else None


# ---------------------------------------------------------------------------
# Built-in allowlists for named profiles
# ---------------------------------------------------------------------------

_READ_ONLY_SHELL_ALLOWLIST: list[dict[str, Any]] = [
    {"program": "ls"},
    {"program": "cat"},
    {"program": "echo"},
    {"program": "pwd"},
    {"program": "whoami"},
    {"program": "date"},
    {"program": "uptime"},
    {"program": "ps"},
    {"program": "grep"},
    {"program": "find"},
    {"program": "head"},
    {"program": "tail"},
    {"program": "wc"},
    {"program": "sort"},
    {"program": "uniq"},
    {"program": "diff"},
    {"program": "which"},
    {"program": "env"},
    {"program": "printenv"},
]

# ---------------------------------------------------------------------------
# KNOWN LIMITATIONS (referenced in docs)
# ---------------------------------------------------------------------------
KNOWN_LIMITATIONS = """
Static shell analysis limitations
==================================

1. Runtime-only data: Commands assembled from environment variables, files,
   or network responses that the gateway cannot see at request time are not
   analysed.  Example: A=$(cat /tmp/payload.sh); eval "$A" — the eval is
   flagged but the payload content is unknown.

2. Script files: If an agent writes a script in one call and executes it in
   a later call, only the execution call is visible here. Write-then-execute
   chains require cross-call behavioural analysis (future task).

3. Compiled binaries: Behaviour hidden inside compiled binaries passed as
   tool arguments is not analysed.

4. Obfuscation beyond decode depth: Nested encoding beyond MAX_DECODE_DEPTH
   is blocked (fail-closed) but the inner payload is not inspected.

5. PowerShell / cmd.exe: Not supported. Tool calls that explicitly target
   PowerShell or cmd.exe are flagged, not fully analysed.

6. Indirect variable indirection beyond one level: $a=rm; $$a is not
   resolved; it is flagged as dynamic_execution.

7. Complex arithmetic expansion: $(( )) contexts are walked but not
   evaluated.

8. Runtime aliases / functions defined and then used later in the same
   session are not tracked across calls.

Recommended layered defences:
  • Allowlist mode for high-risk agents (see profiles).
  • OS least-privilege users, seccomp/AppArmor/SELinux on tool processes.
  • Network egress controls independent of the gateway.
  • Cross-call behavioural baselines (future CyberEye task).
"""
