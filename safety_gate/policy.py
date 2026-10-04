"""Deterministic policy engine.

Pure functions, no LLM, no I/O. Given a requested tool action it returns
ALLOW, REQUIRE_APPROVAL or BLOCK plus the rule that fired. Unknown tools are
blocked (fail-safe default).
"""
from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass
from enum import Enum

WORKSPACE = "/workspace"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    BLOCK = "BLOCK"


# Strictness order, used when two layers disagree: the stricter one wins.
_STRICTNESS = {Decision.ALLOW: 0, Decision.REQUIRE_APPROVAL: 1, Decision.BLOCK: 2}


@dataclass(frozen=True)
class PolicyResult:
    decision: Decision
    rule: str
    reason: str


def stricter(a: PolicyResult, b: PolicyResult) -> PolicyResult:
    return a if _STRICTNESS[a.decision] >= _STRICTNESS[b.decision] else b


SECRET_PATH = re.compile(r"(/run/secrets|\.env\b|id_rsa|\.aws/|credentials|\.ssh/)", re.I)
DESTRUCTIVE_SHELL = re.compile(r"\b(rm\s+-[a-z]*[rf]|mkfs|dd\s+if=|shutdown|reboot|chmod\s+-R)\b", re.I)
PRIVILEGED_SHELL = re.compile(r"\b(sudo|su\s|docker|mount|chown|setcap|nsenter)\b", re.I)
NETWORK_SHELL = re.compile(r"\b(curl|wget|nc|ncat|ssh|scp|telnet|ftp)\b", re.I)
READ_ONLY_SHELL = re.compile(r"^\s*(ls|cat|wc|head|tail|echo|pwd)\b[^;&|`$><]*$")

# Network egress is denied by default; nothing is allowlisted in this POC.
ALLOWED_HOSTS: frozenset[str] = frozenset()


def resolve_path(path: str) -> str:
    """Resolve an agent-supplied path against the workspace root."""
    return posixpath.normpath(posixpath.join(WORKSPACE, str(path).replace("\\", "/")))


def inside_workspace(path: str) -> bool:
    full = resolve_path(path)
    return full == WORKSPACE or full.startswith(WORKSPACE + "/")


def _host(url: str) -> str:
    return re.sub(r"^[a-z]+://", "", str(url), flags=re.I).split("/")[0].split(":")[0].lower()


def evaluate(tool: str, args: dict) -> PolicyResult:
    """Decide what may happen to one requested tool action."""
    B, A, R = Decision.BLOCK, Decision.ALLOW, Decision.REQUIRE_APPROVAL
    path = str(args.get("path", ""))

    if tool == "read_secret" or SECRET_PATH.search(path):
        return PolicyResult(B, "secret-access", "agents never read secrets or credential files")

    if tool in ("read_file", "write_file", "delete_file"):
        if not inside_workspace(path):
            return PolicyResult(B, "fs-boundary", f"{resolve_path(path)} is outside {WORKSPACE}")
        if tool == "delete_file":
            return PolicyResult(R, "delete-needs-approval", "deleting files needs a human decision")
        return PolicyResult(A, "workspace-io", "file access inside the workspace")

    if tool == "http_request":
        host = _host(args.get("url", ""))
        if host not in ALLOWED_HOSTS:
            return PolicyResult(B, "network-egress", f"outbound call to '{host}' is not allowlisted")
        return PolicyResult(R, "external-call", "allowlisted external call still needs approval")

    if tool == "shell":
        cmd = str(args.get("command", ""))
        if DESTRUCTIVE_SHELL.search(cmd):
            return PolicyResult(B, "destructive-shell", "destructive shell command")
        if PRIVILEGED_SHELL.search(cmd):
            return PolicyResult(B, "privileged-operation", "privileged shell command")
        if SECRET_PATH.search(cmd):
            return PolicyResult(B, "secret-access", "shell command touches a secret path")
        if NETWORK_SHELL.search(cmd):
            return PolicyResult(B, "network-egress", "shell command opens a network connection")
        if READ_ONLY_SHELL.match(cmd):
            return PolicyResult(A, "read-only-shell", "allowlisted read-only command")
        return PolicyResult(R, "shell-needs-approval", "shell command is not on the read-only allowlist")

    if tool == "deploy":
        return PolicyResult(R, "deploy-needs-approval", "deployment-like actions need a human decision")

    return PolicyResult(B, "unknown-tool", f"tool '{tool}' is not known to the policy (fail-safe default)")
