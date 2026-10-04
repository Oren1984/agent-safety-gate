"""Checks that sit between the agent and its tools.

- scan_untrusted: heuristic prompt-injection check on untrusted content.
- redact: remove secret-looking values from any structure.
- sanitize: runtime tool gate — rewrites tool arguments before they are
  evaluated or executed (strips self-asserted approval flags, redacts secrets).

The TypeScript mod in runtime-gate/ shows the same interception idea at the
Claude Code tool boundary; this module is the Python pipeline's version.
"""
from __future__ import annotations

import re

INJECTION_PATTERNS = {
    "instruction-override": re.compile(r"ignore (all |any )?(previous|prior|above) instructions", re.I),
    "role-spoofing": re.compile(r"^\s*(system|assistant|developer)\s*:", re.I | re.M),
    "approval-bypass": re.compile(r"(approval|permission) (is |was |has been )?(already |pre-?)?(granted|approved|not (needed|required))", re.I),
    "concealment": re.compile(r"do not (tell|mention|inform|notify)", re.I),
    "exfiltration": re.compile(r"\b(send|post|upload|forward)\b.{0,60}\b(token|secret|credential|key)s?\b", re.I),
}

SECRET_VALUE = re.compile(
    r"(sk-[A-Za-z0-9_-]{8,}|AKIA[0-9A-Z]{16}|"
    r"(?i:(?:token|password|passwd|api[_-]?key|secret)\s*[=:]\s*\S+))"
)
REDACTED = "[REDACTED]"

# Arguments by which an agent claims an approval it cannot grant itself.
BYPASS_ARGS = {"approved", "skip_approval", "bypass", "force", "preapproved", "no_confirm"}


def scan_untrusted(text: str) -> list[str]:
    """Return the names of injection patterns found in untrusted text."""
    return [name for name, pattern in INJECTION_PATTERNS.items() if pattern.search(text)]


def redact(value):
    if isinstance(value, str):
        return SECRET_VALUE.sub(REDACTED, value)
    if isinstance(value, dict):
        return {k: redact(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    return value


def sanitize(tool: str, args: dict) -> tuple[dict, list[str]]:
    """Rewrite tool arguments. Returns (clean_args, findings)."""
    findings = []
    clean = {}
    for key, value in args.items():
        if key.lower() in BYPASS_ARGS:
            findings.append(f"removed self-asserted approval flag '{key}'")
            continue
        clean[key] = value
    redacted = redact(clean)
    if redacted != clean:
        findings.append("redacted secret-looking value in arguments")
    return redacted, findings
