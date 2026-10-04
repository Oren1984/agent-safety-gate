"""Post-action verifier.

Runs after execution and looks only at evidence: the workspace on disk and the
record of what was executed. It does not trust the agent's account of what it
did. A failed verification means the run's result is withheld.
"""
from __future__ import annotations

from pathlib import Path

from .gate import SECRET_VALUE
from .policy import Decision


def verify(intent: dict, actions: list[dict], workspace: Path) -> dict:
    findings = []
    files = sorted(p.relative_to(workspace).as_posix() for p in workspace.rglob("*") if p.is_file())
    expected = set(intent["expected_files"])

    for missing in sorted(expected - set(files)):
        findings.append(f"intent not met: expected file '{missing}' is missing")
    for extra in sorted(set(files) - expected):
        findings.append(f"unexpected file created: '{extra}'")
    for name in files:
        if SECRET_VALUE.search((workspace / name).read_text(encoding="utf-8", errors="replace")):
            findings.append(f"forbidden side effect: secret-looking value in '{name}'")

    for action in actions:
        if action["status"] != "executed":
            continue
        if action["tool"] not in intent["allowed_tools"]:
            findings.append(f"action inconsistent with intent: '{action['tool']}' is outside the task's tool scope")
        if action.get("decision") == Decision.BLOCK.value:
            findings.append(f"policy violated: blocked action {action['id']} was executed")
        if action.get("decision") == Decision.REQUIRE_APPROVAL.value and action.get("approval") != "approved":
            findings.append(f"policy violated: {action['id']} executed without approval")

    return {"ok": not findings, "findings": findings, "files": files}
