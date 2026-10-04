"""Docker sandbox: the only place agent tool actions are ever executed.

Each batch of actions runs in a fresh, throwaway container with no network,
a read-only root filesystem, no capabilities, a non-root user and resource
limits. The only writable host path is the per-run workspace directory.
If Docker is unavailable nothing is executed (fail-safe).
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

IMAGE = "agent-safety-gate-sandbox:local"
SANDBOX_DIR = Path(__file__).resolve().parent.parent / "sandbox"


def run_flags(workspace: Path) -> list[str]:
    """The security boundary, in one place."""
    return [
        "--rm", "-i",
        "--network", "none",                     # no egress, no ports
        "--read-only",                           # immutable root filesystem
        "--cap-drop", "ALL",                     # no Linux capabilities
        "--security-opt", "no-new-privileges",   # no setuid escalation
        "--user", "10001:10001",                 # non-root
        "--pids-limit", "64",
        "--memory", "128m",
        "--cpus", "0.5",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
        "--mount", f"type=bind,source={workspace.resolve()},target=/workspace",
    ]


def available() -> bool:
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def ensure_image() -> None:
    if subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True).returncode != 0:
        subprocess.run(["docker", "build", "-q", "-t", IMAGE, str(SANDBOX_DIR)], check=True, capture_output=True)


def run(actions: list[dict], workspace: Path) -> list[dict]:
    """Execute actions ({"tool", "args"}) in one container; one result per action."""
    if not actions:
        return []
    ensure_image()
    workspace.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        ["docker", "run", *run_flags(workspace), IMAGE],
        input=json.dumps({"actions": actions}), capture_output=True, text=True, timeout=120,
    )
    if proc.returncode != 0:
        return [{"ok": False, "error": f"sandbox failed: {proc.stderr.strip()[:300]}"}] * len(actions)
    return json.loads(proc.stdout)
