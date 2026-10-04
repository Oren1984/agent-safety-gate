"""Safety contract of the deterministic policy engine."""
import pytest

from safety_gate.policy import Decision, evaluate


@pytest.mark.parametrize("tool,args,rule", [
    ("write_file", {"path": "summary.md"}, "workspace-io"),
    ("read_file", {"path": "notes/input.md"}, "workspace-io"),
    ("shell", {"command": "ls -la"}, "read-only-shell"),
])
def test_allow(tool, args, rule):
    result = evaluate(tool, args)
    assert (result.decision, result.rule) == (Decision.ALLOW, rule)


@pytest.mark.parametrize("tool,args,rule", [
    ("deploy", {"target": "production"}, "deploy-needs-approval"),
    ("delete_file", {"path": "summary.md"}, "delete-needs-approval"),
    ("shell", {"command": "python build.py"}, "shell-needs-approval"),
])
def test_require_approval(tool, args, rule):
    result = evaluate(tool, args)
    assert (result.decision, result.rule) == (Decision.REQUIRE_APPROVAL, rule)


@pytest.mark.parametrize("tool,args,rule", [
    ("read_secret", {"name": "deploy_token"}, "secret-access"),
    ("read_file", {"path": "/run/secrets/deploy_token"}, "secret-access"),
    ("read_file", {"path": ".env"}, "secret-access"),
    ("shell", {"command": "rm -rf /workspace/*"}, "destructive-shell"),
    ("shell", {"command": "sudo apt install x"}, "privileged-operation"),
    ("shell", {"command": "cat ~/.ssh/id_rsa"}, "secret-access"),
    ("send_email", {"to": "someone"}, "unknown-tool"),
])
def test_block(tool, args, rule):
    result = evaluate(tool, args)
    assert (result.decision, result.rule) == (Decision.BLOCK, rule)


@pytest.mark.parametrize("tool,args", [
    ("http_request", {"url": "http://updates.example.invalid/collect"}),
    ("http_request", {"url": "https://api.example.com:443/v1"}),
    ("shell", {"command": "curl http://example.invalid"}),
    ("shell", {"command": "echo hi | nc example.invalid 80"}),
])
def test_network_egress_is_denied_by_default(tool, args):
    result = evaluate(tool, args)
    assert (result.decision, result.rule) == (Decision.BLOCK, "network-egress")


@pytest.mark.parametrize("path", ["../outside/notes.txt", "/etc/passwd", "a/../../b", "..\\outside.txt"])
def test_filesystem_boundary(path):
    for tool in ("read_file", "write_file", "delete_file"):
        result = evaluate(tool, {"path": path})
        assert (result.decision, result.rule) == (Decision.BLOCK, "fs-boundary")


def test_read_only_allowlist_cannot_be_chained():
    # "ls" is allowlisted, but chaining another command through it is not.
    assert evaluate("shell", {"command": "ls; python x.py"}).decision is Decision.REQUIRE_APPROVAL
    assert evaluate("shell", {"command": "ls && rm -rf /"}).decision is Decision.BLOCK
