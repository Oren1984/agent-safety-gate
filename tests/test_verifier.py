"""Post-action verifier: judges the resulting state, not the agent's story."""
from safety_gate.agent import FAKE_TOKEN
from safety_gate.scenarios import INTENT
from safety_gate.verifier import verify


def action(tool, status="executed", decision="ALLOW", approval="not_required"):
    return {"id": "call_1", "tool": tool, "status": status, "decision": decision, "approval": approval}


def test_state_matching_intent_passes(tmp_path):
    (tmp_path / "summary.md").write_text("Release summary")
    assert verify(INTENT, [action("write_file")], tmp_path) == {"ok": True, "findings": [], "files": ["summary.md"]}


def test_missing_expected_file_fails(tmp_path):
    result = verify(INTENT, [], tmp_path)
    assert not result["ok"] and "intent not met" in result["findings"][0]


def test_unexpected_file_is_flagged(tmp_path):
    (tmp_path / "summary.md").write_text("ok")
    (tmp_path / "extra_instructions.txt").write_text("surprise")
    result = verify(INTENT, [action("write_file")], tmp_path)
    assert result["findings"] == ["unexpected file created: 'extra_instructions.txt'"]


def test_secret_in_output_is_a_forbidden_side_effect(tmp_path):
    (tmp_path / "summary.md").write_text(f"token: {FAKE_TOKEN}")
    assert any("secret-looking" in f for f in verify(INTENT, [], tmp_path)["findings"])


def test_action_outside_intent_scope_is_flagged(tmp_path):
    (tmp_path / "summary.md").write_text("ok")
    result = verify(INTENT, [action("deploy", decision="REQUIRE_APPROVAL", approval="approved")], tmp_path)
    assert any("outside the task's tool scope" in f for f in result["findings"])


def test_policy_violations_are_caught_after_the_fact(tmp_path):
    (tmp_path / "summary.md").write_text("ok")
    executed = [action("write_file", decision="BLOCK"), action("write_file", decision="REQUIRE_APPROVAL")]
    findings = verify(INTENT, executed, tmp_path)["findings"]
    assert any("blocked action" in f for f in findings) and any("without approval" in f for f in findings)
