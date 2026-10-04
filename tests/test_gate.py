"""Injection check, secret redaction and argument sanitizing."""
from safety_gate.agent import FAKE_TOKEN
from safety_gate.gate import REDACTED, redact, sanitize, scan_untrusted
from safety_gate.scenarios import CLEAN_SOURCE, load_untrusted


def test_injection_is_detected_in_untrusted_content():
    found = scan_untrusted(load_untrusted())
    assert {"instruction-override", "role-spoofing", "concealment", "exfiltration"} <= set(found)


def test_clean_content_is_not_flagged():
    assert scan_untrusted(load_untrusted(CLEAN_SOURCE)) == []


def test_secret_redaction():
    args = {"content": f"Support token: {FAKE_TOKEN}", "nested": ["password=hunter2", {"k": "AKIAABCDEFGHIJKLMNOP"}]}
    text = str(redact(args))
    assert FAKE_TOKEN not in text and "hunter2" not in text and "AKIAABCDEFGHIJKLMNOP" not in text
    assert REDACTED in text


def test_self_asserted_approval_flags_are_stripped():
    clean, findings = sanitize("deploy", {"target": "production", "approved": True, "skip_approval": "yes"})
    assert clean == {"target": "production"}
    assert len(findings) == 2
