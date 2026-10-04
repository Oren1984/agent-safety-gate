# Governance mapping

A high-level map from engineering controls in this POC to the frameworks and principles they relate
to. It is orientation, not a compliance claim.

## Principles

| Principle | Where it shows up |
|---|---|
| Least privilege | Empty network allowlist; workspace-only file access; non-root, capability-free container; the verifier flags tools outside the task's declared scope |
| Defense in depth | Six independent layers; the containment drill shows the sandbox holding when the gates are assumed to have failed |
| Human oversight | REQUIRE_APPROVAL for deploy, delete and non-allowlisted shell; the agent's own approval claims are stripped |
| Auditability | `audit.jsonl` with ordered, redacted events for every decision; `trace.json` per run |
| Fail-safe defaults | Unknown tool → BLOCK; no approval → not executed; no Docker → nothing executed; stricter decision wins |
| Shift-left assurance | The safety contract is a pytest suite that runs before any agent does; the mod has its own tests |

## NIST AI Risk Management Framework

| Function | In this POC |
|---|---|
| GOVERN | Policy is explicit, versioned code (`policy.py`) rather than model behaviour; decision authority sits outside the agent |
| MAP | Threat scenarios are enumerated and tied to controls ([SAFETY_MODEL.md](SAFETY_MODEL.md)) |
| MEASURE | Metrics and evaluators quantify security and utility per scenario ([EXPERIMENTS.md](EXPERIMENTS.md)) |
| MANAGE | Block, escalate, contain, withhold; documented limitations |

Generative AI Profile (NIST AI 600-1): the POC touches the *Information Security* risk area (prompt
injection, data exfiltration) and *Human-AI Configuration* (where a human decision is required).

## OWASP

| Risk | Control |
|---|---|
| LLM01 Prompt Injection (indirect) | Injection check; policy and sandbox limit what an injected instruction can achieve |
| LLM02 Sensitive Information Disclosure | Secret-access rule; argument and audit redaction; no secrets in the sandbox; verifier secret scan |
| LLM06 Excessive Agency — functionality, permissions, autonomy | Tool-level policy; sandbox restrictions; approval gate |
| Agentic threats: tool misuse, privilege compromise, intent manipulation | Runtime gate; capability-free sandbox; post-action verifier against declared intent |
| Agentic threats: repudiation and untraceability | Audit log and trace |

## What is out of scope

No organizational process, roles, risk register or control attestation is defined here. This is an
engineering demonstration of how such controls can be built and tested.
