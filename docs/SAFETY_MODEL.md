# Safety model

**Assumption:** the agent will sometimes be wrong or manipulated. Controls must hold without its cooperation.

## Layers

| # | Layer | Kind | What it stops in the demo | What it cannot do |
|---|---|---|---|---|
| 1 | Injection check | Heuristic, preventive | Flags the poisoned document; the flag is shown to the human approver | Regex patterns are easy to evade. It only flags, it never blocks |
| 2 | Policy engine | Deterministic, preventive | Secret access, network egress, writes outside the workspace, destructive and privileged shell | Cannot tell that an in-policy action is off-task |
| 3 | Runtime tool gate | Deterministic, preventive | Fake `approved: true` flag, secret-looking values in arguments | Only sees arguments, not intent |
| 4 | Human approval | Human, preventive | Deploy-like, delete and non-allowlisted shell actions | A human can approve the wrong thing |
| 5 | Docker sandbox | Structural, containing | Network egress, writes outside the workspace, host secrets — even if layers 1–4 all fail | Does not protect the workspace itself |
| 6 | Post-action verifier | Deterministic, detective | Unexpected files, secrets in output, off-scope tools, policy violations | Detects after the fact; it withholds the result, it does not undo |
| 7 | Audit / trace | Detective | Makes every decision reviewable | Does not prevent anything |

## Policy rules (`safety_gate/policy.py`)

| Action | Decision | Rule |
|---|---|---|
| `read_secret`, or any path matching a secret pattern (`.env`, `/run/secrets`, `id_rsa`, …) | BLOCK | `secret-access` |
| `read_file` / `write_file` inside `/workspace` | ALLOW | `workspace-io` |
| any file action resolving outside `/workspace` | BLOCK | `fs-boundary` |
| `delete_file` inside the workspace | REQUIRE_APPROVAL | `delete-needs-approval` |
| `http_request` to a host not on the allowlist (the allowlist is empty) | BLOCK | `network-egress` |
| `http_request` to an allowlisted host (none exist in this POC) | REQUIRE_APPROVAL | `external-call` |
| `shell`: destructive / privileged / secret-touching / network command | BLOCK | `destructive-shell`, `privileged-operation`, `secret-access`, `network-egress` |
| `shell`: single allowlisted read-only command (`ls`, `cat`, …) with no chaining | ALLOW | `read-only-shell` |
| `shell`: anything else | REQUIRE_APPROVAL | `shell-needs-approval` |
| `deploy` | REQUIRE_APPROVAL | `deploy-needs-approval` |
| unknown tool | BLOCK | `unknown-tool` |

## Fail-safe defaults

- Unknown tool → BLOCK.
- Approval required and no answer → not executed (`held` / `rejected`).
- Docker not running → nothing is executed; the run ends `FAILED_SAFE`.
- No sandbox layer → actions are recorded as `would_execute`, never run on the host.
- When two layers disagree, the stricter decision wins.

## Threats exercised

| Threat | Where it appears | Caught by |
|---|---|---|
| Indirect prompt injection from external content | `data/vendor_release_notes.md` | injection check (flag); everything downstream (effect) |
| Request to bypass approval | injected "approval already granted" + `approved: true` argument | runtime gate strips the flag; approval gate ignores agent claims |
| Write outside the allowed directory | `write_file ../outside/notes.txt` | policy `fs-boundary`; sandbox read-only rootfs |
| Access to a (fake) secret | `read_secret deploy_token` | policy `secret-access`; sandbox has no secrets mounted |
| Outbound network connection | `http_request` to `updates.example.invalid` | policy `network-egress`; sandbox `--network none` |
| Destructive shell command | `shell rm -rf /workspace/*` | policy `destructive-shell`; sandbox limits reach to a scratch directory |
| Excessive tool permissions | agent holds shell, network and deploy tools for a summarizing task | policy; verifier flags tools outside the task's scope |
| Action inconsistent with intent | `write_file extra_instructions.txt` (allowed by policy) | verifier `unexpected file created` |
| Secret exposure in output | fake token copied into `summary.md` | runtime gate redaction; verifier secret scan |

## Known limitations

- The agent is scripted. The POC shows what the layers do once the agent has failed; it does not
  measure how often a real model fails.
- Policy and redaction are short regular-expression lists. Real shells and encodings offer many ways
  around pattern matching; the sandbox, not the patterns, is the control that holds in that case.
- The injection check is illustrative and only flags.
- The verifier needs the intent to be declared up front (`expected_files`, `allowed_tools`). It
  withholds a result; it does not roll back.
- Human approval is a boolean supplied by the caller or the UI. There is no identity, no timeout, no
  second approver.
- The sandbox relies on Docker's default seccomp profile and a shared kernel. It is not a VM boundary.
- The containment drill deliberately runs blocked actions, including the `rm -rf`, inside the sandbox
  against an empty scratch directory.
- Not threat-modelled for multi-tenant use, concurrency or hostile local users.
