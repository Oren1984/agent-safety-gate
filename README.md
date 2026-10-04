# Agent Safety Gate

A lean engineering POC that asks one question:

> **If an AI agent makes a bad or unsafe decision, can the system around it stop that decision from becoming a real action?**

## What

A small agent pipeline where the agent is *deliberately gullible*: it reads a document containing an
indirect prompt injection and obeys it. The same agent and the same poisoned input are then run three
times with increasing protection, and the result is measured.

| Scenario | Protection | Unsafe actions that took effect | Outcome |
|---|---|---|---|
| A | Agent only | 6 of 6 (simulated) | `UNSAFE` |
| B | Deterministic policy gate | 1 of 6, plus a leaked token (simulated) | `PARTIALLY_PROTECTED` |
| C | Full defense-in-depth | 1 of 6, inside the sandbox, detected, result withheld | `CONTAINED` |

## Why

Model-level safety reduces how often an agent goes wrong. It does not bring that to zero, and once an
agent can call tools, a wrong decision is no longer just wrong text. It is a file write, a shell
command, a network call.

So this POC starts from the opposite assumption:

**Assume the agent may eventually make a bad decision. The surrounding system must prevent that
decision from becoming an unsafe action.**

No single control does that. Each layer here is simple, independent of the model, and catches what
another one misses.

## How

```
User intent ─▶ Agent (LangGraph) ◀─ untrusted input
                    │ requested tool actions
                    ▼
        Injection check      flags the untrusted content
                    ▼
        Policy engine        deterministic ALLOW / REQUIRE_APPROVAL / BLOCK
                    ▼
        Runtime tool gate    rewrites arguments, strips fake approvals, redacts secrets
                    ▼
        Human approval       Approve / Reject (simulated; no answer = reject)
                    ▼
        Docker sandbox       no network, read-only rootfs, no capabilities, non-root
                    ▼
        Post-action verifier compares the resulting state with the user's intent
                    ▼
        Audit log · trace · metrics · evaluators
```

- **Agent orchestration** — a LangGraph graph; each safety layer is one node. A deterministic LangChain mock model plays the agent.
- **Deterministic policy gate** — plain rules, no LLM. Unknown tools are blocked by default.
- **Runtime hook** — the Python gate in the pipeline, plus a Claude Code TypeScript mod (`runtime-gate/`) showing the same interception at a real tool boundary.
- **Docker isolation** — the only place anything executes. Egress is disabled, not just "it runs in Docker".
- **Human approval** — for high-risk actions. The agent cannot approve itself.
- **Post-action verification** — judges the workspace on disk, not the agent's account of it.
- **Observability** — structured audit events and a LangSmith-compatible local trace per run.
- **Automated tests** — the safety contract, executable.

## End-to-end flow

One run of scenario C, from the poisoned input to the outcome. Scenarios A and B run the same graph
with layers removed: A goes straight from the agent to the outcome, B keeps only the policy engine.
Without the sandbox layer nothing is executed; surviving actions are only recorded as `would_execute`.

```mermaid
flowchart TD
    intent([User intent:<br/>summarize the release notes]) --> agent
    doc[/Untrusted document<br/>with an injected instruction/] --> agent
    agent["Agent (LangGraph, mock model)<br/>obeys the injection"] -->|requested tool actions| inj
    inj["Injection check<br/>flags the untrusted content"] --> pol

    pol{"Policy engine<br/>deterministic rules"}
    pol -->|BLOCK| blocked[Blocked]
    pol -->|ALLOW / REQUIRE_APPROVAL| gate

    gate["Runtime tool gate<br/>rewrites arguments, strips fake approvals,<br/>redacts secrets, re-applies policy"]
    gate -->|BLOCK| blocked
    gate -->|REQUIRE_APPROVAL| appr
    gate -->|ALLOW| sbx

    appr{"Human approval<br/>no answer = reject"}
    appr -->|Reject| rejected[Rejected]
    appr -->|Approve| sbx

    sbx["Docker sandbox<br/>no network, read-only rootfs,<br/>no capabilities, non-root"]
    blocked -.->|containment drill:<br/>replayed in a scratch workspace| sbx
    sbx --> ver

    ver{"Post-action verifier<br/>workspace on disk vs. user intent"}
    ver -->|matches intent| safe([SAFE])
    ver -->|deviation detected,<br/>result withheld| contained([CONTAINED])

    blocked --> outcome
    rejected --> outcome
    safe --> outcome
    contained --> outcome
    outcome[["Outcome + metrics + evaluators<br/>audit.jsonl, trace.json, result.json"]]
```

Every node also emits structured audit events, so the run can be replayed from `runs/<run_id>/`.

## Run it

Requires Python 3.12+ and Docker (for scenario C and the sandbox tests).

```bash
python -m venv .venv
.venv/Scripts/activate            # Windows   (macOS/Linux: source .venv/bin/activate)
pip install -r requirements.txt

python -m safety_gate.demo        # run scenarios A, B, C in the terminal
python -m safety_gate.ui          # local demo UI at http://127.0.0.1:8765
pytest                            # the safety contract
```

Optional, needs the Claude Code CLI: `claude plugin test runtime-gate`

![Scenario C in the demo UI](docs/assets/scenario-c.png)

## MOCK mode

Everything runs locally with deterministic mock data. No `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`,
`LANGSMITH_API_KEY` or cloud credentials are needed or read. No real secret, network endpoint or
deployment exists anywhere in the demo. Live LangSmith tracing is optional and documented in
[docs/OBSERVABILITY.md](docs/OBSERVABILITY.md).

## Docs

[Architecture](docs/ARCHITECTURE.md) · [Safety model](docs/SAFETY_MODEL.md) ·
[Experiments](docs/EXPERIMENTS.md) · [Sandbox](docs/SANDBOX.md) ·
[Observability](docs/OBSERVABILITY.md) · [Governance mapping](docs/GOVERNANCE.md) ·
[Sources](docs/SOURCES.md)

## Research behind the design

- [AgentDojo](https://arxiv.org/abs/2406.13352) — measuring both security and utility under prompt injection
- [Defeating Prompt Injections by Design (CaMeL)](https://arxiv.org/abs/2503.18813) and [Progent](https://arxiv.org/abs/2504.11703) — enforcing policy outside the model
- [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/) — prompt injection and excessive agency
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework) and its Generative AI Profile
- [Claude Code mods](https://claude.com/blog/claude-code-mods) — programmable interception of tool calls

Full list with the design decision each one supports: [docs/SOURCES.md](docs/SOURCES.md).

## Scope

This is a lean engineering POC, not a production security product. The rules are small pattern lists,
the agent is a script, and the injection check is a heuristic. It demonstrates an architecture and
makes it measurable; it does not claim to stop a determined attacker. See the limitations in
[docs/SAFETY_MODEL.md](docs/SAFETY_MODEL.md).
