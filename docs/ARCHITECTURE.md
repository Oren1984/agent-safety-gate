# Architecture

## Flow

```
fetch_untrusted ─▶ agent ─▶ injection_check ─▶ policy ─▶ runtime_gate ─▶ approval ─▶ sandbox ─▶ verifier
                                                                                    (or simulate)
```

The pipeline is a LangGraph `StateGraph` built in `safety_gate/pipeline.py`. `fetch_untrusted` and
`agent` are always present. Every safety layer is a separate node that is added only when the scenario
enables it, so scenarios differ in wiring and nothing else. When the sandbox layer is absent, a
`simulate` node takes its place and records what *would* have run; nothing is executed.

## Components

| File | Role |
|---|---|
| `safety_gate/agent.py` | Deterministic mock agent: a LangChain `BaseChatModel` that returns scripted tool calls, and obeys injected instructions |
| `safety_gate/policy.py` | Deterministic policy engine: `evaluate(tool, args)` → ALLOW / REQUIRE_APPROVAL / BLOCK |
| `safety_gate/gate.py` | Injection heuristics, secret redaction, argument sanitizing (the Python runtime gate) |
| `safety_gate/sandbox.py` | Runs action batches in a locked-down, throwaway Docker container |
| `sandbox/` | Sandbox image: `Dockerfile` and the in-container `tool_runner.py` |
| `safety_gate/verifier.py` | Post-action check of the workspace against the user's intent |
| `safety_gate/observability.py` | Audit log, local LangSmith-compatible tracer, evaluators |
| `safety_gate/pipeline.py` | The graph, metrics and outcome |
| `safety_gate/scenarios.py`, `data/` | Scenario definitions, the user intent, the poisoned and clean documents |
| `safety_gate/demo.py`, `ui.py`, `ui.html` | CLI demo and local web UI (standard library HTTP server on 127.0.0.1) |
| `runtime-gate/` | Claude Code TypeScript mod: the same gate idea at a real agent's tool boundary |
| `tests/` | pytest suite |

## Life of an action

1. The agent returns tool calls. Each becomes an action record with status `requested`.
2. `policy` attaches a decision and rule. BLOCK sets status `blocked`.
3. `runtime_gate` rewrites the arguments (drops self-asserted approval flags, redacts secrets) and
   re-evaluates policy on the arguments that will actually run. A later layer can only tighten a
   decision, never loosen it.
4. `approval` asks the approver about REQUIRE_APPROVAL actions. Reject sets status `rejected`.
   An escalated action that nobody approved is `held`.
5. `sandbox` executes what is still `requested` in one container, then runs the containment drill
   (see [SANDBOX.md](SANDBOX.md)). Statuses become `executed` or `failed`.
6. `verifier` inspects the workspace and the execution record.
7. Metrics, outcome and evaluator scores are computed, and `audit.jsonl`, `trace.json` and
   `result.json` are written under `runs/<run_id>/`.

## Design choices

- **The agent never decides its own permissions.** Decisions come from `policy.py`, which takes no
  model output other than the requested tool name and arguments.
- **Layers do not share logic.** The sandbox does no policy checking; the verifier does not trust
  earlier decisions and re-checks them from the record.
- **Ground truth is kept away from enforcement.** The mock agent labels which of its calls are
  attacker-chosen. That label is used only for metrics.
- **Two runtime gates, on purpose.** `gate.py` gates the POC's own tools. `runtime-gate/` is a
  self-contained example for Claude Code's tools (`Bash`, `Read`). They implement the same idea and
  are not wired to each other.
