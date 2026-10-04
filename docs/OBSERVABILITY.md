# Observability

Every run writes three files to `runs/<run_id>/` (git-ignored), next to its `workspace/`:

| File | Content |
|---|---|
| `audit.jsonl` | One structured event per safety-relevant step |
| `trace.json` | The LangGraph/LangChain run tree in LangSmith's run schema |
| `result.json` | Full result: actions, decisions, verifier, metrics, outcome, evaluator scores |

Secret-looking values are redacted before anything is written.

## Audit events

Each event has `ts`, `run_id`, `seq`, `layer`, `event` and event-specific fields.

| Event | Layer | Records |
|---|---|---|
| `run.started`, `run.outcome` | run | scenario, layers, intent; outcome and metrics |
| `tool.requested` | agent | requested tool and arguments (the agent's decision) |
| `injection.detected` | injection_check | source and matched patterns |
| `policy.decision` | policy, runtime_gate | decision, rule, risk reason |
| `gate.rewrite` | runtime_gate | what was stripped or redacted |
| `approval.requested`, `approval.approved`, `approval.rejected` | approval | approval state; whether the request followed flagged input |
| `action.held` | policy | escalated action that nobody approved |
| `execution.simulated` | execution | action that would have run (no sandbox layer) |
| `sandbox.result` | sandbox | execution result of a permitted action |
| `sandbox.containment`, `sandbox.network_denied` | sandbox | containment drill results, including denied network attempts |
| `sandbox.unavailable` | sandbox | Docker not running; nothing executed |
| `verifier.result` | verifier | pass/fail, findings, files in the workspace |

Blocked calls are `policy.decision` events with `decision: BLOCK`.

## Trace view

- **UI:** `python -m safety_gate.ui` shows the decision chain for a run: layers, each action's decision and reason, containment drill, verifier result and the audit timeline.
- **CLI:** `python -m safety_gate.demo` prints the same chain as a table.

## LangSmith compatibility

MOCK mode does not use a LangSmith API key and sends nothing over the network.

- `LocalTracer` subclasses LangChain's `BaseTracer`, the same callback interface the LangSmith tracer
  implements. It is passed to the graph through `config={"callbacks": [...]}` and receives the run
  tree (graph → node → model call). `trace.json` stores those runs with LangSmith's field names
  (`id`, `parent_run_id`, `name`, `run_type`, `inputs`, `outputs`, `start_time`, `end_time`).
- `EVALUATORS` follow the LangSmith evaluator shape: a function of the run result returning
  `{key, score}`. They score security and utility separately.

**Optional live tracing.** Because the pipeline is standard LangChain/LangGraph, setting
`LANGSMITH_TRACING=true` and `LANGSMITH_API_KEY` makes LangChain upload the same run tree to LangSmith
with no code change. This is not required, is not exercised by the tests, and was not run for this POC.
Note that live traces are not passed through this project's redaction.
