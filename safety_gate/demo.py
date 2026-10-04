"""CLI demo: run the three experiments and print the decision chain.

    python -m safety_gate.demo                 # scenarios A, B, C
    python -m safety_gate.demo -s C --approve  # C with the human approving
"""
from __future__ import annotations

import argparse

from .gate import redact
from .pipeline import run_scenario
from .scenarios import SCENARIOS


def describe(action: dict) -> str:
    args = redact(action["args"])
    target = args.get("path") or args.get("url") or args.get("command") or args.get("name") or args.get("target")
    return f"{action['tool']}({target})"[:42]


def print_result(result: dict) -> None:
    print(f"\n=== Scenario {result['scenario']} - {result['title']} ===")
    print(f"layers   : {', '.join(result['layers']) or 'none'}")
    print(f"intent   : {result['intent']['task']}")
    print(f"injection: {', '.join(result['injection']) or 'not checked'}")
    print(f"{'action':<44}{'decision':<18}{'status':<15}rule / note")
    for a in result["actions"]:
        note = a["rule"] or ""
        if a["gate_findings"]:
            note += f" | gate: {'; '.join(a['gate_findings'])}"
        if a["approval"] != "not_required":
            note += f" | human: {a['approval']}"
        print(f"{describe(a):<44}{a['decision'] or '-':<18}{a['status']:<15}{note}")
    for c in result["containment"]:
        print(f"  containment drill  {c['tool']:<13} {c['detail']}")
    if result["verifier"]:
        v = result["verifier"]
        print(f"verifier : {'OK' if v['ok'] else 'FAILED - result withheld'}")
        for finding in v["findings"]:
            print(f"  - {finding}")
    m = result["metrics"]
    print(f"metrics  : unsafe requested={m['unsafe_requested']} unsafe effective={m['unsafe_effective']} "
          f"blocked={m['blocked']} secrets exposed={m['secrets_exposed']} task completed={m['task_completed']}")
    print(f"evals    : {'  '.join(f'{e['key']}={e['score']}' for e in result['evals'])}")
    print(f"OUTCOME  : {result['outcome']}   (audit + trace: {result['run_dir']})")


def main() -> None:
    parser = argparse.ArgumentParser(description="Agent Safety Gate demo (MOCK mode)")
    parser.add_argument("-s", "--scenario", choices=[*SCENARIOS, "all"], default="all")
    parser.add_argument("--approve", action="store_true", help="simulated human approves escalated actions")
    opts = parser.parse_args()

    names = list(SCENARIOS) if opts.scenario == "all" else [opts.scenario]
    results = [run_scenario(n, approver=lambda action: opts.approve) for n in names]
    for result in results:
        print_result(result)
    if len(results) > 1:
        print("\nSame agent, same poisoned input:")
        for r in results:
            print(f"  {r['scenario']}  {r['title']:<32} unsafe effective: {r['metrics']['unsafe_effective']}"
                  f"/{r['metrics']['unsafe_requested']}   outcome: {r['outcome']}")


if __name__ == "__main__":
    main()
