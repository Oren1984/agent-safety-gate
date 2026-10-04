# Sources

What motivated the design, and which decision each source supports.

**This POC is inspired by these sources. It does not reproduce any of them.** Simplifications are
listed at the end.

## Research

**AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents**
Debenedetti, Zhang, Balunović, Beurer-Kellner, Fischer, Tramèr — https://arxiv.org/abs/2406.13352
Supports: the experiment shape. A legitimate user task, an injection arriving through tool output, and
security measured *alongside* utility (`unsafe_effective` next to `task_completed`), with ground-truth
labels for attacker-chosen actions.

**Defeating Prompt Injections by Design (CaMeL)**
Debenedetti, Shumailov, Fan, Hayes, Carlini, Fabian, Kern, Shi, Terzis, Tramèr — https://arxiv.org/abs/2503.18813
Supports: putting enforcement in a system layer around the model instead of asking the model to resist,
and treating untrusted data as something that must not gain control over actions.

**Progent: Securing AI Agents with Privilege Control**
Shi, He, Wang, Li, Wu, Guo, Song — https://arxiv.org/abs/2504.11703
Supports: a deterministic, per-tool-call policy with allow/deny decisions and least privilege for
tools — the model for `policy.py` and the runtime gate.

**The lethal trifecta for AI agents: private data, untrusted content, and external communication**
Simon Willison — https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/
Supports: denying egress by default. Removing external communication breaks the exfiltration path even
when the agent has read both a secret and an injection.

## Industry guidance

**OWASP Top 10 for LLM Applications (2025)** — https://genai.owasp.org/llm-top-10/
- LLM01 Prompt Injection — https://genai.owasp.org/llmrisk/llm01-prompt-injection/
- LLM06 Excessive Agency — https://genai.owasp.org/llmrisk/llm062025-excessive-agency/

Supports: the threat list. Excessive agency's three root causes (excessive functionality, permissions,
autonomy) map to the policy engine, the sandbox and the approval gate.

**OWASP Agentic AI – Threats and Mitigations (v1.0, 2025)** — https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/
Supports: treating tool misuse, intent manipulation and untraceability as distinct threats, hence the
post-action verifier and the audit trail.

**NIST AI Risk Management Framework (AI RMF 1.0, NIST AI 100-1)** — https://www.nist.gov/itl/ai-risk-management-framework
**NIST AI RMF: Generative AI Profile (NIST AI 600-1)** — https://doi.org/10.6028/NIST.AI.600-1
Supports: the Govern / Map / Measure / Manage framing in [GOVERNANCE.md](GOVERNANCE.md) and the choice
to make the result measurable.

## Runtime interception

**Customize Claude Code with mods in TypeScript** (Anthropic announcement) — https://claude.com/blog/claude-code-mods
**Create a mod** — https://code.claude.com/docs/en/plugins/mods/create
**React to events** — https://code.claude.com/docs/en/plugins/mods/events
**Hooks reference** (`PreToolUse` allow / deny / ask / `updatedInput`) — https://code.claude.com/docs/en/hooks
Supports: `runtime-gate/`. A `tool.call` hook can deny a call, ask a human, or pass a rewritten input
on with `next(...)`. That is the runtime tool gate, at the boundary of a real agent. The mod API is
early access and may change between Claude Code releases; the mod was validated and tested against
Claude Code 2.1.289.

## Safety culture and defense in depth

**Human error: models and management** — James Reason, BMJ 2000 — https://doi.org/10.1136/bmj.320.7237.768
Supports: the "Swiss cheese" view used throughout. Every layer has holes; safety comes from holes not
lining up. It is why scenario B is reported honestly as partial, and why the containment drill assumes
the upstream layers failed.

**Our framework for developing safe and trustworthy agents** — Anthropic — https://www.anthropic.com/news/our-framework-for-developing-safe-and-trustworthy-agents
Supports: keeping humans in control of high-stakes actions and making agent behaviour transparent.

## Inspired by vs. simplified

| Inspired by | Simplified here |
|---|---|
| AgentDojo's task + injection + utility/security scoring | One task, one injection, a scripted agent. No benchmark, no attack success rates for real models |
| CaMeL's separation of control and data flow | No capability tracking or data-flow analysis; untrusted content is only flagged |
| Progent's programmable privilege policies | A fixed rule table in Python, not a policy language; no per-task policy generation |
| Claude Code mods | A small example gate for two tools, separate from the Python pipeline |
| High-reliability layered defenses | Six small layers on one machine; no organizational process |
