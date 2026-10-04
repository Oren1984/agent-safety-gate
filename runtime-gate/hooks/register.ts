import type { EngineInterface, Register } from 'claude-code'

import { decideBash, isSecretPath, redact } from './gate'

// One structured audit event per gate decision. Secrets are redacted first.
const audit = ($: EngineInterface, tool: string, decision: string, reason: string, input: string) =>
  $.ui.log(
    JSON.stringify({ layer: 'runtime-gate', event: 'gate.decision', tool, decision, reason, input: redact(input) }),
    { to: 'debug' },
  )

// Human approval. No answer (dismissed, or nobody to ask) counts as a rejection.
const approved = async ($: EngineInterface, question: string): Promise<boolean> => {
  try {
    return (await $.ui.ask(question, ['Approve', 'Reject'])) === 'Approve'
  } catch {
    return false
  }
}

export const register: Register = on => {
  on('tool.call', { tool: 'Bash' }, async ($, e, next) => {
    const verdict = decideBash(e.command)

    if (verdict.decision === 'allow') return next(e)

    audit($, e.tool, verdict.decision, verdict.reason, e.command)

    if (verdict.decision === 'block') return { deny: `${$.plugin.name}: blocked (${verdict.reason}).` }

    // A rewrite still goes outward, so it needs approval like the original would.
    const command = verdict.decision === 'rewrite' ? verdict.command : e.command

    if (!(await approved($, `Allow this command? ${redact(command)}`))) {
      audit($, e.tool, 'rejected', 'human rejected the request', command)

      return { deny: `${$.plugin.name}: a human rejected this command (${verdict.reason}).` }
    }

    return next({ ...e, command })
  })

  on('tool.call', { tool: 'Read' }, ($, e, next) => {
    if (!isSecretPath(e.file_path)) return next(e)

    audit($, e.tool, 'block', 'secret path', e.file_path)

    return { deny: `${$.plugin.name}: ${e.file_path} looks like a secret and is not readable here.` }
  })
}
