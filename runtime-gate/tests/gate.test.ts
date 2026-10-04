import type { On } from 'claude-code'
import { expect, test } from 'claude-code/testing'

// The test's own hooks stand in for the engine beneath the mod: `ran` records
// what actually reached execution, `logged` captures the audit events.
const harness = (on: On, answer = 'Reject') => {
  const ran: string[] = []
  const logged: string[] = []

  on('tool.call', { tool: 'Bash' }, (_$, e) => {
    ran.push(e.command)

    return { result: { stdout: '', stderr: '', interrupted: false } }
  })
  on('tool.call', { tool: 'Read' }, (_$, e) => {
    ran.push(e.file_path)

    return { result: { type: 'text', file: { filePath: e.file_path, content: '', numLines: 0, startLine: 1, totalLines: 0 } } }
  })
  on('tool.call', { tool: 'AskUserQuestion' }, (_$, e) => ({
    result: { questions: e.questions, answers: { [e.questions[0]?.question ?? '']: answer } },
  }))
  on('ui.log', (_$, e, next) => {
    logged.push(e.text)

    return next(e)
  })

  return { ran, logged }
}

test('safe commands pass through untouched', async ($, on) => {
  const { ran } = harness(on)

  await $.tool.call({ tool: 'Bash', command: 'ls -la' })

  expect(ran).toEqual(['ls -la'])
})

test('destructive commands are blocked and audited', async ($, on) => {
  const { ran, logged } = harness(on)

  const result = await $.tool.call({ tool: 'Bash', command: 'rm -rf /workspace' })

  expect(result.deny).toContain('destructive')
  expect(ran).toEqual([])
  expect(logged.some(line => line.includes('"decision":"block"'))).toBe(true)
})

test('secret files cannot be read', async ($, on) => {
  const { ran } = harness(on)

  const result = await $.tool.call({ tool: 'Read', file_path: '/repo/.env' })

  expect(result.deny).toContain('secret')
  expect(ran).toEqual([])
})

test('outward commands need approval: reject stops them', async ($, on) => {
  const { ran } = harness(on, 'Reject')

  const result = await $.tool.call({ tool: 'Bash', command: 'curl https://example.invalid' })

  expect(result.deny).toContain('rejected')
  expect(ran).toEqual([])
})

test('an approved force push runs rewritten, and the audit redacts secrets', async ($, on) => {
  const { ran, logged } = harness(on, 'Approve')

  await $.tool.call({ tool: 'Bash', command: 'git push --force origin main # token=abc123' })

  expect(ran).toEqual(['git push --force-with-lease origin main # token=abc123'])
  expect(logged.join('\n')).not.toContain('abc123')
})
