// Deterministic rules for the runtime gate. Pure functions: no engine, no I/O.

export type Verdict =
  | { decision: 'allow' }
  | { decision: 'rewrite'; command: string; reason: string }
  | { decision: 'approve'; reason: string }
  | { decision: 'block'; reason: string }

const SECRET_PATH = /(^|[\\/])(\.env(\.|$)|id_rsa|credentials|\.aws[\\/]|\.ssh[\\/])|[\\/]run[\\/]secrets/i
const SECRET_VALUE = /(sk-[A-Za-z0-9_-]{8,}|AKIA[0-9A-Z]{16}|(?:token|password|api[_-]?key|secret)\s*[=:]\s*\S+)/gi
const DESTRUCTIVE = /\b(rm\s+-[a-z]*[rf]|mkfs|dd\s+if=|shutdown|reboot)\b/i
const PRIVILEGED = /\b(sudo|su\s|nsenter|setcap)\b|--privileged|docker\.sock/i
const OUTWARD = /\b(curl|wget|nc|ssh|scp|git\s+push|npm\s+publish|docker\s+push|kubectl\s+apply|terraform\s+apply)\b/i
const FORCE_PUSH = /(git\s+push\b.*?)\s--force(?!-with-lease)\b/i

export const redact = (text: string): string => text.replace(SECRET_VALUE, '[REDACTED]')

export const isSecretPath = (path: string): boolean => SECRET_PATH.test(path)

export function decideBash(command: string): Verdict {
  if (DESTRUCTIVE.test(command)) return { decision: 'block', reason: 'destructive shell command' }
  if (PRIVILEGED.test(command)) return { decision: 'block', reason: 'privileged operation' }
  if (SECRET_PATH.test(command)) return { decision: 'block', reason: 'command touches a secret path' }
  if (FORCE_PUSH.test(command)) {
    const safer = command.replace(FORCE_PUSH, '$1 --force-with-lease')
    return { decision: 'rewrite', command: safer, reason: 'force push rewritten to --force-with-lease' }
  }
  if (OUTWARD.test(command)) return { decision: 'approve', reason: 'network or deployment-like command' }
  return { decision: 'allow' }
}
