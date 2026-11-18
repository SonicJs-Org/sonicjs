import { randomUUID } from 'node:crypto'
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

/** UUID per allocation, not Date.now()/workerIndex: safe across processes, retries and shards. */
export function uniqueTestId(prefix = 'e2e'): string {
  return `${prefix}-${randomUUID()}`
}

/** Narrow, same-host mutex. Never steal a lease merely because its heartbeat was delayed. */
export async function acquireTestLock(
  root: string,
  name: string,
  options: { timeoutMs?: number; pollMs?: number; onWaiting?: (ms: number) => void } = {},
): Promise<() => void> {
  if (!/^[a-z0-9-]+$/i.test(name)) throw new Error(`Invalid lock name: ${name}`)
  mkdirSync(root, { recursive: true })
  const dir = join(root, name)
  const ownerPath = join(dir, 'owner.json')
  const token = randomUUID()
  const started = Date.now()
  const timeout = options.timeoutMs ?? 300_000
  for (;;) {
    try {
      mkdirSync(dir)
      try {
        writeFileSync(ownerPath, JSON.stringify({ token, pid: process.pid, acquiredAt: new Date().toISOString() }))
      } catch (error) {
        rmSync(dir, { recursive: true, force: true })
        throw error
      }
      let released = false
      return () => {
        if (released) return
        released = true
        // Do not remove somebody else's lock after manual recovery/replacement.
        const owner = JSON.parse(readFileSync(ownerPath, 'utf8')) as { token: string }
        if (owner.token !== token) throw new Error(`Ownership lost for E2E lock ${name}`)
        rmSync(dir, { recursive: true })
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
    }
    const waited = Date.now() - started
    options.onWaiting?.(waited)
    if (waited >= timeout) {
      let owner = 'owner metadata unavailable'
      try { owner = readFileSync(ownerPath, 'utf8') } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error
      }
      throw new Error(`Timed out waiting for E2E lock ${name} after ${timeout}ms; ${owner}. ` +
        `Stop every runner targeting this environment before removing stale lock ${dir}.`)
    }
    await new Promise(resolve => setTimeout(resolve, options.pollMs ?? 100))
  }
}
