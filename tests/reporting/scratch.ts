import { mkdirSync, mkdtempSync } from 'node:fs'
import { join } from 'node:path'
import { repositoryRoot } from './options'

export function reportingScratchParent(): string {
  return process.env.SONICJS_REPORTING_EVIDENCE || process.env.TMPDIR ||
    process.env.RUNNER_TEMP || join(repositoryRoot, '.cache/reporting-contracts')
}

/** Each fixture owns a fresh directory; hosted Linux runners need not set TMPDIR. */
export function reportingScratch(prefix: string): string {
  const parent = reportingScratchParent()
  mkdirSync(parent, { recursive: true })
  return mkdtempSync(join(parent, prefix))
}
