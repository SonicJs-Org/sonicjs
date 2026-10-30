/**
 * CI guard: every catalog event must have a dispatch site.
 *
 * Fails if a new event is added to HOOK_EVENT_NAMES without a matching call to
 * dispatchHookEvent() in a non-test source file. Prevents regressing to a state
 * where the catalog grows but production fires nothing.
 */
import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'fs'
import { join, resolve } from 'path'
import { HOOK_EVENT_NAMES } from '../../plugins/hooks/catalog'

const SRC_ROOT = resolve(__dirname, '../../')

/** Collect all non-test .ts files under dir recursively. */
function collectSourceFiles(dir: string, files: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry)
    try {
      const stat = statSync(full)
      if (stat.isDirectory()) {
        if (entry === 'node_modules' || entry === 'dist' || entry.startsWith('.')) continue
        if (entry === '__tests__') continue
        collectSourceFiles(full, files)
      } else if (
        stat.isFile() &&
        entry.endsWith('.ts') &&
        !entry.endsWith('.test.ts') &&
        !entry.endsWith('.spec.ts') &&
        !entry.endsWith('.d.ts')
      ) {
        files.push(full)
      }
    } catch {
      // Skip unreadable entries
    }
  }
  return files
}

describe('no catalog event without a dispatch site', () => {
  it('every HOOK_EVENT_NAMES entry has at least one dispatchHookEvent() call in source', () => {
    const sourceFiles = collectSourceFiles(SRC_ROOT)

    const missing: string[] = []

    for (const event of HOOK_EVENT_NAMES) {
      // Check: does any non-test source file contain both dispatchHookEvent( AND the event name string?
      const hasDispatchSite = sourceFiles.some((filePath) => {
        const content = readFileSync(filePath, 'utf8')
        return (
          content.includes('dispatchHookEvent(') &&
          (content.includes(`'${event}'`) || content.includes(`"${event}"`))
        )
      })

      if (!hasDispatchSite) {
        missing.push(event)
      }
    }

    expect(
      missing,
      `These catalog events have no dispatchHookEvent() dispatch site in source:\n  ${missing.join('\n  ')}\n` +
        `Add a dispatch site or move the event to an explicit allowlist below.`
    ).toHaveLength(0)
  })
})
