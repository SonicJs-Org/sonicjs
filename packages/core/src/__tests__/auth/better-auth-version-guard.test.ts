/**
 * Static guard on how core declares Better Auth.
 *
 * - EXACT versions: a caret range floats on every lockfile-free install (CI previews, new
 *   `@sonicjs-cms/core` consumers). It has already floated core onto releases with a different
 *   account schema (1.7.0–1.7.2 required `account.issuer`) and new startup checks (1.7.3+).
 * - ONE version across the family: `better-auth` and the `@better-auth/*` packages it composes
 *   must move together, or the adapter and core disagree about the schema contract.
 * - Floor 1.7.7: every release below it is affected by GHSA-965c-763c-88jm (critical — an OAuth
 *   state redeemable as a magic-link token), and SonicJS always composes the magic-link plugin.
 */
import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const pkg = JSON.parse(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), '../../../package.json'), 'utf8'),
) as { dependencies: Record<string, string> }

const family = Object.entries(pkg.dependencies).filter(
  ([name]) => name === 'better-auth' || name.startsWith('@better-auth/'),
)

const parse = (v: string) => v.split('.').map(Number) as [number, number, number]
const atLeast = (v: string, min: string) => {
  const [a, b, c] = parse(v)
  const [x, y, z] = parse(min)
  return a !== x ? a > x : b !== y ? b > y : c >= z
}

describe('Better Auth dependency declaration', () => {
  it('declares better-auth and its @better-auth/* family', () => {
    expect(family.map(([n]) => n)).toEqual(expect.arrayContaining(['better-auth', '@better-auth/core', '@better-auth/drizzle-adapter']))
  })

  it('pins every member to an exact version', () => {
    for (const [name, range] of family) expect(range, name).toMatch(/^\d+\.\d+\.\d+$/)
  })

  it('pins the whole family to one version', () => {
    expect(new Set(family.map(([, v]) => v)).size).toBe(1)
  })

  it('is at or above 1.7.7 (GHSA-965c-763c-88jm)', () => {
    expect(atLeast('1.7.6', '1.7.7')).toBe(false)
    expect(atLeast(pkg.dependencies['better-auth']!, '1.7.7')).toBe(true)
  })
})
