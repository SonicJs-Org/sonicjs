import { readFileSync } from 'node:fs'

import { describe, expect, it } from 'vitest'

const packageJson = JSON.parse(
  readFileSync(new URL('../../package.json', import.meta.url), 'utf8')
) as { dependencies: Record<string, string> }

const starterPackageJson = JSON.parse(
  readFileSync(
    new URL('../../../create-app/templates/starter/package.json', import.meta.url),
    'utf8'
  )
) as { pnpm: { overrides: Record<string, string> } }

const betterAuthPackages = [
  'better-auth',
  '@better-auth/core',
  '@better-auth/drizzle-adapter',
  '@better-auth/telemetry',
] as const

describe('Better Auth dependency compatibility', () => {
  it('pins the schema-compatible dependency family to one exact version', () => {
    const versions = betterAuthPackages.map((name) => packageJson.dependencies[name])

    expect(versions).toEqual(betterAuthPackages.map(() => '1.6.25'))
    expect(new Set(versions).size).toBe(1)
    expect(versions.every((version) => /^\d+\.\d+\.\d+$/.test(version))).toBe(true)
  })

  it('pins the dependency family for generated pnpm consumers', () => {
    const versions = betterAuthPackages.map(
      (name) => starterPackageJson.pnpm.overrides[name]
    )

    expect(versions).toEqual(betterAuthPackages.map(() => '1.6.25'))
  })
})
