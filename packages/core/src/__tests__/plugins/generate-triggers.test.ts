/**
 * Tests for T3.4 — wrangler.toml cron trigger codegen.
 */
import { describe, it, expect } from 'vitest'
import { parseCronTriggers, updateWranglerTriggers } from '../../plugins/generate-triggers'

const BASE_TOML = `name = "my-app"
main = "src/index.ts"
compatibility_date = "2025-01-01"
`

const TOML_WITH_TRIGGERS = `name = "my-app"
main = "src/index.ts"

[triggers]
crons = ["*/15 * * * *", "0 0 * * *"]
`

describe('parseCronTriggers', () => {
  it('returns empty array when no [triggers] section', () => {
    expect(parseCronTriggers(BASE_TOML)).toEqual([])
  })

  it('parses cron expressions from [triggers] section', () => {
    expect(parseCronTriggers(TOML_WITH_TRIGGERS)).toEqual(['*/15 * * * *', '0 0 * * *'])
  })

  it('returns sorted results', () => {
    const toml = `[triggers]\ncrons = ["0 0 * * *", "*/5 * * * *"]\n`
    expect(parseCronTriggers(toml)).toEqual(['*/5 * * * *', '0 0 * * *'])
  })
})

describe('updateWranglerTriggers', () => {
  it('appends [triggers] section when none exists', () => {
    const updated = updateWranglerTriggers(BASE_TOML, ['*/15 * * * *'])
    expect(updated).toContain('[triggers]')
    expect(updated).toContain('"*/15 * * * *"')
  })

  it('replaces existing [triggers] section', () => {
    const updated = updateWranglerTriggers(TOML_WITH_TRIGGERS, ['0 12 * * *'])
    expect(updated).toContain('[triggers]')
    expect(updated).toContain('"0 12 * * *"')
    expect(updated).not.toContain('"*/15 * * * *"')
  })

  it('removes [triggers] section when schedules is empty', () => {
    const updated = updateWranglerTriggers(TOML_WITH_TRIGGERS, [])
    expect(updated).not.toContain('[triggers]')
  })

  it('roundtrip: write then parse returns the same schedules', () => {
    const schedules = ['*/15 * * * *', '0 0 1 * *']
    const updated = updateWranglerTriggers(BASE_TOML, schedules)
    const parsed = parseCronTriggers(updated)
    expect(parsed).toEqual(schedules.sort())
  })
})
