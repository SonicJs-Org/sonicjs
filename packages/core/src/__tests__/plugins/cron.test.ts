import { describe, it, expect } from 'vitest'
import { HookSystemImpl } from '../../plugins/hook-system'
import {
  collectCrons,
  collectCronSchedules,
  dispatchCronTick,
  createScheduledHandler,
  type CronablePlugin,
  type CronContext,
  type CronTickEvent,
} from '../../plugins/cron'

function ctx(): CronContext {
  return { hooks: new HookSystemImpl() }
}

const EVERY_15 = '*/15 * * * *'
const DAILY = '0 0 * * *'

describe('collectCrons', () => {
  it('flattens crons across plugins', () => {
    const plugins: CronablePlugin[] = [
      { name: 'email', crons: [{ schedule: EVERY_15, hookFamily: 'email-reconciliation' }] },
      { name: 'reports', crons: [{ schedule: DAILY, hookFamily: 'daily-report' }] },
      { name: 'no-crons' },
    ]
    expect(collectCrons(plugins)).toEqual([
      { plugin: 'email', schedule: EVERY_15, hookFamily: 'email-reconciliation' },
      { plugin: 'reports', schedule: DAILY, hookFamily: 'daily-report' },
    ])
  })

  it('skips malformed cron entries and null plugins', () => {
    const plugins: any[] = [
      null,
      { name: 'bad', crons: [{ schedule: EVERY_15 /* missing hookFamily */ }, { hookFamily: 'x' }] },
    ]
    expect(collectCrons(plugins)).toEqual([])
  })

  it('collectCronSchedules returns distinct expressions', () => {
    const plugins: CronablePlugin[] = [
      { name: 'a', crons: [{ schedule: EVERY_15, hookFamily: 'a' }] },
      { name: 'b', crons: [{ schedule: EVERY_15, hookFamily: 'b' }] },
      { name: 'c', crons: [{ schedule: DAILY, hookFamily: 'c' }] },
    ]
    expect(collectCronSchedules(plugins).sort()).toEqual([DAILY, EVERY_15].sort())
  })
})

describe('dispatchCronTick', () => {
  it('invokes onCronTick only for plugins matching the fired cron', async () => {
    const fired: string[] = []
    const plugins: CronablePlugin[] = [
      {
        name: 'email',
        crons: [{ schedule: EVERY_15, hookFamily: 'email-reconciliation' }],
        onCronTick: (e) => void fired.push(`email:${e.hookFamily}`),
      },
      {
        name: 'reports',
        crons: [{ schedule: DAILY, hookFamily: 'daily-report' }],
        onCronTick: (e) => void fired.push(`reports:${e.hookFamily}`),
      },
    ]

    const result = await dispatchCronTick(plugins, EVERY_15, 1000, ctx())

    expect(fired).toEqual(['email:email-reconciliation'])
    expect(result.invoked).toEqual([{ plugin: 'email', hookFamily: 'email-reconciliation' }])
    expect(result.unmatched).toBe(false)
  })

  it('passes a well-formed event (cron, scheduledTime, hookFamily)', async () => {
    let seen: CronTickEvent | undefined
    const plugins: CronablePlugin[] = [
      {
        name: 'p',
        crons: [{ schedule: EVERY_15, hookFamily: 'fam' }],
        onCronTick: (e) => void (seen = e),
      },
    ]
    await dispatchCronTick(plugins, EVERY_15, 1717200000000, ctx())
    expect(seen).toEqual({ cron: EVERY_15, scheduledTime: 1717200000000, hookFamily: 'fam' })
  })

  it('reports unmatched when the fired cron matches nothing', async () => {
    const plugins: CronablePlugin[] = [
      { name: 'p', crons: [{ schedule: EVERY_15, hookFamily: 'fam' }], onCronTick: () => {} },
    ]
    const result = await dispatchCronTick(plugins, '0 3 * * *', 1, ctx())
    expect(result.unmatched).toBe(true)
    expect(result.invoked).toEqual([])
  })

  it('fires once per matching declaration for a multi-cron plugin', async () => {
    const families: string[] = []
    const plugins: CronablePlugin[] = [
      {
        name: 'multi',
        crons: [
          { schedule: EVERY_15, hookFamily: 'fast' },
          { schedule: EVERY_15, hookFamily: 'also-fast' },
          { schedule: DAILY, hookFamily: 'slow' },
        ],
        onCronTick: (e) => void families.push(e.hookFamily),
      },
    ]
    await dispatchCronTick(plugins, EVERY_15, 1, ctx())
    expect(families).toEqual(['fast', 'also-fast'])
  })

  it('isolates a throwing onCronTick — others still run', async () => {
    const ran: string[] = []
    const plugins: CronablePlugin[] = [
      {
        name: 'bad',
        crons: [{ schedule: EVERY_15, hookFamily: 'bad' }],
        onCronTick: () => {
          throw new Error('boom')
        },
      },
      {
        name: 'good',
        crons: [{ schedule: EVERY_15, hookFamily: 'good' }],
        onCronTick: () => void ran.push('good'),
      },
    ]
    const result = await dispatchCronTick(plugins, EVERY_15, 1, ctx())
    expect(ran).toEqual(['good'])
    expect(result.invoked).toEqual([{ plugin: 'good', hookFamily: 'good' }])
    expect(result.errors).toHaveLength(1)
    expect(result.errors[0]).toMatchObject({ plugin: 'bad', hookFamily: 'bad' })
  })
})

describe('createScheduledHandler', () => {
  it('dispatches the fired controller.cron and calls waitUntil', async () => {
    const fired: string[] = []
    const plugin: CronablePlugin = {
      name: 'email',
      crons: [{ schedule: EVERY_15, hookFamily: 'email-reconciliation' }],
      onCronTick: (e) => void fired.push(e.hookFamily),
    }
    const hooks = new HookSystemImpl()
    const handler = createScheduledHandler({ plugins: [plugin], getHooks: () => hooks })

    const waited: Promise<unknown>[] = []
    const result = await handler(
      { cron: EVERY_15, scheduledTime: 42 },
      { SOME_BINDING: 'x' },
      { waitUntil: (p) => void waited.push(p) }
    )

    expect(fired).toEqual(['email-reconciliation'])
    expect(result.invoked).toHaveLength(1)
    expect(waited).toHaveLength(1)
  })

  it('passes the Worker env through to the cron context', async () => {
    let seenEnv: unknown
    const plugin: CronablePlugin = {
      name: 'p',
      crons: [{ schedule: EVERY_15, hookFamily: 'fam' }],
      onCronTick: (_e, c) => void (seenEnv = c.env),
    }
    const handler = createScheduledHandler({ plugins: [plugin], getHooks: () => new HookSystemImpl() })
    await handler({ cron: EVERY_15, scheduledTime: 0 }, { DB: 'binding' })
    expect(seenEnv).toEqual({ DB: 'binding' })
  })

  it('evaluates a lazy plugin list at fire time', async () => {
    let calls = 0
    const handler = createScheduledHandler({
      plugins: () => {
        calls++
        return [{ name: 'p', crons: [{ schedule: EVERY_15, hookFamily: 'f' }], onCronTick: () => {} }]
      },
      getHooks: () => new HookSystemImpl(),
    })
    await handler({ cron: EVERY_15, scheduledTime: 0 }, {})
    expect(calls).toBe(1)
  })

  it('is a no-op when disabled (mirrors disableAll)', async () => {
    let ran = false
    const plugin: CronablePlugin = {
      name: 'p',
      crons: [{ schedule: EVERY_15, hookFamily: 'f' }],
      onCronTick: () => void (ran = true),
    }
    const handler = createScheduledHandler({
      plugins: [plugin],
      getHooks: () => new HookSystemImpl(),
      disabled: true,
    })
    const result = await handler({ cron: EVERY_15, scheduledTime: 0 }, {})
    expect(ran).toBe(false)
    expect(result.invoked).toEqual([])
  })
})
