/**
 * Tests for the email-reconciliation cron plugin and EmailService.reconcileDelivery.
 */
import { describe, it, expect, afterEach } from 'vitest'
import { emailReconciliationPlugin } from '../../plugins/core-plugins/email-reconciliation'
import { EmailService } from '../../services/email/email-service'
import { makeMockEmailProvider, makeMockD1Database } from '../utils/mock-factories'
import { resetHookSystem, setHookSystem } from '../../plugins/hooks/hook-system-singleton'
import { HookSystemImpl } from '../../plugins/hook-system'
import { PluginBuilder } from '../../plugins/sdk/plugin-builder'
import type { EmailLogRow } from '../../services/email/types'

afterEach(() => {
  resetHookSystem()
})

describe('emailReconciliationPlugin (definePlugin output)', () => {
  it('is a valid DefinedPlugin with the expected metadata', () => {
    expect(emailReconciliationPlugin.id).toBe('email-reconciliation')
    expect(emailReconciliationPlugin.version).toMatch(/^\d+\.\d+\.\d+/)
    expect(emailReconciliationPlugin.__sonicV3).toBe(true)
  })

  it('declares email:send and db:email_log capabilities', () => {
    expect(emailReconciliationPlugin.capabilities).toContain('email:send')
    expect(emailReconciliationPlugin.capabilities).toContain('db:email_log')
  })

  it('declares exactly one cron with the expected schedule', () => {
    expect(emailReconciliationPlugin.crons).toHaveLength(1)
    expect(emailReconciliationPlugin.crons![0]!.schedule).toBe('0 * * * *')
    expect(emailReconciliationPlugin.crons![0]!.hookFamily).toBe('email-reconciliation')
  })

  it('has an onCronTick handler', () => {
    expect(typeof emailReconciliationPlugin.onCronTick).toBe('function')
  })

  it('onCronTick is a no-op for unknown hook families', async () => {
    const hs = new HookSystemImpl()
    setHookSystem(hs)
    // Should not throw for an unrelated hookFamily
    await expect(
      emailReconciliationPlugin.onCronTick!(
        { cron: '0 * * * *', scheduledTime: 0, hookFamily: 'other-family' },
        { hooks: hs, env: {} }
      )
    ).resolves.toBeUndefined()
  })
})

describe('EmailService.reconcileDelivery', () => {
  function makeService(providerOverrides = {}) {
    const provider = { ...makeMockEmailProvider(), ...providerOverrides }
    const db = makeMockD1Database()
    return new EmailService({ provider, defaultFrom: 'noreply@test.com', db: db as any })
  }

  it('returns empty array when provider does not implement reconcile()', async () => {
    const service = makeService() // makeMockEmailProvider has no reconcile()
    const result = await service.reconcileDelivery([{ id: 'r1', provider: 'mock', status: 'sent' }])
    expect(result).toEqual([])
  })

  it('calls provider.reconcile() and returns its result', async () => {
    const rows: EmailLogRow[] = [
      { id: 'r1', provider: 'cf', status: 'sent', provider_id: 'cf-msg-1' },
    ]
    const service = makeService({
      reconcile: async (_rows: EmailLogRow[]) => [{ id: 'r1', delivery_state: 'delivered' }],
    })
    const result = await service.reconcileDelivery(rows)
    expect(result).toEqual([{ id: 'r1', delivery_state: 'delivered' }])
  })

  it('returns empty array and logs error when provider.reconcile() throws', async () => {
    const service = makeService({
      reconcile: async () => { throw new Error('network error') },
    })
    const result = await service.reconcileDelivery([{ id: 'r1', provider: 'cf', status: 'sent' }])
    expect(result).toEqual([])
  })
})

describe('PluginBuilder.build() v3 compat fields', () => {
  it('build() adds id equal to name', () => {
    const plugin = PluginBuilder.create({ name: 'my-plugin', version: '1.0.0' }).build()
    expect((plugin as any).id).toBe('my-plugin')
  })

  it('build() leaves capabilities undefined (exempt from capability gate)', () => {
    const plugin = PluginBuilder.create({ name: 'my-plugin', version: '1.0.0' }).build()
    expect((plugin as any).capabilities).toBeUndefined()
  })

  it('build() does not override explicitly set capabilities', () => {
    const plugin = PluginBuilder.create({ name: 'x', version: '1.0.0' }).build()
    ;(plugin as any).capabilities = ['email:send']
    expect((plugin as any).capabilities).toEqual(['email:send'])
  })
})
