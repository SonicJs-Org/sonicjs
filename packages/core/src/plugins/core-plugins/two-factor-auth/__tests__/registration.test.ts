/**
 * Plugin registration shape, and the two id/path facts that are silent when wrong.
 */
import { describe, it, expect } from 'vitest'
import { twoFactorAuthPlugin, createTwoFactorAuthPlugin } from '../index'
import manifest from '../manifest.json'
import { TWO_FACTOR_PLUGIN_ID } from '../../../../auth/two-factor-settings'
import { CORE_PLUGIN_IDS } from '../../index'
import { PLUGIN_REGISTRY } from '../../../manifest-registry'

describe('two-factor-auth plugin registration', () => {
  it('is a v3 definePlugin', () => {
    expect(twoFactorAuthPlugin.__sonicV3).toBe(true)
    expect(createTwoFactorAuthPlugin()).toBe(twoFactorAuthPlugin)
  })

  it('uses one id everywhere — code, manifest, registry, core list', () => {
    // `isPluginActive()` and the plugin-settings document both key off this exact string, so a
    // divergence leaves the surface permanently 404 with nothing in the logs.
    expect(twoFactorAuthPlugin.id).toBe('two-factor-auth')
    expect(TWO_FACTOR_PLUGIN_ID).toBe('two-factor-auth')
    expect(manifest.id).toBe('two-factor-auth')
    expect(PLUGIN_REGISTRY['two-factor-auth']?.id).toBe('two-factor-auth')
    expect(CORE_PLUGIN_IDS).toContain('two-factor-auth')
  })

  it('ships active on a fresh install', () => {
    expect(PLUGIN_REGISTRY['two-factor-auth']?.is_core).toBe(true)
    expect(PLUGIN_REGISTRY['two-factor-auth']?.defaultActive).toBe(true)
  })

  it('links its sidebar entry at /admin/two-factor, not under /admin/plugins', () => {
    // /admin/plugins/two-factor would be shadowed by adminPluginRoutes, taking out both the
    // plugin-detail page and this plugin's own /configure settings form.
    expect(twoFactorAuthPlugin.menu?.[0]?.path).toBe('/admin/two-factor')
    expect(manifest.adminMenu.path).toBe('/admin/two-factor')
  })

  it('declares the policy knobs as a configSchema, so the admin form is real', () => {
    const schema = twoFactorAuthPlugin.configSchema
    expect(Object.keys(schema ?? {})).toEqual([
      'issuer',
      'maxFailedAttempts',
      'lockoutDurationSeconds',
      'backupCodeCount',
    ])
  })

  it('keeps configSchema bounds in step with the clamp in normalizeTwoFactorPolicy', () => {
    const schema = twoFactorAuthPlugin.configSchema as Record<string, { min?: number; max?: number }>
    expect(schema.maxFailedAttempts).toMatchObject({ min: 3, max: 10 })
    expect(schema.lockoutDurationSeconds).toMatchObject({ min: 300, max: 3600 })
    expect(schema.backupCodeCount).toMatchObject({ min: 5, max: 20 })
  })

  it('declares only the administrative permission — self-enrolment is not gated', () => {
    expect(Object.keys(manifest.permissions)).toEqual(['two-factor:manage'])
  })

  it('registers ONLY the enrolment surface — the challenge belongs to core', () => {
    // The plugin used to mount `/auth/two-factor` as well, which put the login challenge behind
    // `config.plugins.disableAll`. Better Auth composes `twoFactor()` unconditionally, so with
    // plugins off an enrolled user was still challenged and then redirected to a 404 — locked out
    // of an app that was still demanding their second factor. Core now mounts the challenge
    // (app.ts), and this asserts the plugin does not take it back.
    const mounted: string[] = []
    twoFactorAuthPlugin.register?.({
      route: (path: string) => {
        mounted.push(path)
      },
    } as never)
    expect(mounted).toEqual(['/admin/two-factor'])
  })
})
