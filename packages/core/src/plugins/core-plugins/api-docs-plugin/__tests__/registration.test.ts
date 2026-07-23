import { describe, it, expect } from 'vitest'
import { createSonicJSApp } from '../../../../app'
import { apiDocsPlugin } from '../index'

/**
 * Boot-wiring regression: the plugin must be mounted into the REAL assembled
 * app (not just unit-mountable), and its manifest must keep it active-by-default.
 */
describe('api-docs plugin registration', () => {
  it('mounts /admin/plugins/api-docs into the assembled app', () => {
    const app = createSonicJSApp()
    const mounted = app.routes.some((r) => r.path.startsWith('/admin/plugins/api-docs'))
    expect(mounted).toBe(true)
  })

  it('declares the definePlugin contract (id, register, menu)', () => {
    expect(apiDocsPlugin.id).toBe('api-docs')
    expect(typeof apiDocsPlugin.register).toBe('function')
    expect(apiDocsPlugin.menu?.[0]?.path).toBe('/admin/plugins/api-docs')
  })
})
