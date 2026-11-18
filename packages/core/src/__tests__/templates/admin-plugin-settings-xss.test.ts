import { describe, it, expect, vi } from 'vitest'

// The real layout lazily `require()`s the catalyst layout, which the ESM test runner cannot
// resolve. Only the page body matters here.
vi.mock('../../templates/layouts/admin-layout-v2.template', () => ({
  renderAdminLayout: (data: { content: string }) => data.content,
}))

import { renderPluginSettingsPage } from '../../templates/pages/admin-plugin-settings.template'
import { PLUGIN_REGISTRY } from '../../plugins/manifest-registry'

const ATTR_BREAKOUT = `"><script>alert(1)</script>`

describe('plugin settings', () => {
  // Settings values are `any`, seeded verbatim from a manifest's `defaultSettings`. The
  // generic string branch escapes them, so it must tolerate the non-string values that
  // real manifests actually ship — otherwise the detail page 500s instead of rendering.
  const basePlugin = {
    id: 'ai-search',
    name: 'ai-search',
    displayName: 'AI Search',
    description: 'x',
    version: '1.0.0',
    author: 'SonicJS',
    status: 'active' as const,
    category: 'content',
    icon: '🔍',
    lastUpdated: '',
  }

  it('escapes a string setting value in the value attribute', () => {
    const html = renderPluginSettingsPage({
      plugin: { ...basePlugin, settings: { api_endpoint: `ep-${ATTR_BREAKOUT}` } },
    })

    expect(html).not.toContain(ATTR_BREAKOUT)
    // this file escapes `'` as &#39; rather than &#039;, so assert on its own encoding
    expect(html).toContain('&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;')
  })

  it('renders non-string setting values without throwing', () => {
    // The real ai-search manifest ships two empty arrays.
    const aiSearchDefaults = (PLUGIN_REGISTRY['ai-search'] as { defaultSettings?: Record<string, unknown> })
      .defaultSettings
    expect(aiSearchDefaults).toBeDefined()

    expect(() =>
      renderPluginSettingsPage({ plugin: { ...basePlugin, settings: aiSearchDefaults } })
    ).not.toThrow()

    // Covers the remaining shapes a manifest can hand us.
    expect(() =>
      renderPluginSettingsPage({
        plugin: {
          ...basePlugin,
          settings: {
            an_object: { providers: { google: { enabled: false } } },
            an_array: ['a', 'b'],
            a_null: null,
            an_undefined: undefined,
          },
        },
      })
    ).not.toThrow()
  })
})
