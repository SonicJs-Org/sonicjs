import { describe, it, expect, vi } from 'vitest'

// The real layout lazily `require()`s the catalyst layout, which the ESM test runner cannot
// resolve. Only the page body matters here.
vi.mock('../../templates/layouts/admin-layout-v2.template', () => ({
  renderAdminLayout: (data: { content: string }) => data.content,
}))

import {
  renderPluginSettingsPage,
  type PluginSettingsPageData,
} from '../../templates/pages/admin-plugin-settings.template'

/**
 * The user-profiles plugin stores no user-editable settings — its fields are a code-defined
 * model. The Settings tab is normally gated on "has at least one non-underscore settings key",
 * which hid the panel documenting defineUserProfile() entirely. These lock that gate open.
 */
function pageData(overrides: Partial<PluginSettingsPageData['plugin']> = {}): PluginSettingsPageData {
  return {
    plugin: {
      id: 'user-profiles',
      name: 'user-profiles',
      displayName: 'User Profiles',
      description: 'Custom profile fields for users',
      version: '1.0.0',
      author: 'SonicJS',
      status: 'active',
      category: 'users',
      icon: '👤',
      lastUpdated: '2026-01-01',
      settings: {},
      ...overrides,
    },
    user: { name: 'Admin', email: 'admin@sonicjs.com', role: 'admin' },
  }
}

describe('admin plugin settings page — user-profiles', () => {
  it('renders the Settings tab even though the plugin stores no settings keys', () => {
    const html = renderPluginSettingsPage(pageData())

    expect(html).toContain('id="settings-tab"')
    expect(html).toContain('defineUserProfile')
    expect(html).toContain('my-sonicjs-app/src/index.ts')
  })

  it('reports the unconfigured state when defineUserProfile() has not run', () => {
    const html = renderPluginSettingsPage(pageData({ profileConfig: null }))

    expect(html).toContain('No profile fields defined yet')
    expect(html).not.toContain('Configured Fields')
  })

  it('lists the declared fields once defineUserProfile() has run', () => {
    const html = renderPluginSettingsPage(
      pageData({
        profileConfig: {
          fields: [
            { name: 'company', label: 'Company', type: 'text', required: false },
            { name: 'jobTitle', label: 'Job Title', type: 'text', required: true },
          ],
          registrationFields: ['company'],
        },
      }),
    )

    expect(html).toContain('Configured Fields')
    expect(html).toContain('company')
    expect(html).toContain('jobTitle')
    expect(html).not.toContain('No profile fields defined yet')
  })

  it('still hides the Settings tab for an ordinary plugin with no settings', () => {
    const html = renderPluginSettingsPage(
      pageData({ id: 'some-other-plugin', name: 'some-other-plugin', settings: {} }),
    )

    expect(html).not.toContain('id="settings-tab"')
  })
})
