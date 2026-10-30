import { describe, expect, it } from 'vitest'
import { renderUserNewPage } from '../../templates/pages/admin-user-new.template'

describe('New user role default', () => {
  it('selects Public even when Admin appears first', () => {
    const html = renderUserNewPage({
      roles: [
        { value: 'role-admin', label: 'Admin' },
        { value: 'role-public', label: 'Public' },
        { value: 'role-editor', label: 'Editor' },
      ],
      user: { name: 'Admin', email: 'admin@example.com', role: 'role-admin' },
    })

    expect(html).toContain('<option value="role-public" selected>Public</option>')
    expect(html).toContain('<option value="role-admin">Admin</option>')
    expect(html).toContain('<option value="role-editor">Editor</option>')
  })

  it('preserves available options when Public is absent', () => {
    const html = renderUserNewPage({
      roles: [{ value: 'role-custom', label: 'Custom' }],
    })

    expect(html).toContain('<option value="role-custom">Custom</option>')
    expect(html).not.toContain('<option value="role-public"')
  })
})
