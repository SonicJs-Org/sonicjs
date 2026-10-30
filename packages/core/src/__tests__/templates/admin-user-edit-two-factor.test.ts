/**
 * The Two-Factor Recovery panel on the user edit page.
 *
 * The panel drives a break-glass endpoint that removes someone else's second factor, so the user
 * id it carries must survive the template intact and must never become executable text.
 */
import { describe, it, expect } from 'vitest'
import {
  renderUserEditPage,
  type UserEditData,
  type UserEditPageData,
} from '../../templates/pages/admin-user-edit.template'

function render(overrides: Partial<UserEditData> = {}): string {
  const userToEdit: UserEditData = {
    id: 'user-1',
    email: 'target@test.local',
    firstName: 'T',
    lastName: 'U',
    role: 'editor',
    isActive: true,
    emailVerified: true,
    twoFactorEnabled: true,
    twoFactorRequired: false,
    createdAt: 0,
    ...overrides,
  }
  const data: UserEditPageData = { userToEdit, roles: [{ value: 'editor', label: 'Editor' }] }
  return renderUserEditPage(data)
}

describe('Two-Factor Recovery panel', () => {
  it('passes the user id through a data attribute, not through the handler source', () => {
    const html = render()
    expect(html).toContain('data-user-id="user-1"')
    expect(html).toContain('onclick="resetTwoFactor(this.dataset.userId)"')
  })

  it('cannot be escaped by an id containing a quote', () => {
    // escapeHtml renders ' as &#039;, which the HTML parser decodes back to a bare quote BEFORE
    // the JS parser sees the attribute — so `resetTwoFactor('${id}')` would have executed it.
    const html = render({ id: "u1');alert(1);//" })

    // The payload survives only as escaped text inside a quoted attribute — never as an argument
    // the JS parser reads.
    expect(html).not.toContain("resetTwoFactor('")
    expect(html).toContain('data-user-id="u1&#039;);alert(1);//"')
    expect(html).toContain('onclick="resetTwoFactor(this.dataset.userId)"')
  })

  it('shows the reset action for an enrolled user and for one who owes an enrolment', () => {
    expect(render({ twoFactorEnabled: true, twoFactorRequired: false })).toContain(
      'id="tf-reset-button"',
    )
    expect(render({ twoFactorEnabled: false, twoFactorRequired: true })).toContain(
      'id="tf-reset-button"',
    )
  })

  it('offers no reset for a user who has no second factor and owes none', () => {
    const html = render({ twoFactorEnabled: false, twoFactorRequired: false })
    expect(html).not.toContain('id="tf-reset-button"')
    expect(html).toContain('Not enrolled')
  })
})
