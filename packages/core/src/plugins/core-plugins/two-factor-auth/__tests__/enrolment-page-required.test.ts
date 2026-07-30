/**
 * How the enrolment page renders under `auth_user.two_factor_required`.
 *
 * The flag drives TWO different conditions and conflating them is the easy mistake:
 *   - `required && !verified` → the amber "set up to continue" banner
 *   - `required`              → the disable form is replaced by an explanation
 *
 * A user who has satisfied the requirement is `required && verified`: no banner (they owe
 * nothing), but still no disable form (they may not turn it off).
 */
import { describe, it, expect } from 'vitest'
import { renderTwoFactorEnrolmentPage } from '../components/enrolment-page'

const BANNER = 'Set up two-factor to continue'
const LOCKED = 'Required by an administrator'
const DISABLE_FORM = 'id="disableForm"'

function render(over: Partial<Parameters<typeof renderTwoFactorEnrolmentPage>[0]> = {}) {
  return renderTwoFactorEnrolmentPage({ verified: false, pending: false, ...over })
}

describe('enrolment page under a two-factor requirement', () => {
  it('offers the disable form on an ordinary enrolled account', () => {
    const html = render({ verified: true })
    expect(html).toContain(DISABLE_FORM)
    expect(html).not.toContain(LOCKED)
    expect(html).not.toContain(BANNER)
  })

  it('replaces the disable form with an explanation once 2FA is required', () => {
    const html = render({ verified: true, required: true })
    expect(html).not.toContain(DISABLE_FORM)
    expect(html).toContain(LOCKED)
  })

  it('shows no banner to a required user who HAS enrolled — they owe nothing', () => {
    // Getting this wrong would tell someone with a working second factor that they need to set
    // one up, on every page load, forever.
    expect(render({ verified: true, required: true })).not.toContain(BANNER)
  })

  it('shows the banner to a required user who has NOT enrolled', () => {
    const html = render({ verified: false, required: true })
    expect(html).toContain(BANNER)
    expect(html).toContain('An administrator reset the two-factor authentication on your account')
  })

  it('never renders the banner without the flag, whatever the enrolment state', () => {
    expect(render({ verified: false })).not.toContain(BANNER)
    expect(render({ verified: false, pending: true })).not.toContain(BANNER)
    expect(render({ verified: true })).not.toContain(BANNER)
  })

  it('guards the disable binding so the script survives the form being absent', () => {
    // One IIFE holds the enrol, verify and disable handlers. An unguarded
    // `$('disableForm').addEventListener` throws on null when the form is replaced, taking
    // enrolment down with it — for exactly the users who are being forced to enrol.
    const html = render({ verified: true, required: true })
    expect(html).toContain("if ($('disableForm'))")
  })
})
