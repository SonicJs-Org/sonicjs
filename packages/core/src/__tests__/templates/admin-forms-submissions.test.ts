import { describe, it, expect } from 'vitest'
import {
  renderFormSubmissionsPage,
  type FormSubmissionRow,
} from '../../templates/pages/admin-forms-submissions.template'

const form = { id: 'contact', display_name: 'Contact Form' }

function submission(overrides: Partial<FormSubmissionRow> = {}): FormSubmissionRow {
  return {
    id: 'sub-1',
    submission_number: 1,
    submission_data: JSON.stringify({ name: 'Ada', message: 'hello' }),
    status: 'pending',
    submitted_at: 1760000000000,
    ...overrides,
  }
}

describe('renderFormSubmissionsPage', () => {
  it('renders inside the admin layout with heading and count', () => {
    const html = renderFormSubmissionsPage({ form, submissions: [submission()] })
    expect(html).toContain('<!DOCTYPE html>')
    expect(html).toContain('Submissions: Contact Form')
    expect(html).toContain('Total submissions: 1')
    expect(html).toContain('Back to Forms')
    expect(html).toContain('Ada')
    expect(html).toContain('hello')
  })

  it('escapes HTML in submission data, keys and the form name (stored-XSS prevention)', () => {
    const html = renderFormSubmissionsPage({
      form: { id: 'f', display_name: '<img src=x onerror="alert(1)">' },
      submissions: [
        submission({
          submission_data: JSON.stringify({
            '<b>key</b>': '<script>alert(1)</script>',
            note: '"quoted" & <tag>',
          }),
        }),
      ],
    })
    expect(html).not.toContain('<script>alert(1)</script>')
    expect(html).not.toContain('<img src=x onerror=')
    expect(html).not.toContain('<b>key</b>')
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;')
  })

  it('falls back to escaped raw text when submission_data is not valid JSON', () => {
    const html = renderFormSubmissionsPage({
      form,
      submissions: [submission({ submission_data: '<not json>' })],
    })
    expect(html).toContain('&lt;not json&gt;')
    expect(html).not.toContain('<not json>')
  })

  it('renders an empty state when there are no submissions', () => {
    const html = renderFormSubmissionsPage({ form, submissions: [] })
    expect(html).toContain('Total submissions: 0')
    expect(html).toContain('No submissions yet.')
  })
})
