/**
 * Form-Collection Sync Service Tests
 */

import { describe, it, expect, beforeEach, vi } from 'vitest'
import {
  deriveCollectionSchemaFromFormio,
  deriveSubmissionTitle,
  mapFormStatusToContentStatus,
  syncFormCollection,
  syncAllFormCollections,
  createContentFromSubmission,
  backfillFormSubmissions
} from './form-collection-sync'

// Mock crypto.randomUUID for deterministic IDs
vi.stubGlobal('crypto', {
  randomUUID: vi.fn(() => 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')
})

// Mock D1Database following the same pattern as collection-sync.test.ts
function createMockDb() {
  const mockFirst = vi.fn()
  const mockAll = vi.fn()
  const mockRun = vi.fn()

  const chainable = {
    bind: vi.fn().mockReturnThis(),
    first: mockFirst,
    all: mockAll,
    run: mockRun
  }

  const mockPrepare = vi.fn().mockReturnValue(chainable)

  return {
    prepare: mockPrepare,
    _mocks: {
      prepare: mockPrepare,
      bind: chainable.bind,
      first: mockFirst,
      all: mockAll,
      run: mockRun
    }
  }
}

// ── deriveCollectionSchemaFromFormio ──────────────────────────────────

describe('deriveCollectionSchemaFromFormio', () => {
  it('should always include a title field', () => {
    const schema = deriveCollectionSchemaFromFormio({})
    expect(schema.properties.title).toEqual({ type: 'string', title: 'Title', required: true })
    expect(schema.required).toContain('title')
  })

  it('should handle null/undefined formio schema', () => {
    expect(deriveCollectionSchemaFromFormio(null)).toEqual({
      type: 'object',
      properties: { title: { type: 'string', title: 'Title', required: true } },
      required: ['title']
    })
    expect(deriveCollectionSchemaFromFormio(undefined)).toEqual({
      type: 'object',
      properties: { title: { type: 'string', title: 'Title', required: true } },
      required: ['title']
    })
  })

  it('should map textfield components to string type', () => {
    const schema = deriveCollectionSchemaFromFormio({
      components: [{ type: 'textfield', key: 'firstName', label: 'First Name' }]
    })
    expect(schema.properties.firstName).toEqual({ type: 'string', title: 'First Name' })
  })

  it('should map textarea, password, phoneNumber, url to string type', () => {
    const schema = deriveCollectionSchemaFromFormio({
      components: [
        { type: 'textarea', key: 'bio', label: 'Bio' },
        { type: 'password', key: 'secret', label: 'Secret' },
        { type: 'phoneNumber', key: 'phone', label: 'Phone' },
        { type: 'url', key: 'website', label: 'Website' }
      ]
    })
    for (const key of ['bio', 'secret', 'phone', 'website']) {
      expect(schema.properties[key].type).toBe('string')
    }
  })

  it('should map email to string with format email', () => {
    const schema = deriveCollectionSchemaFromFormio({
      components: [{ type: 'email', key: 'email', label: 'Email' }]
    })
    expect(schema.properties.email).toEqual({ type: 'string', format: 'email', title: 'Email' })
  })

  it('should map number and currency to number type', () => {
    const schema = deriveCollectionSchemaFromFormio({
      components: [
        { type: 'number', key: 'age', label: 'Age' },
        { type: 'currency', key: 'price', label: 'Price' }
      ]
    })
    expect(schema.properties.age.type).toBe('number')
    expect(schema.properties.price.type).toBe('number')
  })

  it('should map checkbox to boolean type', () => {
    const schema = deriveCollectionSchemaFromFormio({
      components: [{ type: 'checkbox', key: 'agree', label: 'I Agree' }]
    })
    expect(schema.properties.agree).toEqual({ type: 'boolean', title: 'I Agree' })
  })

  it('should map select with enum values', () => {
    const schema = deriveCollectionSchemaFromFormio({
      components: [{
        type: 'select', key: 'color', label: 'Color',
        data: { values: [{ value: 'red', label: 'Red' }, { value: 'blue', label: 'Blue' }] }
      }]
    })
    expect(schema.properties.color).toEqual({
      type: 'select', title: 'Color',
      enum: ['red', 'blue'], enumLabels: ['Red', 'Blue']
    })
  })

  it('should map radio with top-level values', () => {
    const schema = deriveCollectionSchemaFromFormio({
      components: [{
        type: 'radio', key: 'size', label: 'Size',
        values: [{ value: 's', label: 'Small' }, { value: 'l', label: 'Large' }]
      }]
    })
    expect(schema.properties.size.type).toBe('select')
    expect(schema.properties.size.enum).toEqual(['s', 'l'])
  })

  it('should map selectboxes to object type', () => {
    const schema = deriveCollectionSchemaFromFormio({
      components: [{ type: 'selectboxes', key: 'hobbies', label: 'Hobbies' }]
    })
    expect(schema.properties.hobbies).toEqual({ type: 'object', title: 'Hobbies' })
  })

  it('should map datetime/day/time to string with date-time format', () => {
    const schema = deriveCollectionSchemaFromFormio({
      components: [
        { type: 'datetime', key: 'startDate', label: 'Start' },
        { type: 'day', key: 'birthday', label: 'Birthday' },
        { type: 'time', key: 'meetingTime', label: 'Time' }
      ]
    })
    for (const key of ['startDate', 'birthday', 'meetingTime']) {
      expect(schema.properties[key].format).toBe('date-time')
    }
  })

  it('should map file and signature to string type', () => {
    const schema = deriveCollectionSchemaFromFormio({
      components: [
        { type: 'file', key: 'resume', label: 'Resume' },
        { type: 'signature', key: 'sig', label: 'Signature' }
      ]
    })
    expect(schema.properties.resume.type).toBe('string')
    expect(schema.properties.sig.type).toBe('string')
  })

  it('should map address to object type', () => {
    const schema = deriveCollectionSchemaFromFormio({
      components: [{ type: 'address', key: 'addr', label: 'Address' }]
    })
    expect(schema.properties.addr).toEqual({ type: 'object', title: 'Address' })
  })

  it('should map hidden to string type', () => {
    const schema = deriveCollectionSchemaFromFormio({
      components: [{ type: 'hidden', key: 'ref', label: 'Ref' }]
    })
    expect(schema.properties.ref.type).toBe('string')
  })

  it('should default unknown types to string', () => {
    const schema = deriveCollectionSchemaFromFormio({
      components: [{ type: 'custom-widget', key: 'thing', label: 'Thing' }]
    })
    expect(schema.properties.thing.type).toBe('string')
  })

  it('should use key as fallback when label is missing', () => {
    const schema = deriveCollectionSchemaFromFormio({
      components: [{ type: 'textfield', key: 'myField' }]
    })
    expect(schema.properties.myField.title).toBe('myField')
  })

  it('should mark required fields', () => {
    const schema = deriveCollectionSchemaFromFormio({
      components: [
        { type: 'textfield', key: 'name', label: 'Name', validate: { required: true } },
        { type: 'email', key: 'email', label: 'Email' }
      ]
    })
    expect(schema.properties.name.required).toBe(true)
    expect(schema.required).toContain('name')
    expect(schema.properties.email.required).toBeUndefined()
    expect(schema.required).not.toContain('email')
  })

  it('should skip submit buttons', () => {
    const schema = deriveCollectionSchemaFromFormio({
      components: [
        { type: 'textfield', key: 'name', label: 'Name' },
        { type: 'button', key: 'submit', label: 'Submit' }
      ]
    })
    expect(schema.properties.submit).toBeUndefined()
  })

  it('should skip components with key "submit" or "title"', () => {
    const schema = deriveCollectionSchemaFromFormio({
      components: [
        { type: 'textfield', key: 'submit', label: 'Submit Field' },
        { type: 'textfield', key: 'title', label: 'Title Field' }
      ]
    })
    // title is always present as the default one, not from components
    expect(Object.keys(schema.properties)).toEqual(['title'])
  })

  it('should skip turnstile components', () => {
    const schema = deriveCollectionSchemaFromFormio({
      components: [
        { type: 'textfield', key: 'name', label: 'Name' },
        { type: 'turnstile', key: 'captcha' }
      ]
    })
    expect(schema.properties.captcha).toBeUndefined()
  })

  it('should skip htmlelement and content components', () => {
    const schema = deriveCollectionSchemaFromFormio({
      components: [
        { type: 'htmlelement', key: 'intro', tag: 'p' },
        { type: 'content', key: 'notice' },
        { type: 'textfield', key: 'name', label: 'Name' }
      ]
    })
    expect(schema.properties.intro).toBeUndefined()
    expect(schema.properties.notice).toBeUndefined()
    expect(schema.properties.name).toBeDefined()
  })

  // extractFieldComponents — tested indirectly through deriveCollectionSchemaFromFormio

  it('should extract fields from panel layout components', () => {
    const schema = deriveCollectionSchemaFromFormio({
      components: [{
        type: 'panel', key: 'panel1',
        components: [{ type: 'textfield', key: 'innerField', label: 'Inner' }]
      }]
    })
    expect(schema.properties.innerField).toBeDefined()
    expect(schema.properties.panel1).toBeUndefined()
  })

  it('should extract fields from fieldset and well components', () => {
    const schema = deriveCollectionSchemaFromFormio({
      components: [
        { type: 'fieldset', components: [{ type: 'textfield', key: 'a', label: 'A' }] },
        { type: 'well', components: [{ type: 'textfield', key: 'b', label: 'B' }] }
      ]
    })
    expect(schema.properties.a).toBeDefined()
    expect(schema.properties.b).toBeDefined()
  })

  it('should extract fields from tabs layout', () => {
    const schema = deriveCollectionSchemaFromFormio({
      components: [{
        type: 'tabs',
        components: [{ type: 'email', key: 'contact', label: 'Contact' }]
      }]
    })
    expect(schema.properties.contact).toBeDefined()
  })

  it('should extract fields from columns layout', () => {
    const schema = deriveCollectionSchemaFromFormio({
      components: [{
        type: 'columns',
        columns: [
          { components: [{ type: 'textfield', key: 'left', label: 'Left' }] },
          { components: [{ type: 'textfield', key: 'right', label: 'Right' }] }
        ]
      }]
    })
    expect(schema.properties.left).toBeDefined()
    expect(schema.properties.right).toBeDefined()
  })

  it('should extract fields from table layout', () => {
    const schema = deriveCollectionSchemaFromFormio({
      components: [{
        type: 'table',
        rows: [
          [
            { components: [{ type: 'textfield', key: 'cell1', label: 'Cell 1' }] },
            { components: [{ type: 'number', key: 'cell2', label: 'Cell 2' }] }
          ]
        ]
      }]
    })
    expect(schema.properties.cell1).toBeDefined()
    expect(schema.properties.cell2.type).toBe('number')
  })

  it('should handle deeply nested layouts', () => {
    const schema = deriveCollectionSchemaFromFormio({
      components: [{
        type: 'panel',
        components: [{
          type: 'columns',
          columns: [{
            components: [{
              type: 'fieldset',
              components: [{ type: 'textfield', key: 'deep', label: 'Deep' }]
            }]
          }]
        }]
      }]
    })
    expect(schema.properties.deep).toBeDefined()
  })

  it('should skip components without a key', () => {
    const schema = deriveCollectionSchemaFromFormio({
      components: [
        { type: 'textfield', label: 'No Key' },
        { type: 'textfield', key: 'hasKey', label: 'Has Key' }
      ]
    })
    expect(schema.properties.hasKey).toBeDefined()
    // Only title and hasKey
    expect(Object.keys(schema.properties)).toEqual(['title', 'hasKey'])
  })
})

// ── deriveSubmissionTitle ────────────────────────────────────────────

describe('deriveSubmissionTitle', () => {
  it('should use name field when present', () => {
    expect(deriveSubmissionTitle({ name: 'John Doe' }, 'Contact')).toBe('John Doe')
  })

  it('should use fullName field', () => {
    expect(deriveSubmissionTitle({ fullName: 'Jane Smith' }, 'Contact')).toBe('Jane Smith')
  })

  it('should use full_name field', () => {
    expect(deriveSubmissionTitle({ full_name: 'Bob Jones' }, 'Contact')).toBe('Bob Jones')
  })

  it('should combine firstName and lastName', () => {
    expect(deriveSubmissionTitle({ firstName: 'Alice', lastName: 'Wonder' }, 'Contact')).toBe('Alice Wonder')
  })

  it('should combine first_name and last_name', () => {
    expect(deriveSubmissionTitle({ first_name: 'Charlie', last_name: 'Brown' }, 'Contact')).toBe('Charlie Brown')
  })

  it('should use firstName alone when no lastName', () => {
    expect(deriveSubmissionTitle({ firstName: 'Solo' }, 'Contact')).toBe('Solo')
  })

  it('should try lowercase lastname variant', () => {
    expect(deriveSubmissionTitle({ firstName: 'Ada', lastname: 'Lovelace' }, 'Contact')).toBe('Ada Lovelace')
  })

  it('should fall back to email when no name fields', () => {
    expect(deriveSubmissionTitle({ email: 'test@example.com' }, 'Contact')).toBe('test@example.com')
  })

  it('should fall back to subject when no name or email', () => {
    expect(deriveSubmissionTitle({ subject: 'Help needed' }, 'Contact')).toBe('Help needed')
  })

  it('should fall back to form display name + date', () => {
    const result = deriveSubmissionTitle({ randomField: 'value' }, 'Contact Form')
    expect(result).toMatch(/^Contact Form - /)
  })

  it('should trim whitespace from name fields', () => {
    expect(deriveSubmissionTitle({ name: '  John  ' }, 'Contact')).toBe('John')
  })

  it('should skip empty string name fields', () => {
    expect(deriveSubmissionTitle({ name: '', email: 'a@b.com' }, 'Contact')).toBe('a@b.com')
  })

  it('should skip whitespace-only name fields', () => {
    expect(deriveSubmissionTitle({ name: '   ', email: 'a@b.com' }, 'Contact')).toBe('a@b.com')
  })

  it('should skip non-string name values', () => {
    expect(deriveSubmissionTitle({ name: 123, email: 'a@b.com' }, 'Contact')).toBe('a@b.com')
  })

  it('should prefer name over email', () => {
    expect(deriveSubmissionTitle({ name: 'Alice', email: 'alice@test.com' }, 'Contact')).toBe('Alice')
  })
})

// ── mapFormStatusToContentStatus ─────────────────────────────────────

describe('mapFormStatusToContentStatus', () => {
  it('should map pending to published', () => {
    expect(mapFormStatusToContentStatus('pending')).toBe('published')
  })

  it('should map reviewed to published', () => {
    expect(mapFormStatusToContentStatus('reviewed')).toBe('published')
  })

  it('should map approved to published', () => {
    expect(mapFormStatusToContentStatus('approved')).toBe('published')
  })

  it('should map rejected to archived', () => {
    expect(mapFormStatusToContentStatus('rejected')).toBe('archived')
  })

  it('should map spam to deleted', () => {
    expect(mapFormStatusToContentStatus('spam')).toBe('deleted')
  })

  it('should default unknown statuses to published', () => {
    expect(mapFormStatusToContentStatus('unknown')).toBe('published')
    expect(mapFormStatusToContentStatus('')).toBe('published')
  })
})

// ── syncFormCollection ───────────────────────────────────────────────

describe('syncFormCollection', () => {
  let mockDb: ReturnType<typeof createMockDb>

  const baseForm = {
    id: 'form-123',
    name: 'contact',
    display_name: 'Contact Us',
    description: 'A contact form',
    formio_schema: { components: [{ type: 'textfield', key: 'name', label: 'Name' }] },
    is_active: 1
  }

  beforeEach(() => {
    mockDb = createMockDb()
    vi.clearAllMocks()
    vi.spyOn(console, 'log').mockImplementation(() => {})
  })

  it('should create a new shadow collection when none exists', async () => {
    mockDb._mocks.first.mockResolvedValue(null)
    mockDb._mocks.run.mockResolvedValue({ success: true })

    const result = await syncFormCollection(mockDb as any, baseForm)

    expect(result.status).toBe('created')
    expect(result.collectionId).toMatch(/^col-form-contact-/)
    expect(mockDb._mocks.prepare).toHaveBeenCalledWith(expect.stringContaining('INSERT INTO collections'))
  })

  it('should return unchanged when schema and metadata match', async () => {
    const schema = deriveCollectionSchemaFromFormio(baseForm.formio_schema)
    mockDb._mocks.first.mockResolvedValue({
      id: 'col-form-contact-abc12345',
      schema: JSON.stringify(schema),
      display_name: 'Contact Us (Form)',
      description: 'A contact form',
      is_active: 1
    })

    const result = await syncFormCollection(mockDb as any, baseForm)

    expect(result.status).toBe('unchanged')
    expect(result.collectionId).toBe('col-form-contact-abc12345')
  })

  it('should update when schema differs', async () => {
    mockDb._mocks.first.mockResolvedValue({
      id: 'col-form-contact-abc12345',
      schema: JSON.stringify({ type: 'object', properties: {}, required: [] }),
      display_name: 'Contact Us (Form)',
      description: 'A contact form',
      is_active: 1
    })
    mockDb._mocks.run.mockResolvedValue({ success: true })

    const result = await syncFormCollection(mockDb as any, baseForm)

    expect(result.status).toBe('updated')
    expect(mockDb._mocks.prepare).toHaveBeenCalledWith(expect.stringContaining('UPDATE collections'))
  })

  it('should update when display_name differs', async () => {
    const schema = deriveCollectionSchemaFromFormio(baseForm.formio_schema)
    mockDb._mocks.first.mockResolvedValue({
      id: 'col-form-contact-abc12345',
      schema: JSON.stringify(schema),
      display_name: 'Old Name (Form)',
      description: 'A contact form',
      is_active: 1
    })
    mockDb._mocks.run.mockResolvedValue({ success: true })

    const result = await syncFormCollection(mockDb as any, baseForm)

    expect(result.status).toBe('updated')
  })

  it('should update when description differs', async () => {
    const schema = deriveCollectionSchemaFromFormio(baseForm.formio_schema)
    mockDb._mocks.first.mockResolvedValue({
      id: 'col-form-contact-abc12345',
      schema: JSON.stringify(schema),
      display_name: 'Contact Us (Form)',
      description: 'Old description',
      is_active: 1
    })
    mockDb._mocks.run.mockResolvedValue({ success: true })

    const result = await syncFormCollection(mockDb as any, baseForm)

    expect(result.status).toBe('updated')
  })

  it('should update when is_active differs', async () => {
    const schema = deriveCollectionSchemaFromFormio(baseForm.formio_schema)
    mockDb._mocks.first.mockResolvedValue({
      id: 'col-form-contact-abc12345',
      schema: JSON.stringify(schema),
      display_name: 'Contact Us (Form)',
      description: 'A contact form',
      is_active: 0
    })
    mockDb._mocks.run.mockResolvedValue({ success: true })

    const result = await syncFormCollection(mockDb as any, baseForm)

    expect(result.status).toBe('updated')
  })

  it('should parse string formio_schema', async () => {
    mockDb._mocks.first.mockResolvedValue(null)
    mockDb._mocks.run.mockResolvedValue({ success: true })

    const form = { ...baseForm, formio_schema: JSON.stringify(baseForm.formio_schema) }
    const result = await syncFormCollection(mockDb as any, form)

    expect(result.status).toBe('created')
  })

  it('should set is_active to 0 when form is inactive', async () => {
    mockDb._mocks.first.mockResolvedValue(null)
    mockDb._mocks.run.mockResolvedValue({ success: true })

    const form = { ...baseForm, is_active: 0 as number | boolean }
    const result = await syncFormCollection(mockDb as any, form)

    expect(result.status).toBe('created')
    // Verify is_active was passed as 0
    expect(mockDb._mocks.bind).toHaveBeenCalledWith(
      expect.any(String), // collectionId
      'form_contact',     // name
      'Contact Us (Form)', // display_name
      'A contact form',   // description
      expect.any(String), // schema
      0,                  // is_active
      'form-123',         // source_id
      expect.any(Number), // created_at
      expect.any(Number)  // updated_at
    )
  })

  it('should handle null description', async () => {
    mockDb._mocks.first.mockResolvedValue(null)
    mockDb._mocks.run.mockResolvedValue({ success: true })

    const form = { ...baseForm, description: null }
    const result = await syncFormCollection(mockDb as any, form)

    expect(result.status).toBe('created')
  })

  it('should handle existing schema as object (not string)', async () => {
    const schema = deriveCollectionSchemaFromFormio(baseForm.formio_schema)
    mockDb._mocks.first.mockResolvedValue({
      id: 'col-form-contact-abc12345',
      schema, // Object, not string
      display_name: 'Contact Us (Form)',
      description: 'A contact form',
      is_active: 1
    })

    const result = await syncFormCollection(mockDb as any, baseForm)

    expect(result.status).toBe('unchanged')
  })

  it('should handle existing with null schema', async () => {
    mockDb._mocks.first.mockResolvedValue({
      id: 'col-form-contact-abc12345',
      schema: null,
      display_name: 'Contact Us (Form)',
      description: 'A contact form',
      is_active: 1
    })
    mockDb._mocks.run.mockResolvedValue({ success: true })

    const result = await syncFormCollection(mockDb as any, baseForm)

    // Schema went from '{}' to actual schema => should update
    expect(result.status).toBe('updated')
  })
})

// ── syncAllFormCollections ───────────────────────────────────────────

describe('syncAllFormCollections', () => {
  let mockDb: ReturnType<typeof createMockDb>

  beforeEach(() => {
    mockDb = createMockDb()
    vi.clearAllMocks()
    vi.spyOn(console, 'log').mockImplementation(() => {})
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  it('should skip when forms table does not exist', async () => {
    mockDb._mocks.first.mockResolvedValue(null) // sqlite_master check

    await syncAllFormCollections(mockDb as any)

    expect(console.log).toHaveBeenCalledWith('[FormSync] Forms table does not exist, skipping form sync')
  })

  it('should skip when no forms found', async () => {
    mockDb._mocks.first.mockResolvedValue({ name: 'forms' }) // table exists
    mockDb._mocks.all.mockResolvedValue({ results: [] })

    await syncAllFormCollections(mockDb as any)

    expect(console.log).toHaveBeenCalledWith('[FormSync] No forms found, skipping')
  })

  it('should skip when forms results is null', async () => {
    mockDb._mocks.first.mockResolvedValue({ name: 'forms' })
    mockDb._mocks.all.mockResolvedValue({ results: null })

    await syncAllFormCollections(mockDb as any)

    expect(console.log).toHaveBeenCalledWith('[FormSync] No forms found, skipping')
  })

  it('should sync forms and log summary', async () => {
    // First call: sqlite_master check
    mockDb._mocks.first.mockResolvedValueOnce({ name: 'forms' })
    // all() returns forms list
    mockDb._mocks.all
      .mockResolvedValueOnce({
        results: [{
          id: 'form-1', name: 'contact', display_name: 'Contact',
          description: null, formio_schema: '{"components":[]}', is_active: 1
        }]
      })
      // backfillFormSubmissions: submissions query returns empty
      .mockResolvedValueOnce({ results: [] })
    // syncFormCollection: no existing collection
    mockDb._mocks.first.mockResolvedValueOnce(null)
    mockDb._mocks.run.mockResolvedValue({ success: true })

    await syncAllFormCollections(mockDb as any)

    expect(console.log).toHaveBeenCalledWith(expect.stringContaining('1 created'))
  })

  it('should continue syncing when one form errors', async () => {
    mockDb._mocks.first.mockResolvedValueOnce({ name: 'forms' })
    mockDb._mocks.all.mockResolvedValueOnce({
      results: [
        { id: 'form-1', name: 'bad', display_name: 'Bad', formio_schema: 'INVALID JSON', is_active: 1 },
        { id: 'form-2', name: 'good', display_name: 'Good', description: null, formio_schema: '{"components":[]}', is_active: 1 }
      ]
    })
    // For form-2: no existing collection, then backfill returns empty
    mockDb._mocks.first.mockResolvedValueOnce(null)
    mockDb._mocks.run.mockResolvedValue({ success: true })
    mockDb._mocks.all.mockResolvedValueOnce({ results: [] })

    await syncAllFormCollections(mockDb as any)

    expect(console.error).toHaveBeenCalledWith(
      expect.stringContaining('Error syncing form bad'),
      expect.anything()
    )
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining('1 created'))
  })

  it('should handle top-level error gracefully', async () => {
    mockDb._mocks.first.mockRejectedValue(new Error('DB down'))

    await syncAllFormCollections(mockDb as any)

    expect(console.error).toHaveBeenCalledWith(
      '[FormSync] Error syncing form collections:',
      expect.any(Error)
    )
  })
})

// ── createContentFromSubmission ──────────────────────────────────────

describe('createContentFromSubmission', () => {
  let mockDb: ReturnType<typeof createMockDb>

  const testForm = { id: 'form-1', name: 'contact', display_name: 'Contact Us' }

  beforeEach(() => {
    mockDb = createMockDb()
    vi.clearAllMocks()
    vi.spyOn(console, 'log').mockImplementation(() => {})
    vi.spyOn(console, 'warn').mockImplementation(() => {})
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  it('should create content when shadow collection exists', async () => {
    // First query: find collection
    mockDb._mocks.first
      .mockResolvedValueOnce({ id: 'col-form-contact-abc' }) // collection lookup
      .mockResolvedValueOnce({ id: 'system-form-submission' }) // system user exists
    mockDb._mocks.run.mockResolvedValue({ success: true })

    const contentId = await createContentFromSubmission(
      mockDb as any,
      { name: 'John', email: 'john@test.com' },
      testForm,
      'sub-12345678-abcd'
    )

    expect(contentId).toBe('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')
    expect(mockDb._mocks.prepare).toHaveBeenCalledWith(expect.stringContaining('INSERT INTO content'))
    expect(mockDb._mocks.prepare).toHaveBeenCalledWith(expect.stringContaining('UPDATE form_submissions'))
  })

  it('should create system user when it does not exist', async () => {
    mockDb._mocks.first
      .mockResolvedValueOnce({ id: 'col-form-contact-abc' }) // collection
      .mockResolvedValueOnce(null) // system user missing
    mockDb._mocks.run.mockResolvedValue({ success: true })

    await createContentFromSubmission(
      mockDb as any,
      { name: 'Test' },
      testForm,
      'sub-12345678'
    )

    expect(mockDb._mocks.prepare).toHaveBeenCalledWith(expect.stringContaining('INSERT OR IGNORE INTO users'))
  })

  it('should use provided userId instead of system user', async () => {
    mockDb._mocks.first.mockResolvedValueOnce({ id: 'col-form-contact-abc' })
    mockDb._mocks.run.mockResolvedValue({ success: true })

    await createContentFromSubmission(
      mockDb as any,
      { name: 'Test' },
      testForm,
      'sub-12345678',
      { userId: 'user-real-123' }
    )

    // Should not check for system user
    expect(mockDb._mocks.prepare).not.toHaveBeenCalledWith('SELECT id FROM users WHERE id = ?')
  })

  it('should attempt on-the-fly collection creation when missing', async () => {
    mockDb._mocks.first
      .mockResolvedValueOnce(null) // collection not found
      .mockResolvedValueOnce({     // form lookup for on-the-fly sync
        id: 'form-1', name: 'contact', display_name: 'Contact Us',
        description: null, formio_schema: '{"components":[]}', is_active: 1
      })
      .mockResolvedValueOnce(null) // syncFormCollection: no existing collection
      .mockResolvedValueOnce({ id: 'col-form-contact-new' }) // re-query after sync
      .mockResolvedValueOnce({ id: 'system-form-submission' }) // system user
    mockDb._mocks.run.mockResolvedValue({ success: true })

    const contentId = await createContentFromSubmission(
      mockDb as any,
      { email: 'test@test.com' },
      testForm,
      'sub-12345678'
    )

    expect(contentId).toBe('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')
    expect(console.warn).toHaveBeenCalledWith(expect.stringContaining('No shadow collection found'))
  })

  it('should return null when collection cannot be found or created', async () => {
    mockDb._mocks.first
      .mockResolvedValueOnce(null) // collection not found
      .mockResolvedValueOnce(null) // form not found either
    mockDb._mocks.run.mockResolvedValue({ success: true })

    const contentId = await createContentFromSubmission(
      mockDb as any,
      { name: 'Test' },
      testForm,
      'sub-12345678'
    )

    expect(contentId).toBeNull()
    expect(console.error).toHaveBeenCalledWith(
      expect.stringContaining('Still no shadow collection')
    )
  })

  it('should return null when on-the-fly sync throws', async () => {
    mockDb._mocks.first
      .mockResolvedValueOnce(null)  // collection not found
      .mockRejectedValueOnce(new Error('sync failed')) // form lookup throws
    mockDb._mocks.run.mockResolvedValue({ success: true })

    const contentId = await createContentFromSubmission(
      mockDb as any,
      { name: 'Test' },
      testForm,
      'sub-12345678'
    )

    expect(contentId).toBeNull()
  })

  it('should embed submission metadata in content data', async () => {
    mockDb._mocks.first
      .mockResolvedValueOnce({ id: 'col-form-contact-abc' })
      .mockResolvedValueOnce({ id: 'system-form-submission' })
    mockDb._mocks.run.mockResolvedValue({ success: true })

    await createContentFromSubmission(
      mockDb as any,
      { name: 'Alice', message: 'Hello' },
      testForm,
      'sub-12345678',
      { ipAddress: '1.2.3.4', userAgent: 'Mozilla/5.0', userEmail: 'alice@test.com' }
    )

    // The 4th bind arg to the INSERT INTO content call is the JSON data
    const insertCall = mockDb._mocks.bind.mock.calls.find(
      (args: any[]) => typeof args[4] === 'string' && args[4].includes('_submission_metadata')
    )
    expect(insertCall).toBeDefined()
    const contentData = JSON.parse(insertCall![4])
    expect(contentData._submission_metadata.ipAddress).toBe('1.2.3.4')
    expect(contentData._submission_metadata.email).toBe('alice@test.com')
    expect(contentData._submission_metadata.formId).toBe('form-1')
  })

  it('should generate slug from submission ID', async () => {
    mockDb._mocks.first
      .mockResolvedValueOnce({ id: 'col-form-contact-abc' })
      .mockResolvedValueOnce({ id: 'system-form-submission' })
    mockDb._mocks.run.mockResolvedValue({ success: true })

    await createContentFromSubmission(
      mockDb as any,
      { name: 'Test' },
      testForm,
      'abcdefgh-1234-5678'
    )

    // slug should be submission-abcdefgh
    const insertCall = mockDb._mocks.bind.mock.calls.find(
      (args: any[]) => typeof args[2] === 'string' && args[2].startsWith('submission-')
    )
    expect(insertCall).toBeDefined()
    expect(insertCall![2]).toBe('submission-abcdefgh')
  })

  it('should return null and log on unexpected error', async () => {
    mockDb._mocks.first.mockRejectedValue(new Error('Unexpected'))

    const contentId = await createContentFromSubmission(
      mockDb as any,
      { name: 'Test' },
      testForm,
      'sub-12345678'
    )

    expect(contentId).toBeNull()
    expect(console.error).toHaveBeenCalledWith(
      '[FormSync] Error creating content from submission:',
      expect.any(Error)
    )
  })
})

// ── backfillFormSubmissions ──────────────────────────────────────────

describe('backfillFormSubmissions', () => {
  let mockDb: ReturnType<typeof createMockDb>

  beforeEach(() => {
    mockDb = createMockDb()
    vi.clearAllMocks()
    vi.spyOn(console, 'log').mockImplementation(() => {})
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  it('should return 0 when no submissions need backfill', async () => {
    mockDb._mocks.all.mockResolvedValue({ results: [] })

    const count = await backfillFormSubmissions(mockDb as any, 'form-1', 'col-1')

    expect(count).toBe(0)
  })

  it('should return 0 when results is null', async () => {
    mockDb._mocks.all.mockResolvedValue({ results: null })

    const count = await backfillFormSubmissions(mockDb as any, 'form-1', 'col-1')

    expect(count).toBe(0)
  })

  it('should return 0 when form not found', async () => {
    mockDb._mocks.all.mockResolvedValue({
      results: [{ id: 'sub-1', submission_data: '{}' }]
    })
    mockDb._mocks.first.mockResolvedValue(null) // form not found

    const count = await backfillFormSubmissions(mockDb as any, 'form-1', 'col-1')

    expect(count).toBe(0)
  })

  it('should backfill submissions and return count', async () => {
    mockDb._mocks.all.mockResolvedValueOnce({
      results: [
        { id: 'sub-1', submission_data: '{"name":"Alice"}', user_email: 'a@b.com', ip_address: null, user_agent: null, user_id: null },
        { id: 'sub-2', submission_data: '{"name":"Bob"}', user_email: null, ip_address: null, user_agent: null, user_id: null }
      ]
    })
    // form lookup
    mockDb._mocks.first
      .mockResolvedValueOnce({ id: 'form-1', name: 'contact', display_name: 'Contact' })
      // createContentFromSubmission calls: collection lookup, system user check (x2 for each submission)
      .mockResolvedValueOnce({ id: 'col-1' }) // collection for sub-1
      .mockResolvedValueOnce({ id: 'system-form-submission' }) // system user for sub-1
      .mockResolvedValueOnce({ id: 'col-1' }) // collection for sub-2
      .mockResolvedValueOnce({ id: 'system-form-submission' }) // system user for sub-2
    mockDb._mocks.run.mockResolvedValue({ success: true })

    const count = await backfillFormSubmissions(mockDb as any, 'form-1', 'col-1')

    expect(count).toBe(2)
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining('Backfilled 2 submissions'))
  })

  it('should handle submission_data as object (not string)', async () => {
    mockDb._mocks.all.mockResolvedValueOnce({
      results: [
        { id: 'sub-1', submission_data: { name: 'Direct Object' }, user_email: null, ip_address: null, user_agent: null, user_id: null }
      ]
    })
    mockDb._mocks.first
      .mockResolvedValueOnce({ id: 'form-1', name: 'contact', display_name: 'Contact' })
      .mockResolvedValueOnce({ id: 'col-1' })
      .mockResolvedValueOnce({ id: 'system-form-submission' })
    mockDb._mocks.run.mockResolvedValue({ success: true })

    const count = await backfillFormSubmissions(mockDb as any, 'form-1', 'col-1')

    expect(count).toBe(1)
  })

  it('should continue when individual submission errors', async () => {
    mockDb._mocks.all.mockResolvedValueOnce({
      results: [
        { id: 'sub-bad', submission_data: 'NOT VALID JSON', user_email: null, ip_address: null, user_agent: null, user_id: null },
        { id: 'sub-good', submission_data: '{"name":"OK"}', user_email: null, ip_address: null, user_agent: null, user_id: null }
      ]
    })
    mockDb._mocks.first
      .mockResolvedValueOnce({ id: 'form-1', name: 'contact', display_name: 'Contact' })
      // sub-good succeeds
      .mockResolvedValueOnce({ id: 'col-1' })
      .mockResolvedValueOnce({ id: 'system-form-submission' })
    mockDb._mocks.run.mockResolvedValue({ success: true })

    const count = await backfillFormSubmissions(mockDb as any, 'form-1', 'col-1')

    // sub-bad errors, sub-good succeeds
    expect(count).toBe(1)
    expect(console.error).toHaveBeenCalledWith(
      expect.stringContaining('Error backfilling submission sub-bad'),
      expect.anything()
    )
  })

  it('should return 0 and log on top-level error', async () => {
    mockDb._mocks.all.mockRejectedValue(new Error('DB error'))

    const count = await backfillFormSubmissions(mockDb as any, 'form-1', 'col-1')

    expect(count).toBe(0)
    expect(console.error).toHaveBeenCalledWith(
      '[FormSync] Error backfilling submissions:',
      expect.any(Error)
    )
  })
})
