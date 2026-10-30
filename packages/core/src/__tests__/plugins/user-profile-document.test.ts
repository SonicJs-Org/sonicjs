// User profile document store — real SQLite (exercises the actual migrations,
// the unique-slug invariant, and DocumentsService batch writes).
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createTestD1 } from '../utils/d1-sqlite'
import { readProfileData, writeProfileData, USER_PROFILE_TYPE_ID } from '../../plugins/core-plugins/user-profiles/user-profile-document'

describe('user-profile-document store', () => {
  let db: any
  beforeEach(() => {
    db = createTestD1()
    db.raw
      .prepare(
        `INSERT INTO document_types (id,name,display_name,schema,queryable_fields,settings,source,schema_version,is_system,is_active,is_auth,created_at,updated_at)
         VALUES (?, ?, 'User Profile','{}','[]','{}','system',1,0,1,1,1,1)`,
      )
      .bind(USER_PROFILE_TYPE_ID, USER_PROFILE_TYPE_ID)
      .run()
  })
  afterEach(() => db.close())

  it('creates a profile document on first write and reads it back', async () => {
    await writeProfileData(db, 'user-1', { displayName: 'Jane', company: 'Acme', custom: { plan: 'free' } })

    const p = await readProfileData(db, 'user-1')
    expect(p.displayName).toBe('Jane')
    expect(p.company).toBe('Acme')
    expect(p.custom).toEqual({ plan: 'free' })

    // Addressed by slug = userId, marked auth-owned via the type.
    const row = db.raw.prepare(`SELECT slug, owner_id FROM documents WHERE type_id=? AND slug='user-1'`).get(USER_PROFILE_TYPE_ID)
    expect(row.slug).toBe('user-1')
    expect(row.owner_id).toBe('user-1')
  })

  it('merges typed fields and the custom namespace across writes', async () => {
    await writeProfileData(db, 'user-1', { displayName: 'Jane', custom: { plan: 'free', theme: 'dark' } })
    await writeProfileData(db, 'user-1', { bio: 'hello', custom: { plan: 'monthly' } })

    const p = await readProfileData(db, 'user-1')
    expect(p.displayName).toBe('Jane')      // preserved
    expect(p.bio).toBe('hello')             // added
    expect(p.custom).toEqual({ plan: 'monthly', theme: 'dark' }) // shallow-merged
  })

  it('keeps exactly one current-draft profile per user (unique slug invariant)', async () => {
    await writeProfileData(db, 'user-1', { displayName: 'A' })
    await writeProfileData(db, 'user-1', { displayName: 'B' })
    await writeProfileData(db, 'user-1', { displayName: 'C' })

    const cnt = db.raw
      .prepare(`SELECT COUNT(*) n FROM documents WHERE type_id=? AND slug='user-1' AND is_current_draft=1 AND deleted_at IS NULL`)
      .get(USER_PROFILE_TYPE_ID)
    expect(cnt.n).toBe(1)
    expect((await readProfileData(db, 'user-1')).displayName).toBe('C')
  })

  it('returns an empty profile when none exists', async () => {
    expect(await readProfileData(db, 'nobody')).toEqual({ custom: {} })
  })
})
