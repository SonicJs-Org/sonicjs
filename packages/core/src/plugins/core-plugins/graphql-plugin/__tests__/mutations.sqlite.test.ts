// @ts-nocheck
// GraphQL createDocument goes through the same ACL as the other mutations and never reaches internal types.
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createTestD1 } from '../../../../__tests__/utils/d1-sqlite'
import { bootstrapDocumentTypes, autoRegisterCollectionDocumentTypes } from '../../../../services/document-types-seed'
import { getCollectionRegistry, resetCollectionRegistry } from '../../../../services/collection-registry'
import { resolveCreateDocument } from '../resolvers/mutations'

const ctxFor = (db: any, role: string) => ({
  db,
  tenantId: 'default',
  userId: `${role}-user`,
  principalSet: [{ type: 'user', id: `${role}-user` }, { type: 'role', id: role }],
})

describe('graphql createDocument', () => {
  let db: any
  const count = (type: string) => db.raw.prepare('SELECT COUNT(*) n FROM documents WHERE type_id=?').get(type).n

  beforeEach(async () => {
    db = createTestD1()
    getCollectionRegistry().register([
      { name: 'notes', displayName: 'Notes', description: '', schema: { type: 'object', properties: {} }, access: { author: ['read', 'create'] } },
    ])
    await bootstrapDocumentTypes(db)
    await autoRegisterCollectionDocumentTypes(db)
  })
  afterEach(() => { db.close(); resetCollectionRegistry() })

  it('needs the create grant', async () => {
    await expect(resolveCreateDocument({ typeId: 'notes', title: 'v', data: {} }, ctxFor(db, 'viewer'))).rejects.toThrow(/Not allowed/)
    expect(count('notes')).toBe(0)
    const doc = await resolveCreateDocument({ typeId: 'notes', title: 'a', data: {} }, ctxFor(db, 'author'))
    expect(doc.typeId).toBe('notes')
  })

  it('publishOnCreate also needs publish', async () => {
    await expect(resolveCreateDocument({ typeId: 'notes', title: 'p', data: {}, publishOnCreate: true }, ctxFor(db, 'author'))).rejects.toThrow(/publish/)
    expect(count('notes')).toBe(0)
    await resolveCreateDocument({ typeId: 'notes', title: 'p', data: {}, publishOnCreate: true }, ctxFor(db, 'admin'))
    expect(count('notes')).toBe(1)
  })

  it('internal types are refused, even for admin', async () => {
    for (const typeId of ['rbac_user_roles', 'site_settings']) {
      const before = count(typeId)
      await expect(resolveCreateDocument({ typeId, slug: 'x', data: { roleIds: ['role-admin'] } }, ctxFor(db, 'admin'))).rejects.toThrow(/Not allowed/)
      expect(count(typeId)).toBe(before)
    }
  })
})
