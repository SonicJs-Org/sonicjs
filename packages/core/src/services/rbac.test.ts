import { describe, expect, it, vi } from 'vitest'
import { RbacService } from './rbac'

function createDbWithGrantRows(rows: Array<{ resource: string; verb: string; scope?: string }>) {
  const all = vi.fn().mockResolvedValue({ results: rows })
  const bind = vi.fn().mockReturnValue({ all })
  const prepare = vi.fn().mockReturnValue({ bind })
  return { db: { prepare } as any, prepare, bind, all }
}

describe('RbacService permission scopes', () => {
  it('returns none when no grant matches', async () => {
    const { db } = createDbWithGrantRows([{ resource: 'media', verb: 'read', scope: 'any' }])
    const rbac = new RbacService(db)

    await expect(rbac.getPermissionScope('user-1', 'content', 'update')).resolves.toBe('none')
    await expect(rbac.can('user-1', 'content', 'update')).resolves.toBe(false)
  })

  it('returns own for matching own-scoped grants', async () => {
    const { db } = createDbWithGrantRows([{ resource: 'collection:blog_posts', verb: 'update', scope: 'own' }])
    const rbac = new RbacService(db)

    await expect(rbac.getPermissionScope('user-1', 'collection:blog_posts', 'update')).resolves.toBe('own')
    await expect(rbac.can('user-1', 'collection:blog_posts', 'update')).resolves.toBe(true)
  })

  it('prefers any over own when multiple roles grant the same permission', async () => {
    const { db } = createDbWithGrantRows([
      { resource: 'content', verb: 'update', scope: 'own' },
      { resource: 'collection:*', verb: 'update', scope: 'any' },
    ])
    const rbac = new RbacService(db)

    await expect(rbac.getPermissionScope('user-1', 'collection:blog_posts', 'update')).resolves.toBe('any')
  })

  it('persists grant scopes when replacing role grants', async () => {
    const statements: any[] = []
    const prepare = vi.fn((sql: string) => ({
      bind: vi.fn((...params: unknown[]) => {
        const stmt = { sql, params }
        statements.push(stmt)
        return stmt
      }),
    }))
    const batch = vi.fn().mockResolvedValue([])
    const rbac = new RbacService({ prepare, batch } as any)

    await rbac.setRoleGrants('role-author', [
      { resource: 'collection:blog_posts', verb: 'update', scope: 'own' },
      { resource: 'collection:blog_posts', verb: 'read', scope: 'any' },
    ])

    expect(batch).toHaveBeenCalledOnce()
    expect(statements.map((stmt) => stmt.params)).toEqual([
      ['role-author'],
      ['role-author', 'collection:blog_posts', 'update', 'own'],
      ['role-author', 'collection:blog_posts', 'read', 'any'],
    ])
  })
})

/**
 * Wildcard + `manage` matching semantics. `grantMatches` is private, so these
 * exercise it through the public `getPermissionScope`/`can` surface — which is
 * also where a regression would actually bite. This is the security-critical
 * core of the engine: a too-broad match here is a privilege-escalation bug.
 */
describe('RbacService grant matching — wildcards and manage', () => {
  describe('resource matching', () => {
    it("'*' resource grant matches every resource (system and collection)", async () => {
      const { db } = createDbWithGrantRows([{ resource: '*', verb: 'read', scope: 'any' }])
      const rbac = new RbacService(db)

      await expect(rbac.can('u', 'settings', 'read')).resolves.toBe(true)
      await expect(rbac.can('u', 'content', 'read')).resolves.toBe(true)
      await expect(rbac.can('u', 'collection:blog_posts', 'read')).resolves.toBe(true)
    })

    it("'collection:*' matches any collection resource but NOT system resources", async () => {
      const { db } = createDbWithGrantRows([{ resource: 'collection:*', verb: 'read', scope: 'any' }])
      const rbac = new RbacService(db)

      await expect(rbac.can('u', 'collection:blog_posts', 'read')).resolves.toBe(true)
      await expect(rbac.can('u', 'collection:news', 'read')).resolves.toBe(true)
      // System resources must not be covered by the collection wildcard.
      await expect(rbac.can('u', 'content', 'read')).resolves.toBe(false)
      await expect(rbac.can('u', 'settings', 'read')).resolves.toBe(false)
      await expect(rbac.can('u', 'collections', 'read')).resolves.toBe(false)
    })

    it('an exact resource grant matches only that resource', async () => {
      const { db } = createDbWithGrantRows([{ resource: 'content', verb: 'read', scope: 'any' }])
      const rbac = new RbacService(db)

      await expect(rbac.can('u', 'content', 'read')).resolves.toBe(true)
      await expect(rbac.can('u', 'media', 'read')).resolves.toBe(false)
      await expect(rbac.can('u', 'collection:blog_posts', 'read')).resolves.toBe(false)
    })

    it("does not treat a system resource name as a collection prefix", async () => {
      // Guard against a substring/startsWith mismatch: 'collections' (system)
      // must not be matched by a 'collection:*' grant.
      const { db } = createDbWithGrantRows([{ resource: 'collection:*', verb: 'manage', scope: 'any' }])
      const rbac = new RbacService(db)

      await expect(rbac.can('u', 'collections', 'manage')).resolves.toBe(false)
    })
  })

  describe('verb matching', () => {
    it("'*' verb grant matches every verb on that resource", async () => {
      const { db } = createDbWithGrantRows([{ resource: 'content', verb: '*', scope: 'any' }])
      const rbac = new RbacService(db)

      for (const verb of ['read', 'create', 'update', 'delete', 'publish']) {
        await expect(rbac.can('u', 'content', verb)).resolves.toBe(true)
      }
    })

    it("'manage' verb implies every verb on that resource", async () => {
      const { db } = createDbWithGrantRows([{ resource: 'content', verb: 'manage', scope: 'any' }])
      const rbac = new RbacService(db)

      await expect(rbac.can('u', 'content', 'read')).resolves.toBe(true)
      await expect(rbac.can('u', 'content', 'delete')).resolves.toBe(true)
      await expect(rbac.can('u', 'content', 'anything-custom')).resolves.toBe(true)
    })

    it('an exact verb grant does not leak to other verbs', async () => {
      const { db } = createDbWithGrantRows([{ resource: 'content', verb: 'read', scope: 'any' }])
      const rbac = new RbacService(db)

      await expect(rbac.can('u', 'content', 'read')).resolves.toBe(true)
      await expect(rbac.can('u', 'content', 'update')).resolves.toBe(false)
      await expect(rbac.can('u', 'content', 'delete')).resolves.toBe(false)
    })
  })

  describe('admin-style full wildcard', () => {
    it("'*:manage' grants every verb on every resource", async () => {
      const { db } = createDbWithGrantRows([{ resource: '*', verb: 'manage', scope: 'any' }])
      const rbac = new RbacService(db)

      await expect(rbac.can('u', 'portal', 'access')).resolves.toBe(true)
      await expect(rbac.can('u', 'settings', 'delete')).resolves.toBe(true)
      await expect(rbac.can('u', 'collection:blog_posts', 'publish')).resolves.toBe(true)
      await expect(rbac.getPermissionScope('u', 'rbac', 'manage')).resolves.toBe('any')
    })
  })

  describe('scope is preserved through wildcard matches', () => {
    it('an own-scoped wildcard grant resolves to own, not any', async () => {
      const { db } = createDbWithGrantRows([{ resource: 'collection:*', verb: 'update', scope: 'own' }])
      const rbac = new RbacService(db)

      await expect(rbac.getPermissionScope('u', 'collection:blog_posts', 'update')).resolves.toBe('own')
    })

    it("treats a missing scope column as 'any' (legacy grants default open)", async () => {
      // COALESCE(scope,'any') in the query means a NULL/absent scope is 'any'.
      const { db } = createDbWithGrantRows([{ resource: 'content', verb: 'read' }])
      const rbac = new RbacService(db)

      await expect(rbac.getPermissionScope('u', 'content', 'read')).resolves.toBe('any')
    })
  })

  describe('no grants', () => {
    it("a user with no matching grants has scope 'none' and can() false", async () => {
      const { db } = createDbWithGrantRows([])
      const rbac = new RbacService(db)

      await expect(rbac.getPermissionScope('u', 'content', 'read')).resolves.toBe('none')
      await expect(rbac.can('u', 'content', 'read')).resolves.toBe(false)
    })
  })
})

/**
 * Computed resources: system set + one `collection:<name>` per active
 * collection + the `collection:*` wildcard row. Regressions here mean new
 * collections silently get no permission rows in the matrix.
 */
describe('RbacService.getResources', () => {
  it('returns system resources plus a row per active collection and a collection:* row', async () => {
    const all = vi.fn().mockResolvedValue({
      results: [
        { name: 'blog_posts', display_name: 'Blog Posts' },
        { name: 'news', display_name: '' },
      ],
    })
    const db = { prepare: vi.fn().mockReturnValue({ all }) } as any
    const resources = await new RbacService(db).getResources()
    const byKey = new Map(resources.map((r) => [r.key, r]))

    // System resources are always present.
    expect(byKey.has('*')).toBe(true)
    expect(byKey.get('*')!.group).toBe('system')
    expect(byKey.has('portal')).toBe(true)
    expect(byKey.has('content')).toBe(true)

    // The collection wildcard plus one row per active collection.
    expect(byKey.get('collection:*')).toMatchObject({ label: 'All collections', group: 'collection' })
    expect(byKey.get('collection:blog_posts')).toMatchObject({ label: 'Blog Posts', group: 'collection' })
    // Falls back to the raw name when display_name is empty.
    expect(byKey.get('collection:news')).toMatchObject({ label: 'news', group: 'collection' })
  })
})

/**
 * Mutation safety: id slugging and the system-role/verb protection that keeps
 * a misfired delete from removing built-in roles enforcement depends on.
 */
describe('RbacService mutations — slugging and system protection', () => {
  function captureDb() {
    const statements: Array<{ sql: string; params: unknown[] }> = []
    const prepare = vi.fn((sql: string) => ({
      bind: vi.fn((...params: unknown[]) => {
        const stmt = { sql, params, run: vi.fn().mockResolvedValue({}) }
        statements.push(stmt)
        return stmt
      }),
    }))
    return { db: { prepare } as any, statements }
  }

  it('createRole slugs the name and stores it as a non-system role', async () => {
    const { db, statements } = captureDb()
    await new RbacService(db).createRole('Content Moderator', 'Content Moderator')

    const insert = statements.find((s) => s.sql.includes('INSERT INTO rbac_roles'))!
    expect(insert.params[0]).toBe('role-content-moderator') // id slug
    expect(insert.params[1]).toBe('content moderator') // name lowercased
    // is_system is a SQL literal in the VALUES clause, not a bound param.
    expect(insert.sql).toMatch(/is_system\)\s*VALUES\s*\(\?,\s*\?,\s*\?,\s*\?,\s*0\)/)
  })

  it('createVerb slugs the verb name and marks it non-system', async () => {
    const { db, statements } = captureDb()
    await new RbacService(db).createVerb('Publish Now')

    const insert = statements.find((s) => s.sql.includes('INSERT INTO rbac_verbs'))!
    expect(insert.params[0]).toBe('verb-publish-now')
    expect(insert.params[1]).toBe('publish now')
    // is_system (0) is a SQL literal in the VALUES clause, not a bound param.
    expect(insert.sql).toMatch(/is_system,\s*sort_order\)\s*VALUES\s*\(\?,\s*\?,\s*\?,\s*0,\s*100\)/)
  })

  it('deleteRole only deletes non-system roles (guarded in SQL)', async () => {
    const { db, statements } = captureDb()
    await new RbacService(db).deleteRole('role-admin')

    const del = statements.find((s) => s.sql.includes('DELETE FROM rbac_roles'))!
    expect(del.sql).toContain('is_system = 0')
  })

  it('deleteVerb only deletes non-system verbs (guarded in SQL)', async () => {
    const { db, statements } = captureDb()
    await new RbacService(db).deleteVerb('verb-read')

    const del = statements.find((s) => s.sql.includes('DELETE FROM rbac_verbs'))!
    expect(del.sql).toContain('is_system = 0')
  })
})
