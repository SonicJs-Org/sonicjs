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
