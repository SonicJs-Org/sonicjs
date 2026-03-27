import { describe, expect, it } from 'vitest'
import type { QueryFilter } from '../../utils/query-filter'
import { normalizePublicContentFilter } from '../../routes/api-content-access-policy'

describe('normalizePublicContentFilter', () => {
  it('forces published status for anonymous requests without a status filter', () => {
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'collection_id', operator: 'equals', value: 'pages-collection' }
        ]
      }
    }

    const result = normalizePublicContentFilter(filter)

    expect(result.where?.and).toEqual([
      { field: 'collection_id', operator: 'equals', value: 'pages-collection' },
      { field: 'status', operator: 'equals', value: 'published' }
    ])
  })

  it('strips anonymous status filters from both and/or groups before forcing published', () => {
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'status', operator: 'equals', value: 'draft' },
          { field: 'title', operator: 'contains', value: 'roadmap' }
        ],
        or: [
          { field: 'status', operator: 'not_equals', value: 'published' },
          { field: 'slug', operator: 'contains', value: 'docs' }
        ]
      }
    }

    const result = normalizePublicContentFilter(filter)

    expect(result.where?.and).toEqual([
      { field: 'title', operator: 'contains', value: 'roadmap' },
      { field: 'status', operator: 'equals', value: 'published' }
    ])
    expect(result.where?.or).toEqual([
      { field: 'slug', operator: 'contains', value: 'docs' }
    ])
  })

  it('preserves admin status filters', () => {
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'status', operator: 'equals', value: 'draft' }
        ]
      }
    }

    const result = normalizePublicContentFilter(filter, 'admin')

    expect(result).toBe(filter)
    expect(result.where?.and).toEqual([
      { field: 'status', operator: 'equals', value: 'draft' }
    ])
  })

  it('forces published status for viewer and author roles', () => {
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'status', operator: 'equals', value: 'draft' }
        ]
      }
    }

    expect(normalizePublicContentFilter(filter, 'viewer').where?.and).toEqual([
      { field: 'status', operator: 'equals', value: 'published' }
    ])

    expect(normalizePublicContentFilter(filter, 'author').where?.and).toEqual([
      { field: 'status', operator: 'equals', value: 'published' }
    ])
  })
})
