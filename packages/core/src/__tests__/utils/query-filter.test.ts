import { describe, it, expect, vi } from 'vitest'
import { QueryFilterBuilder, buildQuery, validateSortOrder, type QueryFilter } from '../../utils/query-filter'

describe('QueryFilterBuilder', () => {
  it('should build basic SELECT query', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {}

    const result = builder.build('users', filter)

    expect(result.sql).toBe('SELECT * FROM users')
    expect(result.params).toEqual([])
    expect(result.errors).toEqual([])
  })

  it('should build query with equals condition', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'name', operator: 'equals', value: 'John' }
        ]
      }
    }

    const result = builder.build('users', filter)

    expect(result.sql).toBe('SELECT * FROM users WHERE (name = ?)')
    expect(result.params).toEqual(['John'])
  })

  it('should build query with multiple AND conditions', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'age', operator: 'greater_than', value: 18 },
          { field: 'status', operator: 'equals', value: 'active' }
        ]
      }
    }

    const result = builder.build('users', filter)

    expect(result.sql).toBe('SELECT * FROM users WHERE (age > ? AND status = ?)')
    expect(result.params).toEqual([18, 'active'])
  })

  it('should build query with OR conditions', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        or: [
          { field: 'role', operator: 'equals', value: 'admin' },
          { field: 'role', operator: 'equals', value: 'editor' }
        ]
      }
    }

    const result = builder.build('users', filter)

    expect(result.sql).toBe('SELECT * FROM users WHERE (role = ? OR role = ?)')
    expect(result.params).toEqual(['admin', 'editor'])
  })

  it('should support LIKE operator', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'email', operator: 'like', value: 'test user' }
        ]
      }
    }

    const result = builder.build('users', filter)

    // LIKE with multiple words creates AND conditions
    expect(result.sql).toContain('email LIKE ?')
    expect(result.params).toContain('%test%')
    expect(result.params).toContain('%user%')
  })

  it('should support contains operator', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'description', operator: 'contains', value: 'example' }
        ]
      }
    }

    const result = builder.build('posts', filter)

    expect(result.sql).toBe('SELECT * FROM posts WHERE (description LIKE ?)')
    expect(result.params).toEqual(['%example%'])
  })

  it('should support IN operator with array', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'status', operator: 'in', value: ['active', 'pending'] }
        ]
      }
    }

    const result = builder.build('users', filter)

    expect(result.sql).toBe('SELECT * FROM users WHERE (status IN (?, ?))')
    expect(result.params).toEqual(['active', 'pending'])
  })

  it('should support NOT IN operator', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'role', operator: 'not_in', value: ['admin', 'superadmin'] }
        ]
      }
    }

    const result = builder.build('users', filter)

    expect(result.sql).toBe('SELECT * FROM users WHERE (role NOT IN (?, ?))')
    expect(result.params).toEqual(['admin', 'superadmin'])
  })

  it('should handle NULL values with equals operator', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'deleted_at', operator: 'equals', value: null }
        ]
      }
    }

    const result = builder.build('users', filter)

    expect(result.sql).toBe('SELECT * FROM users WHERE (deleted_at IS NULL)')
    expect(result.params).toEqual([])
  })

  it('should handle NULL values with not_equals operator', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'email', operator: 'not_equals', value: null }
        ]
      }
    }

    const result = builder.build('users', filter)

    expect(result.sql).toBe('SELECT * FROM users WHERE (email IS NOT NULL)')
    expect(result.params).toEqual([])
  })

  it('should support exists operator', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'bio', operator: 'exists', value: true }
        ]
      }
    }

    const result = builder.build('users', filter)

    expect(result.sql).toBe('SELECT * FROM users WHERE (bio IS NOT NULL AND bio != \'\')')
  })

  it('should add ORDER BY clause', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      sort: [
        { field: 'created_at', order: 'desc' }
      ]
    }

    const result = builder.build('posts', filter)

    expect(result.sql).toBe('SELECT * FROM posts ORDER BY created_at DESC')
  })

  it('should add multiple ORDER BY clauses', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      sort: [
        { field: 'status', order: 'asc' },
        { field: 'created_at', order: 'desc' }
      ]
    }

    const result = builder.build('posts', filter)

    expect(result.sql).toBe('SELECT * FROM posts ORDER BY status ASC, created_at DESC')
  })

  it('should add LIMIT clause', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      limit: 10
    }

    const result = builder.build('users', filter)

    expect(result.sql).toBe('SELECT * FROM users LIMIT ?')
    expect(result.params).toEqual([10])
  })

  it('should add OFFSET clause', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      offset: 20
    }

    const result = builder.build('users', filter)

    expect(result.sql).toBe('SELECT * FROM users OFFSET ?')
    expect(result.params).toEqual([20])
  })

  it('should build complex query with all features', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'status', operator: 'equals', value: 'active' },
          { field: 'age', operator: 'greater_than', value: 18 }
        ]
      },
      sort: [
        { field: 'created_at', order: 'desc' }
      ],
      limit: 10,
      offset: 20
    }

    const result = builder.build('users', filter)

    expect(result.sql).toBe('SELECT * FROM users WHERE (status = ? AND age > ?) ORDER BY created_at DESC LIMIT ? OFFSET ?')
    expect(result.params).toEqual(['active', 18, 10, 20])
  })

  it('should handle offset of 0 (falsy value)', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      limit: 10,
      offset: 0
    }

    const result = builder.build('users', filter)

    // Offset 0 is falsy, so it won't be included in the query
    expect(result.sql).toBe('SELECT * FROM users LIMIT ?')
    expect(result.params).toEqual([10])
  })

  it('should report errors for unsupported operators', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'location', operator: 'near', value: [0, 0] }
        ]
      }
    }

    const result = builder.build('places', filter)

    expect(result.errors.length).toBeGreaterThan(0)
    expect(result.errors[0]).toContain('near')
  })

  it('should sanitize field names', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'user_name', operator: 'equals', value: 'test' }
        ]
      }
    }

    const result = builder.build('users', filter)

    expect(result.sql).toBe('SELECT * FROM users WHERE (user_name = ?)')
  })

  it('should handle JSON field access', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'data.title', operator: 'equals', value: 'Test' }
        ]
      }
    }

    const result = builder.build('posts', filter)

    expect(result.sql).toContain('json_extract(data, \'$.title\')')
  })
})

describe('buildQuery helper', () => {
  it('should build query using helper function', () => {
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'name', operator: 'equals', value: 'John' }
        ]
      },
      limit: 5
    }

    const result = buildQuery('users', filter)

    expect(result.sql).toBe('SELECT * FROM users WHERE (name = ?) LIMIT ?')
    expect(result.params).toEqual(['John', 5])
  })

  it('should parse filter from query string', () => {
    const query = {
      status: 'active',
      limit: '10',
      offset: '20',
      sort: JSON.stringify([{ field: 'id', order: 'asc' }])
    }

    const filter = QueryFilterBuilder.parseFromQuery(query)

    expect(filter.where?.and).toContainEqual({
      field: 'status',
      operator: 'equals',
      value: 'active'
    })
    expect(filter.limit).toBe(10)
    expect(filter.offset).toBe(20)
    expect(filter.sort).toEqual([{ field: 'id', order: 'asc' }])
  })
})

describe('QueryFilterBuilder - Additional Operators', () => {
  it('should support less_than operator', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'price', operator: 'less_than', value: 100 }
        ]
      }
    }

    const result = builder.build('products', filter)

    expect(result.sql).toBe('SELECT * FROM products WHERE (price < ?)')
    expect(result.params).toEqual([100])
  })

  it('should support less_than_equal operator', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'quantity', operator: 'less_than_equal', value: 50 }
        ]
      }
    }

    const result = builder.build('inventory', filter)

    expect(result.sql).toBe('SELECT * FROM inventory WHERE (quantity <= ?)')
    expect(result.params).toEqual([50])
  })

  it('should support greater_than_equal operator', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'score', operator: 'greater_than_equal', value: 90 }
        ]
      }
    }

    const result = builder.build('grades', filter)

    expect(result.sql).toBe('SELECT * FROM grades WHERE (score >= ?)')
    expect(result.params).toEqual([90])
  })

  it('should support not_equals with non-null value', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'status', operator: 'not_equals', value: 'archived' }
        ]
      }
    }

    const result = builder.build('posts', filter)

    expect(result.sql).toBe('SELECT * FROM posts WHERE (status != ?)')
    expect(result.params).toEqual(['archived'])
  })

  it('should support exists operator with false value', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'avatar', operator: 'exists', value: false }
        ]
      }
    }

    const result = builder.build('users', filter)

    expect(result.sql).toBe('SELECT * FROM users WHERE ((avatar IS NULL OR avatar = \'\'))')
  })

  it('should support all operator with array', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'tags', operator: 'all', value: ['tech', 'news'] }
        ]
      }
    }

    const result = builder.build('posts', filter)

    expect(result.sql).toContain('tags LIKE ?')
    expect(result.params).toContain('%tech%')
    expect(result.params).toContain('%news%')
  })

  it('should support all operator with comma-separated string', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'categories', operator: 'all', value: 'a, b, c' }
        ]
      }
    }

    const result = builder.build('articles', filter)

    expect(result.params).toContain('%a%')
    expect(result.params).toContain('%b%')
    expect(result.params).toContain('%c%')
  })

  it('should support all operator with single value', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'tag', operator: 'all', value: 42 }
        ]
      }
    }

    const result = builder.build('items', filter)

    expect(result.params).toContain('%42%')
  })

  it('should handle all operator with empty values', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'tags', operator: 'all', value: [] }
        ]
      }
    }

    const result = builder.build('posts', filter)

    expect(result.sql).toContain('1=1')
  })

  it('should report error for within operator', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'location', operator: 'within', value: { bounds: [] } }
        ]
      }
    }

    const result = builder.build('places', filter)

    expect(result.errors.length).toBeGreaterThan(0)
    expect(result.errors[0]).toContain('within')
  })

  it('should report error for intersects operator', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'area', operator: 'intersects', value: { polygon: [] } }
        ]
      }
    }

    const result = builder.build('regions', filter)

    expect(result.errors.length).toBeGreaterThan(0)
    expect(result.errors[0]).toContain('intersects')
  })

  it('should report error for unknown operator', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'data', operator: 'unknown_op' as any, value: 'test' }
        ]
      }
    }

    const result = builder.build('items', filter)

    expect(result.errors.length).toBeGreaterThan(0)
    expect(result.errors[0]).toContain('Unknown operator')
  })
})

describe('QueryFilterBuilder - IN/NOT IN Edge Cases', () => {
  it('should handle IN with comma-separated string', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'status', operator: 'in', value: 'active, pending, draft' }
        ]
      }
    }

    const result = builder.build('posts', filter)

    expect(result.sql).toBe('SELECT * FROM posts WHERE (status IN (?, ?, ?))')
    expect(result.params).toEqual(['active', 'pending', 'draft'])
  })

  it('should handle IN with single non-array value', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'id', operator: 'in', value: 123 }
        ]
      }
    }

    const result = builder.build('items', filter)

    expect(result.sql).toBe('SELECT * FROM items WHERE (id IN (?))')
    expect(result.params).toEqual([123])
  })

  it('should handle IN with empty array', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'id', operator: 'in', value: [] }
        ]
      }
    }

    const result = builder.build('items', filter)

    expect(result.sql).toContain('1=0')
  })

  it('should handle NOT IN with comma-separated string', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'role', operator: 'not_in', value: 'admin, superadmin' }
        ]
      }
    }

    const result = builder.build('users', filter)

    expect(result.sql).toBe('SELECT * FROM users WHERE (role NOT IN (?, ?))')
    expect(result.params).toEqual(['admin', 'superadmin'])
  })

  it('should handle NOT IN with single non-array value', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'id', operator: 'not_in', value: 999 }
        ]
      }
    }

    const result = builder.build('items', filter)

    expect(result.sql).toBe('SELECT * FROM items WHERE (id NOT IN (?))')
    expect(result.params).toEqual([999])
  })

  it('should handle NOT IN with empty array', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'id', operator: 'not_in', value: [] }
        ]
      }
    }

    const result = builder.build('items', filter)

    expect(result.sql).toContain('1=1')
  })
})

describe('QueryFilterBuilder - LIKE Edge Cases', () => {
  it('should handle LIKE with empty string', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'title', operator: 'like', value: '' }
        ]
      }
    }

    const result = builder.build('posts', filter)

    expect(result.sql).toContain('1=1')
  })

  it('should handle LIKE with whitespace only', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'title', operator: 'like', value: '   ' }
        ]
      }
    }

    const result = builder.build('posts', filter)

    expect(result.sql).toContain('1=1')
  })

  it('should handle LIKE with single word', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'name', operator: 'like', value: 'test' }
        ]
      }
    }

    const result = builder.build('users', filter)

    expect(result.sql).toBe('SELECT * FROM users WHERE ((name LIKE ?))')
    expect(result.params).toEqual(['%test%'])
  })
})

describe('QueryFilterBuilder - Combined AND/OR', () => {
  it('should combine AND and OR groups', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'status', operator: 'equals', value: 'active' }
        ],
        or: [
          { field: 'role', operator: 'equals', value: 'admin' },
          { field: 'role', operator: 'equals', value: 'editor' }
        ]
      }
    }

    const result = builder.build('users', filter)

    expect(result.sql).toBe('SELECT * FROM users WHERE (status = ?) AND (role = ? OR role = ?)')
    expect(result.params).toEqual(['active', 'admin', 'editor'])
  })

  it('should handle empty AND array', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [],
        or: [
          { field: 'active', operator: 'equals', value: true }
        ]
      }
    }

    const result = builder.build('items', filter)

    expect(result.sql).toBe('SELECT * FROM items WHERE (active = ?)')
  })

  it('should handle empty OR array', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'published', operator: 'equals', value: true }
        ],
        or: []
      }
    }

    const result = builder.build('posts', filter)

    expect(result.sql).toBe('SELECT * FROM posts WHERE (published = ?)')
  })
})

describe('QueryFilterBuilder.parseFromQuery - Edge Cases', () => {
  it('should parse where clause as JSON string', () => {
    const query = {
      where: JSON.stringify({
        and: [{ field: 'name', operator: 'equals', value: 'test' }]
      })
    }

    const filter = QueryFilterBuilder.parseFromQuery(query)

    expect(filter.where?.and).toContainEqual({
      field: 'name',
      operator: 'equals',
      value: 'test'
    })
  })

  it('should parse where clause as object', () => {
    const query = {
      where: {
        and: [{ field: 'status', operator: 'equals', value: 'active' }]
      }
    }

    const filter = QueryFilterBuilder.parseFromQuery(query)

    expect(filter.where?.and).toContainEqual({
      field: 'status',
      operator: 'equals',
      value: 'active'
    })
  })

  it('should handle invalid JSON in where clause', () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

    const query = {
      where: 'invalid json {'
    }

    const filter = QueryFilterBuilder.parseFromQuery(query)

    expect(consoleSpy).toHaveBeenCalledWith('Failed to parse where clause:', expect.any(Error))
    expect(filter.where).toEqual({ and: [] })

    consoleSpy.mockRestore()
  })

  it('should handle invalid JSON in sort clause', () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

    const query = {
      sort: 'invalid json ['
    }

    const filter = QueryFilterBuilder.parseFromQuery(query)

    expect(consoleSpy).toHaveBeenCalledWith('Failed to parse sort clause:', expect.any(Error))
    expect(filter.sort).toBeUndefined()

    consoleSpy.mockRestore()
  })

  it('should parse sort clause as object', () => {
    const query = {
      sort: [{ field: 'created_at', order: 'desc' }]
    }

    const filter = QueryFilterBuilder.parseFromQuery(query)

    expect(filter.sort).toEqual([{ field: 'created_at', order: 'desc' }])
  })

  it('should limit max to 1000', () => {
    const query = {
      limit: '5000'
    }

    const filter = QueryFilterBuilder.parseFromQuery(query)

    expect(filter.limit).toBe(1000)
  })

  it('should parse collection_id simple field', () => {
    const query = {
      collection_id: 'posts'
    }

    const filter = QueryFilterBuilder.parseFromQuery(query)

    expect(filter.where?.and).toContainEqual({
      field: 'collection_id',
      operator: 'equals',
      value: 'posts'
    })
  })

  it('should initialize where.and if where exists but and is missing', () => {
    const query = {
      where: { or: [{ field: 'test', operator: 'equals', value: 1 }] }
    }

    const filter = QueryFilterBuilder.parseFromQuery(query)

    expect(filter.where?.and).toEqual([])
    expect(filter.where?.or).toEqual([{ field: 'test', operator: 'equals', value: 1 }])
  })

  it('should handle empty query', () => {
    const query = {}

    const filter = QueryFilterBuilder.parseFromQuery(query)

    expect(filter.where).toEqual({ and: [] })
  })
})

describe('QueryFilterBuilder - Field Sanitization', () => {
  it('should remove special characters from field names', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'user@name!', operator: 'equals', value: 'test' }
        ]
      }
    }

    const result = builder.build('users', filter)

    expect(result.sql).toBe('SELECT * FROM users WHERE (username = ?)')
  })

  it('should handle nested JSON paths', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      where: {
        and: [
          { field: 'data.user.name', operator: 'equals', value: 'John' }
        ]
      }
    }

    const result = builder.build('records', filter)

    expect(result.sql).toContain("json_extract(data, '$.user.name')")
  })

  it('should sanitize field names in sort clause', () => {
    const builder = new QueryFilterBuilder()
    const filter: QueryFilter = {
      sort: [
        { field: 'created@at!', order: 'desc' }
      ]
    }

    const result = builder.build('posts', filter)

    expect(result.sql).toBe('SELECT * FROM posts ORDER BY createdat DESC')
  })
})

describe('Security: Sort order SQL injection prevention', () => {
  describe('validateSortOrder', () => {
    it('should accept "asc"', () => {
      expect(validateSortOrder('asc')).toBe('asc')
    })

    it('should accept "desc"', () => {
      expect(validateSortOrder('desc')).toBe('desc')
    })

    it('should accept "ASC" (case insensitive)', () => {
      expect(validateSortOrder('ASC')).toBe('asc')
    })

    it('should accept "DESC" (case insensitive)', () => {
      expect(validateSortOrder('DESC')).toBe('desc')
    })

    it('should accept "Desc" (mixed case)', () => {
      expect(validateSortOrder('Desc')).toBe('desc')
    })

    it('should default to "asc" for SQL injection payload', () => {
      expect(validateSortOrder('desc; DROP TABLE users; --')).toBe('asc')
    })

    it('should default to "asc" for UNION injection', () => {
      expect(validateSortOrder('desc UNION SELECT * FROM users--')).toBe('asc')
    })

    it('should default to "asc" for empty string', () => {
      expect(validateSortOrder('')).toBe('asc')
    })

    it('should default to "asc" for non-string values', () => {
      expect(validateSortOrder(123)).toBe('asc')
      expect(validateSortOrder(null)).toBe('asc')
      expect(validateSortOrder(undefined)).toBe('asc')
      expect(validateSortOrder({})).toBe('asc')
      expect(validateSortOrder([])).toBe('asc')
    })

    it('should handle whitespace-padded values', () => {
      expect(validateSortOrder(' asc ')).toBe('asc')
      expect(validateSortOrder(' desc ')).toBe('desc')
    })
  })

  describe('QueryFilterBuilder.build - sort order sanitization', () => {
    it('should sanitize malicious sort order in SQL output', () => {
      const builder = new QueryFilterBuilder()
      const filter: QueryFilter = {
        sort: [
          { field: 'created_at', order: 'desc; DROP TABLE users; --' as any }
        ]
      }

      const result = builder.build('content', filter)

      expect(result.sql).toBe('SELECT * FROM content ORDER BY created_at ASC')
      expect(result.sql).not.toContain('DROP')
      expect(result.sql).not.toContain(';')
    })

    it('should sanitize UNION injection in sort order', () => {
      const builder = new QueryFilterBuilder()
      const filter: QueryFilter = {
        sort: [
          { field: 'id', order: 'asc UNION SELECT password FROM users--' as any }
        ]
      }

      const result = builder.build('content', filter)

      expect(result.sql).toBe('SELECT * FROM content ORDER BY id ASC')
      expect(result.sql).not.toContain('UNION')
      expect(result.sql).not.toContain('password')
    })

    it('should allow valid ASC order', () => {
      const builder = new QueryFilterBuilder()
      const filter: QueryFilter = {
        sort: [{ field: 'name', order: 'asc' }]
      }

      const result = builder.build('users', filter)

      expect(result.sql).toBe('SELECT * FROM users ORDER BY name ASC')
    })

    it('should allow valid DESC order', () => {
      const builder = new QueryFilterBuilder()
      const filter: QueryFilter = {
        sort: [{ field: 'name', order: 'desc' }]
      }

      const result = builder.build('users', filter)

      expect(result.sql).toBe('SELECT * FROM users ORDER BY name DESC')
    })
  })

  describe('QueryFilterBuilder.parseFromQuery - sort order sanitization', () => {
    it('should sanitize malicious sort order during parsing', () => {
      const query = {
        sort: JSON.stringify([{ field: 'created_at', order: 'desc; DROP TABLE users;--' }])
      }

      const filter = QueryFilterBuilder.parseFromQuery(query)

      expect(filter.sort).toEqual([{ field: 'created_at', order: 'asc' }])
    })

    it('should preserve valid sort order during parsing', () => {
      const query = {
        sort: JSON.stringify([{ field: 'id', order: 'desc' }])
      }

      const filter = QueryFilterBuilder.parseFromQuery(query)

      expect(filter.sort).toEqual([{ field: 'id', order: 'desc' }])
    })

    it('should filter out sort entries without a field', () => {
      const query = {
        sort: JSON.stringify([
          { field: 'id', order: 'asc' },
          { order: 'desc' },
          { field: '', order: 'asc' }
        ])
      }

      const filter = QueryFilterBuilder.parseFromQuery(query)

      // Entry without field is filtered, entry with empty string field is kept (has typeof string)
      expect(filter.sort?.length).toBe(2)
      expect(filter.sort?.[0]).toEqual({ field: 'id', order: 'asc' })
    })

    it('should ignore non-array sort values', () => {
      const query = {
        sort: JSON.stringify({ field: 'id', order: 'asc' })
      }

      const filter = QueryFilterBuilder.parseFromQuery(query)

      expect(filter.sort).toBeUndefined()
    })
  })
})
