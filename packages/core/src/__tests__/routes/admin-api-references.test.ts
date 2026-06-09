import { describe, it, expect, beforeEach, vi } from 'vitest'

// Mock database operations for references API testing
const createMockDb = (overrides: any = {}) => {
  const defaultMock = {
    prepare: vi.fn().mockReturnValue({
      bind: vi.fn().mockReturnValue({
        run: vi.fn().mockResolvedValue({ success: true }),
        all: vi.fn().mockResolvedValue({ results: [] }),
        first: vi.fn().mockResolvedValue(null)
      }),
      run: vi.fn().mockResolvedValue({ success: true }),
      all: vi.fn().mockResolvedValue({ results: [] }),
      first: vi.fn().mockResolvedValue(null)
    })
  }
  return { ...defaultMock, ...overrides }
}

// References API functions (extracted logic for testing)
const referencesAPI = {
  async getAvailableCollections(db: any) {
    const result = await db.prepare(`
      SELECT name, display_name FROM collections WHERE is_active = 1 ORDER BY display_name
    `).all()
    return (result.results || []).map((c: any) => ({
      name: c.name,
      displayName: c.display_name
    }))
  },

  async getReferenceById(db: any, id: string) {
    const result = await db.prepare(`
      SELECT c.id, c.title, c.status, col.name as collection_name, col.display_name
      FROM content c
      JOIN collections col ON c.collection_id = col.id
      WHERE c.id = ?
    `).bind(id).first()

    if (result) {
      return {
        item: {
          id: result.id,
          title: result.title || 'Untitled',
          collection: result.collection_name,
          collectionDisplay: result.display_name,
          status: result.status
        }
      }
    }
    return { item: null }
  },

  async searchReferences(db: any, options: {
    query?: string
    collectionNames?: string[]
    limit?: number
  }) {
    const { query = '', collectionNames = [], limit = 20 } = options

    // Build collection filter
    let collectionFilter = ''
    const params: (string | number)[] = []

    if (collectionNames.length > 0) {
      const placeholders = collectionNames.map(() => '?').join(', ')
      collectionFilter = `AND col.name IN (${placeholders})`
      params.push(...collectionNames)
    }

    // Build query
    let sql = `
      SELECT c.id, c.title, c.status, col.name as collection_name, col.display_name
      FROM content c
      JOIN collections col ON c.collection_id = col.id
      WHERE 1=1 ${collectionFilter}
    `

    if (query) {
      sql += ` AND c.title LIKE ?`
      params.push(`%${query}%`)
    }

    sql += ` ORDER BY c.updated_at DESC LIMIT ?`
    params.push(limit)

    const results = await db.prepare(sql).bind(...params).all()

    return {
      items: (results.results || []).map((row: any) => ({
        id: String(row.id),
        title: String(row.title || 'Untitled'),
        collection: String(row.collection_name),
        collectionDisplay: String(row.display_name || row.collection_name),
        status: String(row.status || 'draft')
      }))
    }
  },

  validateCollectionNames(requestedCollections: string[], availableCollections: { name: string }[]) {
    const availableNames = availableCollections.map(c => c.name)
    const matched = requestedCollections.filter(name => availableNames.includes(name))
    const unmatched = requestedCollections.filter(name => !availableNames.includes(name))
    return { matched, unmatched }
  }
}

describe('References API', () => {
  let mockDb: any

  beforeEach(() => {
    vi.clearAllMocks()
    mockDb = createMockDb()
  })

  describe('getAvailableCollections', () => {
    it('should return empty array when no collections exist', async () => {
      mockDb.prepare = vi.fn().mockReturnValue({
        all: vi.fn().mockResolvedValue({ results: [] })
      })

      const result = await referencesAPI.getAvailableCollections(mockDb)
      expect(result).toEqual([])
    })

    it('should return mapped collections with name and displayName', async () => {
      mockDb.prepare = vi.fn().mockReturnValue({
        all: vi.fn().mockResolvedValue({
          results: [
            { name: 'pages', display_name: 'Pages' },
            { name: 'blog_post', display_name: 'Blog Posts' }
          ]
        })
      })

      const result = await referencesAPI.getAvailableCollections(mockDb)
      expect(result).toEqual([
        { name: 'pages', displayName: 'Pages' },
        { name: 'blog_post', displayName: 'Blog Posts' }
      ])
    })

    it('should call prepare with correct SQL', async () => {
      mockDb.prepare = vi.fn().mockReturnValue({
        all: vi.fn().mockResolvedValue({ results: [] })
      })

      await referencesAPI.getAvailableCollections(mockDb)
      expect(mockDb.prepare).toHaveBeenCalledWith(expect.stringContaining('SELECT name, display_name FROM collections'))
      expect(mockDb.prepare).toHaveBeenCalledWith(expect.stringContaining('is_active = 1'))
    })
  })

  describe('getReferenceById', () => {
    it('should return null item when reference not found', async () => {
      mockDb.prepare = vi.fn().mockReturnValue({
        bind: vi.fn().mockReturnValue({
          first: vi.fn().mockResolvedValue(null)
        })
      })

      const result = await referencesAPI.getReferenceById(mockDb, 'non-existent-id')
      expect(result).toEqual({ item: null })
    })

    it('should return reference item when found', async () => {
      mockDb.prepare = vi.fn().mockReturnValue({
        bind: vi.fn().mockReturnValue({
          first: vi.fn().mockResolvedValue({
            id: 'ref-123',
            title: 'Test Page',
            status: 'published',
            collection_name: 'pages',
            display_name: 'Pages'
          })
        })
      })

      const result = await referencesAPI.getReferenceById(mockDb, 'ref-123')
      expect(result).toEqual({
        item: {
          id: 'ref-123',
          title: 'Test Page',
          collection: 'pages',
          collectionDisplay: 'Pages',
          status: 'published'
        }
      })
    })

    it('should use "Untitled" for items without title', async () => {
      mockDb.prepare = vi.fn().mockReturnValue({
        bind: vi.fn().mockReturnValue({
          first: vi.fn().mockResolvedValue({
            id: 'ref-456',
            title: null,
            status: 'draft',
            collection_name: 'posts',
            display_name: 'Posts'
          })
        })
      })

      const result = await referencesAPI.getReferenceById(mockDb, 'ref-456')
      expect(result.item?.title).toBe('Untitled')
    })

    it('should bind the id parameter correctly', async () => {
      const bindMock = vi.fn().mockReturnValue({
        first: vi.fn().mockResolvedValue(null)
      })
      mockDb.prepare = vi.fn().mockReturnValue({ bind: bindMock })

      await referencesAPI.getReferenceById(mockDb, 'test-id-789')
      expect(bindMock).toHaveBeenCalledWith('test-id-789')
    })
  })

  describe('searchReferences', () => {
    it('should return empty items array when no results', async () => {
      mockDb.prepare = vi.fn().mockReturnValue({
        bind: vi.fn().mockReturnValue({
          all: vi.fn().mockResolvedValue({ results: [] })
        })
      })

      const result = await referencesAPI.searchReferences(mockDb, {})
      expect(result).toEqual({ items: [] })
    })

    it('should return mapped items from search results', async () => {
      mockDb.prepare = vi.fn().mockReturnValue({
        bind: vi.fn().mockReturnValue({
          all: vi.fn().mockResolvedValue({
            results: [
              { id: '1', title: 'Page 1', status: 'published', collection_name: 'pages', display_name: 'Pages' },
              { id: '2', title: 'Post 1', status: 'draft', collection_name: 'posts', display_name: 'Posts' }
            ]
          })
        })
      })

      const result = await referencesAPI.searchReferences(mockDb, {})
      expect(result.items).toHaveLength(2)
      expect(result.items[0]).toEqual({
        id: '1',
        title: 'Page 1',
        collection: 'pages',
        collectionDisplay: 'Pages',
        status: 'published'
      })
    })

    it('should filter by collection names', async () => {
      const bindMock = vi.fn().mockReturnValue({
        all: vi.fn().mockResolvedValue({ results: [] })
      })
      mockDb.prepare = vi.fn().mockReturnValue({ bind: bindMock })

      await referencesAPI.searchReferences(mockDb, {
        collectionNames: ['pages', 'posts']
      })

      expect(bindMock).toHaveBeenCalledWith('pages', 'posts', 20)
    })

    it('should filter by search query', async () => {
      const bindMock = vi.fn().mockReturnValue({
        all: vi.fn().mockResolvedValue({ results: [] })
      })
      mockDb.prepare = vi.fn().mockReturnValue({ bind: bindMock })

      await referencesAPI.searchReferences(mockDb, {
        query: 'test'
      })

      expect(bindMock).toHaveBeenCalledWith('%test%', 20)
    })

    it('should combine collection filter and search query', async () => {
      const bindMock = vi.fn().mockReturnValue({
        all: vi.fn().mockResolvedValue({ results: [] })
      })
      mockDb.prepare = vi.fn().mockReturnValue({ bind: bindMock })

      await referencesAPI.searchReferences(mockDb, {
        collectionNames: ['pages'],
        query: 'home'
      })

      expect(bindMock).toHaveBeenCalledWith('pages', '%home%', 20)
    })

    it('should respect limit parameter', async () => {
      const bindMock = vi.fn().mockReturnValue({
        all: vi.fn().mockResolvedValue({ results: [] })
      })
      mockDb.prepare = vi.fn().mockReturnValue({ bind: bindMock })

      await referencesAPI.searchReferences(mockDb, { limit: 50 })

      expect(bindMock).toHaveBeenCalledWith(50)
    })

    it('should default limit to 20', async () => {
      const bindMock = vi.fn().mockReturnValue({
        all: vi.fn().mockResolvedValue({ results: [] })
      })
      mockDb.prepare = vi.fn().mockReturnValue({ bind: bindMock })

      await referencesAPI.searchReferences(mockDb, {})

      expect(bindMock).toHaveBeenCalledWith(20)
    })

    it('should handle items with missing title', async () => {
      mockDb.prepare = vi.fn().mockReturnValue({
        bind: vi.fn().mockReturnValue({
          all: vi.fn().mockResolvedValue({
            results: [
              { id: '1', title: null, status: 'draft', collection_name: 'pages', display_name: 'Pages' }
            ]
          })
        })
      })

      const result = await referencesAPI.searchReferences(mockDb, {})
      expect(result.items[0].title).toBe('Untitled')
    })

    it('should handle items with missing status', async () => {
      mockDb.prepare = vi.fn().mockReturnValue({
        bind: vi.fn().mockReturnValue({
          all: vi.fn().mockResolvedValue({
            results: [
              { id: '1', title: 'Test', status: null, collection_name: 'pages', display_name: 'Pages' }
            ]
          })
        })
      })

      const result = await referencesAPI.searchReferences(mockDb, {})
      expect(result.items[0].status).toBe('draft')
    })

    it('should use collection_name as fallback for collectionDisplay', async () => {
      mockDb.prepare = vi.fn().mockReturnValue({
        bind: vi.fn().mockReturnValue({
          all: vi.fn().mockResolvedValue({
            results: [
              { id: '1', title: 'Test', status: 'published', collection_name: 'pages', display_name: null }
            ]
          })
        })
      })

      const result = await referencesAPI.searchReferences(mockDb, {})
      expect(result.items[0].collectionDisplay).toBe('pages')
    })
  })

  describe('validateCollectionNames', () => {
    it('should return all matched when all collections exist', () => {
      const available = [{ name: 'pages' }, { name: 'posts' }]
      const result = referencesAPI.validateCollectionNames(['pages', 'posts'], available)

      expect(result.matched).toEqual(['pages', 'posts'])
      expect(result.unmatched).toEqual([])
    })

    it('should return all unmatched when no collections exist', () => {
      const available = [{ name: 'pages' }]
      const result = referencesAPI.validateCollectionNames(['news', 'events'], available)

      expect(result.matched).toEqual([])
      expect(result.unmatched).toEqual(['news', 'events'])
    })

    it('should split matched and unmatched collections', () => {
      const available = [{ name: 'pages' }, { name: 'posts' }]
      const result = referencesAPI.validateCollectionNames(['pages', 'news'], available)

      expect(result.matched).toEqual(['pages'])
      expect(result.unmatched).toEqual(['news'])
    })

    it('should handle empty requested collections', () => {
      const available = [{ name: 'pages' }]
      const result = referencesAPI.validateCollectionNames([], available)

      expect(result.matched).toEqual([])
      expect(result.unmatched).toEqual([])
    })

    it('should handle empty available collections', () => {
      const result = referencesAPI.validateCollectionNames(['pages'], [])

      expect(result.matched).toEqual([])
      expect(result.unmatched).toEqual(['pages'])
    })
  })
})

describe('Reference Field Type', () => {
  describe('Field type definition', () => {
    const referenceFieldType = {
      name: 'reference',
      displayName: 'Reference',
      category: 'Relationship',
      dataType: 'string',
      storageFormat: 'VARCHAR(255)',
      supportedOptions: ['collection', 'displayField']
    }

    it('should have correct name', () => {
      expect(referenceFieldType.name).toBe('reference')
    })

    it('should have correct display name', () => {
      expect(referenceFieldType.displayName).toBe('Reference')
    })

    it('should be in Relationship category', () => {
      expect(referenceFieldType.category).toBe('Relationship')
    })

    it('should store as string (for ID reference)', () => {
      expect(referenceFieldType.dataType).toBe('string')
    })

    it('should support collection option', () => {
      expect(referenceFieldType.supportedOptions).toContain('collection')
    })

    it('should support displayField option', () => {
      expect(referenceFieldType.supportedOptions).toContain('displayField')
    })
  })

  describe('Field options parsing', () => {
    const parseFieldOptions = (optionsJson: string) => {
      try {
        return JSON.parse(optionsJson)
      } catch {
        return {}
      }
    }

    it('should parse single collection string', () => {
      const options = parseFieldOptions('{"collection": "pages"}')
      expect(options.collection).toBe('pages')
    })

    it('should parse collection array', () => {
      const options = parseFieldOptions('{"collection": ["pages", "posts"]}')
      expect(options.collection).toEqual(['pages', 'posts'])
    })

    it('should handle empty options', () => {
      const options = parseFieldOptions('{}')
      expect(options.collection).toBeUndefined()
    })

    it('should handle invalid JSON gracefully', () => {
      const options = parseFieldOptions('invalid json')
      expect(options).toEqual({})
    })

    it('should parse displayField option', () => {
      const options = parseFieldOptions('{"collection": "pages", "displayField": "name"}')
      expect(options.displayField).toBe('name')
    })
  })

  describe('Collection list normalization', () => {
    const normalizeCollections = (collection: string | string[] | undefined): string[] => {
      if (!collection) return []
      return Array.isArray(collection) ? collection : [collection]
    }

    it('should return empty array for undefined', () => {
      expect(normalizeCollections(undefined)).toEqual([])
    })

    it('should wrap single string in array', () => {
      expect(normalizeCollections('pages')).toEqual(['pages'])
    })

    it('should return array as-is', () => {
      expect(normalizeCollections(['pages', 'posts'])).toEqual(['pages', 'posts'])
    })

    it('should handle empty array', () => {
      expect(normalizeCollections([])).toEqual([])
    })
  })
})

describe('Reference Field Template Rendering', () => {
  const escapeHtml = (str: string) => {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;')
  }

  const renderReferenceField = (options: {
    fieldId: string
    fieldName: string
    value?: string
    collections: string[]
    disabled?: boolean
  }) => {
    const { fieldId, fieldName, value = '', collections, disabled = false } = options
    const collectionAttr = escapeHtml(JSON.stringify(collections))

    return `
      <div class="reference-field-container" data-reference-field data-field-name="${fieldName}" data-collections='${collectionAttr}'>
        <input type="hidden" id="${fieldId}" name="${fieldName}" value="${escapeHtml(value)}">
        <div class="reference-display ${value ? '' : 'hidden'}" data-reference-display>
          <!-- Reference display content -->
        </div>
        <div class="reference-actions ${value ? 'hidden' : ''}" data-reference-actions>
          <button type="button" ${disabled ? 'disabled' : ''}>Select Reference</button>
          <p>Link to: ${collections.join(', ')}</p>
        </div>
      </div>
    `
  }

  it('should render with correct data attributes', () => {
    const html = renderReferenceField({
      fieldId: 'field-ref1',
      fieldName: 'ref1',
      collections: ['pages']
    })

    expect(html).toContain('data-reference-field')
    expect(html).toContain('data-field-name="ref1"')
    // escapeHtml converts " to &quot;
    expect(html).toContain("data-collections='[&quot;pages&quot;]'")
  })

  it('should render hidden input with correct id and name', () => {
    const html = renderReferenceField({
      fieldId: 'field-myref',
      fieldName: 'myref',
      collections: ['pages']
    })

    expect(html).toContain('id="field-myref"')
    expect(html).toContain('name="myref"')
  })

  it('should include value in hidden input', () => {
    const html = renderReferenceField({
      fieldId: 'field-ref',
      fieldName: 'ref',
      value: 'ref-123',
      collections: ['pages']
    })

    expect(html).toContain('value="ref-123"')
  })

  it('should show reference display when value exists', () => {
    const html = renderReferenceField({
      fieldId: 'field-ref',
      fieldName: 'ref',
      value: 'ref-123',
      collections: ['pages']
    })

    expect(html).toContain('reference-display "')
    expect(html).toContain('reference-actions hidden')
  })

  it('should show reference actions when no value', () => {
    const html = renderReferenceField({
      fieldId: 'field-ref',
      fieldName: 'ref',
      value: '',
      collections: ['pages']
    })

    expect(html).toContain('reference-display hidden')
    expect(html).toContain('reference-actions "')
  })

  it('should render disabled button when disabled', () => {
    const html = renderReferenceField({
      fieldId: 'field-ref',
      fieldName: 'ref',
      collections: ['pages'],
      disabled: true
    })

    expect(html).toContain('disabled')
  })

  it('should display collection names', () => {
    const html = renderReferenceField({
      fieldId: 'field-ref',
      fieldName: 'ref',
      collections: ['pages', 'posts']
    })

    expect(html).toContain('Link to: pages, posts')
  })

  it('should escape HTML in collections attribute', () => {
    const html = renderReferenceField({
      fieldId: 'field-ref',
      fieldName: 'ref',
      collections: ['<script>alert("xss")</script>']
    })

    // The data-collections attribute should have escaped HTML
    expect(html).toContain('&lt;script&gt;')
    // Check that the JSON attribute doesn't contain unescaped script
    expect(html).toMatch(/data-collections='[^']*&lt;script&gt;/)
  })

  it('should escape HTML in value', () => {
    const html = renderReferenceField({
      fieldId: 'field-ref',
      fieldName: 'ref',
      value: '"><script>alert("xss")</script>',
      collections: ['pages']
    })

    expect(html).not.toContain('"><script>')
  })
})
