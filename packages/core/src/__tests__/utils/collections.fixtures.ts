import { vi, expect } from 'vitest'

// Collection test fixtures and utilities
export const mockCollections = {
  blog_post: {
    id: 'collection-blog-posts-1',
    name: 'blog_post',
    displayName: 'Blog Posts',
    description: 'Blog post content collection',
    schema: {
      type: 'object',
      properties: {
        title: { type: 'string', title: 'Title', required: true },
        content: { type: 'string', title: 'Content', format: 'richtext' },
        excerpt: { type: 'string', title: 'Excerpt' },
        featured_image: { type: 'string', title: 'Featured Image', format: 'media' },
        tags: { type: 'array', title: 'Tags', items: { type: 'string' } },
        status: { 
          type: 'string', 
          title: 'Status', 
          enum: ['draft', 'published', 'archived'], 
          default: 'draft' 
        }
      },
      required: ['title']
    },
    isActive: true,
    createdAt: new Date('2023-01-01T00:00:00Z'),
    updatedAt: new Date('2023-01-01T00:00:00Z')
  },
  
  pages: {
    id: 'collection-pages-1',
    name: 'pages',
    displayName: 'Pages',
    description: 'Static page content collection',
    schema: {
      type: 'object',
      properties: {
        title: { type: 'string', title: 'Title', required: true },
        content: { type: 'string', title: 'Content', format: 'richtext' },
        slug: { type: 'string', title: 'Slug' },
        meta_description: { type: 'string', title: 'Meta Description' },
        featured_image: { type: 'string', title: 'Featured Image', format: 'media' }
      },
      required: ['title']
    },
    isActive: true,
    createdAt: new Date('2023-01-02T00:00:00Z'),
    updatedAt: new Date('2023-01-02T00:00:00Z')
  },

  products: {
    id: 'collection-products-1',
    name: 'products',
    displayName: 'Products',
    description: 'E-commerce product collection',
    schema: {
      type: 'object',
      properties: {
        name: { type: 'string', title: 'Product Name', required: true },
        description: { type: 'string', title: 'Description', format: 'richtext' },
        price: { type: 'number', title: 'Price', minimum: 0 },
        sku: { type: 'string', title: 'SKU' },
        category: { 
          type: 'string', 
          title: 'Category',
          enum: ['electronics', 'clothing', 'books', 'home'] 
        },
        in_stock: { type: 'boolean', title: 'In Stock', default: true },
        images: { 
          type: 'array', 
          title: 'Product Images',
          items: { type: 'string', format: 'media' }
        },
        specifications: { type: 'object', title: 'Specifications' }
      },
      required: ['name', 'price']
    },
    isActive: true,
    createdAt: new Date('2023-01-03T00:00:00Z'),
    updatedAt: new Date('2023-01-03T00:00:00Z')
  },

  inactive_collection: {
    id: 'collection-inactive-1',
    name: 'old_collection',
    displayName: 'Old Collection',
    description: 'An inactive collection',
    schema: { type: 'object', properties: {} },
    isActive: false,
    createdAt: new Date('2022-01-01T00:00:00Z'),
    updatedAt: new Date('2022-01-01T00:00:00Z')
  }
}

export const mockContent = {
  blog_post_1: {
    id: 'content-blog-1',
    collectionId: 'collection-blog-posts-1',
    slug: 'welcome-to-sonicjs',
    title: 'Welcome to SonicJS AI',
    data: {
      title: 'Welcome to SonicJS AI',
      content: '<h1>Welcome to SonicJS AI</h1><p>This is your first blog post.</p>',
      excerpt: 'Welcome to SonicJS AI, a modern headless CMS.',
      tags: ['welcome', 'cms', 'sonicjs'],
      status: 'published'
    },
    status: 'published',
    publishedAt: new Date('2023-01-01T12:00:00Z'),
    authorId: 'admin-user-id',
    createdAt: new Date('2023-01-01T10:00:00Z'),
    updatedAt: new Date('2023-01-01T12:00:00Z')
  },

  blog_post_2: {
    id: 'content-blog-2',
    collectionId: 'collection-blog-posts-1',
    slug: 'second-post',
    title: 'Second Blog Post',
    data: {
      title: 'Second Blog Post',
      content: '<p>This is the second blog post.</p>',
      status: 'draft'
    },
    status: 'draft',
    publishedAt: null,
    authorId: 'admin-user-id',
    createdAt: new Date('2023-01-02T10:00:00Z'),
    updatedAt: new Date('2023-01-02T10:00:00Z')
  },

  page_1: {
    id: 'content-page-1',
    collectionId: 'collection-pages-1',
    slug: 'about-us',
    title: 'About Us',
    data: {
      title: 'About Us',
      content: '<h1>About Us</h1><p>Learn more about our company.</p>',
      slug: 'about-us',
      meta_description: 'Learn more about our company and mission.'
    },
    status: 'published',
    publishedAt: new Date('2023-01-01T12:00:00Z'),
    authorId: 'admin-user-id',
    createdAt: new Date('2023-01-01T11:00:00Z'),
    updatedAt: new Date('2023-01-01T12:00:00Z')
  }
}

export const mockUsers = {
  admin: {
    id: 'admin-user-id',
    email: 'admin@sonicjs.com',
    firstName: 'Admin',
    lastName: 'User',
    role: 'admin',
    isActive: true,
    createdAt: new Date('2023-01-01T00:00:00Z'),
    updatedAt: new Date('2023-01-01T00:00:00Z')
  },

  editor: {
    id: 'editor-user-id',
    email: 'editor@sonicjs.com',
    firstName: 'Editor',
    lastName: 'User',
    role: 'editor',
    isActive: true,
    createdAt: new Date('2023-01-01T00:00:00Z'),
    updatedAt: new Date('2023-01-01T00:00:00Z')
  }
}

// Database mock factory
export function createMockDatabase(): { db: any; preparedStatement: any } {
  const db = {
    select: vi.fn(),
    insert: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
    prepare: vi.fn()
  }

  // Set up chainable prepared statement mocks
  const preparedStatement = {
    bind: vi.fn().mockReturnThis(),
    run: vi.fn().mockResolvedValue({}),
    all: vi.fn().mockResolvedValue({ results: [] }),
    first: vi.fn().mockResolvedValue(null)
  }

  db.prepare.mockReturnValue(preparedStatement)

  return { db, preparedStatement }
}

// Collection API response builders
export const createCollectionResponse = (collection: any) => ({
  id: collection.id,
  name: collection.name,
  displayName: collection.displayName,
  description: collection.description,
  schema: collection.schema,
  isActive: collection.isActive,
  createdAt: collection.createdAt,
  updatedAt: collection.updatedAt
})

export const createCollectionsListResponse = (collections: any[]) => ({
  collections: collections.map(createCollectionResponse),
  total: collections.length,
  page: 1,
  limit: 50
})

export const createContentResponse = (content: any, author?: any) => ({
  id: content.id,
  title: content.title,
  slug: content.slug,
  status: content.status,
  publishedAt: content.publishedAt,
  author: author ? {
    id: author.id,
    email: author.email,
    firstName: author.firstName,
    lastName: author.lastName
  } : null,
  createdAt: content.createdAt,
  updatedAt: content.updatedAt
})

export const createContentListResponse = (collection: string, content: any[]) => ({
  collection,
  content: content.map(c => createContentResponse(c)),
  total: content.length,
  page: 1,
  limit: 50
})

// Test data generators
export const generateCollectionData = (overrides: Partial<any> = {}) => ({
  name: 'test_collection',
  displayName: 'Test Collection',
  description: 'A test collection for unit tests',
  schema: {
    type: 'object',
    properties: {
      title: { type: 'string', title: 'Title', required: true },
      content: { type: 'string', title: 'Content' }
    },
    required: ['title']
  },
  ...overrides
})

export const generateContentData = (collectionId: string, overrides: Partial<any> = {}) => ({
  collectionId,
  slug: 'test-content',
  title: 'Test Content',
  data: {
    title: 'Test Content',
    content: 'This is test content'
  },
  status: 'draft',
  authorId: 'admin-user-id',
  ...overrides
})

// Validation test cases
export const validCollectionNames = [
  'simple',
  'with_underscore',
  'with123numbers',
  'complex_name_123',
  'a',
  'collection_with_many_underscores_123'
]

export const invalidCollectionNames = [
  '',
  '123starts_with_number',
  'with spaces',
  'with-dashes', // Note: dashes might be valid in some contexts
  'WithCamelCase',
  'with@special',
  'with.dots',
  'with/slash',
  'with#hash',
  'with$dollar',
  'with%percent',
  'collection name with spaces'
]

export const validFieldTypes = [
  'text',
  'rich_text',
  'textarea',
  'number',
  'email',
  'url',
  'boolean',
  'date',
  'datetime',
  'select',
  'multiselect',
  'image',
  'file',
  'json',
  'relation'
]

export const invalidFieldTypes = [
  'invalid_type',
  'TEXT', // uppercase
  'string', // not in enum
  '',
  null,
  undefined
]

// Error message matchers
export const errorMessages = {
  collection: {
    nameRequired: 'Model name is required',
    nameFormat: 'Model name must be alphanumeric with underscores',
    displayNameRequired: 'Model display name is required',
    fieldsRequired: 'Model must have at least one field',
    duplicateName: 'Collection with this name already exists',
    notFound: 'Collection not found',
    hasContent: 'Cannot delete collection that contains content'
  },
  field: {
    nameFormat: 'Field name must be alphanumeric with underscores',
    typeRequired: 'must have a type',
    typeInvalid: 'has invalid type',
    titleRequired: 'must have a title',
    selectOptionsRequired: 'select fields must have options array',
    selectOptionsEmpty: 'select fields must have at least one option',
    minMaxInvalid: 'min value must be less than max value'
  },
  validation: {
    required: 'is required',
    email: 'must be a valid email address',
    url: 'must be a valid URL',
    date: 'must be a valid date',
    number: 'must be a number',
    boolean: 'must be a boolean',
    array: 'must be an array',
    string: 'must be a string',
    minLength: 'must be at least',
    maxLength: 'must be no more than',
    minimum: 'must be at least',
    maximum: 'must be no more than',
    pattern: 'does not match required pattern',
    enum: 'must be one of',
    enumInvalid: 'contains invalid options'
  }
}

// Async helpers for testing
export const waitFor = (ms: number) => new Promise(resolve => setTimeout(resolve, ms))

export const createAsyncMock = <T>(value: T, delay: number = 0): any =>
  vi.fn().mockImplementation(() =>
    delay > 0 ? waitFor(delay).then(() => value) : Promise.resolve(value)
  )

// HTTP request mocking utilities
export const createMockRequest = (method: string, url: string, body?: any): any => ({
  method,
  url,
  headers: new Headers({
    'Content-Type': 'application/json'
  }),
  json: vi.fn().mockResolvedValue(body || {}),
  text: vi.fn().mockResolvedValue(JSON.stringify(body || {}))
})

export const createMockResponse = (status: number = 200, data?: any): any => ({
  status,
  statusText: status === 200 ? 'OK' : 'Error',
  headers: new Headers({
    'Content-Type': 'application/json'
  }),
  json: vi.fn().mockResolvedValue(data || {}),
  text: vi.fn().mockResolvedValue(JSON.stringify(data || {})),
  ok: status >= 200 && status < 300
})

// Environment mocking
export const createMockEnv = (overrides: any = {}) => ({
  DB: createMockDatabase().db,
  CLOUDFLARE_API_TOKEN: 'test-token',
  ...overrides
})

// Test context factory
export const createTestContext = (overrides: any = {}) => ({
  env: createMockEnv(),
  req: {
    param: vi.fn(),
    query: vi.fn(),
    json: vi.fn(),
    text: vi.fn(),
    header: vi.fn()
  },
  json: vi.fn((data, status) => ({ data, status })),
  text: vi.fn((text, status) => ({ text, status })),
  html: vi.fn((html, status) => ({ html, status })),
  redirect: vi.fn((url, status) => ({ redirect: url, status })),
  ...overrides
})

// Assertion helpers
export const expectValidationError = (result: any, fieldName: string, errorType: string) => {
  expect(result.isValid).toBe(false)
  expect(result.errors).toEqual(
    expect.arrayContaining([
      expect.stringContaining(fieldName),
      expect.stringContaining(errorType)
    ])
  )
}

export const expectDatabaseCall = (mockFn: any, expectedSql: string, expectedParams?: any[]) => {
  expect(mockFn).toHaveBeenCalledWith(
    expect.stringContaining(expectedSql)
  )
  
  if (expectedParams) {
    expect(mockFn().bind).toHaveBeenCalledWith(...expectedParams)
  }
}

export const expectHttpResponse = (response: any, expectedStatus: number, expectedData?: any) => {
  expect(response.status).toBe(expectedStatus)
  
  if (expectedData) {
    expect(response.data || response).toMatchObject(expectedData)
  }
}
