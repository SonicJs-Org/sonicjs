/**
 * Demo — Blog Posts collection
 *
 * Code-defined (no DB table). Registered via registerCollections() in src/index.ts;
 * core auto-registers a `document_type` row at bootstrap and exposes CRUD at
 * /admin/content/blog_post. Seeded by the demo-seed plugin (runReseed).
 */

import type { CollectionConfig } from '@sonicjs-cms/core'

export default {
  name: 'blog_post',
  displayName: 'Blog Posts',
  slug: 'blog-posts',
  description: 'Articles and announcements shown on the demo site',
  icon: '📝',

  schema: {
    type: 'object',
    properties: {
      title: { type: 'string', title: 'Title', required: true, maxLength: 200 },
      slug: { type: 'slug', title: 'URL Slug', required: true, maxLength: 200 },
      excerpt: { type: 'textarea', title: 'Excerpt', maxLength: 300 },
      content: { type: 'richtext', title: 'Content', required: true },
      author: { type: 'string', title: 'Author', required: true, maxLength: 100 },
      heroImage: { type: 'media', title: 'Hero Image', description: 'References a media_asset document' },
      category: {
        type: 'select',
        title: 'Category',
        enum: ['announcement', 'tutorial', 'product', 'engineering'],
        enumLabels: ['Announcement', 'Tutorial', 'Product', 'Engineering'],
        default: 'announcement',
      },
      publishedAt: { type: 'datetime', title: 'Published Date' },
      featured: { type: 'boolean', title: 'Featured', default: false },
    },
    required: ['title', 'slug', 'content', 'author'],
  },

  listFields: ['title', 'author', 'category', 'featured', 'publishedAt'],
  searchFields: ['title', 'excerpt', 'content', 'author'],
  defaultSort: 'createdAt',
  defaultSortOrder: 'desc',

  managed: true,
  isActive: true,

  access: {
    public: ['read'],
  },

  cache: {
    enabled: true,
    ttl: 5,
  },
} satisfies CollectionConfig
