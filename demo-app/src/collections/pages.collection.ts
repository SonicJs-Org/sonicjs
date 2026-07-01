/**
 * Demo — Pages collection
 *
 * Static marketing pages (Home, About, Contact). Code-defined; CRUD at
 * /admin/content/page. Seeded by the demo-seed plugin (runReseed).
 */

import type { CollectionConfig } from '@sonicjs-cms/core'

export default {
  name: 'page',
  displayName: 'Pages',
  slug: 'pages',
  description: 'Static marketing pages',
  icon: '📄',

  schema: {
    type: 'object',
    properties: {
      title: { type: 'string', title: 'Title', required: true, maxLength: 200 },
      slug: { type: 'slug', title: 'URL Slug', required: true, maxLength: 200 },
      body: { type: 'richtext', title: 'Body', required: true },
      heroImage: { type: 'media', title: 'Hero Image' },
      showInNav: { type: 'boolean', title: 'Show in Navigation', default: true },
      navOrder: { type: 'number', title: 'Nav Order', default: 0 },
    },
    required: ['title', 'slug', 'body'],
  },

  listFields: ['title', 'showInNav', 'navOrder'],
  searchFields: ['title', 'body'],
  defaultSort: 'createdAt',
  defaultSortOrder: 'asc',

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
