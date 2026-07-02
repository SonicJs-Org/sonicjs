/**
 * Demo — Testimonials collection
 *
 * Customer quotes shown on the demo site. Code-defined; CRUD at
 * /admin/content/testimonial. Seeded by the demo-seed plugin (runReseed).
 */

import type { CollectionConfig } from '@sonicjs-cms/core'

export default {
  name: 'testimonial',
  displayName: 'Testimonials',
  slug: 'testimonials',
  description: 'Customer quotes and reviews',
  icon: '💬',

  schema: {
    type: 'object',
    properties: {
      name: { type: 'string', title: 'Name', required: true, maxLength: 100 },
      role: { type: 'string', title: 'Role / Title', maxLength: 100 },
      company: { type: 'string', title: 'Company', maxLength: 100 },
      quote: { type: 'textarea', title: 'Quote', required: true, maxLength: 500 },
      avatar: { type: 'media', title: 'Avatar Image' },
      rating: { type: 'number', title: 'Rating (1–5)', min: 1, max: 5, default: 5 },
      featured: { type: 'boolean', title: 'Featured', default: false },
    },
    required: ['name', 'quote'],
  },

  listFields: ['name', 'company', 'rating', 'featured'],
  searchFields: ['name', 'company', 'quote'],
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
