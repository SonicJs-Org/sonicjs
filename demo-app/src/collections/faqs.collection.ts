/**
 * Demo — FAQs collection
 *
 * Frequently asked questions. Code-defined; CRUD at /admin/content/faq.
 * Seeded by the demo-seed plugin (runReseed).
 */

import type { CollectionConfig } from '@sonicjs-cms/core'

export default {
  name: 'faq',
  displayName: 'FAQs',
  slug: 'faqs',
  description: 'Frequently asked questions',
  icon: '❓',

  schema: {
    type: 'object',
    properties: {
      question: { type: 'string', title: 'Question', required: true, maxLength: 300 },
      answer: { type: 'richtext', title: 'Answer', required: true },
      category: {
        type: 'select',
        title: 'Category',
        enum: ['general', 'billing', 'technical', 'account'],
        enumLabels: ['General', 'Billing', 'Technical', 'Account'],
        default: 'general',
      },
      order: { type: 'number', title: 'Sort Order', default: 0 },
    },
    required: ['question', 'answer'],
  },

  listFields: ['question', 'category', 'order'],
  searchFields: ['question', 'answer'],
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
