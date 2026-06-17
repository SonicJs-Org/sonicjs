import type { CollectionConfig } from '@sonicjs-cms/core'

export default {
  name: 'faq',
  displayName: 'FAQ',
  slug: 'faqs',
  description: 'Frequently asked questions',
  icon: '❓',

  schema: {
    type: 'object',
    properties: {
      question: {
        type: 'string',
        title: 'Question',
        required: true,
        maxLength: 500,
      },
      answer: {
        type: 'textarea',
        title: 'Answer',
        required: true,
      },
      category: {
        type: 'string',
        title: 'Category',
        maxLength: 100,
      },
      order: {
        type: 'number',
        title: 'Display Order',
      },
    },
    required: ['question', 'answer'],
  },

  listFields: ['question', 'category', 'order'],
  searchFields: ['question', 'answer', 'category'],
  defaultSort: 'order',
  defaultSortOrder: 'asc',

  managed: true,
  isActive: true,
  versioning: true,
} satisfies CollectionConfig
