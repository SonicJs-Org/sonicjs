import type { CollectionConfig } from '@sonicjs-cms/core';

export const faqCollection: CollectionConfig = {
  name: 'faq',
  displayName: 'FAQ',
  slug: 'faqs',
  description: 'Frequently asked questions',
  icon: '❓',

  versioning: true,

  schema: {
    type: 'object',
    properties: {
      question: {
        type: 'string',
        title: 'Question',
        required: true,
      },
      answer: {
        type: 'textarea',
        title: 'Answer',
        required: true,
      },
      category: {
        type: 'string',
        title: 'Category',
      },
    },
    required: ['question', 'answer'],
  },

  listFields: ['question', 'category'],
  searchFields: ['question', 'answer', 'category'],
  defaultSort: 'createdAt',
  defaultSortOrder: 'desc',

  managed: true,
  isActive: true,
};
