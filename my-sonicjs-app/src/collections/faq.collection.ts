import type { CollectionConfig } from '@sonicjs-cms/core';

export const faqCollection: CollectionConfig = {
  name: 'faq',
  displayName: 'FAQ',
  slug: 'faq',
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
        maxLength: 500,
      },
      answer: {
        type: 'string',
        title: 'Answer',
        required: true,
      },
    },
    required: ['question', 'answer'],
  },

  listFields: ['question', 'status'],
  searchFields: ['question', 'answer'],
  defaultSort: 'createdAt',
  defaultSortOrder: 'desc',

  managed: true,
  isActive: true,

  access: {
    public: ['read'],
    admin: ['read', 'create', 'update', 'delete', 'publish', 'manage'],
  },
};
