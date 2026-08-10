import type { CollectionConfig } from '@sonicjs-cms/core';

export const departmentsCollection = {
  name: 'departments',
  displayName: 'Departments',
  slug: 'departments',
  description: 'Company departments — referenced by employees',
  icon: '🏢',

  schema: {
    type: 'object',
    properties: {
      name: {
        type: 'string',
        title: 'Department Name',
        required: true,
        maxLength: 100,
      },
      description: {
        type: 'string',
        title: 'Description',
        maxLength: 500,
      },
      icon: {
        type: 'string',
        title: 'Icon',
        description: 'Emoji or icon identifier',
        maxLength: 10,
      },
      color: {
        type: 'color',
        title: 'Color',
        description: 'Brand color for this department (hex)',
      },
      head_count: {
        type: 'number',
        title: 'Head Count',
        description: 'Current number of employees (denormalized for display)',
      },
    },
    required: ['name'],
  },

  listFields: ['name', 'icon', 'head_count'],
  searchFields: ['name', 'description'],
  defaultSort: 'name',
  defaultSortOrder: 'asc',

  managed: true,
  isActive: true,

  access: {
    public: ['read'],
  },

  cache: {
    enabled: true,
    ttl: 600,
  },
} satisfies CollectionConfig;
