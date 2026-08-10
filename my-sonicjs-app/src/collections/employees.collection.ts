import type { CollectionConfig } from '@sonicjs-cms/core';

export const employeesCollection = {
  name: 'employees',
  displayName: 'Employees',
  slug: 'employees',
  description: 'Employee directory — powers the SonicJS SDK demo',
  icon: '👥',

  schema: {
    type: 'object',
    properties: {
      first_name: {
        type: 'string',
        title: 'First Name',
        required: true,
        maxLength: 100,
      },
      last_name: {
        type: 'string',
        title: 'Last Name',
        required: true,
        maxLength: 100,
      },
      department: {
        type: 'reference',
        title: 'Department',
        required: true,
        collection: 'departments',
        description: 'Reference to departments collection',
      },
      job_title: {
        type: 'string',
        title: 'Job Title',
        required: true,
        maxLength: 150,
      },
      region: {
        type: 'reference',
        title: 'Region',
        required: true,
        collection: 'regions',
        description: 'Reference to regions collection',
      },
      email: {
        type: 'email',
        title: 'Email',
        maxLength: 255,
      },
      phone: {
        type: 'string',
        title: 'Phone',
        maxLength: 50,
      },
      avatar_seed: {
        type: 'string',
        title: 'Avatar Seed',
        description: 'Seed string passed to robohash.org for deterministic avatar generation',
        maxLength: 100,
      },
    },
    required: ['first_name', 'last_name', 'department', 'job_title', 'region'],
  },

  listFields: ['first_name', 'last_name', 'department', 'job_title', 'region'],
  searchFields: ['first_name', 'last_name', 'email', 'job_title'],
  defaultSort: 'last_name',
  defaultSortOrder: 'asc',

  managed: true,
  isActive: true,

  // Public read — demo data, no auth needed
  access: {
    public: ['read'],
  },

  cache: {
    enabled: true,
    ttl: 7_776_000, // 90 days — demo data is static, maximize cache hit rate
  },
} satisfies CollectionConfig;
