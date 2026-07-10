import type { CollectionConfig } from '@sonicjs-cms/core';

export const regionsCollection = {
  name: 'regions',
  displayName: 'Regions',
  slug: 'regions',
  description: 'Geographic regions — referenced by employees',
  icon: '🌍',

  schema: {
    type: 'object',
    properties: {
      name: {
        type: 'string',
        title: 'Region Code',
        required: true,
        maxLength: 50,
        description: 'Short code used in filters, e.g. US-East',
      },
      display_name: {
        type: 'string',
        title: 'Display Name',
        maxLength: 100,
        description: 'Human-readable name, e.g. US East Coast',
      },
      timezone: {
        type: 'string',
        title: 'Primary Timezone',
        maxLength: 50,
        description: 'IANA timezone, e.g. America/New_York',
      },
      flag_emoji: {
        type: 'string',
        title: 'Flag / Emoji',
        maxLength: 10,
      },
      head_count: {
        type: 'number',
        title: 'Head Count',
        description: 'Current number of employees in this region (denormalized)',
      },
    },
    required: ['name'],
  },

  listFields: ['name', 'display_name', 'timezone', 'head_count'],
  searchFields: ['name', 'display_name', 'timezone'],
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
