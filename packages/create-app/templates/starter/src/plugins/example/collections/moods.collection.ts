/**
 * Example Plugin — Moods Collection
 *
 * Demonstrates how a plugin contributes a collection to the document repository.
 * Collections are code-defined (no DB table) — register via registerCollections()
 * in the app entry point. The core then auto-registers a document_type row at
 * bootstrap and exposes full CRUD at /admin/content/example.
 *
 * This collection stores moods that the plugin's public API randomly selects from.
 */

import type { CollectionConfig } from '@sonicjs-cms/core'

export const moodsCollection = {
  name: 'example',
  displayName: 'Example',
  slug: 'example',
  description: 'Moods served by the Example plugin API',
  icon: '😈',

  schema: {
    type: 'object',
    properties: {
      name: {
        type: 'string',
        title: 'Mood Name',
        required: true,
        maxLength: 100,
      },
      emoji: {
        type: 'string',
        title: 'Emoji',
        maxLength: 10,
      },
      description: {
        type: 'string',
        title: 'Description',
        maxLength: 300,
      },
    },
    required: ['name'],
  },

  listFields: ['name', 'emoji', 'description'],
  searchFields: ['name', 'description'],
  defaultSort: 'createdAt',
  defaultSortOrder: 'asc' as const,

  managed: true,
  isActive: true,

  // Publicly readable so the API endpoint can list moods without auth.
  access: {
    public: ['read'],
  },
} satisfies CollectionConfig
