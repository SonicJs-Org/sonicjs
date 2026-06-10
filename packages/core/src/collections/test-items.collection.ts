/**
 * Test Items Collection
 *
 * Simple test collection that uses config instead of database.
 * This is useful for testing collection loading and syncing functionality.
 */

import type { CollectionConfig } from '../types/collection-config'

export default {
  name: 'test_items',
  displayName: 'Test Items',
  description: 'Simple test collection for development and testing',
  icon: '🧪',
  color: '#8B5CF6',
  internal: true,

  schema: {
    type: 'object',
    properties: {
      title: {
        type: 'string',
        title: 'Title',
        required: true,
        maxLength: 100,
        placeholder: 'Enter item title',
        helpText: 'The main title for this test item'
      },
      description: {
        type: 'textarea',
        title: 'Description',
        maxLength: 500,
        placeholder: 'Enter description',
        helpText: 'A brief description of the test item'
      },
      status: {
        type: 'select',
        title: 'Status',
        enum: ['active', 'inactive', 'archived'],
        enumLabels: ['Active', 'Inactive', 'Archived'],
        default: 'active',
        required: true
      },
      priority: {
        type: 'number',
        title: 'Priority',
        min: 1,
        max: 10,
        default: 5,
        helpText: 'Priority from 1 (low) to 10 (high)'
      },
      isPublic: {
        type: 'checkbox',
        title: 'Public',
        default: false,
        helpText: 'Make this item publicly visible'
      },
      tags: {
        type: 'string',
        title: 'Tags',
        placeholder: 'tag1, tag2, tag3',
        helpText: 'Comma-separated tags'
      }
    },
    required: ['title', 'status']
  },

  // List view configuration
  listFields: ['title', 'status', 'priority'],
  searchFields: ['title', 'description', 'tags'],
  defaultSort: 'createdAt',
  defaultSortOrder: 'desc',

  // This collection is managed by config
  managed: true,
  isActive: true,

  // Metadata
  metadata: {
    purpose: 'testing',
    version: '1.0.0'
  }
} satisfies CollectionConfig
