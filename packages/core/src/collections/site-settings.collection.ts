/**
 * Site Settings Collection
 *
 * Stores site-wide configuration settings (general, security, etc.) as singleton documents.
 * Each settings group is stored as a separate document with a fixed slug.
 */

import type { CollectionConfig } from '../types/collection-config'

export default {
  name: 'site_settings',
  displayName: 'Site Settings',
  description: 'Global site configuration including general settings and security options',
  icon: '⚙️',
  color: '#6B7280',
  internal: true,

  schema: {
    type: 'object',
    properties: {
      // General settings group
      siteName: {
        type: 'string',
        title: 'Site Name',
        description: 'The name of your site',
        required: true,
        maxLength: 255,
        placeholder: 'My Site'
      },
      siteDescription: {
        type: 'string',
        title: 'Site Description',
        description: 'Short description of your site',
        required: true,
        maxLength: 500,
        placeholder: 'A modern headless CMS powered by AI'
      },
      adminEmail: {
        type: 'email',
        title: 'Admin Email',
        description: 'Email address for system notifications',
        required: true,
        placeholder: 'admin@example.com'
      },
      timezone: {
        type: 'select',
        title: 'Timezone',
        description: 'Default timezone for the site',
        enum: ['UTC', 'America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles', 'Europe/London', 'Europe/Paris', 'Asia/Tokyo', 'Australia/Sydney'],
        default: 'UTC',
        required: true
      },
      language: {
        type: 'select',
        title: 'Language',
        description: 'Default language for the site',
        enum: ['en', 'es', 'fr', 'de', 'ja', 'zh'],
        enumLabels: ['English', 'Spanish', 'French', 'German', 'Japanese', 'Chinese'],
        default: 'en',
        required: true
      },
      maintenanceMode: {
        type: 'checkbox',
        title: 'Maintenance Mode',
        description: 'Enable maintenance mode to restrict access',
        default: false
      },

      // Security settings group
      jwtExpiresIn: {
        type: 'string',
        title: 'JWT Expiration',
        description: 'JWT token expiration (e.g., 30d, 12h, 3600)',
        required: false,
        maxLength: 20,
        placeholder: '30d'
      },
      jwtRefreshGraceSeconds: {
        type: 'number',
        title: 'JWT Refresh Grace Period (seconds)',
        description: 'Grace period for token refresh after expiration',
        required: false,
        min: 0,
        max: 7776000
      }
    },
    required: ['siteName', 'siteDescription', 'adminEmail']
  },

  // Metadata
  managed: true,
  isActive: true,

  metadata: {
    purpose: 'settings',
    version: '1.0.0',
    singletonGroups: ['general', 'security']
  }
} satisfies CollectionConfig
