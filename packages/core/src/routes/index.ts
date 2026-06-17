/**
 * Routes Module Exports
 *
 * Routes are being migrated incrementally from the monolith.
 * Each route is refactored to remove monolith-specific dependencies.
 */

// Document model routes
export { apiDocumentsRoutes } from './api-documents'
export { adminDocumentsRoutes } from './admin-documents'

// API routes
export { default as apiRoutes } from './api'
export { default as apiContentCrudRoutes } from './api-content-crud'
export { default as apiMediaRoutes } from './api-media'
export { default as apiSystemRoutes } from './api-system'
export { default as adminApiRoutes } from './admin-api'

// Auth routes
export { default as authRoutes } from './auth'

// Test routes (only for development/test environments)
export { default as testCleanupRoutes } from './test-cleanup'

// Admin UI routes
export { default as adminContentRoutes } from './admin-content'
export { userRoutes as adminUsersRoutes } from './admin-users'
export { adminMediaRoutes } from './admin-media'
export { adminPluginRoutes } from './admin-plugins'
export { adminLogsRoutes } from './admin-logs'
export { adminCheckboxRoutes } from './admin-checkboxes'
export { adminDashboardRoutes } from './admin-dashboard'
export { adminCollectionsRoutes } from './admin-collections'
export { adminSettingsRoutes } from './admin-settings'
export { adminApiReferenceRoutes } from './admin-api-reference'

export const ROUTES_INFO = {
  message: 'Core routes available',
  available: [
    'apiRoutes',
    'apiContentCrudRoutes',
    'apiMediaRoutes',
    'apiSystemRoutes',
    'adminApiRoutes',
    'authRoutes',
    'testCleanupRoutes',
    'adminContentRoutes',
    'adminUsersRoutes',
    'adminMediaRoutes',
    'adminPluginRoutes',
    'adminLogsRoutes',
    'adminCheckboxRoutes',
    'adminDashboardRoutes',
    'adminCollectionsRoutes',
    'adminSettingsRoutes',
    'adminApiReferenceRoutes'
  ],
  status: 'Core package routes ready',
  reference: 'https://github.com/sonicjs/sonicjs'
} as const
