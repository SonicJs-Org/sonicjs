// Version configuration for the SonicJS documentation site
// This file provides a single source of truth for version information
//
// NOTE: This version is automatically kept in sync with packages/core/package.json
// When releasing a new version, run `npm run version:patch` (or minor/major) from the root
// which will update this file via scripts/sync-versions.js

export const VERSION = '2.8.0'

// Helper function to get the current month/year for "Last updated"
export function getLastUpdatedDate(): string {
  const now = new Date()
  const months = [
    'January',
    'February',
    'March',
    'April',
    'May',
    'June',
    'July',
    'August',
    'September',
    'October',
    'November',
    'December',
  ]
  return `${months[now.getMonth()]} ${now.getFullYear()}`
}
