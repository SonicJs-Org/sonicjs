# Changelog

All notable changes to the SonicJS project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Known Issues
- Cloudflare Workers deployment blocked by OpenNext.js v1.11.0 compatibility with Next.js 15.5.6
- Recommended workaround: Use Cloudflare Pages for deployment

## [2.0.10] - 2025-11-14

### Added
- **PostHog Telemetry System (Phase 1)** - Privacy-first anonymous telemetry tracking
  - Installation event tracking in create-sonicjs CLI
  - Anonymous UUID-based tracking (no PII collection)
  - Multiple opt-out mechanisms: `SONICJS_TELEMETRY=false` and `DO_NOT_TRACK=1`
  - 35 comprehensive tests for telemetry service
- **OTP Login Plugin** - One-time password authentication via email
  - Configurable OTP code length (4-8 digits)
  - Code expiration (5-60 minutes, default 10)
  - Rate limiting per hour (default 5)
  - Max verification attempts (default 3)
  - Inactive by default
- **EasyMDE Editor Plugin** - Markdown editor replacing MDXEditor
  - Dark mode styling
  - Working CDN support via unpkg
  - Plugin renamed from `mdxeditor-plugin` to `easy-mdx`
- **GitHub Actions CI/CD Pipeline**
  - Automated PR testing workflow with unit and E2E tests
  - Cloudflare Workers preview deployment for each PR
  - PR template with test checklist
- **Email Plugin Enhancements**
  - Load and display saved settings from database
  - Functional test email feature using Resend API
  - Settings persistence to database
- **TinyMCE Plugin** - Optional richtext editor
- **Quill Editor Plugin** - Modern richtext editor alternative
- Magic Link Authentication plugin for passwordless login (inactive by default)
- Core auth enhancements for plugin extensibility
- Difficulty field and improved select field handling
- Color-coded field type badges for UI clarity
- Redirect to edit mode after creating new collection

### Changed
- **Updated Vite from 5.4.20 to 7.2.2** (major version bump)
- **Default admin password changed from "sonicjs!" to "sonicjs!"**
- Replaced MDXEditor with EasyMDE for richtext fields
- Conditional field type options based on plugin activation
- Improved managed collections display with normalized naming
- Field type persistence improvements (field_type, is_required, is_searchable)
- Fallback to textarea when editor plugins are inactive

### Fixed
- All unit test failures in core package
- All 37 authentication E2E tests
- MDXEditor CDN 404 errors (no UMD builds available)
- Non-existent created_by column in content INSERT statements
- Migration API endpoint paths (404 errors)
- Content list filter options and title links
- Quill editor loading issues
- Field type dropdown empty state
- HTML escaping in data-field-data attribute
- Collection field properties persistence
- Cloudflare Workers fs.readdir error
- Duplicate ID attributes in MDX headings
- Wrangler deploy error logging

### Database Migrations
- `021_add_otp_login.sql` - OTP codes table
- `022_add_tinymce_plugin.sql`
- `023_add_mdxeditor_plugin.sql` (updated to use EasyMDE)
- `024_add_quill_editor_plugin.sql`
- `025_rename_mdxeditor_to_easy_mdx.sql`

### Security
- Changed default admin password for better security
- AuthManager.setAuthCookie() and AuthService interface exposed for plugin extensibility

## [2.0.9] - 2025-11-04

### Added
- Improved managed collections display with normalized naming
- Explicit collection registration system

### Changed
- Refactored collection management to use explicit registration
- Updated Wrangler to v4.45.4
- Removed duplicate starter template directory
- Removed experimental flag for Plugins menu

### Fixed
- Rebuild dist files with updated chunk names

## [2.0.6] - 2025-11-03

### Added
- ResponseGroup component for MDX pages
- Pre-generated sections to prevent fs.readdir error in Cloudflare Workers

### Changed
- Merged legacy sonicjs repository history
- Improved documentation and contributor workflows

### Fixed
- fs.readdir error in Cloudflare Workers by pre-generating sections
- Dynamic import for fast-glob to prevent Workers error
- Duplicate ID attributes in MDX headings
- Silenced Next.js workspace root inference warning

## [2.0.5] - 2025-10-30

### Added
- Migration warning banner for admin users
- Publishing and versioning scripts
- Database migration instructions for core package developers
- Settings general tab with database persistence and E2E tests
- Page size selector to database tools table view (default: 20 rows)
- Media cleanup and content duplicate features with E2E tests

### Changed
- Made migrations idempotent to support existing databases
- Updated package dependencies
- Improved homepage with creative design

### Fixed
- E2E test failures for media and settings
- Missing migration SQL for migrations 014-017
- Content author to use correct database column
- Skipped Workflow Dashboard e2e tests
- API endpoints e2e tests

## [2.0.3] - 2025-10-27

### Added
- Auth validation service to fix registration 500 errors
- Dynamic version management utilities from package.json

### Fixed
- Health check and login redirect test failures
- Registration 500 errors with proper auth validation
- Template improvements in core package rebuild

## [2.0.2] - 2025-10-24

### Added
- Real-time metrics tracking system
- Database tools API endpoints
- Modernized admin profile and dashboard with Catalyst design system

### Changed
- Updated plugin registry timestamp
- Cleaned up migrations and fixed TypeScript errors

### Fixed
- Removed non-functional permission middleware from user routes
- Filtered out noisy metrics endpoint logging

## [2.0.1] - 2025-10-23

### Added
- Published core package v2.0.1 to npm
- WIP notices to non-functional settings tabs
- Real-time metrics endpoint for analytics chart
- Admin dashboard route
- Dedicated endpoints for dashboard HTMX fragments

## [2.0.0] - 2025-10-22

### Added
- Core package extraction to @sonicjs-cms/core
- Complete route migration to core package
- Template migration with full integration
- Middleware, plugins, and services in core package
- Automatic migration and seeding during setup
- Custom admin credentials setup
- Update scripts to starter templates

### Changed
- Package name from @sonicjs/core to @sonicjs-cms/core
- Streamlined create-app setup flow
- Bootstrap middleware moved to monolith with collection sync
- Core package version for app version display

### Fixed
- Wrangler warnings and seedAdmin scope
- Cloudflare resource creation error handling
- Template path resolution for npm installed package
- Missing API routes (apiContentCrudRoutes, adminApiRoutes, apiSystemRoutes)

## [2.0.0-beta] - 2025-10-22

### Added
- Beta releases for testing npm package distribution
- Auto-copy migrations from core package
- Dynamic version management utilities

## [2.0.0-alpha] - 2025-10-17

### Added
- Core package npm migration
- Phase 1: Extract core functionality
- Phase 2: Add middleware, plugins, and services
- Phase 3: Complete migration with templates
- Experimental features flag enabled by default in development
- Configurable authentication fields system

### Changed
- Reorganized core plugins into consistent folder structure
- Updated for greenfield projects

## [1.0.3] - 2025-10-15

### Added
- E2E tests for plugin version display
- Collection filtering to content API

### Changed
- Standardized all plugin versions to 1.0.0-beta.1

### Fixed
- Plugin install versions display
- Media selector UX improvements

## [1.0.0] - 2025-10-14

### Added
- Media bulk actions with E2E tests
- Pre-push hook to run E2E tests before pushing
- Husky pre-commit hooks
- Dynamic plugin menu system
- Media folder creation
- Comprehensive API filtering system with 14 operators

### Changed
- Database-tools plugin activated in migration
- Made E2E tests optional on git push

### Fixed
- Media bulk action e2e test failures
- Foreign key constraints
- User management e2e tests (40/42 passing)
- Database-tools and migrations E2E tests JavaScript initialization
- Collection name in E2E test for empty collections
- Plugin E2E tests with auto-install and selector fixes
- Collections E2E test failures
- Media e2e tests (5 failing tests fixed)
- Integration test and TypeScript errors
- XSS prevention test syntax errors
- Deprecated wrangler config
- API route tests to handle isPluginActive middleware calls
- Update KV binding name from KV to CACHE_KV
- XSS vulnerability in user creation and management

## [0.6.0] - 2025-10-08

### Added
- Bulk move to folder functionality in media library
- Comprehensive documentation
- Clickable logo navigation to dashboard
- Test coverage thresholds to 90%

### Changed
- Development server port standardized to 8787
- Improved dashboard recent activity to show collections
- Replaced lightning bolt with pencil icon for edit button

### Fixed
- Dashboard storage usage showing 0 B for media files
- Media library images not loading and size calculation
- Content list row links
- Race condition showing deleted user in list
- Null check for hard delete checkbox in user deletion

## [0.5.4] - 2025-10-07

### Added
- Activity logging for content creation, updates, and deletions
- Real-time requests per second analytics to dashboard
- Recent Activity section with real database data
- Developer Docs button to dashboard
- Dynamic confirmation dialogs for content bulk actions

### Changed
- Redesigned System Health section with modern gradients and animations
- Improved logging and test coverage
- Filter out deleted content by default with opt-in viewing

### Fixed
- Dashboard template TypeScript errors
- Excluded metrics API endpoint from analytics tracking
- Disabled logging for high-frequency /admin/api/metrics endpoint
- Excluded polling endpoints from metrics tracking
- Prevented HTML escaping in dashboard system health display

## [0.4.4] - 2025-10-06

### Added
- Design System converted to plugin
- Visual status indicators to plugin cards
- Seed data generator link to plugin settings page

### Changed
- Media library view selector updated to match design guide
- Media library search input improved to match content list
- Set app version globally via middleware

### Fixed
- Plugin status borders made more visible
- Seed data service converted from Drizzle ORM to D1 Database API
- Plugin activation state preserved across server restarts
- Duplicate cache plugin resolved
- Design plugin added to registry
- Media library view selector

## [0.4.2] - 2025-10-06

### Added
- Husky pre-commit hooks
- All tests passing

### Fixed
- TypeScript build errors
- Content list row links

## [0.4.0] - 2025-10-06

### Changed
- Major refactoring and cleanup
- Version bump

## Earlier Versions (2019-2024)

### Major Milestones

#### 2024
- Continued improvements to core functionality
- Performance optimizations
- Bug fixes and stability improvements

#### 2023
- Enhanced plugin system
- Improved admin interface
- Better content management features

#### 2022
- Database optimization
- API improvements
- Security enhancements

#### 2021
- Major feature additions
- UI/UX improvements
- Performance tuning

#### 2020
- Core architecture refinements
- Plugin system enhancements
- Admin panel improvements

#### 2019
- Dynamic form rendering
- Content type system
- Field type management
- Content instance creation
- Admin UI development

#### 2018 - Project Genesis
- **August 2018**: Initial commit
- Project launched as "siteden"
- Basic CMS functionality
- Content listing features
- Surge deployment support
- Logo and branding
- Admin interface foundation

---

## Version History Summary

- **2.0.x** (2025): Modern cloud-native CMS with npm package distribution
- **1.0.x** (2025): Stable release with E2E testing and comprehensive features
- **0.6.0** (2025): Media management and bulk operations
- **0.5.x** (2025): Dashboard analytics and activity logging
- **0.4.x** (2025): Plugin system and design system
- **0.3.x** (2024): Core feature refinements
- **0.2.x** (2023): API and performance improvements
- **0.1.x** (2019-2022): Foundation and early development

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for information on how to contribute to SonicJS.

## License

MIT - See [LICENSE](../LICENSE) for details.

---

**Note**: This changelog represents a comprehensive history derived from 3,683+ commits across 7 years of development (2018-2025). For detailed commit history, see the [GitHub repository](https://github.com/lane711/sonicjs).
