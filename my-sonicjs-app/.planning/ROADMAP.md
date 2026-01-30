# Roadmap: SonicJS Redirect Plugin

## Overview

This roadmap delivers a redirect management plugin for SonicJS across 6 phases. Starting with the foundational plugin structure and collection schema, we build the core redirect engine with validation and middleware execution, then layer on the admin UI, bulk CSV operations, programmatic API access, and finally analytics/audit capabilities. Each phase delivers a coherent, verifiable capability that builds upon the previous foundation.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: Foundation & Plugin Structure** - Plugin scaffold, collection schema, database migrations
- [x] **Phase 2: Core Redirect Engine** - Redirect execution, validation, middleware, caching
- [ ] **Phase 3: Admin UI** - Forms, list views, search, filters, delete confirmations
- [ ] **Phase 4: CSV Import/Export** - Bulk operations for site migrations
- [ ] **Phase 5: API Endpoints** - Programmatic redirect management for other plugins
- [ ] **Phase 6: Analytics & Audit Trail** - Hit tracking and user audit information

## Phase Details

### Phase 1: Foundation & Plugin Structure
**Goal**: Plugin infrastructure is set up with collection schema and database ready for redirect storage
**Depends on**: Nothing (first phase)
**Requirements**: Foundation for all other requirements
**Plans**: 2 plans
**Success Criteria** (what must be TRUE):
  1. Plugin is registered and appears in SonicJS plugin system
  2. Redirects collection schema is defined with all required fields (source, destination, match type, status code, active)
  3. Database migrations create redirects table in D1
  4. Plugin lifecycle hooks (onLoad, onReady) execute without errors

Plans:
- [x] 01-01-PLAN.md — Plugin scaffold, types, service, and database migration
- [x] 01-02-PLAN.md — Wire plugin into application (gap closure)

### Phase 2: Core Redirect Engine
**Goal**: Redirects execute reliably with validation, caching, and middleware interception
**Depends on**: Phase 1
**Requirements**: REDIR-01, REDIR-02, REDIR-03, REDIR-04, REDIR-05, REDIR-06, VALID-01, VALID-02, VALID-03, VALID-04, STATUS-01, STATUS-02, STATUS-03, STATUS-04, STATUS-05, EXEC-01, EXEC-02, EXEC-03, EXEC-04, EXEC-05
**Plans**: 4 plans
**Success Criteria** (what must be TRUE):
  1. User visiting source URL is redirected to destination URL with correct HTTP status code
  2. Redirect lookup completes in sub-millisecond time (cache hit) or under 10ms (cache miss)
  3. System prevents circular redirects before saving (A->B->A blocked)
  4. System detects redirect chains and warns admin (A->B->C detected)
  5. Inactive redirects do not execute (only active redirects trigger)

Plans:
- [x] 02-01-PLAN.md — URL normalization utilities and LRU cache wrapper
- [x] 02-02-PLAN.md — Validation and circular redirect detection
- [x] 02-03-PLAN.md — Redirect service CRUD operations with validation
- [x] 02-04-PLAN.md — Redirect middleware and application integration

### Phase 3: Admin UI
**Goal**: Admins can create, edit, view, search, filter, and delete redirects via admin interface
**Depends on**: Phase 2
**Requirements**: UI-01, UI-02, UI-03, UI-04, UI-05, UI-06, UI-07
**Plans**: 4 plans
**Success Criteria** (what must be TRUE):
  1. Admin can click "Redirects" link in admin menu and see redirect management page
  2. Admin can create new redirect using form with all required fields (source, destination, match type, status code, active toggle)
  3. Admin can edit existing redirect and changes are saved and take effect
  4. Admin can search/filter redirect list by source URL, destination URL, status code, or active status
  5. Admin can delete redirect with confirmation modal preventing accidental deletion

Plans:
- [ ] 03-01-PLAN.md — Admin redirect list page with route handlers and table template
- [ ] 03-02-PLAN.md — Create and edit forms with validation and HTMX submission
- [ ] 03-03-PLAN.md — Delete confirmation modals and bulk delete functionality
- [ ] 03-04-PLAN.md — Search/filter bar with debounce and filter chips

### Phase 4: CSV Import/Export
**Goal**: Admins can bulk import and export redirects via CSV for site migrations
**Depends on**: Phase 2
**Requirements**: CSV-01, CSV-02, CSV-03, CSV-04
**Success Criteria** (what must be TRUE):
  1. Admin can click "Export CSV" button and download file containing all redirects
  2. Admin can upload CSV file with bulk redirects and see validation feedback
  3. System validates CSV format and shows actionable error messages with line numbers when validation fails
  4. System imports valid redirects in batch and they execute immediately after import
**Plans**: TBD

Plans:
- [ ] 04-01: TBD during planning

### Phase 5: API Endpoints
**Goal**: Other plugins can programmatically create, read, update, delete, and list redirects via API
**Depends on**: Phase 2
**Requirements**: API-01, API-02, API-03, API-04, API-05
**Success Criteria** (what must be TRUE):
  1. Plugin (e.g., QR code plugin) can POST to API endpoint to create redirect programmatically
  2. Plugin can GET redirect by ID to read configuration
  3. Plugin can PUT to API endpoint to update redirect
  4. Plugin can DELETE redirect via API
  5. Plugin can list all redirects with filtering (by status, active state, etc.)
**Plans**: TBD

Plans:
- [ ] 05-01: TBD during planning

### Phase 6: Analytics & Audit Trail
**Goal**: Admins can view hit counts for redirects and see who last updated each redirect
**Depends on**: Phase 2
**Requirements**: ANALYT-01, ANALYT-02, ANALYT-03, AUDIT-01, AUDIT-02, AUDIT-03
**Success Criteria** (what must be TRUE):
  1. System tracks hit count for each redirect execution without blocking redirect performance
  2. Admin can view hit count for each redirect in list view
  3. Admin can view last updated timestamp and user for each redirect
  4. Hit count increments asynchronously (redirect executes immediately, tracking happens in background)
**Plans**: TBD

Plans:
- [ ] 06-01: TBD during planning

## Progress

**Execution Order:**
Phases execute in numeric order: 1 -> 2 -> 3 -> 4 -> 5 -> 6

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Foundation & Plugin Structure | 2/2 | Complete | 2026-01-30 |
| 2. Core Redirect Engine | 4/4 | Complete | 2026-01-30 |
| 3. Admin UI | 0/4 | Planned | - |
| 4. CSV Import/Export | 0/0 | Not started | - |
| 5. API Endpoints | 0/0 | Not started | - |
| 6. Analytics & Audit Trail | 0/0 | Not started | - |
