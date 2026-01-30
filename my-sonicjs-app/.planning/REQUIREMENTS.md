# Requirements: SonicJS Redirect Plugin

**Defined:** 2026-01-30
**Core Value:** Reliable, performant URL redirection that preserves SEO value

## v1 Requirements

Requirements for initial release. Each maps to roadmap phases.

### Core Redirect Management

- [ ] **REDIR-01**: Admin can create redirect with source URL, destination URL, match type (exact), and HTTP status code
- [ ] **REDIR-02**: Admin can edit existing redirect configuration
- [ ] **REDIR-03**: Admin can delete redirect
- [ ] **REDIR-04**: Admin can toggle redirect active/inactive status
- [ ] **REDIR-05**: Admin can view list of all redirects with search and filter
- [ ] **REDIR-06**: System warns when creating redirect with duplicate source URL

### Validation

- [ ] **VALID-01**: System detects and prevents circular redirects (A→B→A) before saving
- [ ] **VALID-02**: System detects redirect chains (A→B→C) and warns admin
- [ ] **VALID-03**: System validates URL format for source and destination URLs
- [ ] **VALID-04**: System normalizes URLs (handles trailing slashes, case sensitivity) for consistent matching

### HTTP Status Codes

- [ ] **STATUS-01**: Redirect supports 301 (Moved Permanently) status code
- [ ] **STATUS-02**: Redirect supports 302 (Found/Temporary) status code
- [ ] **STATUS-03**: Redirect supports 307 (Temporary Redirect) status code
- [ ] **STATUS-04**: Redirect supports 308 (Permanent Redirect) status code
- [ ] **STATUS-05**: Redirect supports 410 (Gone) status code

### CSV Operations

- [ ] **CSV-01**: Admin can export all redirects to CSV file
- [ ] **CSV-02**: Admin can import redirects from CSV file
- [ ] **CSV-03**: System validates CSV format and redirect data during import
- [ ] **CSV-04**: System shows actionable error messages with line numbers for CSV import failures

### Analytics

- [ ] **ANALYT-01**: System tracks hit count per redirect
- [ ] **ANALYT-02**: Admin can view hit count for each redirect in list view
- [ ] **ANALYT-03**: System updates hit count asynchronously without blocking redirect execution

### API Integration

- [ ] **API-01**: Plugin exposes API endpoint to create redirect programmatically
- [ ] **API-02**: Plugin exposes API endpoint to read redirect by ID
- [ ] **API-03**: Plugin exposes API endpoint to update redirect
- [ ] **API-04**: Plugin exposes API endpoint to delete redirect
- [ ] **API-05**: Plugin exposes API endpoint to list all redirects with filtering

### Redirect Execution

- [ ] **EXEC-01**: Middleware intercepts incoming requests before routing
- [ ] **EXEC-02**: System looks up redirect rule for incoming URL
- [ ] **EXEC-03**: System executes redirect with configured HTTP status code
- [ ] **EXEC-04**: System caches redirect lookups in memory for sub-millisecond performance
- [ ] **EXEC-05**: System increments hit count when redirect executes

### Admin UI

- [ ] **UI-01**: Admin menu includes "Redirects" link
- [ ] **UI-02**: Redirect creation form with all required fields
- [ ] **UI-03**: Redirect edit form with all fields editable
- [ ] **UI-04**: Redirect list view with search, filter, and sort capabilities
- [ ] **UI-05**: Delete confirmation modal prevents accidental deletion
- [ ] **UI-06**: CSV upload interface with file selection and validation feedback
- [ ] **UI-07**: CSV download button exports all redirects

### Audit Trail

- [ ] **AUDIT-01**: System records last updated timestamp for each redirect
- [ ] **AUDIT-02**: System records which user last updated each redirect
- [ ] **AUDIT-03**: Admin can view audit information in redirect details

## v2 Requirements

Deferred to future release. Tracked but not in current roadmap.

### Performance Optimization

- **PERF-01**: Cloudflare bulk redirect integration for edge-level redirects
- **PERF-02**: Automatic offloading of simple redirects to Cloudflare
- **PERF-03**: Cloudflare API rate limit handling (1,200 req/5min)

### Monitoring & Detection

- **MONITOR-01**: 404 error detection and logging
- **MONITOR-02**: Suggest redirects for common 404 URLs

### Advanced Matching

- **MATCH-01**: Wildcard pattern matching (e.g., /blog/* → /articles/*)
- **MATCH-02**: Regex pattern support for complex URL transformations
- **MATCH-03**: Path/query parameter preservation during redirect
- **MATCH-04**: Priority/ordering system for overlapping patterns

### Enhanced UX

- **UX-01**: Bulk edit operations (update multiple redirects at once)
- **UX-02**: Redirect preview/testing interface
- **UX-03**: Redirect expiration dates for temporary campaigns

## Out of Scope

Explicitly excluded. Documented to prevent scope creep.

| Feature | Reason |
|---------|--------|
| Real-time advanced analytics (referrer, user agent, timestamps) | Over-engineering; future analytics plugin can hook into redirect events for deeper metrics |
| A/B testing redirects | Adds complexity and unpredictability; use dedicated A/B testing tools |
| User-level redirect rules | Database overhead, caching nightmare, SEO confusion |
| Historical redirect versioning | Database bloat; use git for redirect CSV exports instead |
| Complex conditional logic (if/then/else) | Makes debugging impossible, hurts performance |
| Automatic AI-suggested redirects | False positives, loss of control; suggest but require human approval |
| Redirect chains (A→B→C) | Wastes crawl budget, dilutes link equity; detect and warn instead |

## Traceability

Which phases cover which requirements. Updated during roadmap creation.

| Requirement | Phase | Status |
|-------------|-------|--------|
| REDIR-01 | Phase 2 | Complete |
| REDIR-02 | Phase 2 | Complete |
| REDIR-03 | Phase 2 | Complete |
| REDIR-04 | Phase 2 | Complete |
| REDIR-05 | Phase 2 | Complete |
| REDIR-06 | Phase 2 | Complete |
| VALID-01 | Phase 2 | Complete |
| VALID-02 | Phase 2 | Complete |
| VALID-03 | Phase 2 | Complete |
| VALID-04 | Phase 2 | Complete |
| STATUS-01 | Phase 2 | Complete |
| STATUS-02 | Phase 2 | Complete |
| STATUS-03 | Phase 2 | Complete |
| STATUS-04 | Phase 2 | Complete |
| STATUS-05 | Phase 2 | Complete |
| CSV-01 | Phase 4 | Pending |
| CSV-02 | Phase 4 | Pending |
| CSV-03 | Phase 4 | Pending |
| CSV-04 | Phase 4 | Pending |
| ANALYT-01 | Phase 6 | Pending |
| ANALYT-02 | Phase 6 | Pending |
| ANALYT-03 | Phase 6 | Pending |
| API-01 | Phase 5 | Pending |
| API-02 | Phase 5 | Pending |
| API-03 | Phase 5 | Pending |
| API-04 | Phase 5 | Pending |
| API-05 | Phase 5 | Pending |
| EXEC-01 | Phase 2 | Complete |
| EXEC-02 | Phase 2 | Complete |
| EXEC-03 | Phase 2 | Complete |
| EXEC-04 | Phase 2 | Complete |
| EXEC-05 | Phase 2 | Complete |
| UI-01 | Phase 3 | Pending |
| UI-02 | Phase 3 | Pending |
| UI-03 | Phase 3 | Pending |
| UI-04 | Phase 3 | Pending |
| UI-05 | Phase 3 | Pending |
| UI-06 | Phase 3 | Pending |
| UI-07 | Phase 3 | Pending |
| AUDIT-01 | Phase 6 | Pending |
| AUDIT-02 | Phase 6 | Pending |
| AUDIT-03 | Phase 6 | Pending |

**Coverage:**
- v1 requirements: 36 total
- Mapped to phases: 36 (100% coverage)
- Unmapped: 0

---
*Requirements defined: 2026-01-30*
*Last updated: 2026-01-30 after roadmap creation*
