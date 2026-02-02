---
phase: 03-redirect-integration
plan: 03
subsystem: qr-generator
tags: [qr-codes, redirects, analytics, routes, hono]
dependency-graph:
  requires: [03-02]
  provides: [qr-redirect-route, scan-count-display]
  affects: [04-admin-ui]
tech-stack:
  added: []
  patterns: [route-handler, query-joins, branded-error-pages]
key-files:
  created:
    - sonicjs/my-sonicjs-app/src/plugins/qr-generator/routes/qr-redirect.ts
  modified:
    - sonicjs/my-sonicjs-app/src/plugins/qr-generator/index.ts
    - sonicjs/my-sonicjs-app/src/plugins/qr-generator/types.ts
    - sonicjs/my-sonicjs-app/src/plugins/qr-generator/services/qr.service.ts
decisions:
  - id: redirect-302-status
    choice: "302 temporary redirect for active QR codes"
    reason: "Allows destination changes without cache invalidation issues"
  - id: expired-410-status
    choice: "410 Gone with branded page for expired QR codes"
    reason: "HTTP semantically correct for permanently removed resources"
  - id: scan-count-join
    choice: "LEFT JOIN redirects and redirect_analytics in list/getById queries"
    reason: "Single query efficiency, real-time counts"
metrics:
  duration: 4 min
  completed: 2026-02-01
---

# Phase 03 Plan 03: QR Redirect Route and Scan Counts Summary

QR redirect route handler with branded expired page and scan count integration for QR code listing.

## What Was Built

### Task 1: QR Redirect Route Handler
Created `/qr/:code` route handler that:
- Queries redirects table by source path `/qr/{code}`
- Returns 302 redirect for active QR codes
- Returns 410 Gone with branded expired page for deleted/inactive codes
- Returns 404 for unknown codes

**Route Registration:**
- Registered in plugin index.ts via `builder.addRoute('/', qrRedirectRoutes, {...})`
- Priority 10 ensures QR routes are matched before catch-all routes
- Public access (no authentication required)

**Expired Page Design:**
- Gradient background matching QR generator branding
- Clean card layout with warning icon (SVG)
- Clear messaging about expired status
- Responsive and accessible

### Task 2: Scan Count Integration
Updated QR code listing to include scan counts:
- Added `scanCount?: number` to QRCode interface
- Modified `list()` with LEFT JOIN to redirects and redirect_analytics
- Modified `getById()` with same JOIN pattern for consistency
- Updated `mapRowToQRCode()` to map scan_count column

**Query Pattern:**
```sql
SELECT
  q.*, COALESCE(a.hit_count, 0) as scan_count
FROM qr_codes q
LEFT JOIN redirects r ON r.source = '/qr/' || q.short_code AND r.deleted_at IS NULL
LEFT JOIN redirect_analytics a ON r.id = a.redirect_id
WHERE q.deleted_at IS NULL
```

## Key Files

| File | Purpose |
|------|---------|
| `routes/qr-redirect.ts` | Route handler for /qr/:code with expired page |
| `index.ts` | Route registration and export |
| `types.ts` | QRCode interface with scanCount field |
| `services/qr.service.ts` | Updated list() and getById() with analytics JOIN |

## Decisions Made

1. **302 Temporary Redirect**: Using temporary redirect status allows destination URL changes without requiring cache invalidation at CDN/browser level.

2. **410 Gone for Expired**: HTTP 410 semantically indicates the resource existed but is permanently gone, which is correct for deleted QR codes.

3. **Branded Expired Page**: Clean, professional page design maintains brand consistency and provides clear messaging to users who scan expired codes.

4. **JOIN-based Scan Counts**: Using SQL JOINs in list/getById queries provides real-time counts in a single query, avoiding N+1 query problems.

## Deviations from Plan

None - plan executed exactly as written.

## Verification Results

- [x] Route handler file created
- [x] Route registered in plugin index.ts
- [x] scanCount field added to QRCode interface
- [x] list() uses JOIN with redirect_analytics
- [x] getById() uses JOIN with redirect_analytics
- [x] mapRowToQRCode maps scan_count to scanCount

## Next Phase Readiness

Phase 3 (Redirect Integration) is now complete:
- Short code generation (03-01)
- Atomic redirect operations (03-02)
- QR redirect route with scan counts (03-03)

Ready for Phase 4 (Admin UI) which will display scan counts in the QR code management interface.

## Commits

| Hash | Message |
|------|---------|
| 9297c217f | feat(03-03): add QR redirect route handler with expired page |
| a29410edd | feat(03-03): add scan count to QR code listing |
