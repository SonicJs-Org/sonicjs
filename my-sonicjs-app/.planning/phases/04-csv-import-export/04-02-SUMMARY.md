---
phase: 04
plan: 02
subsystem: csv-export
tags: [csv, export, filters, admin-routes]
requires:
  - phase: 04
    plan: 01
    provides: csv-service-foundation
  - phase: 03
    plan: 04
    provides: admin-ui-foundation
provides:
  - csv-export-route
  - filter-aware-export
  - descriptive-filenames
affects:
  - phase: 04
    plan: 03
    needs: csv-import-route
tech-stack:
  added: []
  patterns:
    - Filter-aware CSV export
    - Descriptive filename generation based on active filters
    - Proper CSV download headers (Content-Type, Content-Disposition)
key-files:
  created: []
  modified:
    - src/plugins/redirect-management/services/csv.service.ts
    - src/plugins/redirect-management/routes/admin.ts
decisions:
  - name: Export up to 10,000 redirects without pagination
    rationale: Balance between completeness and safety - prevents memory issues while allowing large exports
  - name: Place export route before /:id routes
    rationale: Prevents 'export' from being matched as an :id parameter
  - name: Reuse exact filter logic from list route
    rationale: Consistency ensures export matches what admin sees in filtered list
duration: 2min
completed: 2026-01-31
---

# Phase 04 Plan 02: CSV Export Route Summary

**One-liner:** Filter-aware CSV export endpoint with descriptive filenames generated from active filters (redirects-301-active.csv)

## What Was Built

Implemented CSV export functionality that respects the admin's current list filters:

1. **buildExportFilename Function** (`csv.service.ts`)
   - Generates descriptive filenames based on active filters
   - Examples: `redirects.csv`, `redirects-301.csv`, `redirects-301-active.csv`, `redirects-partial-match.csv`
   - Sanitizes search terms for safe filename inclusion (removes special chars, max 20 chars)
   - Handles all filter types: statusCode, matchType, isActive, search

2. **GET /admin/redirects/export Route** (`admin.ts`)
   - Accepts filter parameters: statusCode, matchType, isActive, search
   - Exports up to 10,000 redirects (safety limit to prevent memory issues)
   - Removes pagination to export all matching redirects
   - Returns CSV with proper download headers
   - Content-Type: `text/csv; charset=utf-8`
   - Content-Disposition: `attachment; filename="[descriptive-name].csv"`

## Implementation Details

### Filter Parameter Handling
The export route uses identical filter parsing logic as the list route:
- Validates statusCode against allowed values (301, 302, 307, 308, 410)
- Validates matchType against valid enum values (0, 1, 2)
- Parses isActive as boolean from string 'true'/'false'
- Passes search term directly to service

### Filename Generation Logic
```typescript
// No filters: redirects.csv
// Status 301: redirects-301.csv
// Active only: redirects-active.csv
// Status 301 + Active: redirects-301-active.csv
// Match type partial: redirects-partial-match.csv
// Search term: redirects-search-sanitized.csv
```

Parts are joined with hyphens in order:
1. Base: "redirects"
2. Status code (if filtered)
3. Match type + "-match" (if filtered)
4. "active" or "inactive" (if filtered)
5. "search-[term]" (if searching, sanitized and truncated)

### Export Flow
1. Parse query parameters from request
2. Build RedirectFilter object (same as list route)
3. Set limit=10000, offset=0 (no pagination)
4. Fetch redirects via RedirectService.list(filter)
5. Generate CSV via generateCSV(redirects)
6. Build filename via buildExportFilename(filters)
7. Return Response with CSV content and download headers

### Route Placement
Export route placed BEFORE `/new` route to prevent 'export' from being matched as an :id parameter. Route order matters in Hono routing.

## Decisions Made

**1. Export up to 10,000 redirects without pagination**
- Removes pagination to export all matching redirects
- Safety limit of 10,000 prevents memory exhaustion in Workers environment
- Reasonable for most use cases (typical sites have < 1000 redirects)
- Future enhancement could add streaming for larger datasets

**2. Place export route before /:id routes**
- Prevents route parameter matching conflict
- 'export' would match /:id pattern if placed after
- Follows best practice of specific routes before parameterized routes

**3. Reuse exact filter logic from list route**
- Ensures export matches what admin sees in filtered list
- No surprises - "export what I see" is intuitive UX
- Maintains consistency between UI and export functionality

**4. Pass filter params to filename builder**
- Filenames describe content (redirects-301-active.csv)
- Helps admins organize multiple exports
- Better than generic timestamp-based names

## Key Patterns Established

**Filter-Aware Export:**
```typescript
// Build filter from query params (same as list route)
const filter: RedirectFilter = {}
if (statusCodeParam && ['301', '302', '307', '308', '410'].includes(statusCodeParam)) {
  filter.statusCode = parseInt(statusCodeParam) as StatusCode
}
// ... other filters

// Export with filters applied
const redirects = await service.list(filter)
const csv = generateCSV(redirects)
```

**Descriptive Filename Generation:**
```typescript
const filename = buildExportFilename({
  statusCode: statusCodeParam,
  matchType: matchTypeParam,
  isActive: isActiveParam,
  search
})
// Returns: "redirects-301-active.csv"
```

**Proper CSV Download Headers:**
```typescript
return new Response(csv, {
  status: 200,
  headers: {
    'Content-Type': 'text/csv; charset=utf-8',
    'Content-Disposition': `attachment; filename="${filename}"`
  }
})
```

## Testing Notes

TypeScript compilation successful - no errors in redirect-management admin.ts or csv.service.ts.

Pre-existing TypeScript errors in other files (blog-posts collection, contact-form plugin) are unrelated to this implementation.

Manual testing recommended:
1. Visit `/admin/redirects/export` - should download `redirects.csv`
2. Visit `/admin/redirects/export?statusCode=301` - should download `redirects-301.csv`
3. Visit `/admin/redirects/export?statusCode=301&isActive=true` - should download `redirects-301-active.csv`
4. Verify CSV opens correctly in Excel/Google Sheets
5. Verify exported data matches filtered list view

## Deviations from Plan

None - plan executed exactly as written.

## Next Phase Readiness

**Ready for 04-03 (CSV Import Route):**
- Export route pattern established
- Filter parsing logic can be reused
- CSV service functions ready for import flow
- Form upload handling will follow similar error pattern as create/update routes

**Blockers/Concerns:**
None. Export route complete and ready for testing.

## Commits

| Commit | Type | Description |
|--------|------|-------------|
| 1d46818 | feat | Add buildExportFilename function to CSV service |
| 89be342 | feat | Add CSV export route to redirect admin |

## Related Files

**Modified:**
- `src/plugins/redirect-management/services/csv.service.ts` - Added buildExportFilename function
- `src/plugins/redirect-management/routes/admin.ts` - Added GET /export route with filter support

## Success Metrics

- ✅ TypeScript compiles without errors in modified files
- ✅ buildExportFilename exported from csv.service.ts
- ✅ GET /admin/redirects/export route exists
- ✅ Route placed before /:id routes to avoid parameter conflicts
- ✅ Export respects filter parameters (statusCode, matchType, isActive, search)
- ✅ Filename is descriptive based on active filters
- ✅ Proper Content-Type header (text/csv; charset=utf-8)
- ✅ Proper Content-Disposition header with filename
- ✅ Filter logic matches list route for consistency
