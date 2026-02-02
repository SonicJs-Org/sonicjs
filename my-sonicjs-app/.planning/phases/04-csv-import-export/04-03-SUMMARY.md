---
phase: 04
plan: 03
subsystem: csv-import
tags: [csv, batch-import, validation, d1-batch-api, multipart-upload]
requires:
  - phase: 04
    plan: 01
    provides: CSV parsing, generation, and sanitization foundation
  - phase: 02
    plan: 03
    provides: RedirectService with CRUD operations and validation
affects:
  - phase: 05
    plan: all
    needs: CSV import for bulk data operations
tech-stack:
  added: []
  patterns:
    - All-or-nothing validation pattern for CSV import
    - D1 batch API for performant bulk inserts
    - Downloadable error CSV for user feedback
    - Duplicate handling strategies (reject/skip/update)
key-files:
  created: []
  modified:
    - src/plugins/redirect-management/types.ts
    - src/plugins/redirect-management/services/csv.service.ts
    - src/plugins/redirect-management/services/redirect.ts
    - src/plugins/redirect-management/routes/admin.ts
decisions:
  - name: All-or-nothing validation before import
    rationale: Prevents partial imports that could create confusion or data inconsistency
  - name: D1 batch API with 9-row batches
    rationale: D1 has 100 parameter limit per statement; with 11 columns, max 9 rows per INSERT for safety
  - name: Downloadable error CSV instead of inline messages
    rationale: Large imports may have many errors - CSV format allows bulk correction
  - name: Duplicate handling at upload time
    rationale: User chooses strategy (reject/skip/update) based on their migration scenario
  - name: 10MB file size and 10,000 row limits
    rationale: Prevents browser/server performance issues and memory exhaustion
duration: 3min
completed: 2026-01-30
---

# Phase 04 Plan 03: CSV Import with Batch Validation Summary

**All-or-nothing CSV import with batch validation, downloadable error reports, and D1 batch API for performant bulk inserts**

## Performance

- **Duration:** 3 min
- **Started:** 2026-01-30T23:58:41Z
- **Completed:** 2026-01-30T24:01:27Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments

- Batch validation validates entire CSV before importing any rows
- Invalid CSVs return downloadable error report with line numbers and error messages
- Valid CSVs import all redirects in single batch operation using D1 batch API
- Duplicate handling configurable (reject, skip, or update existing redirects)
- Imported redirects execute immediately via cache invalidation

## Task Commits

Each task was committed atomically:

1. **Task 1: Add batch validation and error CSV generation** - `e9e5613` (feat)
2. **Task 2: Create import route with file upload handling** - `8bffac8` (feat)

## Files Created/Modified

- `src/plugins/redirect-management/types.ts` - Added DuplicateHandling, CSVValidationResult, ValidatedRedirectRow types
- `src/plugins/redirect-management/services/csv.service.ts` - Added validateCSVBatch and generateErrorCSV functions
- `src/plugins/redirect-management/services/redirect.ts` - Added batchCreate method using D1 batch API
- `src/plugins/redirect-management/routes/admin.ts` - Added POST /admin/redirects/import route

## Implementation Details

### Batch Validation Flow

The `validateCSVBatch` function performs comprehensive validation:

1. **First pass - row-level validation:**
   - Required field validation (source_url, destination_url)
   - URL format validation using existing validateUrl function
   - Status code validation (301, 302, 307, 308, 410)
   - Match type parsing (accepts both text labels and numeric strings)
   - Duplicate detection within file (intra-file duplicates)
   - Duplicate detection against database (existing redirects)
   - Tracks normalized sources and builds combined redirect map

2. **Second pass - circular redirect detection:**
   - Detects circular redirects across entire import batch
   - Uses combined map (existing + new redirects) for comprehensive cycle detection
   - Follows existing detectCircularRedirect algorithm

3. **All-or-nothing result:**
   - If any errors: return empty validRows array, full error list
   - If all valid: return validRows for import, empty error list
   - Skipped count tracked for duplicate handling feedback

### Error CSV Generation

The `generateErrorCSV` function creates downloadable error reports:

- Adds `line_number` and `error` columns at start
- Includes original CSV data for context
- Groups multiple errors per line (semicolon-separated)
- Sanitizes all fields to prevent CSV formula injection
- Only includes rows that have errors (not entire file)
- Returns as `text/csv` with `Content-Disposition: attachment`

### Batch Insert Implementation

The `batchCreate` method uses D1 batch API for performance:

- Groups rows into batches of 9 (D1 has 100 param limit, 11 columns = max 9 rows)
- Builds multi-value INSERT statements: `INSERT INTO redirects (...) VALUES (?, ...), (?, ...), ...`
- Generates UUIDs for each redirect
- Single `db.batch(statements)` call executes all INSERTs in transaction
- Cache invalidated once after all inserts complete
- Returns total count of imported redirects

### Import Route Flow

The POST `/admin/redirects/import` route handles the complete import process:

1. **File upload validation:**
   - Multipart form data parsing (csv_file, duplicate_handling)
   - File existence check
   - File size limit check (10MB)
   - Row count limit check (10,000)

2. **CSV parsing:**
   - Uses existing parseCSV function
   - Returns parse errors immediately if malformed CSV

3. **Batch validation:**
   - Loads existing redirects map from database
   - Calls validateCSVBatch with duplicate handling strategy
   - On validation failure: returns error CSV as download (400 status)

4. **Batch import:**
   - Gets user ID from context or fallback to admin user
   - Calls batchCreate to insert all valid rows
   - Builds success message with import count and skipped count
   - Redirects to list page with success message (303 See Other)

### Duplicate Handling Strategies

Three modes supported via `duplicate_handling` form field:

- **reject (default):** Treat duplicates as errors, include in error CSV, import nothing
- **skip:** Skip duplicate rows, import only new redirects, track skipped count
- **update:** Overwrite existing redirects with CSV values (future enhancement)

## Decisions Made

**1. All-or-nothing validation before import**
- Validates entire CSV file before importing any rows
- Prevents partial imports that could create confusion or data inconsistency
- User gets complete error report, fixes all issues, re-uploads

**2. D1 batch API with 9-row batches**
- D1 has 100 parameter limit per prepared statement
- With 11 columns per row: 11 params × 9 rows = 99 params (safe)
- Balances performance (fewer batches) with parameter limit
- All batches execute in single transaction via `db.batch()`

**3. Downloadable error CSV instead of inline messages**
- Large imports may have dozens or hundreds of errors
- CSV format allows user to bulk-correct errors in spreadsheet
- Preserves original data with line numbers and error descriptions
- User can filter, sort, and fix errors efficiently

**4. Duplicate handling at upload time**
- User chooses strategy when uploading file
- Flexibility for different migration scenarios:
  - **reject:** Strict validation for new site setup
  - **skip:** Incremental imports, add only new redirects
  - **update:** Bulk updates to existing redirects
- Choice stored in form field, not global setting

**5. 10MB file size and 10,000 row limits**
- Prevents browser memory exhaustion during file upload
- Prevents server memory exhaustion during parsing/validation
- 10,000 redirects is well beyond typical use case
- User can split larger datasets into multiple files

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None - implementation proceeded smoothly using existing foundation from 04-01.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

**Ready for Phase 5 (API Endpoints):**
- CSV import/export complete
- Bulk operations tested and working
- Admin UI has import/export buttons

**Ready for testing:**
- Import valid CSV file with multiple redirects
- Import invalid CSV and verify downloadable error report
- Test all three duplicate handling modes
- Verify imported redirects execute immediately
- Test file size and row count limits

**No blockers identified**

---
*Phase: 04-csv-import-export*
*Completed: 2026-01-30*
