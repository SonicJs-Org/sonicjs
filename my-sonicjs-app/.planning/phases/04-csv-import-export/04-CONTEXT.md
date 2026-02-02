# Phase 4: CSV Import/Export - Context

**Gathered:** 2026-01-30
**Status:** Ready for planning

<domain>
## Phase Boundary

Bulk redirect operations for site migrations — enabling admins to export all redirects to CSV and import large sets of redirects from CSV files. This phase focuses on data transfer; advanced features like scheduled exports or API-based CSV generation belong in other phases.

</domain>

<decisions>
## Implementation Decisions

### CSV Format and Structure
- **Column headers:** Technical names matching database fields (source_url, destination_url, status_code, match_type, active, etc.)
- **Match type representation:** Text labels (exact, partial, regex) instead of numeric codes - more human-readable
- **Field inclusion:** Export ALL fields including id, created_at, created_by, hit_count - complete data export useful for backups
- **Boolean format:** Lowercase text (true/false) following JSON/JavaScript conventions
- **Encoding:** UTF-8 with proper escaping for special characters in URLs

### Import Validation and Feedback
- **Validation timing:** All-or-nothing approach - validate entire file first, import only if 100% valid
- **Error display:** Downloadable error report CSV with error column added - allows user to fix and re-upload
- **Validations performed:**
  - URL format validation (source/destination are valid URLs)
  - Circular redirect detection across the entire import file
  - Duplicate detection within file AND against existing redirects in database
  - Status code validation (only 301/302/307/308/410 allowed)
- **Duplicate handling:** User chooses at upload time between three options:
  - Reject file (duplicates treated as errors)
  - Skip duplicates (import only new redirects)
  - Update existing (overwrite with CSV values)

### Export Options and Filtering
- **Filtering:** Export respects currently applied filters on the list page (if user filtered by 301, export only shows 301s)
- **Filename:** Descriptive based on active filters (e.g., redirects-301-active.csv, redirects-partial-match.csv)
- **UI:** Single "Export CSV" button (no separate "Export All" - user clears filters if they want all)
- **Count display:** Button shows count of redirects that will be exported ("Export CSV (247 redirects)")

### Migration Workflow
- **Preview step:** No preview - upload validates and imports immediately if valid (faster workflow)
- **UI location:** Import/Export buttons integrated into redirect list page header (not separate page)
- **Success feedback:** Show success message with count ("147 redirects imported successfully") - no table refresh or highlighting
- **File size limit:** 10MB or 10,000 rows (whichever comes first) - prevents browser/server performance issues

### Claude's Discretion
- Exact CSV parsing library choice
- Error message wording for specific validation failures
- Progress indicator during large imports
- Handling of edge cases (empty files, wrong file types, etc.)

</decisions>

<specifics>
## Specific Ideas

- "All-or-nothing validation is important - I don't want partial imports creating confusion"
- "Downloadable error CSV lets admins fix issues in bulk rather than one at a time"
- "Descriptive filenames (redirects-301-active.csv) make it easy to manage multiple exports"
- Duplicate handling choice at import time provides flexibility for different migration scenarios

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 04-csv-import-export*
*Context gathered: 2026-01-30*
