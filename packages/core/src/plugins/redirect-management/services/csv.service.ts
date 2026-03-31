/**
 * CSV Service
 *
 * Handles CSV parsing and generation for redirect import/export
 */

import { parse } from 'csv-parse/browser/esm/sync'
import { sanitizeCSVField } from '../utils/csv-sanitizer.js'
import { validateUrl, detectCircularRedirect } from '../utils/validator.js'
import { normalizeUrl } from '../utils/url-normalizer.js'
import type { Redirect, CSVParseResult, CSVError, ParsedRedirectRow, MatchType, CSVValidationResult, ValidatedRedirectRow, DuplicateHandling, StatusCode } from '../types.js'

/**
 * Parse CSV content into redirect rows
 *
 * @param content - Raw CSV content string
 * @returns Parse result with rows and any errors
 *
 * @example
 * const result = parseCSV(csvContent)
 * if (result.isValid) {
 *   // Process result.rows
 * } else {
 *   // Handle result.errors
 * }
 */
export function parseCSV(content: string): CSVParseResult {
  const errors: CSVError[] = []
  const rows: ParsedRedirectRow[] = []

  try {
    // Parse CSV with headers
    const records = parse(content, {
      columns: true,
      skip_empty_lines: true,
      trim: true
    }) as Array<Record<string, string>>

    // Validate and map each row
    for (let i = 0; i < records.length; i++) {
      const lineNumber = i + 2 // +1 for 0-index, +1 for header row
      const record = records[i]!

      // Check required fields
      if (!record.source_url || !record.destination_url) {
        errors.push({
          line: lineNumber,
          error: 'Missing required fields: source_url and destination_url'
        })
        continue
      }

      // Map to ParsedRedirectRow
      rows.push({
        source_url: record.source_url,
        destination_url: record.destination_url,
        match_type: record.match_type || 'exact',
        status_code: record.status_code || '301',
        active: record.active || 'true',
        preserve_query_string: record.preserve_query_string,
        include_subdomains: record.include_subdomains,
        subpath_matching: record.subpath_matching,
        preserve_path_suffix: record.preserve_path_suffix
      })
    }
  } catch (error) {
    errors.push({
      line: 1,
      error: `CSV parsing failed: ${error instanceof Error ? error.message : 'Unknown error'}`
    })
  }

  return {
    isValid: errors.length === 0,
    rows,
    errors
  }
}

/**
 * Generate CSV content from redirect records
 *
 * @param redirects - Array of redirect records to export
 * @returns CSV content string with headers and sanitized data
 *
 * @example
 * const csv = generateCSV(redirects)
 * // Returns: "id,source_url,destination_url,match_type,..."
 */
export function generateCSV(redirects: Redirect[]): string {
  // Define headers (Cloudflare-aligned column names)
  const headers = [
    'id',
    'source_url',
    'destination_url',
    'match_type',
    'status_code',
    'active',
    'preserve_query_string',
    'include_subdomains',
    'subpath_matching',
    'preserve_path_suffix',
    'created_at',
    'updated_at'
  ]

  // Map redirects to CSV rows
  const rows = redirects.map(r => [
    r.id,
    sanitizeCSVField(r.source),
    sanitizeCSVField(r.destination),
    matchTypeToLabel(r.matchType),
    r.statusCode.toString(),
    r.isActive ? 'true' : 'false',
    r.preserveQueryString ? 'true' : 'false',
    r.includeSubdomains ? 'true' : 'false',
    r.subpathMatching ? 'true' : 'false',
    r.preservePathSuffix ? 'true' : 'false',
    new Date(r.createdAt).toISOString(),
    new Date(r.updatedAt).toISOString()
  ])

  // Build CSV content
  const csvLines = [
    headers.join(','),
    ...rows.map(row => row.join(','))
  ]

  return csvLines.join('\n')
}

/**
 * Convert match type number to text label
 *
 * @param matchType - Numeric match type (0, 1, 2)
 * @returns Text label ('exact', 'wildcard', 'regex')
 */
export function matchTypeToLabel(matchType: MatchType): string {
  switch (matchType) {
    case 0:
      return 'exact'
    case 1:
      return 'wildcard'
    case 2:
      return 'regex'
    default:
      return 'exact'
  }
}

/**
 * Convert match type label to number
 *
 * @param label - Text label or numeric string
 * @returns Numeric match type (0, 1, 2) or undefined if invalid
 */
export function labelToMatchType(label: string): MatchType | undefined {
  const normalized = label.toLowerCase().trim()

  switch (normalized) {
    case 'exact':
    case '0':
      return 0
    case 'wildcard':
    case 'partial':  // Keep backwards compatibility with old CSV exports
    case '1':
      return 1
    case 'regex':
    case '2':
      return 2
    default:
      return undefined
  }
}

/**
 * Build descriptive filename based on active filters
 *
 * @param filters - Active filter parameters
 * @returns Descriptive filename for CSV export
 *
 * @example
 * buildExportFilename({}) // "redirects.csv"
 * buildExportFilename({ statusCode: '301' }) // "redirects-301.csv"
 * buildExportFilename({ statusCode: '301', isActive: 'true' }) // "redirects-301-active.csv"
 * buildExportFilename({ matchType: '1' }) // "redirects-partial-match.csv"
 */
export function buildExportFilename(filters: {
  statusCode?: string
  matchType?: string
  isActive?: string
  search?: string
}): string {
  const parts = ['redirects']

  if (filters.statusCode) {
    parts.push(filters.statusCode)
  }

  if (filters.matchType !== undefined) {
    const labels = { '0': 'exact', '1': 'wildcard', '2': 'regex' }
    parts.push(`${labels[filters.matchType as keyof typeof labels] || filters.matchType}-match`)
  }

  if (filters.isActive === 'true') {
    parts.push('active')
  } else if (filters.isActive === 'false') {
    parts.push('inactive')
  }

  if (filters.search) {
    // Sanitize search term for filename (remove special chars)
    const sanitized = filters.search.replace(/[^a-zA-Z0-9-]/g, '').slice(0, 20)
    if (sanitized) {
      parts.push(`search-${sanitized}`)
    }
  }

  return `${parts.join('-')}.csv`
}

/**
 * Validate entire CSV batch before import (all-or-nothing)
 *
 * @param rows - Parsed CSV rows from parseCSV
 * @param existingRedirects - Map of source->destination for existing redirects
 * @param duplicateHandling - How to handle duplicates ('reject', 'skip', 'update')
 * @returns Validation result with valid rows or errors
 *
 * @example
 * const result = await validateCSVBatch(rows, existingMap, 'reject')
 * if (result.isValid) {
 *   // Import result.validRows
 * } else {
 *   // Show result.errors to user
 * }
 */
export async function validateCSVBatch(
  rows: ParsedRedirectRow[],
  existingRedirects: Map<string, string>,
  duplicateHandling: DuplicateHandling
): Promise<CSVValidationResult> {
  const errors: CSVError[] = []
  const validRows: ValidatedRedirectRow[] = []
  let skipped = 0

  // Build combined map: existing + import file (for circular detection)
  const combinedMap = new Map(existingRedirects)

  // Track sources seen in this import file (for intra-file duplicate detection)
  const seenInFile = new Set<string>()

  for (let i = 0; i < rows.length; i++) {
    const lineNumber = i + 2  // +1 for 0-index, +1 for header row
    const row = rows[i]!

    // Required field validation
    if (!row.source_url || !row.destination_url) {
      errors.push({
        line: lineNumber,
        error: 'Missing required fields: source_url and destination_url are required'
      })
      continue
    }

    // URL format validation
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

    const destValidation = validateUrl(row.destination_url)
    if (!destValidation.isValid) {
      errors.push({
        line: lineNumber,
        field: 'destination_url',
        value: row.destination_url,
        error: destValidation.error!
      })
      continue
    }

    // Parse and validate status code
    const statusCode = parseInt(row.status_code || '301')
    if (![301, 302, 307, 308, 410].includes(statusCode)) {
      errors.push({
        line: lineNumber,
        field: 'status_code',
        value: row.status_code,
        error: 'Invalid status code. Must be 301, 302, 307, 308, or 410'
      })
      continue
    }

    // Parse match type (accept both labels and numbers)
    const matchType = labelToMatchType(row.match_type || 'exact')
    if (matchType === undefined) {
      errors.push({
        line: lineNumber,
        field: 'match_type',
        value: row.match_type,
        error: 'Invalid match type. Must be exact, wildcard, regex (or 0, 1, 2)'
      })
      continue
    }

    // Normalize source for duplicate detection
    const normalizedSource = normalizeUrl(row.source_url)

    // Check for intra-file duplicates
    if (seenInFile.has(normalizedSource)) {
      if (duplicateHandling === 'reject') {
        errors.push({
          line: lineNumber,
          field: 'source_url',
          value: row.source_url,
          error: 'Duplicate source URL found earlier in this file'
        })
        continue
      } else {
        skipped++
        continue  // skip or update: skip the duplicate row in file
      }
    }

    // Check for database duplicates
    if (existingRedirects.has(normalizedSource)) {
      if (duplicateHandling === 'reject') {
        errors.push({
          line: lineNumber,
          field: 'source_url',
          value: row.source_url,
          error: 'Source URL already exists in database'
        })
        continue
      } else if (duplicateHandling === 'skip') {
        skipped++
        continue
      }
      // 'update' mode: will overwrite, continue processing
    }

    // Add to tracking sets
    seenInFile.add(normalizedSource)
    combinedMap.set(normalizedSource, row.destination_url)

    // Create validated row
    validRows.push({
      source: normalizedSource,
      destination: row.destination_url,
      matchType: matchType as MatchType,
      statusCode: statusCode as StatusCode,
      isActive: row.active?.toLowerCase() !== 'false',
      preserveQueryString: (row.preserve_query_string ?? '').toLowerCase() === 'true',
      includeSubdomains: (row.include_subdomains ?? '').toLowerCase() === 'true',
      subpathMatching: (row.subpath_matching ?? '').toLowerCase() === 'true',
      preservePathSuffix: (row.preserve_path_suffix ?? '').toLowerCase() !== 'false'  // Default true
    })
  }

  // Second pass: circular redirect detection across entire batch
  for (const validRow of validRows) {
    const lineNumber = findLineNumberForSource(rows, validRow.source)

    const circularCheck = detectCircularRedirect(
      validRow.source,
      validRow.destination,
      combinedMap
    )

    if (!circularCheck.isValid) {
      errors.push({
        line: lineNumber,
        field: 'destination_url',
        value: validRow.destination,
        error: circularCheck.error!
      })
    }
  }

  // If any errors, return empty validRows (all-or-nothing)
  return {
    isValid: errors.length === 0,
    validRows: errors.length === 0 ? validRows : [],
    errors,
    skipped
  }
}

/**
 * Helper to find line number for a source URL
 */
function findLineNumberForSource(rows: ParsedRedirectRow[], normalizedSource: string): number {
  for (let i = 0; i < rows.length; i++) {
    const row = rows[i]
    if (row && normalizeUrl(row.source_url) === normalizedSource) {
      return i + 2
    }
  }
  return 0
}

/**
 * Generate error CSV with line numbers and error messages
 *
 * @param rows - Original parsed CSV rows
 * @param errors - Validation errors to include
 * @returns CSV content string with error information
 *
 * @example
 * const errorCSV = generateErrorCSV(rows, validationResult.errors)
 * // Download as "import-errors.csv"
 */
export function generateErrorCSV(rows: ParsedRedirectRow[], errors: CSVError[]): string {
  // Map errors by line number for quick lookup
  const errorMap = new Map<number, string[]>()
  for (const err of errors) {
    const existing = errorMap.get(err.line) || []
    existing.push(err.error)
    errorMap.set(err.line, existing)
  }

  // Headers: add line_number and error columns at the start
  const headers = ['line_number', 'error', 'source_url', 'destination_url', 'match_type', 'status_code', 'active']

  const csvRows: string[] = [headers.join(',')]

  // Only include rows that have errors
  for (let i = 0; i < rows.length; i++) {
    const lineNumber = i + 2
    const rowErrors = errorMap.get(lineNumber)

    if (rowErrors) {
      const errRow = rows[i]!
      csvRows.push([
        lineNumber.toString(),
        sanitizeCSVField(rowErrors.join('; ')),
        sanitizeCSVField(errRow.source_url),
        sanitizeCSVField(errRow.destination_url),
        sanitizeCSVField(errRow.match_type),
        sanitizeCSVField(errRow.status_code),
        sanitizeCSVField(errRow.active)
      ].join(','))
    }
  }

  return csvRows.join('\n')
}
