# Phase 3: Admin UI - Context

**Gathered:** 2026-01-30
**Status:** Ready for planning

<domain>
## Phase Boundary

Admin interface for managing redirects — creating, editing, viewing, searching, filtering, and deleting redirect rules. Admins need full CRUD capabilities without touching code or database directly.

This phase builds on the redirect engine from Phase 2. Bulk operations (CSV) and programmatic access (API) are separate phases.

</domain>

<decisions>
## Implementation Decisions

### Form Design & Validation

**Page Structure:**
- Separate pages for create and edit (not modal or inline)
- Navigate to `/admin/redirects/new` for creation
- Navigate to `/admin/redirects/:id/edit` for editing
- Standard admin pattern with full space for form fields

**Field Organization:**
- Group fields by purpose into 3 sections:
  - Section 1: URLs (Source URL, Destination URL)
  - Section 2: Behavior (Status Code, Match Type)
  - Section 3: Options (Query Params checkboxes, Active toggle)

**Validation Timing:**
- Hybrid approach:
  - Real-time validation: URL format, required fields (on blur)
  - Submit-time validation: Circular redirect detection (requires API call)
- Show errors immediately where possible, defer expensive checks to submit

**Help & Guidance:**
- Inline help text for all fields
- Placeholder examples in fields (e.g., `/old-page` for source URL)
- Help text below complex fields (Match Type explanation, Query Params behavior)
- Assume admin knows redirect concepts, but provide examples

### List View & Data Display

**Layout:**
- Table layout (not cards or compact list)
- Traditional data table with clear column headers
- Good for scanning many rows and comparing values

**Columns:**
- Full visibility approach, show all key info:
  1. Source URL
  2. Destination URL
  3. Status Code (with badge/color coding)
  4. Match Type
  5. Active (toggle or indicator)
  6. Hit Count (if available from Phase 2 analytics)
  7. Actions (Edit, Delete buttons)

**URL Display:**
- Truncate long URLs with ellipsis after ~50 characters
- Hover to see full URL in tooltip
- Keeps table width manageable

**Sorting:**
- All columns sortable (click header to sort)
- Include Status Code, Match Type, Active, Hit Count
- Default sort: newest first (created_at DESC)

### Search & Filtering

**UI Structure:**
- Combined filter bar (search box + filter chips)
- Search box searches across source and destination URLs
- Filter chips show active filters visually (e.g., "Status: 301", "Active: Yes")
- Easy to see what's filtered and clear individual filters

**Filter Timing:**
- Debounced real-time filtering
- Wait ~300ms after user stops typing before applying filter
- Responsive feel without excessive API calls

**Available Filters:**
- Extended filter set matching all database fields:
  - Active status (Yes/No/All)
  - Status Code (301/302/307/308/410/All)
  - Match Type (Exact/Partial/Regex/All)
- Full query capability for admins

**Clear Filters:**
- "Clear all filters" button appears only when filters are active
- Shows when action is possible, cleaner UI when no filters
- Can also remove individual filters by clicking X on filter chips

### Delete & Destructive Actions

**Delete Confirmation:**
- Modal dialog on delete action
- "Are you sure?" with redirect details
- Confirm/Cancel buttons (clear primary action)

**Confirmation Content:**
- Show impact information:
  - Redirect being deleted (source → destination)
  - Hit count if available: "This redirect has been used 342 times"
  - Warning: "This action cannot be undone"
- Helps admin make informed decision

**Bulk Delete:**
- Yes, support bulk delete with checkboxes
- Checkbox per row in table
- "Delete selected" button appears when items checked
- Efficient for cleanup tasks

**Bulk Confirmation:**
- Count only for bulk delete: "Delete 5 redirects? This cannot be undone."
- Simple, fast to scan
- Don't list all items being deleted (overwhelming for large selections)

</decisions>

<specifics>
## Specific Ideas

No specific product references mentioned. UI should follow standard SonicJS admin patterns and conventions established in existing plugins.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 03-admin-ui*
*Context gathered: 2026-01-30*
