# Phase 3: Admin UI - Research

**Researched:** 2026-01-30
**Domain:** Server-rendered admin interfaces with HTMX and Tailwind CSS
**Confidence:** HIGH

## Summary

This phase requires building an admin interface for redirect management using SonicJS's established patterns: server-rendered HTML templates with HTMX for interactivity, Tailwind CSS for styling, and Hono routes for request handling. The codebase already contains comprehensive template utilities for forms, tables, filters, pagination, and confirmation dialogs that follow Catalyst design system conventions.

The standard approach is to create dedicated route handlers that render full HTML pages using the existing template system. Forms submit via HTMX with hybrid validation (real-time for format, submit-time for business logic). List views use sortable tables with filter bars, debounced search (300ms), and bulk selection checkboxes. Delete operations use native HTML `<dialog>` modals with typed confirmation for safety.

Key findings show that SonicJS templates already implement 2026 best practices: native dialog elements for accessibility, server-side state management via HTMX, Tailwind CSS utility classes for consistent styling, and reusable template functions for common UI patterns. The redirect admin UI should follow these existing patterns exactly rather than introducing new patterns.

**Primary recommendation:** Use existing SonicJS template components (form.template.ts, table.template.ts, filter-bar.template.ts, confirmation-dialog.template.ts, pagination.template.ts) composed into new redirect-specific page templates rendered by Hono routes.

## Standard Stack

The established libraries/tools for this domain:

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Hono | 4.11+ | Web routing and request handling | SonicJS's chosen web framework, already integrated |
| HTMX | 2.0.3 | HTML-over-the-wire interactivity | Powers all admin UI without frontend build step |
| Tailwind CSS | 2.2.19 (CDN) | Utility-first styling | Used consistently across all SonicJS admin templates |
| TypeScript | 5.8+ | Type-safe template functions | All SonicJS templates are TypeScript functions |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| HTML Dialog Element | Native | Confirmation modals | Delete confirmations, destructive actions (built-in accessibility) |
| Tailwind Plus Elements | 1.x (CDN) | Dialog component enhancement | Adds backdrop animations and WCAG focus management |
| Drizzle ORM | 0.44+ | Database queries in routes | Already used for all data access |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Server templates | React/Vue SPA | Would break SonicJS architecture, require build step, lose SSR benefits |
| HTMX | Alpine.js | Would require more client-side JS, less server-centric |
| Native dialog | Custom modal library | More dependencies, less accessible, reinventing browser features |

**Installation:**
```bash
# No additional packages needed - all dependencies already in SonicJS core
# Templates use CDN resources (HTMX, Tailwind, Tailwind Plus Elements)
```

## Architecture Patterns

### Recommended Project Structure
```
src/plugins/redirects/
├── routes/
│   └── admin.ts              # Admin UI route handlers
├── templates/
│   ├── redirect-list.template.ts      # List view page
│   ├── redirect-form.template.ts      # Create/edit form page
│   └── redirect-delete-modal.template.ts  # Delete confirmation
├── services/
│   └── redirect-service.ts   # From Phase 2 (already exists)
└── index.ts                  # Plugin registration
```

### Pattern 1: Route Handler with Template Rendering

**What:** Hono route handlers query data via services, pass to template functions, return HTML

**When to use:** All admin UI pages (list, create, edit)

**Example:**
```typescript
// Source: SonicJS database-tools-plugin admin-routes.ts (verified in codebase)
router.get('/admin/redirects', requireAuth(), async (c) => {
  const user = c.get('user')
  if (!user || user.role !== 'admin') {
    return c.redirect('/admin/login')
  }

  // Query parameters for filtering/pagination
  const page = parseInt(c.req.query('page') || '1')
  const limit = parseInt(c.req.query('limit') || '20')
  const statusFilter = c.req.query('status')

  // Fetch data via service
  const service = new RedirectService(c.env.DB)
  const redirects = await service.listRedirects({ page, limit, status: statusFilter })

  // Render template with data
  return c.html(renderRedirectListPage({
    redirects: redirects.items,
    pagination: redirects.pagination,
    filters: { status: statusFilter },
    user
  }))
})
```

### Pattern 2: Composed Templates from Reusable Components

**What:** Page templates use renderForm(), renderTable(), renderFilterBar(), renderPagination() from core

**When to use:** Building any admin page to maintain consistency

**Example:**
```typescript
// Source: SonicJS form.template.ts and table.template.ts (verified in codebase)
export function renderRedirectListPage(data: RedirectListData): string {
  const filterBar = renderFilterBar({
    filters: [
      {
        name: 'status',
        label: 'Status Code',
        options: [
          { value: 'all', label: 'All Status', selected: !data.filters.status },
          { value: '301', label: '301 Permanent', selected: data.filters.status === '301' },
          { value: '302', label: '302 Temporary', selected: data.filters.status === '302' }
        ]
      }
    ]
  })

  const table = renderTable({
    columns: [
      { key: 'source', label: 'Source URL', sortable: true },
      { key: 'destination', label: 'Destination URL', sortable: true },
      { key: 'status_code', label: 'Status', sortable: true }
    ],
    rows: data.redirects,
    selectable: true
  })

  const pagination = renderPagination({
    currentPage: data.pagination.page,
    totalPages: data.pagination.totalPages,
    totalItems: data.pagination.total,
    itemsPerPage: data.pagination.limit,
    baseUrl: '/admin/redirects'
  })

  return renderAdminLayoutCatalyst({
    title: 'Redirects',
    content: filterBar + table + pagination
  })
}
```

### Pattern 3: HTMX-Powered Forms with Server Validation

**What:** Forms submit via hx-post/hx-put, server returns HTML partial or full page with errors

**When to use:** Create and edit forms

**Example:**
```typescript
// Source: HTMX documentation (htmx.org/examples/inline-validation)
export function renderRedirectForm(data: RedirectFormData): string {
  return renderForm({
    hxPost: data.isEdit ? undefined : '/admin/redirects',
    hxPut: data.isEdit ? `/admin/redirects/${data.id}` : undefined,
    fields: [
      {
        name: 'source',
        label: 'Source URL',
        type: 'text',
        value: data.source || '',
        placeholder: '/old-page',
        required: true,
        helpText: 'The URL path to redirect from (e.g., /old-page)'
      },
      {
        name: 'destination',
        label: 'Destination URL',
        type: 'text',
        value: data.destination || '',
        placeholder: '/new-page',
        required: true,
        helpText: 'The URL to redirect to'
      },
      {
        name: 'status_code',
        label: 'Status Code',
        type: 'select',
        value: data.status_code || '301',
        options: [
          { value: '301', label: '301 Permanent' },
          { value: '302', label: '302 Temporary' },
          { value: '307', label: '307 Temporary (Preserve Method)' }
        ],
        required: true
      },
      {
        name: 'active',
        label: 'Active',
        type: 'checkbox',
        value: data.active !== false,
        helpText: 'Inactive redirects are not applied'
      }
    ],
    submitButtons: [
      { label: data.isEdit ? 'Update Redirect' : 'Create Redirect', type: 'submit' },
      { label: 'Cancel', type: 'button', className: 'btn-secondary', onclick: 'history.back()' }
    ]
  })
}
```

### Pattern 4: Native Dialog for Delete Confirmation

**What:** HTML `<dialog>` element with Tailwind Plus Elements for animations and focus trap

**When to use:** Delete actions, any destructive operation requiring confirmation

**Example:**
```typescript
// Source: SonicJS confirmation-dialog.template.ts (verified in codebase)
export function renderDeleteConfirmationDialog(redirect: Redirect): string {
  return renderConfirmationDialog({
    id: `delete-redirect-${redirect.id}`,
    title: 'Delete Redirect',
    message: `Are you sure you want to delete the redirect from "${redirect.source}" to "${redirect.destination}"?${redirect.hit_count ? ` This redirect has been used ${redirect.hit_count} times.` : ''} This action cannot be undone.`,
    confirmText: 'Delete Redirect',
    cancelText: 'Cancel',
    confirmClass: 'bg-red-500 hover:bg-red-400',
    iconColor: 'red',
    onConfirm: `htmx.ajax('DELETE', '/admin/redirects/${redirect.id}', {target: '#redirect-list', swap: 'outerHTML'})`
  })
}

// In template, trigger with:
<button onclick="showConfirmDialog('delete-redirect-${redirect.id}')">Delete</button>
```

### Pattern 5: Debounced Search with URL Update

**What:** Search input with JavaScript debounce that updates URL query params

**When to use:** Search boxes in filter bars

**Example:**
```typescript
// Source: Pattern from filter-bar.template.ts (verified in codebase)
// In filter bar template:
<input
  type="text"
  name="search"
  placeholder="Search redirects..."
  class="form-input"
  value="${data.search || ''}"
  oninput="debounceSearch(this.value, 300)"
>

<script>
let searchTimeout;
function debounceSearch(value, delay) {
  clearTimeout(searchTimeout);
  searchTimeout = setTimeout(() => {
    const params = new URLSearchParams(window.location.search);
    if (value) {
      params.set('search', value);
    } else {
      params.delete('search');
    }
    params.set('page', '1'); // Reset to page 1
    window.location.href = window.location.pathname + '?' + params.toString();
  }, delay);
}
</script>
```

### Anti-Patterns to Avoid

- **Client-side state management:** Don't use localStorage, sessionStorage, or complex JS state. Keep all state in URL query params (filters, pagination) or server-side (form data). HTMX philosophy is server-centric.

- **Custom modal libraries:** Don't import modal libraries. Use native `<dialog>` element with renderConfirmationDialog() helper. More accessible, lighter weight, already in codebase.

- **Inline editing in tables:** Don't make table cells editable inline. Use dedicated create/edit pages at `/admin/redirects/new` and `/admin/redirects/:id/edit`. Keeps complexity low, follows SonicJS patterns.

- **Real-time validation for business logic:** Don't validate circular redirects or destination existence on every keystroke. Expensive checks run on submit only. Validate URL format on blur, complex validations on submit.

- **Custom styling outside Tailwind:** Don't write custom CSS. Use Tailwind utility classes to match existing admin UI. SonicJS templates use consistent Tailwind patterns (rounded-lg, bg-white dark:bg-zinc-900, etc).

## Don't Hand-Roll

Problems that look simple but have existing solutions:

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Form rendering | Manual HTML strings with interpolation | `renderForm()` from core templates | Handles validation display, field types, help text, consistent styling, accessibility |
| Table with sorting | Custom table HTML and JS | `renderTable()` from core templates | Built-in client-side sorting, checkbox selection, row actions, empty states |
| Filter UI | Custom filter controls | `renderFilterBar()` from core templates | URL param syncing, filter chips, consistent layout |
| Pagination | Custom prev/next buttons | `renderPagination()` from core templates | Page numbers, page size selector, mobile responsive |
| Delete confirmation | Custom modal overlay | `renderConfirmationDialog()` + native dialog | WCAG compliant, focus trap, keyboard nav, backdrop animations |
| URL truncation | Manual substring + tooltips | Tailwind truncate class + title attribute | `<span class="truncate max-w-[200px]" title="${fullUrl}">${url}</span>` handles ellipsis and native tooltip |
| Debouncing | Custom debounce implementation | Simple setTimeout pattern | 8 lines of code, clear behavior, no library needed |

**Key insight:** SonicJS has spent significant effort building reusable template components. These templates embody best practices for accessibility, responsive design, dark mode, and HTMX integration. New UI should compose these templates, not recreate them. The redirect admin UI is standard CRUD, not a special case requiring custom components.

## Common Pitfalls

### Pitfall 1: Validation Logic in Templates

**What goes wrong:** Putting validation rules in template strings (pattern attributes, min/max values) without matching server-side validation

**Why it happens:** HTML5 validation attributes are easy to add and seem sufficient

**How to avoid:**
- Define validation schemas in service layer (Zod schemas preferred)
- Use same schema for both server validation and generating HTML attributes
- Template should receive validation config from service, not define it

**Warning signs:** Finding yourself duplicating regex patterns between templates and route handlers

### Pitfall 2: Over-Using Real-Time Validation

**What goes wrong:** Every field validates on every keystroke, causing UX annoyance and excessive API calls

**Why it happens:** Real-time validation feels modern and responsive

**How to avoid:**
- Validate format on blur (when user leaves field)
- Validate expensive checks (circular redirects) only on submit
- Use 300ms debounce if real-time is truly needed
- Show success states only, not "this field is incomplete" while user is still typing

**Warning signs:** Users complaining about red error messages appearing while they're still typing

### Pitfall 3: Breaking Browser Back Button

**What goes wrong:** Using HTMX to swap page content without updating URL, so back button doesn't work as expected

**Why it happens:** hx-target swaps content in place, which is great for partials but breaks navigation for full pages

**How to avoid:**
- Full page navigation (list to create, list to edit) should be regular links (no HTMX)
- HTMX for partials only (form submit, delete action, filter/sort)
- Use hx-push-url="true" if you do want HTMX navigation to update browser history

**Warning signs:** Users clicking back button and ending up in wrong place or seeing old data

### Pitfall 4: Forgetting Dark Mode in Custom Styles

**What goes wrong:** Custom components only work in light mode, look broken in dark mode

**Why it happens:** Tailwind requires explicit dark: variants, easy to forget

**How to avoid:**
- Always pair light colors with dark: variants (bg-white dark:bg-zinc-900)
- Test UI with dark mode enabled (many users prefer dark mode)
- Copy color patterns from existing SonicJS templates

**Warning signs:** White text on white background in dark mode, invisible borders

### Pitfall 5: Not Handling Empty States

**What goes wrong:** Tables show blank white box when no redirects exist, confusing users

**Why it happens:** Focusing on happy path (data exists), forgetting first-run experience

**How to avoid:**
- renderTable() has built-in empty state support via emptyMessage prop
- Provide contextual empty messages: "No redirects created yet. Click 'New Redirect' to get started."
- Show different messages for "no data" vs "no results matching filter"

**Warning signs:** Blank pages, users asking "is it broken?" when they have no data yet

### Pitfall 6: Search/Filter State Loss on Create/Edit

**What goes wrong:** User filters list, clicks Edit, saves, returns to list with filters cleared

**Why it happens:** Navigation loses query params unless explicitly preserved

**How to avoid:**
- Pass referrerParams from list page URL to form template
- Form's "Cancel" and "Back" buttons use preserved params
- After successful save, redirect back with original params

**Warning signs:** Users complaining they have to re-apply filters after every edit

## Code Examples

Verified patterns from official sources:

### Bulk Delete with Checkboxes

```typescript
// Source: SonicJS table.template.ts and bulk operations best practices
// In list page template:

const table = renderTable({
  selectable: true,  // Enables checkboxes
  columns: [...],
  rows: redirects,
  tableId: 'redirect-table'
})

// Add bulk action bar (appears when items selected):
const bulkActionBar = `
  <div id="bulk-actions" class="hidden mb-4 p-4 rounded-lg bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10">
    <div class="flex items-center justify-between">
      <span class="text-sm text-zinc-500 dark:text-zinc-400">
        <span id="selected-count">0</span> items selected
      </span>
      <button
        onclick="showConfirmDialog('bulk-delete-dialog')"
        class="inline-flex items-center rounded-lg bg-red-500 px-3 py-2 text-sm font-semibold text-white hover:bg-red-400"
      >
        Delete Selected
      </button>
    </div>
  </div>

  <script>
    // Show/hide bulk action bar based on selection
    const table = document.getElementById('redirect-table');
    const bulkActions = document.getElementById('bulk-actions');
    const selectedCount = document.getElementById('selected-count');

    table.addEventListener('change', (e) => {
      if (e.target.matches('.row-checkbox')) {
        const checked = table.querySelectorAll('.row-checkbox:checked');
        if (checked.length > 0) {
          bulkActions.classList.remove('hidden');
          selectedCount.textContent = checked.length;
        } else {
          bulkActions.classList.add('hidden');
        }
      }
    });
  </script>
`

// Bulk delete confirmation dialog:
const bulkDeleteDialog = renderConfirmationDialog({
  id: 'bulk-delete-dialog',
  title: 'Delete Multiple Redirects',
  message: 'Delete <span id="delete-count"></span> redirects? This cannot be undone.',
  confirmText: 'Delete',
  confirmClass: 'bg-red-500 hover:bg-red-400',
  iconColor: 'red',
  onConfirm: `
    const checked = document.querySelectorAll('.row-checkbox:checked');
    const ids = Array.from(checked).map(cb => cb.value);
    htmx.ajax('POST', '/admin/redirects/bulk-delete', {
      target: '#redirect-table',
      swap: 'outerHTML',
      values: { ids: ids }
    });
  `
})
```

### URL Truncation with Tooltip

```typescript
// Source: PatternFly truncate guidelines and Carbon Design System
// In table column render function:

{
  key: 'source',
  label: 'Source URL',
  sortable: true,
  render: (url: string) => `
    <span
      class="truncate max-w-[200px] inline-block align-bottom"
      title="${url}"
    >
      ${url}
    </span>
  `
}

// Alternative for very long URLs (show start and end):
function truncateUrl(url: string, maxLength: number = 50): string {
  if (url.length <= maxLength) return url;
  const keepChars = Math.floor((maxLength - 3) / 2);
  return url.slice(0, keepChars) + '...' + url.slice(-keepChars);
}
```

### Form Section Organization

```typescript
// Source: SonicJS admin-content-form.template.ts pattern
// Group fields by purpose for clarity:

export function renderRedirectForm(data: RedirectFormData): string {
  const urlSection = renderFieldGroup({
    title: 'URLs',
    description: 'Source and destination paths',
    fields: [
      {
        name: 'source',
        label: 'Source URL',
        type: 'text',
        required: true,
        placeholder: '/old-page',
        helpText: 'The URL path to redirect from'
      },
      {
        name: 'destination',
        label: 'Destination URL',
        type: 'text',
        required: true,
        placeholder: '/new-page',
        helpText: 'The URL to redirect to'
      }
    ]
  })

  const behaviorSection = renderFieldGroup({
    title: 'Behavior',
    description: 'How the redirect works',
    fields: [
      {
        name: 'status_code',
        label: 'Status Code',
        type: 'select',
        options: [
          { value: '301', label: '301 Permanent Redirect' },
          { value: '302', label: '302 Temporary Redirect' }
        ],
        helpText: 'Use 301 for permanent URL changes (SEO), 302 for temporary'
      },
      {
        name: 'match_type',
        label: 'Match Type',
        type: 'select',
        options: [
          { value: '0', label: 'Exact Match' },
          { value: '1', label: 'Partial Match' },
          { value: '2', label: 'Regular Expression' }
        ],
        helpText: 'Exact: URL must match exactly. Partial: Matches if URL starts with source. Regex: Advanced pattern matching.'
      }
    ]
  })

  const optionsSection = renderFieldGroup({
    title: 'Options',
    fields: [
      {
        name: 'preserve_query',
        label: 'Preserve Query Parameters',
        type: 'checkbox',
        helpText: 'Keep ?param=value from original URL'
      },
      {
        name: 'preserve_hash',
        label: 'Preserve Hash/Fragment',
        type: 'checkbox',
        helpText: 'Keep #section from original URL'
      },
      {
        name: 'active',
        label: 'Active',
        type: 'checkbox',
        value: true,
        helpText: 'Inactive redirects are saved but not applied'
      }
    ]
  })

  return renderAdminLayoutCatalyst({
    title: data.isEdit ? 'Edit Redirect' : 'New Redirect',
    content: `
      <form hx-post="/admin/redirects" hx-target="#form-messages">
        ${urlSection}
        ${behaviorSection}
        ${optionsSection}
        <div class="mt-6 flex gap-4">
          <button type="submit" class="btn btn-primary">
            ${data.isEdit ? 'Update' : 'Create'} Redirect
          </button>
          <a href="/admin/redirects" class="btn btn-secondary">Cancel</a>
        </div>
      </form>
    `
  })
}
```

### Filter Chips with Clear Individual Filters

```typescript
// Source: Filter bar with chips from CONTEXT.md decisions
// Show active filters as removable chips:

function renderActiveFilterChips(filters: Record<string, string>): string {
  const chips: string[] = []

  if (filters.status && filters.status !== 'all') {
    chips.push(`
      <span class="inline-flex items-center gap-x-1 rounded-md bg-blue-50 dark:bg-blue-900/20 px-2 py-1 text-xs font-medium text-blue-700 dark:text-blue-300">
        Status: ${filters.status}
        <button
          onclick="removeFilter('status')"
          class="group relative -mr-1 h-3.5 w-3.5 rounded-sm hover:bg-blue-600/20"
        >
          <span class="sr-only">Remove</span>
          <svg viewBox="0 0 14 14" class="h-3.5 w-3.5">
            <path d="M4 4l6 6m0-6l-6 6" />
          </svg>
        </button>
      </span>
    `)
  }

  if (filters.match_type && filters.match_type !== 'all') {
    chips.push(`
      <span class="inline-flex items-center gap-x-1 rounded-md bg-green-50 dark:bg-green-900/20 px-2 py-1 text-xs font-medium text-green-700 dark:text-green-300">
        Match: ${filters.match_type}
        <button onclick="removeFilter('match_type')">...</button>
      </span>
    `)
  }

  if (chips.length > 0) {
    return `
      <div class="flex items-center gap-2 mb-4">
        ${chips.join('')}
        <button
          onclick="clearAllFilters()"
          class="text-xs text-zinc-500 dark:text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200"
        >
          Clear all
        </button>
      </div>

      <script>
        function removeFilter(name) {
          const params = new URLSearchParams(window.location.search);
          params.delete(name);
          params.set('page', '1');
          window.location.href = window.location.pathname + '?' + params.toString();
        }

        function clearAllFilters() {
          window.location.href = window.location.pathname;
        }
      </script>
    `
  }

  return ''
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| SPA with React/Vue admin | Server-rendered HTMX templates | 2025-2026 | No build step, faster initial load, simpler mental model, easier to maintain |
| Custom modal libraries (Bootstrap, jQuery UI) | Native HTML `<dialog>` element | 2022+ (widespread browser support) | Zero dependencies, better accessibility, lighter weight |
| Client-side filtering/sorting | Hybrid: client sort, server filter with debounce | 2024+ | Balance UX responsiveness with server authority on data |
| Separate mobile templates | Tailwind responsive classes | Always | Single template serves mobile and desktop, reduced maintenance |
| Custom CSS files | Tailwind utility classes via CDN | 2023+ | No build step, consistent design system, dark mode support |

**Deprecated/outdated:**
- **jQuery for DOM manipulation**: HTMX replaced jQuery for admin UIs, more declarative, less JavaScript
- **Bootstrap modals**: Native `<dialog>` element with Tailwind Plus Elements provides better UX and accessibility
- **Separate API + admin endpoints**: SonicJS pattern is unified routes that return HTML for browser, JSON for API (content negotiation)

## Open Questions

Things that couldn't be fully resolved:

1. **Hit count display in table**
   - What we know: Phase 2 implemented analytics table with hit tracking
   - What's unclear: Whether hit count should show in list view or only in detail view
   - Recommendation: Include hit count column in list view (users want to see popular redirects), but make it sortable so users can find most/least used

2. **Query parameter handling complexity**
   - What we know: User decided to support preserve_query and preserve_hash checkboxes
   - What's unclear: Whether UI should show examples or validate that query params make sense for each match type (regex with query params is complex)
   - Recommendation: Show help text with examples, trust admin to understand implications, defer validation to Phase 5 (testing interface)

3. **Bulk operations beyond delete**
   - What we know: User decided bulk delete is in scope
   - What's unclear: Whether "activate/deactivate selected" should also be bulk operation
   - Recommendation: Start with bulk delete only (most common destructive action), add bulk activate/deactivate in future iteration if users request it

4. **Mobile responsiveness for wide tables**
   - What we know: SonicJS templates use Tailwind responsive classes
   - What's unclear: Whether redirect list should switch to card layout on mobile or rely on horizontal scroll
   - Recommendation: Keep table layout with horizontal scroll (renderTable() handles this), redirect data is inherently wide (two URLs), card layout would be verbose

## Sources

### Primary (HIGH confidence)
- SonicJS codebase templates (verified):
  - `/packages/core/src/templates/form.template.ts` - Form rendering
  - `/packages/core/src/templates/table.template.ts` - Table with sorting and checkboxes
  - `/packages/core/src/templates/filter-bar.template.ts` - Filter UI patterns
  - `/packages/core/src/templates/confirmation-dialog.template.ts` - Delete modals
  - `/packages/core/src/templates/pagination.template.ts` - Pagination component
  - `/packages/core/src/plugins/core-plugins/database-tools-plugin/admin-routes.ts` - Route handler patterns
- [HTMX Documentation](https://htmx.org/docs/) - Core HTMX attributes
- [HTMX Inline Validation Example](https://htmx.org/examples/inline-validation/) - Validation pattern

### Secondary (MEDIUM confidence)
- [HTMX Best Practices 2026](https://dev.to/hexshift/htmx-best-practices-building-responsive-web-apps-without-javascript-frameworks-25dm) - Form handling and state management
- [Smashing Magazine: Live Validation UX](https://www.smashingmagazine.com/2022/09/inline-validation-web-forms-ux/) - Real-time vs submit validation
- [LogRocket: Form Validation UX](https://blog.logrocket.com/ux-design/ux-form-validation-inline-after-submission/) - Hybrid validation approach
- [NN/Group: Confirmation Dialogs](https://www.nngroup.com/articles/confirmation-dialog/) - Delete confirmation best practices
- [UX Psychology: Destructive Action Modals](https://uxpsychology.substack.com/p/how-to-design-better-destructive) - Modal design patterns
- [PatternFly: Bulk Selection](https://www.patternfly.org/patterns/bulk-selection/) - Checkbox selection patterns
- [Medium: Checkboxes on Data Tables](https://medium.com/@levibait/check-boxes-on-data-tables-ded40456f76b) - Table bulk operations
- [PatternFly: Truncate Guidelines](https://www.patternfly.org/components/truncate/design-guidelines/) - URL truncation with tooltips

### Tertiary (LOW confidence)
- WebSearch results on debouncing (200-300ms consensus but not officially documented)
- Community patterns on filter chips (user preference, not standard)

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - All libraries verified in SonicJS package.json and existing templates
- Architecture: HIGH - Patterns directly copied from working SonicJS core plugins
- Pitfalls: MEDIUM - Based on combination of documented best practices and observed patterns, not all verified in production at scale
- Code examples: HIGH - All examples derived from verified SonicJS templates or official HTMX documentation

**Research date:** 2026-01-30
**Valid until:** 2026-03-01 (30 days) - Stack is stable, HTMX and Tailwind CSS are mature
