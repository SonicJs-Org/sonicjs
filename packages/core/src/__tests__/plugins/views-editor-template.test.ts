/**
 * MUST-FIX 2 (deep review 2026-07-04) — script-context JSON in the views editor.
 *
 * `renderViewEditorPage` embeds the collections list as `var collections = <json>;` inside a
 * `<script>` block. Plain `JSON.stringify` output is NOT script-safe: a document-type
 * display_name containing `</script><script>…` closes the block and executes in the admin's
 * browser (stored XSS — the #1135 class; naming types is privileged, but privilege is not a
 * sanitizer). `jsonForScript` escapes every `<` as `\\u003c` — a JSON-level no-op that makes
 * breakout impossible.
 *
 * Break-it proof: revert `jsonForScript` to bare `JSON.stringify` and the first assertion
 * goes green→red (the raw payload lands verbatim inside the script block).
 */
import { describe, it, expect } from 'vitest'
import { renderViewEditorPage } from '../../plugins/core-plugins/views-plugin/templates/admin-views-editor.template'

describe('MUST-FIX 2 — editor script-context JSON escapes `<` (stored XSS)', () => {
  it('a </script> payload in a collection display_name cannot close the script block', () => {
    const payload = '</script><script>window.__pwned=1</script>'
    const html = renderViewEditorPage({
      isEdit: false,
      collections: [{ id: 'c1', name: 'c1', display_name: payload }],
    })
    // The raw breakout sequence must not appear ANYWHERE in the page…
    expect(html).not.toContain('</script><script>window.__pwned')
    // …because the embedded JSON carries the <-escaped form instead.
    expect(html).toContain('\\u003c/script>\\u003cscript>window.__pwned=1\\u003c/script>')
  })

  it('benign collection metadata round-trips through the script JSON unchanged', () => {
    const html = renderViewEditorPage({
      isEdit: false,
      collections: [{ id: 'blog_post', name: 'blog_post', display_name: 'Blog Post' }],
    })
    expect(html).toContain('"display_name":"Blog Post"')
  })
})

describe('editor — no bulk-operations surface', () => {
  // The bulk-operations backend (/admin/api/bulk-operations/*) was never ported and is
  // unrouted (404); the panel was removed to become its own plugin later. Lock it out so
  // dead UI can't creep back in.
  it('the edit-mode editor renders no Bulk Actions panel or bulk-operations calls', () => {
    const html = renderViewEditorPage({
      isEdit: true,
      id: 'v1',
      name: 'my-view',
      collections: [{ id: 'blog_post', name: 'blog_post', display_name: 'Blog Post' }],
    })
    expect(html).not.toContain('Bulk Actions')
    expect(html).not.toContain('bulk-operations')
    expect(html).not.toContain('bulk-op-select')
  })
})
