// @ts-nocheck
// Real-SQLite coverage for the documents_fts FTS5 index (migration 0003).
// Validates the spike's 10-column layout and the bm25 arity that v1 got wrong.
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createTestD1 } from '../utils/d1-sqlite'

describe('documents_fts schema (migration 0003) — real SQLite', () => {
  let db
  beforeEach(() => {
    db = createTestD1()
  })
  afterEach(() => db.close())

  it('creates the documents_fts virtual table', () => {
    const t = db.raw.prepare("SELECT name FROM sqlite_master WHERE name = 'documents_fts'").get()
    expect(t?.name).toBe('documents_fts')
  })

  it('has exactly 10 columns (3 indexed + 7 UNINDEXED) in spike order', () => {
    const cols = db.raw.prepare('PRAGMA table_info(documents_fts)').all().map((c) => c.name)
    expect(cols).toEqual([
      'title', 'slug', 'body',
      'document_id', 'type_id', 'status',
      'created_at', 'updated_at', 'tenant_id', 'is_published',
    ])
  })

  it('accepts insert and MATCH returns the row with porter stemming (run → runs)', () => {
    db.raw
      .prepare(
        `INSERT INTO documents_fts(title,slug,body,document_id,type_id,status,created_at,updated_at,tenant_id,is_published)
         VALUES (?,?,?,?,?,?,?,?,?,?)`,
      )
      .run('Brewing Coffee', 'brewing-coffee', 'the quick brown fox runs daily', 'd1', 'blog_post', 'published', 1, 1, 'default', 1)
    const rows = db.raw.prepare('SELECT document_id FROM documents_fts WHERE documents_fts MATCH ?').all('run')
    expect(rows.map((r) => r.document_id)).toContain('d1')
  })

  it('bm25 with exactly 10 weights executes without arity error (v1 regression guard)', () => {
    db.raw
      .prepare(
        `INSERT INTO documents_fts(title,slug,body,document_id,type_id,status,created_at,updated_at,tenant_id,is_published)
         VALUES (?,?,?,?,?,?,?,?,?,?)`,
      )
      .run('Coffee', 'coffee', 'beans and espresso', 'd1', 'blog_post', 'published', 1, 1, 'default', 1)
    const r = db.raw
      .prepare('SELECT bm25(documents_fts, 5,2,1,0,0,0,0,0,0,0) AS s FROM documents_fts WHERE documents_fts MATCH ?')
      .all('coffee')
    expect(r.length).toBe(1)
    expect(typeof r[0].s).toBe('number')
  })

  it('title-field boost ranks a title hit above a body-only hit', () => {
    const ins = db.raw.prepare(
      `INSERT INTO documents_fts(title,slug,body,document_id,type_id,status,created_at,updated_at,tenant_id,is_published)
       VALUES (?,?,?,?,?,?,?,?,?,?)`,
    )
    ins.run('Telescope Guide', 'telescope-guide', 'unrelated prose', 'inTitle', 'blog_post', 'published', 1, 1, 'default', 1)
    ins.run('Random Title', 'random', 'a passing mention of telescope here', 'inBody', 'blog_post', 'published', 1, 1, 'default', 1)
    // bm25 returns more-negative = better; ORDER BY score ASC puts the best first.
    const ranked = db.raw
      .prepare('SELECT document_id FROM documents_fts WHERE documents_fts MATCH ? ORDER BY bm25(documents_fts, 5,2,1,0,0,0,0,0,0,0)')
      .all('telescope')
    expect(ranked[0].document_id).toBe('inTitle')
  })
})
