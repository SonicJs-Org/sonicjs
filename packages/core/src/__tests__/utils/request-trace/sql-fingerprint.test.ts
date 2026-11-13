import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  KNOWN_KEY_SEGMENTS, extractTables, fingerprintSql, identityKey, maskParams, redactKey, redactSql, sqlOp,
} from '../../../utils/request-trace/sql-fingerprint'

describe('redactSql', () => {
  it('replaces string, numeric and blob literals', () => {
    expect(redactSql("SELECT * FROM t WHERE token = 'abc123' AND n = 5 AND b = X'00ff'"))
      .toBe('SELECT * FROM t WHERE token = ? AND n = ? AND b = ?')
  })
  it('handles escaped quotes and keeps identifiers with digits', () => {
    expect(redactSql("select q_1, t2.col from t2 where a = 'it''s' limit 20")).toBe('select q_1, t2.col from t2 where a = ? limit ?')
  })
  it('keeps backtick identifiers and table-position quoted identifiers, collapses whitespace', () => {
    expect(redactSql('SELECT  a\n FROM `t`  WHERE x = 1.5e3')).toBe('SELECT a FROM `t` WHERE x = ?')
    expect(redactSql('SELECT * FROM "my table" JOIN "o"')).toBe('SELECT * FROM "my table" JOIN "o"')
  })
  it('redacts double-quoted tokens outside table position (SQLite string-literal fallback)', () => {
    expect(redactSql('SELECT * FROM t WHERE token = "secretToken"')).toBe('SELECT * FROM t WHERE token = ?')
    expect(redactSql('SELECT "a@b.com" FROM t')).toBe('SELECT ? FROM t')
  })
  it('strips line and block comments, but not comment-like text inside literals', () => {
    expect(redactSql('SELECT 1 -- alice@example.com\nFROM t /* tok_abc */ WHERE a = 2')).toBe('SELECT ? FROM t WHERE a = ?')
    expect(redactSql("SELECT '-- not a comment', 'a /* b */' FROM t -- real")).toBe('SELECT ?, ? FROM t')
    expect(redactSql('SELECT 1 /* unterminated secret')).toBe('SELECT ?')
  })
  it('keeps bind placeholders and never leaks emails', () => {
    const out = redactSql("WHERE email = 'x@y.com' AND id = ?")
    expect(out).toBe('WHERE email = ? AND id = ?')
  })
})

describe('fingerprintSql', () => {
  it('lowercases and collapses IN lists', () => {
    expect(fingerprintSql('SELECT * FROM t WHERE id IN (?, ?, ?)')).toBe('select * from t where id in (?…)')
    expect(fingerprintSql("SELECT * FROM t WHERE id IN (1, 2)")).toBe('select * from t where id in (?…)')
  })
  it('collapses whitespace', () => {
    expect(fingerprintSql('SELECT 1\n  FROM   t')).toBe('select ? from t')
  })
})

describe('sqlOp / extractTables / maskParams', () => {
  it('maps ops, WITH → verb after the CTE list', () => {
    expect(sqlOp('  select 1')).toBe('SELECT')
    expect(sqlOp('WITH x AS (select 1) select * from x')).toBe('SELECT')
    expect(sqlOp('WITH RECURSIVE x(n) AS (select 1 union select n+1 from x) select * from x')).toBe('SELECT')
    expect(sqlOp('WITH x AS (select id from t) DELETE FROM u WHERE id IN (select id from x)')).toBe('DELETE')
    expect(sqlOp('WITH x AS (select 1) INSERT INTO t select * from x')).toBe('INSERT')
    expect(sqlOp("WITH x AS (select 'update') UPDATE t SET a = 1")).toBe('UPDATE')
    expect(sqlOp('WITH x AS (select 1)')).toBe('OTHER')
    expect(sqlOp('insert into t values (1)')).toBe('INSERT')
    expect(sqlOp('UPDATE t SET a=1')).toBe('UPDATE')
    expect(sqlOp('DELETE FROM t')).toBe('DELETE')
    expect(sqlOp('PRAGMA table_info(t)')).toBe('PRAGMA')
    expect(sqlOp('CREATE TABLE t(a)')).toBe('OTHER')
  })
  it('extracts quoted/backticked/joined tables, deduped', () => {
    expect(extractTables('SELECT * FROM "a" JOIN `b` ON 1 JOIN [c] ON 1 LEFT JOIN a ON 1')).toEqual(['a', 'b', 'c'])
    expect(extractTables('INSERT INTO documents (a) VALUES (?) ON CONFLICT DO UPDATE SET a = 1')).toEqual(['documents'])
    expect(extractTables('UPDATE users SET a=1')).toEqual(['users'])
  })
  it('never copies words from string literals, comments or non-table quotes into tables', () => {
    expect(extractTables("SELECT 'from secretToken' FROM real_t")).toEqual(['real_t'])
    expect(extractTables('SELECT 1 FROM t -- join leaked\n')).toEqual(['t'])
    expect(extractTables('SELECT * FROM t WHERE a = "from evil"')).toEqual(['t'])
  })
  it('masks params by shape', () => {
    expect(maskParams(['abc', 5, null, true])).toEqual(['string(3)', 'number', 'null', 'bool'])
  })
})

describe('redactKey', () => {
  it.each([
    ['content:item:3f2b1c9a-1111-4222-8333-444455556666:v1', 'content:item:<uuid>:v1'],
    ['rbac:perms:3f2b1c9a-1111-4222-8333-444455556666', 'rbac:perms:<uuid>'],
    ['session:abcdef0123456789abcdef', 'session:<redacted:22>'], // letter-led token is NOT allowlisted
    ['session:secretToken', 'session:<redacted:11>'],
    ['user:jane@x.com', 'user:<email>'],
    ['ratelimit:login:1.2.3.4', 'ratelimit:<redacted:5>:<redacted:7>'],
    ['content:list:42', 'content:list:<n>'],
    ['unknownprefix:42', '<redacted:13>:<n>'],
  ])('%s -> %s', (input, expected) => {
    expect(redactKey(input)).toBe(expected)
  })
  it('preserves separators', () => {
    expect(redactKey('content:item/abc|v1')).toBe('content:item/<redacted:3>|v1')
  })
})

describe('identityKey', () => {
  it('differs by values, matches for same values, differs by salt', () => {
    const fp = 'select * from t where a = ?'
    expect(identityKey(fp, ['a'])).not.toBe(identityKey(fp, ['b']))
    expect(identityKey(fp, ['a'])).toBe(identityKey(fp, ['a']))
    expect(identityKey(fp, ['a'], 's1')).not.toBe(identityKey(fp, ['a'], 's2'))
  })
  it('distinguishes inline literals via raw sql even though the fingerprint is identical', () => {
    const a = 'SELECT * FROM t WHERE id = 1'
    const b = 'SELECT * FROM t WHERE id = 2'
    expect(fingerprintSql(a)).toBe(fingerprintSql(b))
    expect(identityKey(fingerprintSql(a), [], 's', a)).not.toBe(identityKey(fingerprintSql(b), [], 's', b))
    expect(identityKey(fingerprintSql(a), [], 's', a)).toBe(identityKey(fingerprintSql(a), [], 's', a))
  })
  it('hashes ArrayBuffer / typed-array blobs by bytes', () => {
    const fp = 'x'
    const u = new Uint8Array([1, 2, 3])
    expect(identityKey(fp, [u])).toBe(identityKey(fp, [new Uint8Array([1, 2, 3])]))
    expect(identityKey(fp, [u])).toBe(identityKey(fp, [u.buffer]))
    expect(identityKey(fp, [u])).not.toBe(identityKey(fp, [new Uint8Array([1, 2, 4])]))
    const big = new Uint8Array(5_000_000)
    const t0 = performance.now()
    identityKey(fp, [big])
    expect(performance.now() - t0).toBeLessThan(200)
  })
})

describe('KNOWN_KEY_SEGMENTS', () => {
  // Only the files that actually build cache/KV keys (CACHE_CONFIGS, generateKey, fixed prefixes).
  // Searching the whole repo would pass vacuously for common words like "id" / "user" / "email".
  const KEY_BUILDING_FILES = [
    'services/cache.ts', // CACHE_CONFIGS namespaces + generateKey()
    'plugins/cache/services/cache-config.ts',
    'plugins/cache/services/cache-warming.ts',
    'plugins/cache/services/catalog.ts', // _catalog
    'services/rbac.ts', // rbac:perms
    'plugins/core-plugins/security-audit-plugin/services/brute-force-detector.ts', // security:bf:*, locked, ip
    'middleware/rate-limit.ts', // ratelimit
    'middleware/bootstrap.ts', // _sonicjs_installation_id
    'routes/api-system.ts', // __health_check__
  ]
  it('every entry still exists as a key segment in a key-building file', () => {
    const root = join(dirname(fileURLToPath(import.meta.url)), '../../..')
    const corpus = KEY_BUILDING_FILES.map((f) => readFileSync(join(root, f), 'utf8')).join('\n')
    // a segment is "present" when it is a whole quoted string, or sits next to a ':' separator
    const missing = [...KNOWN_KEY_SEGMENTS].filter(
      (seg) => !new RegExp(`['"\`]${seg}['"\`]|[:'"\`]${seg}:|:${seg}['"\`$\\s]`).test(corpus)
    )
    expect(missing).toEqual([])
  })
})
