import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
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
  it('keeps quoted identifiers and collapses whitespace', () => {
    expect(redactSql('SELECT  "a b"\n FROM `t`  WHERE x = 1.5e3')).toBe('SELECT "a b" FROM `t` WHERE x = ?')
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
  it('maps ops, WITH → SELECT', () => {
    expect(sqlOp('  select 1')).toBe('SELECT')
    expect(sqlOp('WITH x AS (select 1) select * from x')).toBe('SELECT')
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
})

describe('KNOWN_KEY_SEGMENTS', () => {
  it('every entry still exists as a literal in packages/core/src', () => {
    const root = join(dirname(fileURLToPath(import.meta.url)), '../../..')
    const files: string[] = []
    const walk = (d: string) => {
      for (const n of readdirSync(d)) {
        const p = join(d, n)
        if (statSync(p).isDirectory()) { if (n !== '__tests__' && n !== 'node_modules') walk(p) }
        else if (p.endsWith('.ts') && !p.endsWith('.test.ts') && !p.endsWith('sql-fingerprint.ts')) files.push(p)
      }
    }
    walk(root)
    const corpus = files.map((f) => readFileSync(f, 'utf8')).join('\n')
    const missing = [...KNOWN_KEY_SEGMENTS].filter((s) => !new RegExp(`['"\`]${s}['"\`:/]|[:'"\`]${s}[:'"\`]`).test(corpus))
    expect(missing).toEqual([])
  })
})
