/**
 * CSV formula-injection neutralization (deep-review 2026-07-04 hardening item 1).
 *
 * /api/views/:name?format=csv serves USER-AUTHORED content publicly; a cell beginning
 * with = + - @ (or tab/CR) executes as a formula when the file is opened in Excel/
 * Google Sheets. formatCsvResponse prefixes such STRING cells with an apostrophe (the
 * spreadsheet "treat as text" marker). Numbers stay data (-5 must not become '-5), and
 * the pre-existing quote/comma/newline escaping must survive the neutralization.
 *
 * Break-it proof: remove the `typeof val === 'string' && /^[=+\-@\t\r]/` prefix branch
 * in formatCsvResponse and the first two tests go green→red.
 */
import { describe, it, expect } from 'vitest'
import { formatCsvResponse } from '../../plugins/core-plugins/views-plugin/services/response-formatter'

describe('formatCsvResponse — formula-injection neutralization', () => {
  it("prefixes formula-leading string cells with ' (all five trigger chars)", () => {
    const rows = [
      { a: '=cmd|/c calc!A1', b: '+1+2', c: '-1+2', d: '@SUM(A1)', e: '\tlead' },
    ]
    const csv = formatCsvResponse(rows)
    const dataLine = csv.split('\n')[1]!
    expect(dataLine).toBe("'=cmd|/c calc!A1,'+1+2,'-1+2,'@SUM(A1),'\tlead")
  })

  it('neutralized cells still get CSV-quoted when they contain a comma or quote', () => {
    const rows = [{ a: '=1,2', b: '=say "hi"' }]
    const csv = formatCsvResponse(rows)
    const dataLine = csv.split('\n')[1]!
    // Apostrophe first, then the standard quote-wrapping/doubling on top.
    expect(dataLine).toBe('"\'=1,2","\'=say ""hi"""')
  })

  it('negative NUMBERS are data, not formulas — no apostrophe', () => {
    const csv = formatCsvResponse([{ n: -5, s: 'plain' }])
    expect(csv.split('\n')[1]).toBe('-5,plain')
  })

  it('benign strings and JSON-object cells are untouched', () => {
    const csv = formatCsvResponse([{ s: 'hello world', o: { k: 'v' } }])
    // JSON.stringify output starts with { — quoted for its comma-free shape here.
    expect(csv.split('\n')[1]).toBe('hello world,"{""k"":""v""}"')
  })
})
