import { describe, it, expect } from 'vitest'
import { parseJsonRpc, rpcResult, rpcError, JSON_RPC } from '../jsonrpc'

describe('parseJsonRpc', () => {
  it('accepts a well-formed request and defaults params to {}', () => {
    const r = parseJsonRpc({ jsonrpc: '2.0', id: 1, method: 'tools/list' })
    expect('error' in r).toBe(false)
    if (!('error' in r)) {
      expect(r.method).toBe('tools/list')
      expect(r.id).toBe(1)
      expect(r.params).toEqual({})
    }
  })

  it('preserves provided params', () => {
    const r = parseJsonRpc({ jsonrpc: '2.0', id: 'a', method: 'tools/call', params: { name: 'x' } })
    if (!('error' in r)) expect(r.params).toEqual({ name: 'x' })
  })

  it('normalizes a missing id to null', () => {
    const r = parseJsonRpc({ jsonrpc: '2.0', method: 'initialize' })
    if (!('error' in r)) expect(r.id).toBeNull()
  })

  it('rejects a non-object body', () => {
    const r = parseJsonRpc('nope')
    expect('error' in r && r.error.code).toBe(JSON_RPC.INVALID_REQUEST)
  })

  it('rejects an array body', () => {
    const r = parseJsonRpc([{ jsonrpc: '2.0', method: 'x' }])
    expect('error' in r && r.error.code).toBe(JSON_RPC.INVALID_REQUEST)
  })

  it('rejects a wrong jsonrpc version', () => {
    const r = parseJsonRpc({ jsonrpc: '1.0', method: 'x' })
    expect('error' in r && r.error.code).toBe(JSON_RPC.INVALID_REQUEST)
  })

  it('rejects a missing/empty method', () => {
    expect('error' in parseJsonRpc({ jsonrpc: '2.0', id: 1 })).toBe(true)
    expect('error' in parseJsonRpc({ jsonrpc: '2.0', id: 1, method: '' })).toBe(true)
  })
})

describe('rpc envelopes', () => {
  it('builds a success envelope', () => {
    expect(rpcResult(1, { ok: true })).toEqual({ jsonrpc: '2.0', id: 1, result: { ok: true } })
  })

  it('coerces undefined id to null', () => {
    expect(rpcResult(undefined as any, {}).id).toBeNull()
    expect(rpcError(undefined as any, JSON_RPC.INTERNAL_ERROR, 'x').id).toBeNull()
  })

  it('builds an error envelope and only includes data when provided', () => {
    expect(rpcError(2, JSON_RPC.METHOD_NOT_FOUND, 'nope')).toEqual({
      jsonrpc: '2.0',
      id: 2,
      error: { code: JSON_RPC.METHOD_NOT_FOUND, message: 'nope' },
    })
    expect(rpcError(2, JSON_RPC.INVALID_PARAMS, 'bad', { field: 'x' }).error.data).toEqual({ field: 'x' })
  })
})
