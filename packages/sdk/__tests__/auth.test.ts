import { describe, it, expect, vi } from 'vitest'
import { createClient } from '../src/client'

function mockFetch(body: unknown, status = 200) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    statusText: 'OK',
    text: () => Promise.resolve(JSON.stringify(body)),
    headers: new Headers(),
  } as Response)
}

const authResult = {
  token: 'jwt.abc.xyz',
  user: { userId: 'u1', email: 'admin@example.com', role: 'admin' },
}

describe('AuthResource', () => {
  it('login — POST /auth/login with credentials', async () => {
    const fetchFn = mockFetch(authResult)
    const sonic = createClient({ url: 'https://cms.test', fetch: fetchFn as typeof fetch })
    const res = await sonic.auth.login({ email: 'admin@example.com', password: 'secret' })

    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('https://cms.test/auth/login')
    expect(init.method).toBe('POST')
    const body = JSON.parse(init.body as string)
    expect(body).toEqual({ email: 'admin@example.com', password: 'secret' })
    expect(res.token).toBe('jwt.abc.xyz')
  })

  it('login — stores token so subsequent calls include Authorization header', async () => {
    const listBody = { data: [], meta: { count: 0, timestamp: '' } }
    const fetchFn = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true, status: 200,
        text: () => Promise.resolve(JSON.stringify(authResult)),
        headers: new Headers(),
      } as Response)
      .mockResolvedValueOnce({
        ok: true, status: 200,
        text: () => Promise.resolve(JSON.stringify(listBody)),
        headers: new Headers(),
      } as Response)

    const sonic = createClient({ url: 'https://cms.test', fetch: fetchFn as typeof fetch })
    await sonic.auth.login({ email: 'admin@example.com', password: 'secret' })
    await sonic.content.list()

    const [, init] = fetchFn.mock.calls[1] as [string, RequestInit]
    expect((init.headers as Record<string, string>)['Authorization']).toBe('Bearer jwt.abc.xyz')
  })

  it('register — POST /auth/register and stores token', async () => {
    const fetchFn = mockFetch({ ...authResult, token: 'reg.token' })
    const sonic = createClient({ url: 'https://cms.test', fetch: fetchFn as typeof fetch })
    const res = await sonic.auth.register({ email: 'new@example.com', password: 'pass123', firstName: 'Jane' })

    const [url, init] = fetchFn.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('https://cms.test/auth/register')
    expect(init.method).toBe('POST')
    expect(res.token).toBe('reg.token')
  })

  it('logout — clears token and POSTs /auth/logout', async () => {
    const listBody = { data: [], meta: { count: 0, timestamp: '' } }
    const fetchFn = vi
      .fn()
      .mockResolvedValueOnce({ ok: true, status: 200, text: () => Promise.resolve(JSON.stringify(authResult)), headers: new Headers() } as Response)
      .mockResolvedValueOnce({ ok: true, status: 200, text: () => Promise.resolve('{}'), headers: new Headers() } as Response)
      .mockResolvedValueOnce({ ok: true, status: 200, text: () => Promise.resolve(JSON.stringify(listBody)), headers: new Headers() } as Response)

    const sonic = createClient({ url: 'https://cms.test', fetch: fetchFn as typeof fetch })
    await sonic.auth.login({ email: 'a@b.com', password: 'x' })
    await sonic.auth.logout()
    await sonic.content.list()

    // After logout, third call should have no Authorization header
    const [, init] = fetchFn.mock.calls[2] as [string, RequestInit]
    expect((init.headers as Record<string, string>)?.['Authorization']).toBeUndefined()
  })

  it('setToken — manually setting token is used in subsequent calls', async () => {
    const fetchFn = mockFetch({ data: [], meta: { count: 0, timestamp: '' } })
    const sonic = createClient({ url: 'https://cms.test', fetch: fetchFn as typeof fetch })
    sonic.setToken('manual.token')
    await sonic.content.list()
    const [, init] = fetchFn.mock.calls[0] as [string, RequestInit]
    expect((init.headers as Record<string, string>)['Authorization']).toBe('Bearer manual.token')
  })

  it('setApiKey — overrides token with api key', async () => {
    const fetchFn = mockFetch({ data: [], meta: { count: 0, timestamp: '' } })
    const sonic = createClient({ url: 'https://cms.test', token: 'old.token', fetch: fetchFn as typeof fetch })
    sonic.setApiKey('sk_new')
    await sonic.content.list()
    const [, init] = fetchFn.mock.calls[0] as [string, RequestInit]
    // apiKey wins over token
    expect((init.headers as Record<string, string>)['x-api-key']).toBe('sk_new')
    expect((init.headers as Record<string, string>)?.['Authorization']).toBeUndefined()
  })
})
