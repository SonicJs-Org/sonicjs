import { type HttpClient } from '../http'
import { type AuthResult } from '../types'

type SetAuthFn = (a: { token?: string; apiKey?: string }) => void

export class AuthResource {
  constructor(
    private http: HttpClient,
    private setAuth: SetAuthFn,
  ) {}

  async register(input: {
    email: string
    password: string
    firstName?: string
    lastName?: string
    [k: string]: unknown
  }): Promise<AuthResult> {
    const res = await this.http.request<AuthResult>('POST', '/auth/register', { body: input })
    if (res.token) this.setAuth({ token: res.token })
    return res
  }

  async login(input: { email: string; password: string }): Promise<AuthResult> {
    const res = await this.http.request<AuthResult>('POST', '/auth/login', { body: input })
    if (res.token) this.setAuth({ token: res.token })
    return res
  }

  logout(): Promise<unknown> {
    this.setAuth({ token: undefined })
    return this.http.request<unknown>('POST', '/auth/logout')
  }
}
