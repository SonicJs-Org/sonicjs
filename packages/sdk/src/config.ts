export interface ClientOptions {
  url: string
  apiKey?: string
  token?: string
  tenant?: string
  fetch?: (input: string | URL | Request, init?: RequestInit) => Promise<Response>
  headers?: Record<string, string>
}

export interface RequestAuth {
  apiKey?: string
  token?: string
}

export function resolveAuthHeaders(
  opts: ClientOptions,
  override?: RequestAuth,
): Record<string, string> {
  const h: Record<string, string> = {}
  const apiKey = override?.apiKey ?? opts.apiKey
  const token = override?.token ?? opts.token
  // Precedence: call-override apiKey → call-override token → client apiKey → client token → anon
  if (apiKey) {
    h['x-api-key'] = apiKey
  } else if (token) {
    h['Authorization'] = `Bearer ${token}`
  }
  return h
}
