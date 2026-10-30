import { HttpClient } from './http'
import { type ClientOptions } from './config'
import { ContentResource } from './resources/content'
import { CollectionsResource, ScopedCollection } from './resources/collections'
import { DocumentsResource } from './resources/documents'
import { MediaResource } from './resources/media'
import { AuthResource } from './resources/auth'
import { SystemResource } from './resources/system'

type DefaultCollections = Record<string, { data: Record<string, unknown> }>

export function createClient<
  TCollections extends Record<string, { data: Record<string, unknown> }> = DefaultCollections,
>(opts: ClientOptions) {
  const state: ClientOptions = { ...opts }
  const http = new HttpClient(state)

  const setAuth = (a: { token?: string; apiKey?: string }) => {
    if ('token' in a) state.token = a.token
    if ('apiKey' in a) state.apiKey = a.apiKey
  }

  return {
    content: new ContentResource(http),
    collections: new CollectionsResource(http),
    collection: <K extends keyof TCollections>(name: K) =>
      new ScopedCollection<TCollections[K]['data']>(http, String(name)),
    documents: new DocumentsResource(http),
    media: new MediaResource(http),
    auth: new AuthResource(http, setAuth),
    system: new SystemResource(http),
    setToken: (t?: string) => setAuth({ token: t }),
    setApiKey: (k?: string) => setAuth({ apiKey: k }),
  }
}

export type SonicClient<
  T extends Record<string, { data: Record<string, unknown> }> = DefaultCollections,
> = ReturnType<typeof createClient<T>>
