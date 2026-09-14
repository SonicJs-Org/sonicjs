import { describe, expect, it } from 'vitest';
import { createSonicJSApp } from '../app';
import { createRedirectPlugin } from '../plugins/redirect-management';

describe('createSonicJSApp — plugin route ordering', () => {
  it('GET /api/redirects reaches the redirect plugin, not the /:collection catch-all', async () => {
    const app = createSonicJSApp({
      plugins: {
        register: [createRedirectPlugin() as any],
      },
    });

    // Simulate a request with a minimal env (DB stub, development mode for open API access)
    const res = await app.request(
      '/api/redirects',
      {
        headers: { 'x-test-role': 'admin' },
      },
      {
        DB: {
          prepare: () => ({
            bind: (..._args: unknown[]) => ({
              all: async () => ({ results: [] }),
              first: async () => null,
              run: async () => ({ success: true }),
            }),
            all: async () => ({ results: [] }),
          }),
          batch: async () => [],
        },
        ENVIRONMENT: 'development',
      },
    );

    const body = await res.json();

    // The redirect plugin should handle this request.
    // If the catch-all shadows it, we get { error: "Collection not found" } with 404.
    expect(res.status).not.toBe(404);
    expect(body).not.toHaveProperty('error', 'Collection not found');
  });
});
