/**
 * Proxy Worker — serves employee-directory.sonicjs.com
 *
 * Cloudflare doesn't allow cross-account proxied CNAMEs (Error 1014), so this
 * Worker fetches from the Pages deployment (edgecache-demo.pages.dev) which
 * lives in a different CF account and returns the response verbatim.
 *
 * To update the Pages build: re-run deploy-demo.yml or push to main.
 * The Pages URL is pinned to the project root (not a specific deployment hash)
 * so it always serves the latest production build automatically.
 */
export default {
  async fetch(request: Request, env: { PAGES_URL: string }): Promise<Response> {
    const url = new URL(request.url);
    const pagesUrl = new URL(url.pathname + url.search, env.PAGES_URL);

    const pagesRequest = new Request(pagesUrl.toString(), {
      method: request.method,
      headers: request.headers,
      body: request.method !== 'GET' && request.method !== 'HEAD' ? request.body : undefined,
      redirect: 'follow',
    });

    const response = await fetch(pagesRequest);

    // Strip the x-robots-tag from Pages so search engines index the real domain
    const headers = new Headers(response.headers);
    headers.delete('x-robots-tag');

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
  },
};
