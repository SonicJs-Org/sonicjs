import type { Context } from 'hono'

/**
 * The origin to put in links we email or hand out (password reset, invitations).
 *
 * `BETTER_AUTH_URL` when it is configured, otherwise the origin of the URL this request was
 * actually served on. Never the `Origin` request header: that is attacker-controlled, and
 * `/auth/request-password-reset` is anonymous and CSRF-exempt, so building the link from it let
 * anyone have a real reset token emailed to a victim inside a link to their own site.
 *
 * Behind a proxy that does not pin the Host header (self-host/Docker), set `BETTER_AUTH_URL`.
 */
export function siteOrigin(c: Context): string {
  const configured = (c.env as { BETTER_AUTH_URL?: string } | undefined)?.BETTER_AUTH_URL
  if (configured) {
    try {
      return new URL(configured).origin
    } catch {
      // Misconfigured value: fall through to the request URL rather than emit a broken link.
    }
  }
  return new URL(c.req.url).origin
}
