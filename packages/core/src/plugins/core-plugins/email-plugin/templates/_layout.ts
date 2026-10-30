/**
 * Shared layout + component helpers for the v3 email-plugin templates.
 *
 * Inline styles set the SonicJS-dark baseline (the "always works" layer);
 * a `<style>` block in `<head>` provides a `prefers-color-scheme: light`
 * override for clients that honour media queries (Apple Mail, iOS Mail,
 * modern Outlook, Gmail web). Clients that strip `<style>` blocks fall
 * back to dark — which is the branded baseline, so degradation is
 * graceful.
 *
 * Layout uses tables (single outer for page centring, nested for the
 * card) because Outlook's Word-engine renderer ignores flex/grid and
 * mishandles `display: block` margins.
 *
 * All caller-derived strings flow through `escapeHtml` before insertion.
 * The body fragment passed to `renderEmailLayout` is interpolated
 * verbatim and is the caller's responsibility to escape.
 *
 * See plan: plans/CF-email-build/email-template-dark-design.md
 */
import { escapeHtml } from './_escape'

export interface EmailLayoutInput {
  siteName: string
  preheader: string
  heading: string
  bodyHtml: string
  footerSlot?: string
}

const DARK = {
  pageBg: '#09090b',
  cardBg: '#18181b',
  cardBorder: '#27272a',
  heading: '#f4f4f5',
  text: '#a1a1aa',
  muted: '#71717a',
  site: '#71717a',
  link: '#818cf8',
  buttonBg: '#ffffff',
  buttonFg: '#09090b',
  codeBg: '#09090b',
  codeFg: '#f4f4f5',
  codeBorder: '#3f3f46',
  accentGradient: 'linear-gradient(135deg,#8b5cf6 0%,#06b6d4 100%)',
} as const

const FONT_STACK =
  "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif"

const PREHEADER_HIDE_STYLE =
  'display:none;max-height:0;max-width:0;overflow:hidden;mso-hide:all;visibility:hidden;opacity:0;color:transparent;height:0;width:0;font-size:0;line-height:0;'

function lightOverrideStyle(): string {
  return `
    @media (prefers-color-scheme: light) {
      body.email-body { background: #ffffff !important; }
      table.email-card {
        background: #ffffff !important;
        border-color: #e4e4e7 !important;
      }
      .email-heading { color: #18181b !important; }
      .email-text    { color: #3f3f46 !important; }
      .email-muted   { color: #71717a !important; }
      .email-site    { color: #71717a !important; }
      .email-code    {
        background: #fafafa !important;
        color: #18181b !important;
        border-color: #e4e4e7 !important;
      }
      .email-button-a {
        background: #18181b !important;
        color: #ffffff !important;
      }
      .email-link    { color: #4f46e5 !important; }
      .email-footer  { color: #a1a1aa !important; }
    }
  `
}

export function renderEmailLayout(input: EmailLayoutInput): string {
  const siteSafe = escapeHtml(input.siteName)
  const preSafe = escapeHtml(input.preheader)
  const headSafe = escapeHtml(input.heading)
  const footer =
    input.footerSlot ??
    `<p class="email-footer" style="margin:24px 0 0 0;font-family:${FONT_STACK};font-size:12px;line-height:18px;color:${DARK.muted};text-align:center;">Sent by ${siteSafe}. If you didn't expect this email, you can safely ignore it.</p>`

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark light">
<meta name="supported-color-schemes" content="dark light">
<title>${headSafe}</title>
<style>${lightOverrideStyle()}</style>
</head>
<body class="email-body" style="margin:0;padding:0;background:${DARK.pageBg};font-family:${FONT_STACK};">
<div class="email-preheader" style="${PREHEADER_HIDE_STYLE}">${preSafe}&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;&zwnj;&nbsp;</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:${DARK.pageBg};">
  <tr>
    <td align="center" style="padding:32px 16px;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" class="email-card" style="max-width:560px;background:${DARK.cardBg};border:1px solid ${DARK.cardBorder};border-radius:12px;overflow:hidden;">
        <tr>
          <td style="height:4px;background:${DARK.accentGradient};line-height:4px;font-size:0;">&nbsp;</td>
        </tr>
        <tr>
          <td style="padding:32px 32px 8px 32px;">
            <p class="email-site" style="margin:0;font-family:${FONT_STACK};font-size:13px;font-weight:600;letter-spacing:0.5px;color:${DARK.site};text-transform:uppercase;">${siteSafe}</p>
          </td>
        </tr>
        <tr>
          <td style="padding:8px 32px 0 32px;">
            <h1 class="email-heading" style="margin:0;font-family:${FONT_STACK};font-size:22px;font-weight:700;line-height:30px;color:${DARK.heading};">${headSafe}</h1>
          </td>
        </tr>
        <tr>
          <td style="padding:16px 32px 32px 32px;font-family:${FONT_STACK};font-size:15px;line-height:24px;color:${DARK.text};">
            ${input.bodyHtml}
          </td>
        </tr>
      </table>
      ${footer}
    </td>
  </tr>
</table>
</body>
</html>`
}

export function renderCodeBlock(code: string): string {
  return `<div class="email-code" style="margin:24px 0;padding:24px;background:${DARK.codeBg};border:1px solid ${DARK.codeBorder};border-radius:8px;text-align:center;">
    <div style="font-family:ui-monospace,SFMono-Regular,'SF Mono',Menlo,Consolas,'Liberation Mono',monospace;font-size:28px;font-weight:700;letter-spacing:6px;color:${DARK.codeFg};line-height:32px;">${escapeHtml(code)}</div>
  </div>`
}

export function renderPrimaryButton(href: string, label: string): string {
  const hrefSafe = escapeHtml(href)
  const labelSafe = escapeHtml(label)
  return `<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:24px 0;">
    <tr>
      <td style="border-radius:8px;background:${DARK.buttonBg};">
        <a class="email-button-a" href="${hrefSafe}" target="_blank" rel="noopener noreferrer" style="display:inline-block;padding:12px 24px;font-family:${FONT_STACK};font-size:15px;font-weight:600;line-height:20px;color:${DARK.buttonFg};text-decoration:none;border-radius:8px;background:${DARK.buttonBg};">${labelSafe}</a>
      </td>
    </tr>
  </table>`
}

export function renderTextLink(href: string, label?: string): string {
  const hrefSafe = escapeHtml(href)
  const labelSafe = escapeHtml(label ?? href)
  return `<a class="email-link" href="${hrefSafe}" target="_blank" rel="noopener noreferrer" style="color:${DARK.link};text-decoration:underline;word-break:break-all;">${labelSafe}</a>`
}

export function renderInfoLine(label: string, value: string): string {
  return `<p class="email-muted" style="margin:8px 0 0 0;font-family:${FONT_STACK};font-size:13px;line-height:20px;color:${DARK.muted};"><span style="font-weight:600;">${escapeHtml(label)}:</span> ${escapeHtml(value)}</p>`
}

export { escapeHtml }
