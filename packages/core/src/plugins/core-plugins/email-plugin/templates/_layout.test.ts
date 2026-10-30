import { describe, it, expect } from 'vitest'
import {
  renderEmailLayout,
  renderCodeBlock,
  renderPrimaryButton,
  renderTextLink,
  renderInfoLine,
} from './_layout'

const HOOK_CLASSES = [
  'email-body',
  'email-card',
  'email-heading',
  'email-text',
  'email-muted',
  'email-site',
  'email-code',
  'email-button-a',
  'email-link',
  'email-footer',
] as const

describe('renderEmailLayout', () => {
  function baseInput() {
    return {
      siteName: 'SonicJS',
      preheader: 'Inbox preview text',
      heading: 'Hello',
      bodyHtml: '<p class="email-text" style="margin:0;">Body content here</p>',
    }
  }

  it('produces a full HTML document with doctype, html, body', () => {
    const out = renderEmailLayout(baseInput())
    expect(out.startsWith('<!doctype html>')).toBe(true)
    expect(out).toMatch(/<html[^>]*>/)
    expect(out).toMatch(/<body[^>]*>/)
    expect(out).toContain('</body>')
    expect(out).toContain('</html>')
  })

  it('includes charset, viewport, and color-scheme meta tags', () => {
    const out = renderEmailLayout(baseInput())
    expect(out).toContain('<meta charset="utf-8">')
    expect(out).toContain('<meta name="viewport" content="width=device-width,initial-scale=1">')
    expect(out).toContain('<meta name="color-scheme" content="dark light">')
    expect(out).toContain('<meta name="supported-color-schemes" content="dark light">')
  })

  it('emits a <style> block with prefers-color-scheme: light media query', () => {
    const out = renderEmailLayout(baseInput())
    expect(out).toMatch(/<style>[\s\S]*@media \(prefers-color-scheme: light\)[\s\S]*<\/style>/)
  })

  it('light override rules carry !important (so inline dark styles are overridden)', () => {
    const out = renderEmailLayout(baseInput())
    expect(out).toMatch(/background:\s*#ffffff\s*!important/)
    expect(out).toMatch(/color:\s*#18181b\s*!important/)
    expect(out).toMatch(/color:\s*#4f46e5\s*!important/)
  })

  it.each(HOOK_CLASSES.filter(c => c !== 'email-button-a' && c !== 'email-link' && c !== 'email-code'))(
    'rendered output contains hook class %s',
    cls => {
      const out = renderEmailLayout(baseInput())
      expect(out).toContain(cls)
    },
  )

  it('escapes hostile siteName, preheader, and heading', () => {
    const out = renderEmailLayout({
      siteName: '<script>',
      preheader: '<img src=x>',
      heading: '"alert"',
      bodyHtml: '<p>safe body</p>',
    })
    expect(out).not.toContain('<script>')
    expect(out).toContain('&lt;script&gt;')
    expect(out).not.toContain('<img src=x>')
    expect(out).toContain('&lt;img src=x&gt;')
    expect(out).toContain('&quot;alert&quot;')
  })

  it('passes bodyHtml through verbatim (caller-pre-escaped)', () => {
    const out = renderEmailLayout({
      siteName: 'X',
      preheader: 'p',
      heading: 'h',
      bodyHtml: '<p data-marker="kept">verbatim</p>',
    })
    expect(out).toContain('<p data-marker="kept">verbatim</p>')
  })

  it('preheader sits inside a div whose inline style hides it across clients', () => {
    const out = renderEmailLayout(baseInput())
    const preMatch = out.match(/<div class="email-preheader" style="([^"]+)"[^>]*>/)
    expect(preMatch).not.toBeNull()
    const style = preMatch?.[1] ?? ''
    expect(style).toContain('display:none')
    expect(style).toContain('max-height:0')
    expect(style).toContain('overflow:hidden')
    expect(style).toContain('mso-hide:all')
  })

  it('preheader text is included in the hidden div', () => {
    const out = renderEmailLayout(baseInput())
    expect(out).toContain('Inbox preview text')
  })

  it('renders a default footer mentioning the siteName when footerSlot omitted', () => {
    const out = renderEmailLayout(baseInput())
    expect(out).toContain('email-footer')
    expect(out).toContain('Sent by SonicJS')
  })

  it('honors caller-provided footerSlot', () => {
    const out = renderEmailLayout({
      ...baseInput(),
      footerSlot: '<p class="email-footer" data-marker="custom">custom footer</p>',
    })
    expect(out).toContain('data-marker="custom"')
    expect(out).not.toContain('Sent by SonicJS')
  })
})

describe('renderCodeBlock', () => {
  it('renders a code block with the email-code hook class', () => {
    const out = renderCodeBlock('482915')
    expect(out).toContain('email-code')
    expect(out).toContain('482915')
  })

  it('escapes hostile code input', () => {
    const out = renderCodeBlock('<script>alert(1)</script>')
    expect(out).not.toContain('<script>')
    expect(out).toContain('&lt;script&gt;')
  })
})

describe('renderPrimaryButton', () => {
  it('renders an anchor with the email-button-a hook class', () => {
    const out = renderPrimaryButton('https://example.com', 'Click here')
    expect(out).toContain('email-button-a')
    expect(out).toContain('Click here')
    expect(out).toContain('https://example.com')
  })

  it('includes target="_blank" and rel="noopener noreferrer"', () => {
    const out = renderPrimaryButton('https://example.com', 'Click')
    expect(out).toContain('target="_blank"')
    expect(out).toContain('rel="noopener noreferrer"')
  })

  it('escapes the href so a hostile quote cannot break out of the attribute', () => {
    const out = renderPrimaryButton('https://x.com"/><script>', 'Click')
    expect(out).not.toContain('"/><script>')
    expect(out).toContain('&quot;')
  })

  it('escapes the label', () => {
    const out = renderPrimaryButton('https://x.com', '<b>bold</b>')
    expect(out).not.toContain('<b>bold</b>')
    expect(out).toContain('&lt;b&gt;bold&lt;/b&gt;')
  })
})

describe('renderTextLink', () => {
  it('renders an anchor with the email-link hook class', () => {
    const out = renderTextLink('https://example.com', 'see here')
    expect(out).toContain('email-link')
    expect(out).toContain('see here')
  })

  it('defaults the label to href when label is omitted', () => {
    const out = renderTextLink('https://example.com/path')
    expect(out).toContain('>https://example.com/path<')
  })

  it('includes target="_blank" and rel="noopener noreferrer"', () => {
    const out = renderTextLink('https://example.com')
    expect(out).toContain('target="_blank"')
    expect(out).toContain('rel="noopener noreferrer"')
  })

  it('escapes the href attribute', () => {
    const out = renderTextLink('https://x.com"/><script>')
    expect(out).not.toContain('"/><script>')
    expect(out).toContain('&quot;')
  })
})

describe('renderInfoLine', () => {
  it('renders a muted info line containing label and value', () => {
    const out = renderInfoLine('Expires at', '2026-05-16T00:00:00Z')
    expect(out).toContain('email-muted')
    expect(out).toContain('Expires at')
    expect(out).toContain('2026-05-16T00:00:00Z')
  })

  it('escapes both label and value', () => {
    const out = renderInfoLine('<b>L</b>', '<i>V</i>')
    expect(out).not.toContain('<b>L</b>')
    expect(out).not.toContain('<i>V</i>')
    expect(out).toContain('&lt;b&gt;L&lt;/b&gt;')
    expect(out).toContain('&lt;i&gt;V&lt;/i&gt;')
  })
})
