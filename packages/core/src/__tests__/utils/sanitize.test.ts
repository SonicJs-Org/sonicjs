import { describe, it, expect } from 'vitest'
import { escapeHtml, sanitizeInput, sanitizeObject, sanitizeRichText } from '../../utils/sanitize'

describe('escapeHtml', () => {
  it('should escape HTML special characters', () => {
    expect(escapeHtml('<script>alert("xss")</script>'))
      .toBe('&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;')
  })

  it('should escape ampersands', () => {
    expect(escapeHtml('foo & bar')).toBe('foo &amp; bar')
  })

  it('should escape single quotes', () => {
    expect(escapeHtml("it's")).toBe('it&#039;s')
  })

  it('should handle empty strings', () => {
    expect(escapeHtml('')).toBe('')
  })

  it('should handle strings without special characters', () => {
    expect(escapeHtml('hello world')).toBe('hello world')
  })

  it('should return empty string for non-string input', () => {
    expect(escapeHtml(123 as any)).toBe('')
    expect(escapeHtml(null as any)).toBe('')
    expect(escapeHtml(undefined as any)).toBe('')
  })
})

describe('sanitizeInput', () => {
  it('should escape HTML in strings', () => {
    const input = '<script>alert("xss")</script>'
    expect(sanitizeInput(input)).toBe('&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;')
  })

  it('should trim whitespace', () => {
    expect(sanitizeInput('  hello  ')).toBe('hello')
    expect(sanitizeInput('  <b>test</b>  ')).toBe('&lt;b&gt;test&lt;/b&gt;')
  })

  it('should return empty string for null', () => {
    expect(sanitizeInput(null)).toBe('')
  })

  it('should return empty string for undefined', () => {
    expect(sanitizeInput(undefined)).toBe('')
  })

  it('should handle empty strings', () => {
    expect(sanitizeInput('')).toBe('')
  })

  it('should escape all special characters', () => {
    expect(sanitizeInput('<>"\'&')).toBe('&lt;&gt;&quot;&#039;&amp;')
  })
})

describe('sanitizeObject', () => {
  it('should sanitize specified string fields in object', () => {
    const input = {
      title: '<script>alert()</script>',
      count: 42,
      active: true,
    }
    const result = sanitizeObject(input, ['title'])
    expect(result).toEqual({
      title: '&lt;script&gt;alert()&lt;/script&gt;',
      count: 42,
      active: true,
    })
  })

  it('should only sanitize specified fields', () => {
    const input = {
      name: '<b>Admin</b>',
      email: '<script>xss</script>',
      bio: '<i>hello</i>',
    }
    const result = sanitizeObject(input, ['name', 'bio'])
    expect(result.name).toBe('&lt;b&gt;Admin&lt;/b&gt;')
    expect(result.email).toBe('<script>xss</script>') // Not sanitized
    expect(result.bio).toBe('&lt;i&gt;hello&lt;/i&gt;')
  })

  it('should handle empty field list', () => {
    const input = {
      name: '<script>',
      email: 'test@example.com',
    }
    const result = sanitizeObject(input, [])
    expect(result).toEqual(input) // No fields sanitized
  })

  it('should handle non-string fields gracefully', () => {
    const input = {
      count: 42,
      active: true,
      data: null,
    }
    const result = sanitizeObject(input, ['count', 'active', 'data'])
    expect(result).toEqual(input) // Non-string fields unchanged
  })

  it('should create new object without mutating original', () => {
    const input = {
      title: '<script>',
      description: '<b>test</b>',
    }
    const result = sanitizeObject(input, ['title'])
    expect(result).not.toBe(input) // Different object reference
    expect(input.title).toBe('<script>') // Original unchanged
  })

  it('should handle empty objects', () => {
    const result = sanitizeObject({}, [])
    expect(result).toEqual({})
  })
})

describe('sanitizeRichText', () => {
  it('should remove script tags and their contents', () => {
    const input = '<p>Hello</p><script>alert("xss")</script><p>World</p>'
    expect(sanitizeRichText(input)).toBe('<p>Hello</p><p>World</p>')
  })

  it('should remove multiple script tags', () => {
    const input = '<script>a()</script><p>safe</p><script>b()</script>'
    expect(sanitizeRichText(input)).toBe('<p>safe</p>')
  })

  it('should remove event handler attributes', () => {
    const input = '<img src="x.jpg" onerror="alert(1)">'
    const result = sanitizeRichText(input)
    expect(result).not.toContain('onerror')
    expect(result).toContain('src="x.jpg"')
  })

  it('should remove various event handlers', () => {
    const input = '<div onmouseover="alert(1)" onclick="steal()">text</div>'
    const result = sanitizeRichText(input)
    expect(result).not.toContain('onmouseover')
    expect(result).not.toContain('onclick')
    expect(result).toContain('text')
  })

  it('should remove javascript: URLs in href', () => {
    const input = '<a href="javascript:alert(1)">click</a>'
    const result = sanitizeRichText(input)
    expect(result).not.toContain('javascript:')
    expect(result).toContain('click')
  })

  it('should remove javascript: URLs in src', () => {
    const input = '<iframe src="javascript:alert(1)"></iframe>'
    const result = sanitizeRichText(input)
    expect(result).not.toContain('javascript:')
  })

  it('should preserve safe HTML tags', () => {
    const input = '<h1>Title</h1><p>Paragraph with <strong>bold</strong> and <em>italic</em></p>'
    expect(sanitizeRichText(input)).toBe(input)
  })

  it('should preserve safe links', () => {
    const input = '<a href="https://example.com">link</a>'
    expect(sanitizeRichText(input)).toBe(input)
  })

  it('should handle empty string', () => {
    expect(sanitizeRichText('')).toBe('')
  })

  it('should return empty string for non-string input', () => {
    expect(sanitizeRichText(null as any)).toBe('')
    expect(sanitizeRichText(undefined as any)).toBe('')
    expect(sanitizeRichText(123 as any)).toBe('')
  })

  it('should handle script tags with attributes', () => {
    const input = '<script type="text/javascript" src="evil.js"></script><p>safe</p>'
    expect(sanitizeRichText(input)).toBe('<p>safe</p>')
  })
})
