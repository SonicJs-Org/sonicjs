import { createServer } from 'node:http'
import { test, expect } from './fixtures'
import { submitAndWaitForXhr } from './utils/test-helpers'

// A real HTTP server tests runner contracts, not mocked SonicJS behavior.
// Product CRUD/auth tests remain in the normal suite.
test.describe('Runner contracts @smoke', () => {
  test('explicit load timeouts are not downgraded or swallowed', async ({ page }) => {
    const server = createServer((req, res) => {
      if (req.url === '/pending.png') return
      res.writeHead(200, { 'Content-Type': 'text/html' })
      res.end('<h1>Ready document</h1><img src="/pending.png">')
    })
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    const address = server.address() as { port: number }
    try {
      await expect(page.goto(`http://127.0.0.1:${address.port}`, {
        waitUntil: 'load', timeout: 150,
      })).rejects.toThrow(/Timeout/)
    } finally {
      server.closeAllConnections()
      await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()))
    }
  })

  test('XHR helper waits for the response body and fires the mutation once', async ({ page }) => {
    let puts = 0
    let finishResponse: (() => void) | undefined
    const server = createServer((req, res) => {
      if (req.method === 'PUT') {
        puts++
        res.writeHead(200, { 'Content-Type': 'text/plain' })
        res.write('saved')
        finishResponse = () => res.end(' completely')
        return
      }
      res.writeHead(200, { 'Content-Type': 'text/html' })
      res.end('<button onclick="fetch(\'/save\', {method:\'PUT\'}).then(r=>r.text()).then(t=>document.querySelector(\'output\').textContent=t)">Save</button><output></output>')
    })
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    const address = server.address() as { port: number }
    try {
      await page.goto(`http://127.0.0.1:${address.port}`, { waitUntil: 'domcontentloaded' })
      let settled = false
      const saving = submitAndWaitForXhr(page, 'PUT', '/save', () => page.getByRole('button', { name: 'Save' }).click()).then(() => { settled = true })
      await expect.poll(() => puts).toBe(1)
      expect(settled).toBe(false)
      finishResponse!()
      await saving
      await expect(page.locator('output')).toHaveText('saved completely')
      expect(puts).toBe(1)
    } finally {
      finishResponse?.()
      server.closeAllConnections()
      await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()))
    }
  })
})
