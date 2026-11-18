import { test, expect } from '@playwright/test'

test.describe('Compare Page Portability', () => {
  test('intro states SonicJS self-hosts on Docker and Node/Bun', async ({ page }) => {
    await page.goto('/compare')
    await expect(page.getByText(/also self-hosts on/i).first()).toBeVisible()
    await expect(page.getByText(/Docker or any Node\/Bun server/i).first()).toBeVisible()
  })

  test('matrix runtime row reflects Workers plus Node/Bun', async ({ page }) => {
    await page.goto('/compare')
    await expect(page.getByText('Workers · Node/Bun').first()).toBeVisible()
  })

  test('differentiation section frames Postgres as roadmap, not shipped', async ({ page }) => {
    await page.goto('/compare')
    await expect(page.getByText(/managed Postgres is on the roadmap/i)).toBeVisible()
  })
})
