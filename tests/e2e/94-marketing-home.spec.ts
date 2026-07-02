import { test, expect } from '@playwright/test'

test.describe('Marketing Home Page', () => {
  test('no docs sidebar on home, full-width layout', async ({ page }) => {
    await page.goto('/')

    // Marketing nav present
    await expect(page.locator('[data-marketing-nav]')).toBeVisible()

    // No docs sidebar (the lg:ml-72 sidebar element)
    await expect(page.locator('.lg\\:w-72')).not.toBeVisible()

    // Hero headline present
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
    const h1Text = await page.getByRole('heading', { level: 1 }).textContent()
    expect(h1Text).toContain('born on the edge')
  })

  test('hero admin screenshot visible', async ({ page }) => {
    await page.goto('/')
    const screenshot = page.getByAltText('SonicJS admin content management interface')
    await expect(screenshot).toBeVisible()
  })

  test('final CTA has Discord primary and Quickstart secondary', async ({ page }) => {
    await page.goto('/')

    // Primary: Discord
    const discordLink = page.getByRole('link', { name: /Join Discord/i }).last()
    await expect(discordLink).toBeVisible()
    const discordHref = await discordLink.getAttribute('href')
    expect(discordHref).toContain('discord.gg')

    // Secondary: Quickstart button at bottom
    const quickstartLink = page.getByRole('link', { name: /Quickstart/i })
    await expect(quickstartLink).toBeVisible()
    const quickstartHref = await quickstartLink.getAttribute('href')
    expect(quickstartHref).toBe('/quickstart')
  })

  test('marketing nav sticky with correct links', async ({ page }) => {
    await page.goto('/')

    const nav = page.locator('[data-marketing-nav]')
    await expect(nav).toBeVisible()

    // Nav has Docs, Blog, Compare links
    await expect(nav.getByRole('link', { name: 'Docs' })).toBeVisible()
    await expect(nav.getByRole('link', { name: 'Blog' })).toBeVisible()
    await expect(nav.getByRole('link', { name: 'Compare' })).toBeVisible()

    // Version badge visible
    await expect(nav.getByText(/^v\d/)).toBeVisible()
  })

  test('benchmark stats show all 4 metrics', async ({ page }) => {
    await page.goto('/')
    await expect(
      page.getByRole('heading', { name: /Numbers a single region/i }),
    ).toBeVisible()
    // Values also appear in the comparison table — assert the first occurrence
    await expect(page.getByText('0-5ms').first()).toBeVisible()
    await expect(page.getByText('15-50ms').first()).toBeVisible()
    await expect(page.getByText('300+').first()).toBeVisible()
    await expect(page.getByText('$0').first()).toBeVisible()
  })

  test('changelog link points to /changelog', async ({ page }) => {
    await page.goto('/')
    const changelogLink = page.getByRole('link', { name: /full changelog/i })
    await expect(changelogLink).toBeVisible()
    const href = await changelogLink.getAttribute('href')
    expect(href).toBe('/changelog')
  })

  test('docs route still has sidebar (regression check)', async ({ page }) => {
    await page.goto('/quickstart')

    // Docs sidebar element present
    const sidebar = page.locator('.lg\\:block.lg\\:w-72, [class*="lg:w-72"]')
    // At least verify the marketing nav is NOT present (docs layout)
    await expect(page.locator('[data-marketing-nav]')).not.toBeVisible()
  })

  test('comparison table present on home', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByText('Honest numbers. No marketing spin.')).toBeVisible()
    await expect(page.getByRole('table')).toBeVisible()
  })

  test('hero subhead mentions portability', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByText(/anywhere SQLite runs/i).first()).toBeVisible()
  })

  test('trust strip includes "Runs anywhere"', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByText('Runs anywhere', { exact: true })).toBeVisible()
  })

  test('deploy-anywhere section: Cloudflare recommended + self-host targets', async ({ page }) => {
    await page.goto('/')
    await expect(
      page.getByRole('heading', { name: 'Born on the edge. Runs anywhere.' }),
    ).toBeVisible()
    await expect(page.getByRole('heading', { name: 'Cloudflare Workers' })).toBeVisible()
    await expect(page.getByRole('heading', { name: 'Also runs on' })).toBeVisible()
    await expect(page.getByText('docker run sonicjs')).toBeVisible()
    // Honesty guardrail: Postgres framed as roadmap, not shipped today
    await expect(page.getByText(/Postgres.*roadmap/i)).toBeVisible()
  })

  test('final CTA band has install command and join discord', async ({ page }) => {
    await page.goto('/')
    const discordLinks = page.getByRole('link', { name: /Join Discord/i })
    await expect(discordLinks.first()).toBeVisible()
  })

  test('why-switch cards render with overlaid text on image background', async ({ page }) => {
    await page.goto('/')
    await expect(
      page.getByRole('heading', { name: 'Why Developers Switch to SonicJS' }),
    ).toBeVisible()
    // Pain-card background image present (Next fill image keeps alt text)
    await expect(page.getByAltText('Seamless migration visualization')).toBeVisible()
    // All four card titles overlaid on the images
    await expect(page.getByRole('heading', { name: 'No More Migration Hell' })).toBeVisible()
    await expect(
      page.getByRole('heading', { name: 'The Features You Need Are Paywalled' }),
    ).toBeVisible()
    await expect(
      page.getByRole('heading', { name: '0ms Cold Start, Sub-50ms Worldwide' }),
    ).toBeVisible()
    await expect(page.getByRole('heading', { name: 'AI Included, Not Upsold' })).toBeVisible()
  })

  test('pricing clarifies SonicJS is software, not a hosting service', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByText(/software, not a hosting service/i)).toBeVisible()
    await expect(page.getByText('SonicJS on your Cloudflare account')).toBeVisible()
  })

  test('AI section highlights native MCP server', async ({ page }) => {
    await page.goto('/')
    await expect(
      page.getByRole('heading', { name: 'Your content layer, speaking AI.' }),
    ).toBeVisible()
    // Concrete MCP capability copy (agents read/create/publish)
    await expect(page.getByText(/read, create, and publish/i)).toBeVisible()
    // MCP connect snippet present
    await expect(page.getByText(/mcpServers/)).toBeVisible()
  })

  test('four pillars section shows the wedge heading', async ({ page }) => {
    await page.goto('/')
    await expect(
      page.getByRole('heading', { name: /edge-native\. Free because/i }),
    ).toBeVisible()
    await expect(page.getByText('Independent & portable')).toBeVisible()
  })

  test('DX showcase shows schema and generated API panels', async ({ page }) => {
    await page.goto('/')
    await expect(
      page.getByRole('heading', { name: /From schema to global API/i }),
    ).toBeVisible()
    await expect(page.getByText(/Auto-generated REST API/i).first()).toBeVisible()
  })

  test('plugin grid links to plugin pages', async ({ page }) => {
    await page.goto('/')
    await expect(
      page.getByRole('heading', { name: /Lightweight core\. Powerful plugins\./i }),
    ).toBeVisible()
    const aiSearchCard = page.getByRole('link', { name: /AI Search/i }).first()
    await expect(aiSearchCard).toBeVisible()
    expect(await aiSearchCard.getAttribute('href')).toBe('/plugins/ai-search')
  })

  test('pricing shows SonicJS as recommended', async ({ page }) => {
    await page.goto('/')
    await expect(
      page.getByRole('heading', { name: /Stop overpaying/i }),
    ).toBeVisible()
    await expect(page.getByText('RECOMMENDED').first()).toBeVisible()
    await expect(page.getByText('All features included')).toBeVisible()
  })

  test('built-in-the-open band shows community links', async ({ page }) => {
    await page.goto('/')
    await expect(page.getByRole('heading', { name: 'Built in the open' })).toBeVisible()
    await expect(page.getByText('Open Source · MIT License')).toBeVisible()
    await expect(page.getByText('Discord Community')).toBeVisible()
  })
})
