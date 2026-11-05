# Testing Guide

SonicJS AI includes comprehensive testing strategies covering unit tests and end-to-end testing with Playwright. This guide covers all testing approaches, tools, and best practices used in the project.

## Table of Contents

- [Overview](#overview)
- [Testing Stack](#testing-stack)
- [Setup and Installation](#setup-and-installation)
- [Unit Testing with Vitest](#unit-testing-with-vitest)
- [End-to-End Testing with Playwright](#end-to-end-testing-with-playwright)
- [Test Organization](#test-organization)
- [Running Tests](#running-tests)
- [Coverage Reporting](#coverage-reporting)
- [Testing Plugins](#testing-plugins)
- [Testing Middleware and Routes](#testing-middleware-and-routes)
- [Testing Database Operations](#testing-database-operations)
- [Test Helpers and Utilities](#test-helpers-and-utilities)
- [CI/CD Integration](#cicd-integration)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

## Overview

### Testing Philosophy

SonicJS AI follows a comprehensive testing approach:

- **Unit Tests** - Fast, isolated tests for individual functions and services
- **End-to-End Tests** - Browser-based tests for critical user journeys and workflows

### Test Coverage Goals

- **90%** minimum code coverage for core business logic
- **All API endpoints** have E2E test coverage
- **Key user workflows** have comprehensive test coverage
- **Plugin functionality** is thoroughly tested

### Current Coverage Status

As of the latest test run:
- **Overall Coverage**: 90.86%
- **Total Tests**: 684 passing
- **Test Files**: 26 test files
- **Statements**: 90.86%
- **Branches**: 90.34%
- **Functions**: 96.23%
- **Lines**: 90.86%

## Testing Stack

### Core Testing Tools

| Tool | Purpose | Version |
|------|---------|---------|
| **Vitest** | Unit Testing | 2.1.8 |
| **Playwright** | End-to-End Testing | 1.53.1 |
| **@vitest/coverage-v8** | Code Coverage | 2.1.9 |

### Why These Tools?

- **Vitest**: Fast, Vite-native test runner with excellent TypeScript support
- **Playwright**: Reliable cross-browser testing with powerful debugging capabilities
- **Coverage-v8**: Fast, accurate code coverage using V8's built-in coverage

## Setup and Installation

### Prerequisites

```bash
# Install dependencies
npm install

# Install Playwright browsers (first time only)
npx playwright install
```

### Configuration Files

The project includes pre-configured test setups:

- `/Users/lane/Dev/refs/sonicjs-ai/vitest.config.ts` - Vitest configuration
- `/Users/lane/Dev/refs/sonicjs-ai/playwright.config.ts` - Playwright configuration
- `/Users/lane/Dev/refs/sonicjs-ai/tests/e2e/utils/test-helpers.ts` - Shared test utilities

## Unit Testing with Vitest

### Vitest Configuration

```typescript
// vitest.config.ts
import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['src/**/*.{test,spec}.{js,mjs,cjs,ts,mts,cts,jsx,tsx}'],
    exclude: ['node_modules', 'dist', '.next'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      include: ['src/**/*.{js,ts}'],
      exclude: [
        'src/**/*.{test,spec}.{js,ts}',
        'src/**/*.d.ts',
        'src/scripts/**',
        'src/templates/**'
      ],
      thresholds: {
        global: {
          branches: 90,
          functions: 90,
          lines: 90,
          statements: 90
        }
      }
    }
  },
})
```

### Real-World Unit Test Example: Cache Plugin

From `/Users/lane/Dev/refs/sonicjs-ai/src/plugins/cache/tests/cache.test.ts`:

```typescript
import { describe, it, expect, beforeEach, vi } from 'vitest'
import {
  CacheService,
  createCacheService,
  getCacheService,
  clearAllCaches,
  getAllCacheStats
} from '../services/cache.js'
import {
  CACHE_CONFIGS,
  getCacheConfig,
  generateCacheKey,
  parseCacheKey,
  hashQueryParams,
  createCachePattern
} from '../services/cache-config.js'

describe('CacheConfig', () => {
  it('should have predefined cache configurations', () => {
    expect(CACHE_CONFIGS.content).toBeDefined()
    expect(CACHE_CONFIGS.user).toBeDefined()
    expect(CACHE_CONFIGS.config).toBeDefined()
    expect(CACHE_CONFIGS.media).toBeDefined()
  })

  it('should generate cache key with correct format', () => {
    const key = generateCacheKey('content', 'post', '123', 'v1')
    expect(key).toBe('content:post:123:v1')
  })

  it('should parse cache key correctly', () => {
    const key = 'content:post:123:v1'
    const parsed = parseCacheKey(key)

    expect(parsed).toBeDefined()
    expect(parsed?.namespace).toBe('content')
    expect(parsed?.type).toBe('post')
    expect(parsed?.identifier).toBe('123')
    expect(parsed?.version).toBe('v1')
  })

  it('should hash query parameters consistently', () => {
    const params1 = { limit: 10, offset: 0, sort: 'asc' }
    const params2 = { offset: 0, limit: 10, sort: 'asc' }

    const hash1 = hashQueryParams(params1)
    const hash2 = hashQueryParams(params2)

    expect(hash1).toBe(hash2) // Order shouldn't matter
  })
})

describe('CacheService - Basic Operations', () => {
  let cache: CacheService

  beforeEach(() => {
    const config = {
      ttl: 60,
      kvEnabled: false,
      memoryEnabled: true,
      namespace: 'test',
      invalidateOn: [],
      version: 'v1'
    }
    cache = createCacheService(config)
  })

  it('should set and get value from cache', async () => {
    await cache.set('test:key', 'value')
    const result = await cache.get('test:key')

    expect(result).toBe('value')
  })

  it('should return null for non-existent key', async () => {
    const result = await cache.get('non-existent')
    expect(result).toBeNull()
  })

  it('should delete value from cache', async () => {
    await cache.set('test:key', 'value')
    await cache.delete('test:key')

    const result = await cache.get('test:key')
    expect(result).toBeNull()
  })
})

describe('CacheService - TTL and Expiration', () => {
  let cache: CacheService

  beforeEach(() => {
    const config = {
      ttl: 1, // 1 second TTL for testing
      kvEnabled: false,
      memoryEnabled: true,
      namespace: 'test',
      invalidateOn: [],
      version: 'v1'
    }
    cache = createCacheService(config)
  })

  it('should expire entries after TTL', async () => {
    await cache.set('test:key', 'value')

    // Wait for expiration
    await new Promise(resolve => setTimeout(resolve, 1100))

    const result = await cache.get('test:key')
    expect(result).toBeNull()
  })

  it('should allow custom TTL per entry', async () => {
    await cache.set('test:key', 'value', { ttl: 10 }) // 10 second TTL

    // Entry should still be there after 1 second
    await new Promise(resolve => setTimeout(resolve, 1100))

    const result = await cache.get('test:key')
    expect(result).toBe('value')
  })
})

describe('CacheService - Pattern Invalidation', () => {
  let cache: CacheService

  beforeEach(() => {
    cache = createCacheService(CACHE_CONFIGS.content!)
  })

  it('should invalidate entries matching pattern', async () => {
    await cache.set('content:post:1', 'value1')
    await cache.set('content:post:2', 'value2')
    await cache.set('content:page:1', 'value3')

    const count = await cache.invalidate('content:post:*')

    expect(count).toBe(2)

    const post1 = await cache.get('content:post:1')
    const post2 = await cache.get('content:post:2')
    const page1 = await cache.get('content:page:1')

    expect(post1).toBeNull()
    expect(post2).toBeNull()
    expect(page1).toBe('value3') // Should not be invalidated
  })
})

describe('Global Cache Management', () => {
  it('should get singleton cache instance', () => {
    const cache1 = getCacheService(CACHE_CONFIGS.content!)
    const cache2 = getCacheService(CACHE_CONFIGS.content!)

    expect(cache1).toBe(cache2) // Same instance
  })

  it('should clear all cache instances', async () => {
    const contentCache = getCacheService(CACHE_CONFIGS.content!)
    const userCache = getCacheService(CACHE_CONFIGS.user!)

    await contentCache.set('content:key', 'value')
    await userCache.set('user:key', 'value')

    await clearAllCaches()

    const contentValue = await contentCache.get('content:key')
    const userValue = await userCache.get('user:key')

    expect(contentValue).toBeNull()
    expect(userValue).toBeNull()
  })
})
```

### Unit Testing Patterns

#### Testing with Mocks

```typescript
import { vi } from 'vitest'

describe('Service with Dependencies', () => {
  it('should not call fetcher when value is cached', async () => {
    await cache.set('test:key', 'cached-value')

    const fetcher = vi.fn(async () => 'fetched-value')
    const result = await cache.getOrSet('test:key', fetcher)

    expect(result).toBe('cached-value')
    expect(fetcher).not.toHaveBeenCalled()
  })
})
```

#### Testing Async Operations

```typescript
it('should fetch and cache value when not found', async () => {
  let fetchCount = 0
  const fetcher = async () => {
    fetchCount++
    return 'fetched-value'
  }

  const result1 = await cache.getOrSet('test:key', fetcher)
  const result2 = await cache.getOrSet('test:key', fetcher)

  expect(result1).toBe('fetched-value')
  expect(result2).toBe('fetched-value')
  expect(fetchCount).toBe(1) // Fetcher should only be called once
})
```

## End-to-End Testing with Playwright

### Playwright Configuration

```typescript
// playwright.config.ts
import { defineConfig, devices } from '@playwright/test'

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: 'html',
  globalSetup: require.resolve('./tests/e2e/global-setup.ts'),
  globalTeardown: require.resolve('./tests/e2e/global-teardown.ts'),
  use: {
    baseURL: 'http://localhost:8787',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    command: 'npm run dev',
    url: 'http://localhost:8787',
    reuseExistingServer: !process.env.CI,
    timeout: 120 * 1000,
  },
})
```

### Health Check Tests

From `/Users/lane/Dev/refs/sonicjs-ai/tests/e2e/01-health.spec.ts`:

```typescript
import { test, expect } from '@playwright/test'
import { checkAPIHealth } from './utils/test-helpers'

test.describe('Health Checks', () => {
  test('API health endpoint should return running status', async ({ page }) => {
    const health = await checkAPIHealth(page)

    expect(health).toHaveProperty('name', 'SonicJS AI')
    expect(health).toHaveProperty('version', '0.1.0')
    expect(health).toHaveProperty('status', 'running')
    expect(health).toHaveProperty('timestamp')
  })

  test('Home page should redirect to login', async ({ page }) => {
    const response = await page.goto('/')
    expect(response?.status()).toBe(200)

    // Should redirect to login page
    await page.waitForURL(/\/auth\/login/)

    // Verify we're on the login page
    expect(page.url()).toContain('/auth/login')
    await expect(page.locator('h2')).toContainText('Welcome Back')
  })

  test('Admin routes should require authentication', async ({ page }) => {
    // Try to access admin without auth
    await page.goto('/admin')

    // Should redirect to login
    await page.waitForURL(/\/auth\/login/)

    // Verify error message is shown
    await expect(page.locator('.bg-error\\/10')).toContainText(
      'Please login to access the admin area'
    )
  })

  test('404 routes should return not found', async ({ page }) => {
    const response = await page.goto('/nonexistent-route')
    expect(response?.status()).toBe(404)
  })
})
```

### Authentication Tests

From `/Users/lane/Dev/refs/sonicjs-ai/tests/e2e/02-authentication.spec.ts`:

```typescript
import { test, expect } from '@playwright/test'
import { loginAsAdmin, logout, isAuthenticated, ADMIN_CREDENTIALS } from './utils/test-helpers'

test.describe('Authentication', () => {
  test.beforeEach(async ({ page }) => {
    await logout(page)
  })

  test('should display login form', async ({ page }) => {
    await page.goto('/auth/login')

    await expect(page.locator('h2')).toContainText('Welcome Back')
    await expect(page.locator('[name="email"]')).toBeVisible()
    await expect(page.locator('[name="password"]')).toBeVisible()
    await expect(page.locator('button[type="submit"]')).toBeVisible()
  })

  test('should login successfully with valid credentials', async ({ page }) => {
    await loginAsAdmin(page)

    // Should be on admin dashboard
    await expect(page).toHaveURL('/admin')
    await expect(page.locator('nav').first()).toBeVisible()
  })

  test('should show error with invalid credentials', async ({ page }) => {
    await page.goto('/auth/login')

    await page.fill('[name="email"]', 'invalid@email.com')
    await page.fill('[name="password"]', 'wrongpassword')
    await page.click('button[type="submit"]')

    // Should show error message
    await expect(page.locator('.error, .bg-red-100')).toBeVisible()
  })

  test('should protect admin routes from unauthenticated access', async ({ page }) => {
    const adminRoutes = [
      '/admin',
      '/admin/collections',
      '/admin/content',
      '/admin/media',
      '/admin/users'
    ]

    for (const route of adminRoutes) {
      await page.goto(route)
      await page.waitForURL(/\/auth\/login/)
      await expect(page.locator('h2')).toContainText('Welcome Back')
    }
  })

  test('should maintain session across page reloads', async ({ page }) => {
    await loginAsAdmin(page)

    await page.reload()

    // Should still be authenticated
    await expect(page).toHaveURL('/admin')
    await expect(await isAuthenticated(page)).toBe(true)
  })
})
```

### Content Management Tests

From `/Users/lane/Dev/refs/sonicjs-ai/tests/e2e/05-content.spec.ts`:

```typescript
import { test, expect } from '@playwright/test'
import {
  loginAsAdmin,
  navigateToAdminSection,
  waitForHTMX,
  ensureTestContentExists
} from './utils/test-helpers'

test.describe('Content Management', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
    await ensureTestContentExists(page)
    await navigateToAdminSection(page, 'content')
  })

  test('should display content list', async ({ page }) => {
    await expect(page.locator('h1').first()).toContainText('Content Management')

    // Should have filter dropdowns
    await expect(page.locator('select[name="model"]')).toBeVisible()
    await expect(page.locator('select[name="status"]')).toBeVisible()
  })

  test('should filter content by status', async ({ page }) => {
    // Filter by published status
    await page.selectOption('select[name="status"]', 'published')

    // Wait for HTMX to update the content
    await waitForHTMX(page)

    const table = page.locator('table')
    const hasTable = await table.count() > 0

    if (hasTable) {
      const publishedRows = page.locator('tr').filter({ hasText: 'published' })
      const rowCount = await publishedRows.count()
      expect(rowCount).toBeGreaterThanOrEqual(0)
    }
  })

  test('should navigate to new content form', async ({ page }) => {
    await page.click('a[href="/admin/content/new"]')

    await page.waitForURL('/admin/content/new', { timeout: 10000 })

    // Should show collection selection page
    await expect(page.locator('h1')).toContainText('Create New Content')
    await expect(page.locator('text=Select a collection to create content in:')).toBeVisible()

    // Should have at least one collection to select
    const collectionLinks = page.locator('a[href^="/admin/content/new?collection="]')
    const count = await collectionLinks.count()
    expect(count).toBeGreaterThan(0)
  })
})
```

### Media Management Tests

From `/Users/lane/Dev/refs/sonicjs-ai/tests/e2e/06-media.spec.ts`:

```typescript
import { test, expect } from '@playwright/test'
import { loginAsAdmin, navigateToAdminSection } from './utils/test-helpers'

test.describe('Media Management', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
    await navigateToAdminSection(page, 'media')
  })

  test('should display media library', async ({ page }) => {
    await expect(page.locator('h1')).toContainText('Media Library')
    await expect(page.locator('button').filter({ hasText: 'Upload Files' }).first())
      .toBeVisible()
  })

  test('should handle file upload', async ({ page }) => {
    await page.locator('button').filter({ hasText: 'Upload Files' }).first().click()

    // Create a small test image file
    const testImageBuffer = Buffer.from([
      0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
      // ... (truncated for brevity)
    ])

    await page.setInputFiles('#file-input', {
      name: 'test-image.jpg',
      mimeType: 'image/jpeg',
      buffer: testImageBuffer
    })

    await page.locator('button[type="submit"]').click()

    // Should show upload success
    await expect(page.locator('#upload-results'))
      .toContainText('Successfully uploaded', { timeout: 10000 })
  })

  test('should validate file types', async ({ page }) => {
    await page.locator('button').filter({ hasText: 'Upload Files' }).first().click()

    // Try to upload an invalid file type
    await page.setInputFiles('#file-input', {
      name: 'test.exe',
      mimeType: 'application/octet-stream',
      buffer: Buffer.from('fake executable')
    })

    await page.locator('button[type="submit"]').click()

    // Should show validation error
    await expect(page.locator('#upload-results'))
      .toContainText('Unsupported file type')
  })
})
```

### API Testing with Playwright

From `/Users/lane/Dev/refs/sonicjs-ai/tests/e2e/07-api.spec.ts`:

```typescript
import { test, expect } from '@playwright/test'

test.describe('API Endpoints', () => {
  test('should return health check', async ({ request }) => {
    const response = await request.get('/health')

    expect(response.ok()).toBeTruthy()

    const health = await response.json()
    expect(health).toHaveProperty('name', 'SonicJS AI')
    expect(health).toHaveProperty('version', '0.1.0')
    expect(health).toHaveProperty('status', 'running')
  })

  test('should return OpenAPI spec', async ({ request }) => {
    const response = await request.get('/api')

    expect(response.ok()).toBeTruthy()

    const spec = await response.json()
    expect(spec).toHaveProperty('openapi')
    expect(spec).toHaveProperty('info')
    expect(spec).toHaveProperty('paths')
  })

  test('should handle CORS for API endpoints', async ({ request }) => {
    const response = await request.get('/api', {
      headers: {
        'Origin': 'http://localhost:3000'
      }
    })

    expect(response.ok()).toBeTruthy()

    const corsHeader = response.headers()['access-control-allow-origin']
    expect(corsHeader).toBeDefined()
  })

  test('should validate request methods', async ({ request }) => {
    // Test unsupported method
    const response = await request.patch('/health')

    // Should return method not allowed or not found
    expect([404, 405]).toContain(response.status())
  })
})
```

### Collections API Tests

From `/Users/lane/Dev/refs/sonicjs-ai/tests/e2e/08-collections-api.spec.ts`:

```typescript
import { test, expect } from '@playwright/test'

test.describe('Collections API', () => {
  test('should return all active collections', async ({ request }) => {
    const response = await request.get('/api/collections')

    expect(response.ok()).toBeTruthy()
    expect(response.status()).toBe(200)

    const data = await response.json()

    // Verify response structure
    expect(data).toHaveProperty('data')
    expect(data).toHaveProperty('meta')
    expect(data.meta).toHaveProperty('count')
    expect(data.meta).toHaveProperty('timestamp')

    // Verify data is an array
    expect(Array.isArray(data.data)).toBeTruthy()

    // Should contain at least the default blog_posts collection
    expect(data.data.length).toBeGreaterThan(0)

    // Meta count should match data length
    expect(data.meta.count).toBe(data.data.length)
  })

  test('should handle SQL injection attempts safely', async ({ request }) => {
    const sqlInjectionAttempts = [
      "'; DROP TABLE collections; --",
      "' OR '1'='1",
      "'; SELECT * FROM users; --",
    ]

    for (const injection of sqlInjectionAttempts) {
      const response = await request.get(
        `/api/collections/${encodeURIComponent(injection)}/content`
      )

      // Should safely return 404, not expose database errors
      expect(response.status()).toBe(404)

      const data = await response.json()
      expect(data.error).toBe('Collection not found')

      // Should not expose SQL error messages
      expect(data.error).not.toContain('SQL')
      expect(data.error).not.toContain('database')
    }
  })

  test('should respond within reasonable time', async ({ request }) => {
    const startTime = Date.now()
    const response = await request.get('/api/collections')
    const endTime = Date.now()

    expect(response.ok()).toBeTruthy()

    // Should respond within 2 seconds
    const responseTime = endTime - startTime
    expect(responseTime).toBeLessThan(2000)
  })
})
```

### Plugin Tests

From `/Users/lane/Dev/refs/sonicjs-ai/tests/e2e/15-plugins.spec.ts`:

```typescript
import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

test.describe('Plugin Management', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('should access plugins page and show basic UI', async ({ page }) => {
    await page.goto('/admin/plugins')

    // Check page title
    await expect(page.locator('h1')).toContainText('Plugins')

    // Check for install plugin button
    await expect(page.locator('button:has-text("Install Plugin")')).toBeVisible()

    // Check for at least one plugin card
    await expect(page.locator('.plugin-card').first()).toBeVisible()
  })

  test('should show plugin stats', async ({ page }) => {
    await page.goto('/admin/plugins')

    // Check for stats cards
    await expect(page.locator('text=Total Plugins').first()).toBeVisible()

    const statsCards = page.locator('div')
      .filter({ hasText: 'Total Plugins' })
      .locator('p.text-white.text-2xl')
    await expect(statsCards.first()).toBeVisible()
  })

  test('should toggle plugin status', async ({ page }) => {
    await page.goto('/admin/plugins')

    const pluginCards = page.locator('.plugin-card')
    const count = await pluginCards.count()

    for (let i = 0; i < Math.min(count, 3); i++) {
      const card = pluginCards.nth(i)
      const activateBtn = card.locator('button:has-text("Activate")')
      const deactivateBtn = card.locator('button:has-text("Deactivate")')

      const hasActivate = await activateBtn.count()

      if (hasActivate > 0) {
        await activateBtn.click()

        // Wait for status change
        await expect(card.locator('.status-badge'))
          .toContainText('Active', { timeout: 5000 })
        break
      }
    }
  })
})
```

## Test Organization

### Directory Structure

```
/Users/lane/Dev/refs/sonicjs-ai/
├── tests/
│   └── e2e/                           # End-to-end tests
│       ├── 01-health.spec.ts          # Health check tests
│       ├── 02-authentication.spec.ts  # Auth flow tests
│       ├── 03-admin-dashboard.spec.ts # Dashboard tests
│       ├── 04-collections.spec.ts     # Collection tests
│       ├── 05-content.spec.ts         # Content management tests
│       ├── 06-media.spec.ts           # Media upload tests
│       ├── 07-api.spec.ts             # API endpoint tests
│       ├── 08-collections-api.spec.ts # Collections API tests
│       ├── 15-plugins.spec.ts         # Plugin tests
│       └── utils/
│           └── test-helpers.ts        # Shared test utilities
├── src/
│   └── plugins/
│       └── cache/
│           └── tests/
│               └── cache.test.ts      # Unit tests for cache plugin
├── vitest.config.ts                   # Vitest configuration
└── playwright.config.ts               # Playwright configuration
```

### Test Naming Convention

- **Unit tests**: `*.test.ts` or `*.spec.ts`
- **E2E tests**: `##-feature.spec.ts` (numbered for execution order)

## Running Tests

### Unit Tests

```bash
# Run all unit tests
npm test

# Run tests in watch mode
npm run test:watch

# Run with coverage
npm run test:cov

# Run with coverage in watch mode
npm run test:cov:watch

# Run with coverage and UI
npm run test:cov:ui
```

### E2E Tests

```bash
# Run all E2E tests
npm run test:e2e

# Run E2E tests with UI mode
npm run test:e2e:ui

# Run specific test file
npm run e2e -- auth-ui.spec.ts

# Run tests in headed mode (see browser)
npx playwright test --headed

# Run tests in debug mode
npx playwright test --debug
```

### Running Specific Tests

```bash
# Run single test file
npx vitest src/plugins/cache/tests/cache.test.ts

# Run tests matching pattern
npx vitest --grep "CacheService"

# Run E2E tests for specific feature
npx playwright test tests/e2e/05-content.spec.ts
```

## Coverage Reporting

### Viewing Coverage Reports

```bash
# Generate coverage report
npm run test:cov

# Coverage files are generated in:
# - coverage/index.html (HTML report)
# - coverage/coverage-final.json (JSON report)
```

### Coverage Thresholds

The project enforces minimum coverage thresholds:

```typescript
thresholds: {
  global: {
    branches: 90,
    functions: 90,
    lines: 90,
    statements: 90
  }
}
```

**Recent Coverage Improvements:**

The project recently increased coverage from 87% to over 90% by adding comprehensive tests for:
- Media storage operations (`src/media/storage.ts` - 92.96%)
- Image optimization (`src/media/images.ts` - 91.74%)
- Cache plugin functionality (`src/plugins/cache/` - extensive coverage)
- Core services (CDN, notifications, scheduler, workflow - all >93%)

### Coverage Exclusions

The following directories are excluded from coverage:

- Test files (`**/*.{test,spec}.{js,ts}`)
- Type definitions (`**/*.d.ts`)
- Scripts (`src/scripts/**`)
- Templates (`src/templates/**`)

## Testing Plugins

### Plugin Structure

Plugins include their own test files:

```
src/plugins/cache/
├── services/
│   ├── cache.ts
│   └── cache-config.ts
└── tests/
    └── cache.test.ts
```

### Example Plugin Test

```typescript
describe('CacheService - Batch Operations', () => {
  let cache: CacheService

  beforeEach(() => {
    cache = createCacheService(CACHE_CONFIGS.content!)
  })

  it('should get multiple values at once', async () => {
    await cache.set('key1', 'value1')
    await cache.set('key2', 'value2')
    await cache.set('key3', 'value3')

    const results = await cache.getMany(['key1', 'key2', 'key3', 'key4'])

    expect(results.size).toBe(3)
    expect(results.get('key1')).toBe('value1')
    expect(results.get('key2')).toBe('value2')
    expect(results.has('key4')).toBe(false)
  })

  it('should set multiple values at once', async () => {
    await cache.setMany([
      { key: 'key1', value: 'value1' },
      { key: 'key2', value: 'value2' },
      { key: 'key3', value: 'value3' }
    ])

    const value1 = await cache.get('key1')
    const value2 = await cache.get('key2')

    expect(value1).toBe('value1')
    expect(value2).toBe('value2')
  })
})
```

## Testing Middleware and Routes

### API Route Testing

Use Playwright's `request` fixture for API testing:

```typescript
test('should require authentication for admin API', async ({ request }) => {
  const response = await request.get('/admin/api/collections')

  // Should redirect to login or return 401
  expect([401, 302, 200]).toContain(response.status())
})

test('should handle large requests gracefully', async ({ request }) => {
  const largeData = 'x'.repeat(10000)

  const response = await request.post('/admin/api/collections', {
    data: {
      name: 'large_test',
      displayName: 'Large Test Collection',
      description: largeData
    }
  })

  // Should handle gracefully
  expect([200, 201, 400, 401, 413, 422]).toContain(response.status())
})
```

## Testing Database Operations

### Testing with Mock Data

Database operations are tested through E2E tests:

```typescript
test('should ensure collection IDs are consistent', async ({ request }) => {
  const collectionsResponse = await request.get('/api/collections')
  const collectionsData = await collectionsResponse.json()

  const contentResponse = await request.get('/api/content')
  const contentData = await contentResponse.json()

  // All content items should reference valid collection IDs
  const collectionIds = collectionsData.data.map((c: any) => c.id)

  contentData.data.forEach((content: any) => {
    if (content.collectionId) {
      expect(collectionIds).toContain(content.collectionId)
    }
  })
})
```

## Test Helpers and Utilities

### Location

`/Users/lane/Dev/refs/sonicjs-ai/tests/e2e/utils/test-helpers.ts`

### Common Test Helpers

```typescript
// Authentication
export const ADMIN_CREDENTIALS = {
  email: 'admin@sonicjs.com',
  password: 'sonicjs!'
}

export async function loginAsAdmin(page: Page) {
  await ensureAdminUserExists(page)

  await page.goto('/auth/login')
  await page.fill('[name="email"]', ADMIN_CREDENTIALS.email)
  await page.fill('[name="password"]', ADMIN_CREDENTIALS.password)
  await page.click('button[type="submit"]')

  await expect(page.locator('#form-response .bg-green-100')).toBeVisible()
  await page.waitForURL('/admin', { timeout: 15000 })
}

// Navigation
export async function navigateToAdminSection(
  page: Page,
  section: 'collections' | 'content' | 'media' | 'users'
) {
  await page.click(`a[href="/admin/${section}"]`)
  await page.waitForURL(`/admin/${section}`)
}

// HTMX Support
export async function waitForHTMX(page: Page) {
  try {
    await page.waitForLoadState('networkidle', { timeout: 5000 })
  } catch {
    await page.waitForTimeout(1000)
  }
}

// API Health Check
export async function checkAPIHealth(page: Page) {
  const response = await page.request.get('/health')
  expect(response.ok()).toBeTruthy()
  const health = await response.json()
  expect(health.status).toBe('running')
  return health
}

// Test Data Creation
export async function createTestContent(page: Page, contentData?: {
  title: string
  slug: string
  content: string
}) {
  const data = contentData || {
    title: 'Test Content',
    slug: 'test-content',
    content: 'This is test content for E2E testing.'
  }

  await page.goto('/admin/content/new')

  const collectionLinks = page.locator('a[href*="/admin/content/new?collection="]')
  await collectionLinks.first().click()

  await page.fill('input[name="title"]', data.title)
  await page.fill('input[name="slug"]', data.slug)
  await page.fill('textarea[name="content"]', data.content)

  await page.click('button[type="submit"]')
  await page.waitForTimeout(2000)
}
```

### Using Test Helpers

```typescript
import { loginAsAdmin, navigateToAdminSection, waitForHTMX } from './utils/test-helpers'

test('my test', async ({ page }) => {
  await loginAsAdmin(page)
  await navigateToAdminSection(page, 'content')

  // Perform actions...
  await page.selectOption('select[name="status"]', 'published')
  await waitForHTMX(page)

  // Assertions...
})
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Test Suite

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Run unit tests
        run: npm run test:cov

      - name: Upload coverage
        uses: codecov/codecov-action@v3

  e2e-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Install Playwright
        run: npx playwright install --with-deps

      - name: Run E2E tests
        run: npm run test:e2e

      - name: Upload test results
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: playwright-report
          path: playwright-report/
```

## Best Practices

### 1. Test Organization

- **Keep tests close to code**: Unit tests live alongside the code they test
- **Logical grouping**: Use `describe` blocks to organize related tests
- **Clear naming**: Test names should describe what is being tested and expected outcome

```typescript
describe('CacheService - Pattern Invalidation', () => {
  it('should invalidate entries matching pattern', async () => {
    // Test implementation
  })

  it('should not invalidate entries that do not match pattern', async () => {
    // Test implementation
  })
})
```

### 2. Test Independence

- Each test should be independent and not rely on other tests
- Use `beforeEach` to set up fresh state
- Clean up after tests when necessary

```typescript
describe('My Feature', () => {
  beforeEach(() => {
    // Set up fresh state for each test
    cache = createCacheService(config)
  })

  afterEach(async () => {
    // Clean up if needed
    await cache.clear()
  })
})
```

### 3. Async Testing

- Always use `async/await` for asynchronous operations
- Don't forget to `await` promises in tests

```typescript
// Good
it('should fetch data', async () => {
  const result = await fetchData()
  expect(result).toBeDefined()
})

// Bad - missing await
it('should fetch data', async () => {
  const result = fetchData() // Missing await!
  expect(result).toBeDefined() // Will fail
})
```

### 4. Playwright Best Practices

- **Use test helpers**: Create reusable functions for common operations
- **Wait for elements**: Use Playwright's built-in waiting mechanisms
- **Avoid fixed timeouts**: Prefer `waitForSelector` over `waitForTimeout`
- **Handle HTMX**: Use the `waitForHTMX` helper for dynamic updates

```typescript
// Good - wait for specific condition
await expect(page.locator('.success-message')).toBeVisible()

// Avoid - arbitrary timeout
await page.waitForTimeout(5000)
```

### 5. Test Data Management

- Use fixtures and factories for consistent test data
- Don't hard-code IDs or timestamps
- Clean up test data after tests

```typescript
// Use helper to create test data
const TEST_DATA = {
  collection: {
    name: 'test_collection',
    displayName: 'Test Collection',
    description: 'Test collection for E2E testing'
  }
}

// Clean up after tests
test.afterAll(async ({ page }) => {
  await deleteTestCollection(page, TEST_DATA.collection.name)
})
```

### 6. Error Handling

- Test both success and failure cases
- Verify error messages and status codes
- Ensure graceful degradation

```typescript
test('should validate file types', async ({ page }) => {
  // Upload invalid file
  await page.setInputFiles('#file-input', {
    name: 'test.exe',
    mimeType: 'application/octet-stream',
    buffer: Buffer.from('fake executable')
  })

  await page.click('button[type="submit"]')

  // Verify error is shown
  await expect(page.locator('#upload-results'))
    .toContainText('Unsupported file type')
})
```

## Troubleshooting

### Common Issues

#### 1. Tests Timing Out

**Problem**: E2E tests timeout waiting for elements

**Solution**: Increase timeout or improve element selectors

```typescript
// Increase timeout for specific assertion
await expect(page.locator('.slow-loading'))
  .toBeVisible({ timeout: 10000 })

// Or increase global timeout in config
use: {
  timeout: 60000, // 60 seconds
}
```

#### 2. Flaky Tests

**Problem**: Tests pass sometimes but fail randomly

**Solutions**:
- Use Playwright's auto-waiting features
- Avoid race conditions
- Use `waitForLoadState` for network requests

```typescript
// Wait for network to be idle
await page.waitForLoadState('networkidle')

// Wait for specific request
await page.waitForResponse(resp =>
  resp.url().includes('/api/content') && resp.status() === 200
)
```

#### 3. Coverage Not Meeting Thresholds

**Problem**: Coverage reports below 90%

**Solutions**:
- Add tests for uncovered branches
- Review coverage report: `coverage/index.html`
- Identify untested code paths
- Focus on business logic in `src/services`, `src/media`, and `src/content`
- Infrastructure code (routes, templates, middleware) is excluded from coverage

```bash
# Generate coverage and open report
npm run test:cov
open coverage/index.html  # macOS

# View detailed coverage by file
npm run test:cov | grep -A 30 "Coverage report"
```

#### 4. Playwright Browser Issues

**Problem**: Playwright can't find browsers

**Solution**: Reinstall Playwright browsers

```bash
npx playwright install --with-deps
```

#### 5. HTMX Dynamic Content

**Problem**: Tests fail because HTMX updates aren't complete

**Solution**: Use the `waitForHTMX` helper

```typescript
import { waitForHTMX } from './utils/test-helpers'

await page.selectOption('select[name="status"]', 'published')
await waitForHTMX(page)  // Wait for HTMX to update DOM
```

### Debugging Tests

#### Playwright Debugging

```bash
# Run in debug mode with inspector
npx playwright test --debug

# Run headed to see browser
npx playwright test --headed

# Run with slow motion
npx playwright test --headed --slow-mo=1000
```

#### Vitest Debugging

```bash
# Run in watch mode
npm run test:watch

# Run with UI
npm run test:cov:ui

# Run single test file
npx vitest src/plugins/cache/tests/cache.test.ts
```

### Test Artifacts

Playwright saves artifacts on failure:

- **Screenshots**: `test-results/*/test-failed-1.png`
- **Videos**: `test-results/*/video.webm`
- **Traces**: `test-results/*/trace.zip`

View trace files:

```bash
npx playwright show-trace test-results/*/trace.zip
```

## Additional Resources

### Documentation

- [Vitest Documentation](https://vitest.dev/)
- [Playwright Documentation](https://playwright.dev/)
- [Playwright Best Practices](https://playwright.dev/docs/best-practices)

### Related Documentation

- [API Reference](api-reference.md) - API endpoint specifications
- [Plugin Development](plugin-development.md) - Creating and testing plugins
- [Contributing](contributing.md) - Contribution guidelines

## Summary

SonicJS AI uses a comprehensive testing strategy combining:

- **Vitest** for fast, isolated unit tests
- **Playwright** for reliable end-to-end testing
- **Real test examples** from the actual codebase
- **Shared utilities** for consistent test patterns
- **CI/CD integration** for automated testing

Follow the patterns and examples in this guide to write effective tests for your features and ensure the quality of the SonicJS AI platform.
