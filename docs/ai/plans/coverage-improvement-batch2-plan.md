# Code Coverage Improvement Plan - Batch 2

## Overview

This plan outlines the next batch of unit tests to improve code coverage from the current **72.35%** to approximately **80%+**. The focus is on high-impact, testable modules that currently have moderate coverage gaps.

## Current Coverage Status (Accurate as of main branch)

| Category | Current Coverage | Target |
|----------|-----------------|--------|
| Overall | 72.35% | 80%+ |
| Statements | 72.35% | 80% |
| Branches | 50.63% | 65% |
| Functions | 72.65% | 80% |
| Lines | 72.74% | 80% |

**Tests:** 783 passing, 328 skipped

## Coverage Analysis

### Already Well Covered (>80%) - No Action Needed
| File | Coverage |
|------|----------|
| `middleware/bootstrap.ts` | 100% |
| `middleware/plugin-middleware.ts` | 100% |
| *(otp-login-plugin removed; OTP via Better Auth)* | — |
| `plugins/cache/services/cache-config.ts` | 100% |
| `services/cache.ts` | 100% |
| `services/collection-sync.ts` | 100% |
| `services/settings.ts` | 100% |
| `utils/telemetry-id.ts` | 100% |
| `utils/sanitize.ts` | 100% |
| `utils/telemetry-config.ts` | 95.65% |
| `plugins/sdk/plugin-builder.ts` | 94.64% |
| `turnstile-plugin/services/turnstile.ts` | 94.87% |
| `routes/api-system.ts` | 94.64% |
| `routes/admin-plugins.ts` | 89.44% |
| `email-templates-plugin/services/email.ts` | 85.54% |

### Needs Improvement - Priority Targets

| File | Current | Target | Gap | Priority |
|------|---------|--------|-----|----------|
| `plugins/cache/services/cache.ts` | 54.34% | 80% | ~26% | **P1** |
| `services/collection-loader.ts` | 65.27% | 85% | ~20% | **P1** |
| `utils/query-filter.ts` | 71.42% | 85% | ~14% | **P2** |
| `services/telemetry-service.ts` | 78.16% | 90% | ~12% | **P2** |
| `email-renderer.ts` | 77.14% | 85% | ~8% | **P3** |
| `middleware/auth.ts` | 79.26% | 90% | ~11% | **P3** |

### Low Coverage - Templates (Deprioritized)
Templates are UI code better covered by E2E tests:
- `templates/components/form.template.ts` - 14.22%
- `templates/layouts/admin-layout-v2.template.ts` - 0%
- `templates/pages/admin-plugins-list.template.ts` - 0%

## Implementation Plan

### Batch 2A: Cache Service Tests (Priority P1) ⭐ Highest Impact

**File:** `src/plugins/cache/tests/cache.test.ts` (expand existing)
**Current:** 54.34% → **Target:** 80%

The cache service has 40 existing tests but significant uncovered lines (516-567, 594+).

**Additional Test Cases Needed:**
- [ ] `invalidateByPattern` - Invalidate entries matching pattern
- [ ] `invalidateByTags` - Invalidate entries by tags
- [ ] `getStats` - Return cache statistics (hits, misses, size)
- [ ] `warmCache` - Pre-populate cache with values
- [ ] `batchGet` - Get multiple entries at once
- [ ] `batchSet` - Set multiple entries at once
- [ ] Memory limit enforcement
- [ ] Cache eviction when full (LRU)
- [ ] Concurrent access handling
- [ ] Error handling for storage failures

**Estimated Coverage Gain:** +8-10%

### Batch 2B: Collection Loader Service Tests (Priority P1)

**File:** `src/__tests__/services/collection-loader.test.ts` (expand or create)
**Current:** 65.27% → **Target:** 85%

**Uncovered Lines:** 110-111, 126-132

**Test Cases Needed:**
- [ ] `loadCollectionConfigs` - Load with no registered collections (warning path)
- [ ] `loadCollectionConfigs` - Handle glob import failures
- [ ] `loadCollectionConfigs` - Skip collections without default export
- [ ] `loadCollectionConfigs` - Skip collections with missing required fields
- [ ] `getCollectionConfig` - Return undefined for unknown collection
- [ ] `clearCollections` - Reset registry for tests
- [ ] Edge case: Duplicate collection names
- [ ] Edge case: Invalid collection schema

**Estimated Coverage Gain:** +5-7%

### Batch 2C: Query Filter Utils (Priority P2)

**File:** `src/__tests__/utils/query-filter.test.ts` (expand existing)
**Current:** 71.42% → **Target:** 85%

**Uncovered Lines:** 369-374, 383, 420

**Test Cases Needed:**
- [ ] Complex nested filter combinations
- [ ] `$in` operator with empty array
- [ ] `$nin` operator edge cases
- [ ] Date range filters with invalid dates
- [ ] SQL injection prevention verification
- [ ] `$regex` operator with invalid regex
- [ ] `$exists` operator
- [ ] Deeply nested field access
- [ ] Array field filtering

**Estimated Coverage Gain:** +3-5%

### Batch 2D: Telemetry Service Enhancement (Priority P2)

**File:** `src/services/telemetry-service.test.ts` (expand existing)
**Current:** 78.16% → **Target:** 90%

**Uncovered Lines:** 246-248, 288-300

**Test Cases Needed:**
- [ ] `trackEvent` - Handle network failures gracefully
- [ ] `trackEvent` - Respect telemetry disabled setting
- [ ] `flush` - Batch send pending events
- [ ] `flush` - Handle partial failures
- [ ] Session management edge cases
- [ ] Rate limiting behavior

**Estimated Coverage Gain:** +3-4%

### Batch 2E: Auth Middleware Enhancement (Priority P3)

**File:** `src/__tests__/middleware/auth.test.ts` (expand existing)
**Current:** 79.26% → **Target:** 90%

**Uncovered Lines:** 144, 158, 198-199

**Test Cases Needed:**
- [ ] Token refresh edge cases
- [ ] Session expiry handling
- [ ] Role-based access control edge cases
- [ ] API key authentication failures
- [ ] Rate limiting for auth attempts

**Estimated Coverage Gain:** +2-3%

## Testing Strategy

### Unit Test Pattern
```typescript
import { describe, it, expect, beforeEach, vi } from 'vitest'

describe('ModuleName', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('functionName', () => {
    it('should handle normal case', async () => {
      // Arrange
      const input = { /* test data */ }

      // Act
      const result = await functionName(input)

      // Assert
      expect(result).toMatchObject({ /* expected */ })
    })

    it('should handle error case', async () => {
      // Test error paths to improve branch coverage
    })
  })
})
```

### Mocking Strategy

**D1 Database Mock:**
```typescript
const mockDb = {
  prepare: vi.fn().mockReturnValue({
    bind: vi.fn().mockReturnThis(),
    run: vi.fn().mockResolvedValue({ success: true }),
    first: vi.fn().mockResolvedValue(null),
    all: vi.fn().mockResolvedValue({ results: [] })
  })
}
```

**KV Store Mock:**
```typescript
const mockKV = {
  get: vi.fn(),
  put: vi.fn(),
  delete: vi.fn(),
  list: vi.fn().mockResolvedValue({ keys: [], complete: true })
}
```

## File Changes Summary

| File | Action | Description |
|------|--------|-------------|
| `src/plugins/cache/tests/cache.test.ts` | Modify | Add 10+ new test cases |
| `src/__tests__/services/collection-loader.test.ts` | Create/Modify | Add 8+ test cases |
| `src/__tests__/utils/query-filter.test.ts` | Modify | Add 9+ edge case tests |
| `src/services/telemetry-service.test.ts` | Modify | Add 6+ test cases |
| `src/__tests__/middleware/auth.test.ts` | Modify | Add 5+ test cases |

## Expected Outcomes

### Coverage Goals
| Metric | Before | After | Gain |
|--------|--------|-------|------|
| Statements | 72.35% | 80%+ | +8% |
| Branches | 50.63% | 65%+ | +15% |
| Functions | 72.65% | 80%+ | +8% |
| Lines | 72.74% | 80%+ | +8% |

### Test Count
- Current: 783 passing, 328 skipped
- Target: 830+ passing (~50 new tests)

## Implementation Order

1. **Phase 1** (Highest Impact):
   - Cache Service tests (P1) - biggest coverage gap
   - Collection Loader tests (P1) - core functionality

2. **Phase 2** (Moderate Impact):
   - Query Filter edge cases (P2)
   - Telemetry Service enhancement (P2)

3. **Phase 3** (Polish):
   - Auth Middleware enhancement (P3)
   - Review branch coverage gaps

## Risks & Considerations

1. **Cache Service Complexity**: May require understanding internal cache eviction logic
2. **Mock Complexity**: D1/KV mocks need to accurately simulate Cloudflare behavior
3. **Branch Coverage**: Improving branch coverage (50.63%) requires testing error paths
4. **Skipped Tests**: 328 tests are skipped - some may need module implementation first

## Verification Commands

```bash
# Run all tests with coverage
npm run test:cov

# Run specific test file
npx vitest run src/plugins/cache/tests/cache.test.ts

# Run with verbose output
npx vitest run --reporter=verbose

# Generate HTML coverage report
npm run test:cov && open packages/core/coverage/index.html
```

## Approval

- [ ] Plan reviewed and approved by user
