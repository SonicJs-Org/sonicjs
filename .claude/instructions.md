# SonicJS Project Instructions

## Testing Requirements

### E2E Testing is Mandatory
- **ALWAYS create E2E tests** for any feature or fix you implement
- Tests should go in `tests/e2e/` directory using Playwright
- Run tests after implementation to verify they pass
- Include both happy path and error cases
- Tests should be comprehensive and cover edge cases

## E2E Test Workflow

When implementing features or fixes:

1. **Implement** the requested feature/fix
2. **Create** corresponding E2E test file in `tests/e2e/`
3. **Run** the test with `npx playwright test <test-file>` or `npm run e2e -- <test-file>`
4. **Fix** any issues found during testing
5. **Verify** tests pass before considering the task complete
6. **Commit** both implementation and tests together

## E2E Test Guidelines

### File Naming
- Use descriptive names: `##-feature-description.spec.ts`
- Number sequentially based on existing tests
- Example: `richtext.spec.ts`

### Test Structure
```typescript
import { test, expect } from '@playwright/test'
import { loginAsAdmin } from './utils/test-helpers'

test.describe('Feature Name', () => {
  test.beforeEach(async ({ page }) => {
    await loginAsAdmin(page)
  })

  test('should do something specific', async ({ page }) => {
    // Test implementation
  })
})
```

### Test Coverage
- User interactions (clicks, form submissions, navigation)
- Data persistence (database changes)
- UI state changes (visibility, content updates)
- Error handling (validation, edge cases)
- Integration points (API calls, plugin interactions)

## Running Tests

### Run specific test
```bash
npx playwright test tests/e2e/36-feature-name.spec.ts
```

### Run with headed browser (for debugging)
```bash
npx playwright test tests/e2e/36-feature-name.spec.ts --headed
```

### Run all E2E tests
```bash
npm run e2e
```

## Technology Stack

- **Framework**: Hono (web framework)
- **Runtime**: Cloudflare Workers
- **Database**: D1 (SQLite)
- **Templates**: HTML tagged templates
- **Testing**: Playwright E2E tests
- **Package Manager**: npm workspaces

## Code Quality

- Write TypeScript with proper types
- Follow existing code patterns in the codebase
- Use meaningful variable and function names
- Add comments for complex logic
- Keep functions focused and single-purpose

## Security

- Never expose secrets in code or tests
- Use environment variables for sensitive data
- Validate all user inputs
- Sanitize data before database operations
- Follow OWASP best practices
