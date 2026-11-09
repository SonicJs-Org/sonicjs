# Forms Testing - Quick Start Guide

**Get started testing the Forms system in 5 minutes**

---

## ⚡ Quick Commands

```bash
# Run everything
npm test && npm run e2e

# Just unit tests
npm test

# Just E2E tests
npm run e2e

# Forms tests specifically
npm test -- forms.test.ts
npx playwright test tests/e2e/forms.spec.ts

# With UI (interactive)
npx playwright test tests/e2e/forms.spec.ts --ui

# Debug mode
npx playwright test tests/e2e/forms.spec.ts --debug
```

---

## 🎯 What Gets Tested

### Automated Tests (80+ tests)

**Unit Tests** (`forms.test.ts`)
- Form creation & validation
- Schema validation
- Submission handling
- Wizard logic

**E2E Tests** (`forms.spec.ts`)
- Form CRUD operations
- Builder UI interactions
- Public form rendering
- Form submissions
- Headless API endpoints

### Manual Tests (25 scenarios)

See `/docs/FORMS_TESTING_SCENARIOS.md` for step-by-step testing guide.

---

## 🚀 Before Running Tests

1. **Start dev server:**
   ```bash
   npm run dev
   ```

2. **Setup database:**
   ```bash
   cd my-sonicjs-app
   npm run setup:db
   cd ..
   ```

3. **Verify server is running:**
   ```bash
   curl http://localhost:8787/health
   ```

---

## 📊 Expected Results

### Unit Tests
```
✓ Forms Service (45 tests)
  ✓ Form Creation (5)
  ✓ Form Schema Validation (5)
  ✓ Form Settings (3)
  ✓ Form Submission Data (5)
  ✓ Form Queries (4)
  ✓ Form Updates (3)
  ✓ JSON Serialization (4)
  ✓ Validation Rules (6)
  ✓ Wizard Form Logic (5)
  ✓ Component Configuration (5)

Test Files: 1 passed (1)
Tests:      45 passed (45)
```

### E2E Tests
```
✓ Forms Management (7 tests)
✓ Form Builder UI (8 tests)
✓ Public Form Rendering (4 tests)
✓ Form Submissions (5 tests)
✓ Headless API (6 tests)
✓ Multi-Page Wizards (5 tests)

35 passed (35)
```

---

## 🐛 Common Issues

### Issue: "Form not found" in tests
**Fix:** Ensure database is set up with `npm run setup:db`

### Issue: "Builder not loading"
**Fix:** Increase timeout in test (Form.io takes 10-15 seconds to load)

### Issue: "Drag and drop not working"
**Fix:** Wait for Form.io to fully initialize before dragging

### Issue: Tests timeout
**Fix:** Check that dev server is running on port 8787

---

## 📋 Test Checklist

Before launch, verify:

- [ ] `npm test` - All unit tests pass
- [ ] `npm run e2e` - All E2E tests pass
- [ ] Manual testing complete (25/25 scenarios)
- [ ] Tested in Chrome, Firefox, Safari
- [ ] Tested on mobile
- [ ] No console errors
- [ ] Performance acceptable

---

## 📚 Full Documentation

- **Testing Suite Overview:** `/docs/FORMS_TESTING_SUITE.md`
- **Manual Testing Scenarios:** `/docs/FORMS_TESTING_SCENARIOS.md`
- **E2E Test File:** `/tests/e2e/forms.spec.ts`
- **Unit Test File:** `/packages/core/src/__tests__/services/forms.test.ts`

---

## 🎯 Success Criteria

**Tests are passing when:**
- ✅ 100% unit tests pass
- ✅ 100% E2E tests pass
- ✅ No flaky tests
- ✅ No console errors
- ✅ Performance targets met

---

**Ready to test? Run `npm test && npm run e2e` now!** 🚀
