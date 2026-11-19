# Form.io + Turnstile Testing Summary

## Verified Turnstile source scopes

The consolidated suite preserves two relevant original source scopes. Current
Playwright collection contains **3 tests in each scope**:

| File and source scope | Collected coverage |
| --- | --- |
| `tests/e2e/forms.spec.ts` → `Source: 51-turnstile-integration.spec.ts` | Forms list buttons and navigation to Examples and Quick Reference |
| `tests/e2e/plugin-catalog.spec.ts` → `Source: 38-turnstile-plugin.spec.ts` | Turnstile plugin listing, settings fields, and saving settings |

### Forms list navigation (original source 51)

- `should show Examples and Quick Reference buttons on forms list`
- `should navigate to Examples page from forms list`
- `should navigate to Quick Reference page from forms list`

These tests assert button visibility and destination URLs. The integration source
name does not imply automated widget rendering or token validation coverage.

### Plugin settings (original source 38)

- `should display Turnstile plugin in plugins list`
- `should show Turnstile settings page`
- `should save Turnstile settings`

These tests assert the plugin heading and description, settings page headings and
fields, and a successful settings-save response while remaining on the settings
page. The save test fills dummy keys and changes theme, size, and enabled state;
it does not verify a live challenge or persisted settings after a reload.

The previous Turnstile and combined inventories overstated these scopes.
Builder drag and drop, public widget rendering, missing/invalid/valid token
submission, and challenge completion are **manual verification targets**, not
coverage established by these six declarations. Other forms scopes share
`forms.spec.ts`; selecting that entire file also runs those scopes. This document
does not claim a total for all forms or all Turnstile-related tests elsewhere.

## Running the tests

Run the forms list navigation scope only:

```bash
npm run e2e -- tests/e2e/forms.spec.ts --grep 'Source: 51-turnstile-integration.spec.ts'
```

Run the Turnstile plugin settings scope only:

```bash
npm run e2e -- tests/e2e/plugin-catalog.spec.ts --grep 'Source: 38-turnstile-plugin.spec.ts'
```

Add `--list` to either command to verify current selection without running tests.
Run all consolidated forms scopes with `npm run e2e -- tests/e2e/forms.spec.ts`,
or the full suite with `npm run e2e`. Use `npm run e2e:ui` for interactive debugging.

## Test environment

Use the setup and validation workflow in
[the E2E consolidation guide](testing/e2e-consolidation.md).
[tests/playwright.config.ts](../tests/playwright.config.ts) controls server
startup, Chromium, timeouts, workers, and environment-dependent retries.
The local default origin is `http://localhost:8787`; `BASE_URL` selects a remote
target. Local secrets belong in the gitignored `my-sonicjs-app/.dev.vars`.

## Manual verification targets

- Builder component visibility, drag and drop, placeholder rendering, and saving.
- Public form widget rendering, script loading, challenge completion, and submission.
- Rejection of missing/invalid tokens and acceptance of a valid token.
- Server-side token expiry, reuse prevention, and validation bypass attempts.
- Real keys in an owned deployment, mobile/other browsers, accessibility, and slow networks.

A passing source scope establishes only its assertions above; it does not certify
complete Turnstile functionality or production readiness.

## Related sources

- [Forms tests](../tests/e2e/forms.spec.ts)
- [Plugin catalog tests](../tests/e2e/plugin-catalog.spec.ts)
- [Test helpers](../tests/e2e/utils/test-helpers.ts)

Last scope verification: November 5, 2026 (`--list`, Chromium).
