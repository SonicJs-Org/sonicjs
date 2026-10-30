import { defineConfig, devices } from '@playwright/test';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * @see https://playwright.dev/docs/test-configuration
 *
 * CI budget, as of the switch to unfiltered runs: `pr-tests.yml` now runs this config with no
 * `--grep`, so every PR pays for all ~740 tests rather than the ~500 that changed-area tag
 * selection used to pick. The job cap moved 90 -> 150 minutes with it. Several notes below
 * reason against the old 90-minute cap and against the suite being filtered; their arithmetic
 * still holds for the numbers they cite, but the cap they compare to is now 150.
 */
export default defineConfig({
  testDir: './e2e',
  /* Files run in parallel; tests WITHIN a file do not.
   *
   * `fullyParallel: true` spreads the tests of one file across all four workers, and this suite
   * cannot take that: every spec shares one database, one `admin@sonicjs.com` account, one
   * site-settings row and one set of plugin activation flags. 27-settings-general is the clearest
   * case — eight tests, each POSTing the whole general-settings form, so the one asserting its
   * unique site name read back "SonicJS AI" where a sibling had just saved the form it had loaded
   * before the write. Several specs say "workers:1 → the tests run serially" in their own headers;
   * this makes that true again without giving up file-level parallelism.
   *
   * Cross-FILE conflicts over the same global are handled by the `@lock-*` tags — see fixtures.ts. */
  fullyParallel: false,
  /* Fail the build on CI if you accidentally left test.only in the source code. */
  forbidOnly: !!process.env.CI,
  /* Retry on CI only.
   *
   * Was 2, for "consecutive transient CF Worker cold-starts". That cause is gone: the menu
   * plugin's onBoot was ~51 serial D1 round trips and is now 2-3 (1ff44bdeb), which took a cold
   * preview isolate from 11-13s to a p50 of 0.45s. What the third attempt buys now is mostly a
   * third 120s timeout on a test that was going to fail anyway.
   *
   * It has to come down because the job does not fit any more. This PR touches
   * middleware/bootstrap.ts, which trips the "select the lot" branch of the workflow's changed-
   * area detection, so CI runs the whole suite — and tagging the previously-unselectable specs
   * took that from 468 tests to 740. The last completed run did 468 in 28 minutes; the next one
   * was still going at 88 and was killed by the job's 90-minute cap, which uploads videos but no
   * report. A cancelled run is worth less than a run that completes with failures in it: one
   * tells you nothing, the other tells you what to fix. Dropping the third attempt takes the
   * worst case per failing test from 360s to 240s.
   *
   * The job cap itself is not adjustable from here — pull_request_target runs the base branch's
   * copy of pr-tests.yml, so a timeout-minutes change on this branch stays inert until merge.
   *
   * Back to 2, now that halving `workers` (below) bought the room. Run 39649589162 went
   * 5 failed / 22 flaky / 478 passed in 42.7 min, a 47-minute job against a 90-minute cap, and
   * four of those five failures were the same thing twice in a row: a request that left the
   * runner and never came back, once on the first attempt and once on the retry. Nothing about
   * them is specific to the test — three are `goto('/admin')` inside `loginAsAdmin`, one is a
   * bare `apiRequestContext.post('/auth/register')` with no browser involved.
   *
   * The server is not what is failing, and that is measured rather than assumed. Against this
   * same preview deployment, 24 concurrent real registrations — each one a scrypt hash plus a
   * two-statement D1 batch — answered in 3.6s worst case; 40 concurrent POSTs answered in 4.3s
   * worst case; 28 concurrent authenticated admin page loads in 2.9s. No load reproducible from
   * outside CI makes it hang, and the hangs themselves are binary rather than slow: the requests
   * that fail never produce a first byte, while the slowest that completes is ~10s.
   *
   * So the residual is infrastructure between the runner and Cloudflare, at roughly a 10% chance
   * per attempt — and the arithmetic falls out of that exactly: 0.1^2 x 533 = 5.3 against the 5
   * seen, which also says the hangs are independent *between* attempts (a fresh browser context,
   * so fresh connections) even though the in-fixture navigation retry hangs along with the
   * attempt it belongs to.
   *
   * Each extra attempt is near-free, because only the tests that already failed every previous
   * one ever reach it: the third costs five tests x 30-75s, about 4 minutes, and the fourth costs
   * the ~0.5 tests expected to get that far. Expected failures go 5.3 -> 0.5 -> 0.05. Stopping at
   * 2 would leave a ~40% chance of a green run, which is not a gate. */
  retries: process.env.CI ? 3 : 0,
  /* Circuit breaker for the retries above.
   *
   * Three retries are cheap only while failures are rare. If something systemic breaks — a bad
   * deploy, a migration that did not apply, an expired token — then every test fails four times
   * instead of once, which is 4x the slowest possible run and would blow the job's 90-minute cap.
   * That is the one outcome worth avoiding outright: a killed job uploads videos but no report,
   * so it tells you nothing, while a run that stops early still says exactly what broke.
   *
   * 25 sits well clear of the 0-5 this suite produces when it is merely flaky, and is reached
   * within the first few minutes of a systemic break. */
  maxFailures: process.env.CI ? 25 : 0,
  /* Per-test timeout.
   *
   * Most specs log in (3 API round trips + a navigation) before their first assertion, then make
   * several more navigations against a remote CF Worker. On an idle machine that whole shape runs
   * in 10-15s, but CI packs four Chromium instances onto a four-vCPU runner and every admin page
   * compiles its own CSS in-browser via the Tailwind Play CDN, so the renderers contend for cores
   * and individual navigations stretch by an order of magnitude. At 60s a run produced 28 failures
   * and 52 flakes, nearly all of them "Test timeout of 60000ms exceeded" parked on whichever
   * navigation happened to be in flight rather than on a real defect. Headroom is cheap here —
   * a passing test still finishes in its usual 15s and never touches this number.
   *
   * 90s is still short against a preview deployment. The run at that number failed 9 tests, and
   * all 9 were "Test timeout of 90000ms exceeded" with not one assertion failure among them;
   * several were a bare `apiRequestContext.post` with no browser in the picture, so it is the
   * Worker that did not answer, not a renderer that could not keep up. Cause is below the suite:
   * the KV fast path in `middleware/bootstrap.ts` still runs three serial D1 writes on the first
   * request of every isolate (bootstrapDocumentTypes, autoRegisterCollectionDocumentTypes,
   * bootstrapDefaultContent), D1 serializes writes, and four workers churn isolates for the whole
   * run — measured ~5.5s cold against ~0.5s warm. Until that is restructured, this number has to
   * cover it. The same suite is 730/730 against a local wrangler, so the budget is what is
   * environment-specific, not the tests.
   *
   * 120 and not more: the job's own budget is 90 minutes, and every timeout that does fire costs
   * every attempt `retries` allows. One run spent roughly 25 of its 49 minutes burning the 90s
   * limit, so the headroom has to stay small enough that the worst case still lands inside the
   * job. What keeps that worst case in hand now is `actionTimeout` below: a hung request fails
   * its action at 30s and names itself, so a test rarely reaches this number at all. */
  timeout: process.env.CI ? 120 * 1000 : 90 * 1000,
  /* 1 worker locally (in-memory D1 conflicts); 2 in CI.
   *
   * Was 4, on the reasoning that a remote D1 makes the suite I/O bound. The run data says
   * otherwise: of 568 results in run 39638222664, 107 (19%) took 15s or more, and every single
   * one of the 31 failures overlapped in time with 2-8 other slow results on *other* workers.
   * A per-test or server-side cause does not produce that — the workers degrade together, in
   * lockstep, for the whole 30 minutes.
   *
   * The server is not what is degrading. Probing the same preview deployment directly: 28
   * concurrent authenticated admin requests (4 simultaneous dashboard loads, page + all six HTMX
   * fragments each) all answered in under 2.9s, and the six fragments measured 0.69-2.62s
   * serially. Meanwhile the hangs in the traces are binary rather than slow — of ~1300 completed
   * requests the worst was ~10s, while the ones that failed never completed at all and sat at
   * exactly the Playwright timeout. That is a client that never got scheduled to send or parse,
   * not a server that answered late. It also explains why `apiRequestContext` calls hang with no
   * browser in the picture: a starved runner starves the Node test process too.
   *
   * The runner is `ubuntu-24.04` with four vCPUs. Four Chromium instances on it is double what
   * Playwright itself would pick — its default worker count is half the core count, for exactly
   * this reason — and each admin page here is unusually expensive to render: a ~270KB document
   * plus htmx, Alpine and the Tailwind Play CDN, which compiles the stylesheet in-browser by
   * scanning that DOM on every single navigation.
   *
   * Two workers is that default. The suite stays parallel, and the lock lanes (fixtures.ts) that
   * dominate wall time are serialized either way, so the cost is far less than 2x: halving the
   * login rate also keeps the suite under the 30 req/min/IP auth limiter it was tripping, and
   * each trip was costing a test a ~60s backoff. */
  workers: process.env.CI ? 2 : 1,
  /* Reporter to use. See https://playwright.dev/docs/test-reporters */
  reporter: [
    ['html'],
    ['json', { outputFile: resolve(__dirname, '../test-results/results.json') }],
  ],
  /* Global setup and teardown */
  globalSetup: resolve(__dirname, './e2e/global-setup.ts'),
  globalTeardown: resolve(__dirname, './e2e/global-teardown.ts'),
  /* Shared settings for all the projects below. See https://playwright.dev/docs/api/class-testoptions. */
  use: {
    /* Base URL to use in actions like `await page.goto('/')`. */
    baseURL: process.env.BASE_URL || 'http://localhost:8787',

    /* Playwright's own defaults for these two are 0 — meaning NO timeout, not 30s. An operation
     * given no budget of its own runs until the TEST budget expires, which is why so many CI
     * failures read `page.originalGoto: Test timeout of 120000ms exceeded` rather than naming a
     * navigation timeout: the navigation never had one. A single stalled `goto` therefore consumed
     * the whole 120s, twice over with `retries`, and reported an error that pointed at the test's
     * last line instead of at the hop that hung.
     *
     * 30s is far above anything healthy here — `domcontentloaded` lands in well under a second
     * warm and ~5.5s on a cold isolate, and no spec in the suite asks for more than 30s anywhere.
     * So nothing that passes today starts failing; what changes is that a hang now costs 30s and
     * says which operation hung, instead of costing 120s and blaming the test. */
    actionTimeout: 30 * 1000,
    navigationTimeout: 30 * 1000,

    /* Collect trace when retrying the failed test. See https://playwright.dev/docs/trace-viewer */
    trace: 'on-first-retry',

    /* Screenshot on failure */
    screenshot: 'only-on-failure',

    /* Video on retry, matching `trace` above.
     *
     * 'retain-on-failure' sounds cheaper than it is: Playwright has to record EVERY test and then
     * throw the file away when it passes, so the ~95% of the suite that is green still pays for
     * four concurrent video encoders on a four-vCPU runner. That CPU is taken straight from the
     * browsers, which is what pushes navigations past the test timeout in the first place. With
     * two retries configured, anything that really fails is still recorded on its first retry. */
    video: 'on-first-retry',
  },

  /* Configure projects for major browsers */
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },

    // {
    //   name: 'firefox',
    //   use: { ...devices['Desktop Firefox'] },
    // },

    // {
    //   name: 'webkit',
    //   use: { ...devices['Desktop Safari'] },
    // },

    // /* Test against mobile viewports. */
    // {
    //   name: 'Mobile Chrome',
    //   use: { ...devices['Pixel 5'] },
    // },
    // {
    //   name: 'Mobile Safari',
    //   use: { ...devices['iPhone 12'] },
    // },

    /* Test against branded browsers. */
    // {
    //   name: 'Microsoft Edge',
    //   use: { ...devices['Desktop Edge'], channel: 'msedge' },
    // },
    // {
    //   name: 'Google Chrome',
    //   use: { ...devices['Desktop Chrome'], channel: 'chrome' },
    // },
  ],

  /* Run your local dev server before starting the tests (local only) */
  webServer: process.env.BASE_URL ? undefined : {
    command: 'npm run dev',
    cwd: resolve(__dirname, '../my-sonicjs-app'),
    url: 'http://localhost:8787',
    reuseExistingServer: true,
    timeout: 180 * 1000, // Increased to 3 minutes
  },
}); 