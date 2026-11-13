# Query Trace Plugin

An admin-only performance panel. On a traced `/admin` page it shows every D1 query, KV operation and cache-plugin lookup the request made, how long each took, which middleware issued it, and a list of "opportunities" (N+1 queries, missing indexes, slow batches, …).

Plan and design rationale: `docs/plans/2026-11-12-query-trace-plugin.md`.

## Activation

Query Trace is **off by default**: it is listed under **Admin → Plugins** as available but has no installation row.

- **On:** click **Install** (installs it active) or **Activate**.
- **Off:** **Deactivate** or **Uninstall**.

Each installation has its own D1, so on/off is per installation. While inactive, the cost is one cached in-memory check (refreshed from D1 at most every 30 s per isolate) and a passthrough proxy around the `DB` / `CACHE_KV` bindings. Nothing is recorded, no headers are added, no response body is rewritten.

Under `plugins.disableAll` the middleware is not mounted at all.

### Requirement: `nodejs_compat`

Tracing is request-scoped through `AsyncLocalStorage`. Add the flag to `wrangler.toml`:

```toml
compatibility_flags = ["nodejs_compat"]
```

Without it the plugin still activates, logs one warning, and the plugin page shows "Tracing unavailable: enable nodejs_compat". Page rendering and tracing are skipped, so no panel appears. The `?trace=1` / `?trace=0` toggle still sets or clears the cookie and redirects, because that runs before the `nodejs_compat` check.

## Settings

Admin → Plugins → Query Trace → Settings (`/admin/plugins/query-trace/configure`).

| Setting | Default | Meaning |
|---|---|---|
| `visibility` | `opt-in` | `opt-in`: only admins who turned it on for themselves see the panel. `all-admins`: every admin sees it on every `/admin` page |
| `warnQueryMs` | 25 | Amber threshold for the `ms` column |
| `slowQueryMs` | 100 | Red threshold, and the "slow query / slow batch" finding |
| `captureCallers` | on | Record the calling `function file:line` per query |
| `serverTimingHeader` | on | Send a `Server-Timing` header on traced responses |
| `maxEntries` | 1000 | Per-request cap (100–5000); extra entries are counted as "dropped" |

## Opt-in flow

In `opt-in` mode, turn tracing on for yourself:

- add `?trace=1` to any admin URL. This sets the `sjs_trace` cookie (path `/admin`, HttpOnly, SameSite=Lax, Secure on https, 7 days) and redirects to the same URL without the parameter;
- `?trace=0` clears it (also the **Hide for me** link in the panel footer);
- or use **Enable for me / Disable for me** on `/admin/plugins/query-trace`.

A request is traced when the plugin is active, the path is `/admin` or under `/admin/`, and (`visibility = all-admins` or the cookie is present).

The panel is added only when the signed-in user is an `admin`, the response is non-redirect `text/html` containing `</body>`, and the request is not an HTMX partial (`HX-Request`). `Server-Timing` is added for admins on every traced response, HTMX partials included.

## Reading the panel

The summary line: `⚡ Trace · 412 ms server · 37 D1 (31 unique) · DB 288 ms Σ · 6 dupes · cache 4 hit / 3 miss · KV 2 · slowest 92 ms`. The badge is green under 150 ms, amber under 500 ms, red above.

### Queries & cache ops table

Sorted by duration, descending. Click a header to re-sort. Click a query to see the full redacted SQL, masked params and caller.

| Column | Meaning | How to act |
|---|---|---|
| `ms` | Wall time around the awaited call, coloured by `warnQueryMs` / `slowQueryMs` | Start at the top |
| `D1 ms` | Server-side time D1 reports (`meta.duration`). `ms − D1 ms` is network/RPC overhead | Large gap: latency is the cost, so batch or cache. Small gap: SQL is slow, so add an index or narrow the query |
| `Type` / `Op` | `d1` / `kv` / `cache`, and the operation (`SELECT all`, `get`, …) | |
| `Query / key` | Redacted SQL, or redacted KV/cache key | |
| `Tables` | Tables the statement touches | |
| `Rows ret/read/written` | Rows returned (reads), scanned, written. For writes (`run()` and `batch()` members) the value is rows changed, shown under *written*; *returned* stays `–` | For `SELECT`s, `read` ≫ `returned` means a missing or unusable index |
| `Cached` | D1: `not cached`. KV `get`: `hit` / `miss`. Cache plugin: `hit:memory` / `hit:kv` / `miss` | Frequent `miss` on a hot key: check TTL or warming |
| `×` | Number of times this fingerprint ran in the request | `×3` or more: see N+1 |
| `Span` | Which middleware or `handler` issued it | Find the layer to fix |
| `Start` | Offset from request start, with a waterfall bar | Overlapping bars are concurrent; a staircase is serial |

A `batch(N)` row is one wall time shared by N statements. The members are indented under it with their own server time.

### Opportunities (findings)

Ordered by severity, then impact in ms.

| Finding | Trigger | How to act |
|---|---|---|
| N+1 / repeated query | Same fingerprint 3+ times | Replace with one `WHERE id IN (…)` query, or memoize per request |
| Identical repeat | Same query **and** same bound values 2+ times | Cache the result in request context |
| Missing index suspect (reads only: `SELECT` statements) | `rows_read ≥ 1000` and `read / max(returned,1) ≥ 20` | Add an index on the filtered/sorted columns, or select fewer rows |
| Slow query / slow batch | Per-statement time, or a batch's wall time, ≥ `slowQueryMs` | Check the plan; split or index |
| Latency-bound | 5+ D1 calls where more than 80% of wall time is not SQL | Use `db.batch()` or a cache |
| Serial chain | 3+ consecutive non-overlapping queries in the same span | `Promise.all` or `batch` if they are independent (a hint, not a defect) |
| Cache miss → DB | A cache `miss` followed by D1 queries in the same span | Check TTL, warming and key stability |
| Write on GET | A GET request wrote rows | Move the write out of the read path |
| Middleware-heavy | Non-handler middleware self time > 50% of server time | Look at the top span named in the message |
| Cold bootstrap | `bootstrap` span > 200 ms | Isolate warm-up, not page cost; reload to measure the warm path |

### Grouped by fingerprint, Spans, footer

- **Grouped by fingerprint:** count, total, average, max and total `rows_read` per normalized query, by total ms.
- **Spans:** each wrapped middleware with start, total, self (excluding `next()`), query count and DB ms, by self time.
- **Footer:** **Copy JSON** (the full redacted trace, to paste into an agent session), **Hide for me** (opt-in mode), a cold-isolate note, the dropped-entry count, and a link to settings.

### `Server-Timing`

`total;dur=412, db;dur=288;desc="37 q", cache;desc="4 hit/3 miss", mw;dur=130`. Visible in DevTools → Network → Timing, including for HTMX partials.

## Accuracy notes

- **Workers timers:** `performance.now()` on Workers advances only across I/O. Pure-CPU work such as template rendering reads about 0 ms. D1 and KV timings are accurate; do not read the `server` total as CPU time.
- **Not captured:** outbound `fetch()` calls and R2 operations. Time spent in them shows up in `server` total (and span self time) but not in the tables.
- Dashboards and tables measure what the request awaited; concurrent calls overlap, so `DB Σ` can exceed wall time.

## Security

- **Admin only.** The panel and `Server-Timing` are emitted only when the response is for a user with the `admin` role. Anonymous and non-admin requests get neither, even in `all-admins` mode. The plugin page is admin-gated too.
- **Nothing sensitive is stored or shown.** SQL string, numeric and blob literals are replaced with `?` before they are recorded. KV and cache keys keep only allowlisted segments (`user`, `content`, …); everything else becomes `<uuid>`, `<email>`, `<n>` or `<redacted:LEN>`. Bound parameters are shown only as shapes (`string(36)`, `number`, `null`). Identical-repeat detection uses a private per-request salted hash that is never rendered or exported.
- **Opt-in cookie:** `sjs_trace=1` only selects whether *you* get traced; it grants nothing. A non-admin who sets it sees no change.
- The trace lives in memory for one request and is never persisted.
