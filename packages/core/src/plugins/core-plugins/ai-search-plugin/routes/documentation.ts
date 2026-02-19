/**
 * AI Search Documentation Page
 * Comprehensive documentation covering all search features
 */

import { Hono } from 'hono'
import type { Bindings } from '../../../../app'

const documentationRoutes = new Hono<{ Bindings: Bindings }>()

documentationRoutes.get('/docs', async (c) => {
  const baseUrl = new URL(c.req.url).origin;
  const dashboardUrl = `${baseUrl}/admin/plugins/ai-search`;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>AI Search — Documentation</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --bg: #0f1117;
      --surface: #1a1d27;
      --surface2: #22263a;
      --border: #2e3348;
      --accent: #6366f1;
      --accent-dim: rgba(99,102,241,0.15);
      --text: #e2e8f0;
      --text-dim: #94a3b8;
      --text-faint: #64748b;
      --green: #22c55e;
      --yellow: #eab308;
      --red: #ef4444;
      --blue: #3b82f6;
      --code-bg: #0d1117;
      --sidebar-width: 260px;
      --header-height: 56px;
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      font-size: 14px;
      line-height: 1.7;
    }

    /* ─── Header ─── */
    .header {
      position: fixed;
      top: 0; left: 0; right: 0;
      height: var(--header-height);
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      padding: 0 24px;
      gap: 16px;
      z-index: 100;
    }
    .header a.back {
      color: var(--text-dim);
      text-decoration: none;
      font-size: 13px;
      display: flex;
      align-items: center;
      gap: 6px;
      transition: color 0.15s;
    }
    .header a.back:hover { color: var(--text); }
    .header-title {
      font-size: 15px;
      font-weight: 600;
      color: var(--text);
    }
    .header-badge {
      margin-left: auto;
      font-size: 11px;
      color: var(--text-faint);
    }

    /* ─── Layout ─── */
    .layout {
      display: flex;
      padding-top: var(--header-height);
      min-height: 100vh;
    }

    /* ─── Sidebar ─── */
    .sidebar {
      width: var(--sidebar-width);
      position: fixed;
      top: var(--header-height);
      bottom: 0;
      left: 0;
      overflow-y: auto;
      border-right: 1px solid var(--border);
      padding: 24px 0;
    }
    .sidebar-section {
      padding: 0 16px 16px;
    }
    .sidebar-label {
      font-size: 10px;
      font-weight: 700;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: var(--text-faint);
      padding: 0 8px;
      margin-bottom: 8px;
    }
    .sidebar a {
      display: block;
      padding: 5px 8px;
      border-radius: 6px;
      color: var(--text-dim);
      text-decoration: none;
      font-size: 13px;
      transition: background 0.15s, color 0.15s;
    }
    .sidebar a:hover {
      background: var(--surface2);
      color: var(--text);
    }
    .sidebar a.active {
      background: var(--accent-dim);
      color: var(--accent);
    }
    .sidebar-divider {
      border: none;
      border-top: 1px solid var(--border);
      margin: 12px 16px;
    }

    /* ─── Content ─── */
    .content {
      margin-left: var(--sidebar-width);
      flex: 1;
      max-width: 900px;
      padding: 48px 48px 96px;
    }

    /* ─── Sections ─── */
    .doc-section {
      margin-bottom: 64px;
      scroll-margin-top: calc(var(--header-height) + 24px);
    }
    .section-header {
      display: flex;
      align-items: baseline;
      gap: 12px;
      margin-bottom: 20px;
      padding-bottom: 12px;
      border-bottom: 1px solid var(--border);
    }
    .section-number {
      font-size: 12px;
      font-weight: 700;
      color: var(--accent);
      background: var(--accent-dim);
      padding: 2px 8px;
      border-radius: 4px;
    }
    h2 {
      font-size: 22px;
      font-weight: 700;
      color: var(--text);
    }
    h3 {
      font-size: 16px;
      font-weight: 600;
      color: var(--text);
      margin: 28px 0 10px;
    }
    h4 {
      font-size: 13px;
      font-weight: 600;
      color: var(--text-dim);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin: 20px 0 8px;
    }
    p { margin-bottom: 12px; color: var(--text-dim); }
    p strong { color: var(--text); }

    /* ─── Lists ─── */
    ul, ol {
      padding-left: 20px;
      margin-bottom: 12px;
      color: var(--text-dim);
    }
    li { margin-bottom: 5px; }
    li strong { color: var(--text); }

    /* ─── Code ─── */
    code {
      font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
      font-size: 12.5px;
      background: var(--code-bg);
      border: 1px solid var(--border);
      padding: 2px 6px;
      border-radius: 4px;
      color: #e2c08d;
    }
    pre {
      background: var(--code-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px 20px;
      overflow-x: auto;
      margin: 12px 0 20px;
    }
    pre code {
      background: none;
      border: none;
      padding: 0;
      color: #cdd6f4;
      font-size: 13px;
      line-height: 1.6;
    }
    .comment { color: #6272a4; }
    .keyword { color: #bd93f9; }
    .string { color: #f1fa8c; }
    .value { color: #50fa7b; }

    /* ─── Cards / callouts ─── */
    .callout {
      border-radius: 8px;
      padding: 14px 16px;
      margin: 16px 0;
      border-left: 3px solid;
      font-size: 13px;
    }
    .callout-info { background: rgba(59,130,246,0.08); border-color: var(--blue); color: #93c5fd; }
    .callout-warn { background: rgba(234,179,8,0.08); border-color: var(--yellow); color: #fde68a; }
    .callout-tip  { background: rgba(34,197,94,0.08); border-color: var(--green); color: #86efac; }
    .callout strong { display: block; margin-bottom: 4px; }

    /* ─── Mode cards ─── */
    .mode-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
      margin: 16px 0;
    }
    .mode-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
    }
    .mode-card h4 { margin: 0 0 6px; color: var(--text); text-transform: none; letter-spacing: 0; font-size: 14px; }
    .mode-card .badge {
      display: inline-block;
      font-size: 10px;
      font-weight: 700;
      padding: 2px 7px;
      border-radius: 4px;
      margin-bottom: 8px;
    }
    .badge-ai { background: rgba(139,92,246,0.2); color: #c4b5fd; }
    .badge-fts { background: rgba(59,130,246,0.2); color: #93c5fd; }
    .badge-hybrid { background: rgba(34,197,94,0.2); color: #86efac; }
    .badge-kw { background: rgba(100,116,139,0.2); color: #94a3b8; }
    .mode-card p { font-size: 12.5px; margin: 0; }
    .mode-card .latency { margin-top: 8px; font-size: 11px; color: var(--text-faint); }

    /* ─── Decision table ─── */
    table {
      width: 100%;
      border-collapse: collapse;
      margin: 16px 0 24px;
      font-size: 13px;
    }
    th {
      text-align: left;
      padding: 8px 12px;
      background: var(--surface2);
      color: var(--text-dim);
      font-weight: 600;
      border: 1px solid var(--border);
    }
    td {
      padding: 8px 12px;
      border: 1px solid var(--border);
      color: var(--text-dim);
      vertical-align: top;
    }
    tr:nth-child(even) td { background: var(--surface); }
    td strong { color: var(--text); }
    td.check { text-align: center; color: var(--green); }
    td.cross { text-align: center; color: var(--text-faint); }

    /* ─── Pipeline flow ─── */
    .pipeline {
      display: flex;
      flex-direction: column;
      gap: 0;
      margin: 16px 0 24px;
    }
    .pipeline-step {
      display: flex;
      align-items: flex-start;
      gap: 16px;
    }
    .pipeline-connector {
      display: flex;
      flex-direction: column;
      align-items: center;
      width: 32px;
      flex-shrink: 0;
    }
    .pipeline-dot {
      width: 32px;
      height: 32px;
      border-radius: 50%;
      background: var(--accent-dim);
      border: 2px solid var(--accent);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 11px;
      font-weight: 700;
      color: var(--accent);
      flex-shrink: 0;
    }
    .pipeline-line {
      width: 2px;
      height: 24px;
      background: var(--border);
      margin: 0 auto;
    }
    .pipeline-body {
      padding: 4px 0 24px;
    }
    .pipeline-body strong { color: var(--text); font-size: 14px; }
    .pipeline-body p { margin: 4px 0 0; font-size: 12.5px; }

    /* ─── Analyzer grid ─── */
    .analyzer-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 10px;
      margin: 16px 0;
    }
    .analyzer-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px;
    }
    .analyzer-card h4 {
      margin: 0 0 6px;
      font-size: 13px;
      text-transform: none;
      letter-spacing: 0;
      color: var(--accent);
    }
    .analyzer-card p { font-size: 12px; margin: 0; }

    /* ─── Step list ─── */
    .step-list { list-style: none; padding: 0; margin: 12px 0; }
    .step-list li {
      display: flex;
      gap: 12px;
      padding: 10px 0;
      border-bottom: 1px solid var(--border);
    }
    .step-list li:last-child { border-bottom: none; }
    .step-num {
      width: 22px;
      height: 22px;
      border-radius: 50%;
      background: var(--accent);
      color: white;
      font-size: 11px;
      font-weight: 700;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
      margin-top: 1px;
    }

    /* ─── API endpoint ─── */
    .endpoint {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px 16px;
      margin: 12px 0;
    }
    .endpoint-line {
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 8px;
    }
    .method {
      font-size: 11px;
      font-weight: 700;
      padding: 3px 8px;
      border-radius: 4px;
    }
    .method-get { background: rgba(34,197,94,0.2); color: var(--green); }
    .method-post { background: rgba(234,179,8,0.2); color: var(--yellow); }
    .endpoint-path { font-family: monospace; font-size: 13px; color: var(--text); }
    .endpoint-desc { font-size: 12.5px; color: var(--text-dim); }

    /* ─── Scope tags ─── */
    .scope {
      display: inline-block;
      font-family: monospace;
      font-size: 11px;
      padding: 2px 7px;
      background: rgba(99,102,241,0.15);
      color: var(--accent);
      border-radius: 4px;
      margin: 2px 2px 2px 0;
    }

    /* ─── Tabs nav for sections ─── */
    .known-issue {
      display: flex;
      align-items: flex-start;
      gap: 10px;
      padding: 10px 14px;
      background: rgba(234,179,8,0.06);
      border: 1px solid rgba(234,179,8,0.2);
      border-radius: 6px;
      margin: 8px 0;
      font-size: 13px;
      color: #fde68a;
    }
    .known-issue .issue-id {
      font-family: monospace;
      font-size: 11px;
      background: rgba(234,179,8,0.15);
      padding: 1px 6px;
      border-radius: 4px;
      flex-shrink: 0;
      margin-top: 1px;
    }

    /* Scrollbar */
    ::-webkit-scrollbar { width: 6px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }

    @media (max-width: 900px) {
      .sidebar { display: none; }
      .content { margin-left: 0; padding: 32px 24px 64px; }
      .mode-grid, .analyzer-grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>

<!-- Header -->
<header class="header">
  <a href="${dashboardUrl}" class="back">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 12H5M12 5l-7 7 7 7"/></svg>
    Search Dashboard
  </a>
  <span class="header-title">AI Search — Documentation</span>
  <span class="header-badge">Last updated: February 2026</span>
</header>

<div class="layout">

  <!-- Sidebar -->
  <nav class="sidebar">
    <div class="sidebar-section">
      <div class="sidebar-label">Getting Started</div>
      <a href="#getting-started">Getting Started</a>
      <a href="#search-modes">Search Modes</a>
    </div>
    <hr class="sidebar-divider" />
    <div class="sidebar-section">
      <div class="sidebar-label">Configuration</div>
      <a href="#configuration">Configuration Reference</a>
      <a href="#relevance">Relevance & Ranking</a>
      <a href="#synonym-import">Synonym Import</a>
    </div>
    <hr class="sidebar-divider" />
    <div class="sidebar-section">
      <div class="sidebar-label">Admin Features</div>
      <a href="#benchmark">Benchmark</a>
      <a href="#analytics">Analytics</a>
      <a href="#quality-agent">Quality Agent</a>
      <a href="#ab-testing">A/B Testing</a>
      <a href="#faceted-search">Faceted Search</a>
    </div>
    <hr class="sidebar-divider" />
    <div class="sidebar-section">
      <div class="sidebar-label">API & Integration</div>
      <a href="#api-reference">API Reference</a>
      <a href="#instantsearch">InstantSearch</a>
    </div>
  </nav>

  <!-- Content -->
  <main class="content">

    <!-- Section 1: Getting Started -->
    <section class="doc-section" id="getting-started">
      <div class="section-header">
        <span class="section-number">01</span>
        <h2>Getting Started</h2>
      </div>

      <p>The SonicJS AI Search plugin provides four search modes (full-text keyword, semantic AI, hybrid, and simple keyword), a 7-tab admin dashboard, click-through analytics, a relevance ranking pipeline, synonym management, BEIR benchmark evaluation, and an AI-powered quality agent — all running on Cloudflare Workers without any external search service.</p>

      <h3>Enabling Search</h3>
      <p>Search is configured from the <strong>Configuration tab</strong> in the Search Dashboard.</p>
      <ol>
        <li>Navigate to <strong>Admin → AI Search → Configuration</strong></li>
        <li>Enable the <strong>Search</strong> toggle</li>
        <li>Select which <strong>Collections</strong> to index (e.g. <code>posts</code>, <code>products</code>)</li>
        <li>Save — FTS5 indexing begins immediately for existing content</li>
      </ol>

      <h3>How Indexing Works</h3>
      <p>SonicJS maintains two search indexes that serve different search modes:</p>

      <table>
        <thead><tr><th>Index</th><th>Modes Served</th><th>Auto-updated?</th><th>Setup Required</th></tr></thead>
        <tbody>
          <tr>
            <td><strong>FTS5</strong> (SQLite full-text)</td>
            <td>FTS5, Keyword, Hybrid</td>
            <td class="check">✓ On every content save</td>
            <td>None — always available</td>
          </tr>
          <tr>
            <td><strong>Vectorize</strong> (semantic)</td>
            <td>AI, Hybrid</td>
            <td class="cross">Manual trigger</td>
            <td>Vectorize binding required</td>
          </tr>
        </tbody>
      </table>

      <p>FTS5 is always available and requires no configuration. Vectorize semantic search requires a Cloudflare Vectorize binding in your <code>wrangler.toml</code>. To trigger Vectorize indexing, go to <strong>Configuration → Reindex</strong> or call the admin API endpoint.</p>

      <div class="callout callout-tip">
        <strong>Quick test</strong>
        After enabling search, use the <strong>Test Search</strong> page (top-right nav) to run queries against your content and verify results before configuring the frontend.
      </div>
    </section>


    <!-- Section 2: Search Modes -->
    <section class="doc-section" id="search-modes">
      <div class="section-header">
        <span class="section-number">02</span>
        <h2>Search Modes</h2>
      </div>

      <p>The plugin supports four search modes. The active mode is set in the Configuration tab and can also be specified per-request via the <code>mode</code> API parameter.</p>

      <div class="mode-grid">
        <div class="mode-card">
          <span class="badge badge-hybrid">★ Recommended</span>
          <h4>Hybrid</h4>
          <p>Combines FTS5 and AI results using Reciprocal Rank Fusion (RRF). Best overall ranking quality — surfaces results that keyword search would miss and results that pure semantic search would rank poorly.</p>
          <div class="latency">~550ms uncached · ~25ms cached</div>
        </div>
        <div class="mode-card">
          <span class="badge badge-ai">AI</span>
          <h4>AI (Semantic)</h4>
          <p>Uses Cloudflare Vectorize with <code>bge-base-en-v1.5</code> embeddings. Understands meaning, not just keywords. Best for natural language queries and conceptual matching. Requires Vectorize binding.</p>
          <div class="latency">~260ms uncached · ~25ms cached</div>
        </div>
        <div class="mode-card">
          <span class="badge badge-fts">FTS5</span>
          <h4>Full-Text (FTS5)</h4>
          <p>SQLite FTS5 with porter stemming and BM25 ranking. Understands word variations (run/running/ran), ignores diacritics, and weights title matches above body matches. Fast and always available.</p>
          <div class="latency">~150ms uncached · ~25ms cached</div>
        </div>
        <div class="mode-card">
          <span class="badge badge-kw">Fallback</span>
          <h4>Keyword</h4>
          <p>Simple SQL <code>LIKE %query%</code> search. No ranking, no stemming — an exact substring match. Useful as an absolute fallback when the FTS5 table is unavailable.</p>
          <div class="latency">~100–200ms</div>
        </div>
      </div>

      <h3>Which Mode Should I Use?</h3>
      <table>
        <thead><tr><th>Situation</th><th>Recommended mode</th></tr></thead>
        <tbody>
          <tr><td>Default for most sites</td><td><strong>Hybrid</strong></td></tr>
          <tr><td>Users search in natural language ("how to configure caching")</td><td><strong>AI</strong> or <strong>Hybrid</strong></td></tr>
          <tr><td>Users search for exact terms, codes, model numbers</td><td><strong>FTS5</strong></td></tr>
          <tr><td>No Vectorize binding available (local dev)</td><td><strong>FTS5</strong></td></tr>
          <tr><td>Cost-sensitive — minimise AI inference calls</td><td><strong>FTS5</strong> (no AI cost)</td></tr>
        </tbody>
      </table>

      <h3>How Hybrid RRF Works</h3>
      <p>Hybrid mode runs FTS5 and AI search in parallel, then merges the two ranked lists using Reciprocal Rank Fusion with <code>k=60</code>. Each result receives a score based on its position in each list:</p>
      <pre><code>RRF_score(doc) = Σ 1 / (60 + rank_in_system)</code></pre>
      <p>This means a result ranked #1 in FTS5 and #3 in AI will outscore a result that only appears in one list. The AI reranker is intentionally not applied on top of hybrid results — it would degrade the carefully fused bi-encoder scores.</p>

      <div class="callout callout-info">
        <strong>KV caching applies to all modes</strong>
        All search results are cached in Cloudflare KV using a SHA-256 key derived from the query parameters. Cache hits return in ~25ms regardless of mode. The TTL is configurable in the Configuration tab.
      </div>
    </section>


    <!-- Section 3: Configuration Reference -->
    <section class="doc-section" id="configuration">
      <div class="section-header">
        <span class="section-number">03</span>
        <h2>Configuration Reference</h2>
      </div>

      <p>All settings are managed in the <strong>Configuration tab</strong> of the Search Dashboard. Changes take effect immediately — no restart required.</p>

      <h3>Search Settings</h3>
      <table>
        <thead><tr><th>Setting</th><th>Default</th><th>Description</th></tr></thead>
        <tbody>
          <tr><td><strong>Search enabled</strong></td><td>Off</td><td>Master switch. Must be on for any search to work.</td></tr>
          <tr><td><strong>Default mode</strong></td><td>FTS5</td><td>Which search mode to use when <code>mode</code> is not specified in the request.</td></tr>
          <tr><td><strong>Results limit</strong></td><td>10</td><td>Maximum results returned per query (can be overridden per-request with <code>limit</code> param, up to this maximum).</td></tr>
          <tr><td><strong>Cache TTL</strong></td><td>300s</td><td>How long search results are cached in KV. Set to 0 to disable caching.</td></tr>
        </tbody>
      </table>

      <h3>AI Features</h3>
      <table>
        <thead><tr><th>Setting</th><th>Default</th><th>Description</th></tr></thead>
        <tbody>
          <tr><td><strong>Semantic search (AI)</strong></td><td>Off</td><td>Enables AI/Hybrid modes. Requires Vectorize binding.</td></tr>
          <tr><td><strong>Query rewriting</strong></td><td>Off</td><td>Uses Workers AI to expand short or ambiguous queries before searching. Adds latency; most useful for short queries (&lt;3 words).</td></tr>
          <tr><td><strong>Reranking</strong></td><td>Off</td><td>Applies a cross-encoder model to re-score FTS5 results. <em>Note: not applied in Hybrid mode.</em></td></tr>
        </tbody>
      </table>

      <h3>Collections & Field Weights</h3>
      <p>Select which collections are indexed and how each field contributes to relevance scoring. Higher weight = more influence on ranking.</p>
      <table>
        <thead><tr><th>Field</th><th>Default weight</th><th>Notes</th></tr></thead>
        <tbody>
          <tr><td><code>title</code></td><td>5.0</td><td>Strong signal — a title match is highly relevant</td></tr>
          <tr><td><code>slug</code></td><td>2.0</td><td>URL slugs often contain important keywords</td></tr>
          <tr><td><code>body</code></td><td>1.0</td><td>Baseline — body text provides broad coverage</td></tr>
        </tbody>
      </table>
      <p>Weights are passed directly to SQLite's <code>bm25()</code> function. Adjust based on your content structure — for example, if your content has short bodies but highly descriptive titles, increasing the title weight further improves precision.</p>
    </section>


    <!-- Section 4: Relevance & Ranking -->
    <section class="doc-section" id="relevance">
      <div class="section-header">
        <span class="section-number">04</span>
        <h2>Relevance & Ranking</h2>
      </div>

      <p>Every search query passes through a deterministic pipeline before results are returned. Understanding this pipeline lets you tune relevance precisely.</p>

      <h3>Query Pipeline</h3>
      <div class="pipeline">
        <div class="pipeline-step">
          <div class="pipeline-connector"><div class="pipeline-dot">1</div><div class="pipeline-line"></div></div>
          <div class="pipeline-body">
            <strong>Query Rules</strong>
            <p>Deterministic substitutions applied before anything else. Exact or prefix match rules fire here — e.g. replace "PS5" with "PlayStation 5, PS 5". First matching rule wins.</p>
          </div>
        </div>
        <div class="pipeline-step">
          <div class="pipeline-connector"><div class="pipeline-dot">2</div><div class="pipeline-line"></div></div>
          <div class="pipeline-body">
            <strong>Synonym Expansion</strong>
            <p>Bidirectional groups expand all terms (couch → couch OR sofa OR settee). One-way mappings expand the source term only (PS5 → PS5 OR "PlayStation 5", but not the reverse).</p>
          </div>
        </div>
        <div class="pipeline-step">
          <div class="pipeline-connector"><div class="pipeline-dot">3</div><div class="pipeline-line"></div></div>
          <div class="pipeline-body">
            <strong>Cache Check</strong>
            <p>SHA-256 key built from the normalised query + parameters. Cache hit returns results in ~25ms and exits the pipeline early.</p>
          </div>
        </div>
        <div class="pipeline-step">
          <div class="pipeline-connector"><div class="pipeline-dot">4</div><div class="pipeline-line"></div></div>
          <div class="pipeline-body">
            <strong>Search Execution</strong>
            <p>FTS5, AI, or both (parallel) depending on the active mode. Results are scored by BM25, cosine similarity, or RRF fusion.</p>
          </div>
        </div>
        <div class="pipeline-step">
          <div class="pipeline-connector"><div class="pipeline-dot">5</div><div class="pipeline-line"></div></div>
          <div class="pipeline-body">
            <strong>Ranking Pipeline</strong>
            <p>Six configurable stages re-score and re-sort results. Each stage has an adjustable weight. Stages include: freshness boost, popularity score, field weight boost, content score, query match boost, and position decay.</p>
          </div>
        </div>
        <div class="pipeline-step">
          <div class="pipeline-connector"><div class="pipeline-dot">6</div></div>
          <div class="pipeline-body">
            <strong>Cache Store & Return</strong>
            <p>Final results are written to KV with the configured TTL and returned to the caller.</p>
          </div>
        </div>
      </div>

      <h3>Synonyms</h3>
      <p>Synonyms are managed in the <strong>Relevance tab → Synonyms</strong> section. Two types are supported:</p>

      <table>
        <thead><tr><th>Type</th><th>Behaviour</th><th>Example</th></tr></thead>
        <tbody>
          <tr>
            <td><strong>Bidirectional</strong></td>
            <td>Searching any term in the group finds all of them</td>
            <td><code>couch, sofa, settee</code> — searching "sofa" also finds "couch" content</td>
          </tr>
          <tr>
            <td><strong>One-way</strong></td>
            <td>Searching the source term expands to targets; targets do not expand back</td>
            <td><code>PS5 → PlayStation 5, PS 5</code> — searching "PS5" finds "PlayStation 5" content, but not vice versa</td>
          </tr>
        </tbody>
      </table>

      <div class="callout callout-tip">
        <strong>Tip: one-way synonyms for abbreviations and brand names</strong>
        Use one-way mappings for abbreviations (PS5 → PlayStation 5), acronyms (AI → Artificial Intelligence), and brand aliases. Use bidirectional groups for true equivalents (couch / sofa / settee).
      </div>

      <h3>Query Rules</h3>
      <p>Query rules are pre-search substitutions applied before synonym expansion. Useful for redirecting stop-word-heavy queries to their meaningful core. Two match types are supported:</p>
      <ul>
        <li><strong>Exact match</strong> — fires only when the full query matches exactly (case-insensitive)</li>
        <li><strong>Prefix match</strong> — fires when the query starts with the specified string</li>
      </ul>
      <p>Rules are evaluated in priority order (lowest number = highest priority). Only the first matching rule is applied.</p>

      <h3>Relevance Preview</h3>
      <p>The Relevance tab includes a live preview panel. As you adjust field weights, pipeline stages, synonyms, or query rules, the preview re-runs your test query and shows results with per-stage score breakdowns. Use this before saving to verify that changes improve ranking for your actual content.</p>
    </section>


    <!-- Section 5: Synonym Import -->
    <section class="doc-section" id="synonym-import">
      <div class="section-header">
        <span class="section-number">05</span>
        <h2>Synonym Import</h2>
      </div>

      <p>Instead of building synonym groups one at a time, you can import an entire synonym dictionary from a CSV or Elasticsearch-format synonyms file. The import routes entries through the Quality Agent's review queue, so nothing is applied automatically.</p>

      <h3>Supported Formats</h3>

      <h4>CSV — bidirectional groups</h4>
      <pre><code><span class="comment"># Each line is one synonym group — all terms are equivalent</span>
couch, sofa, settee
laptop, notebook, portable computer
mobile phone, cell phone, smartphone</code></pre>

      <h4>CSV — one-way mappings</h4>
      <pre><code><span class="comment"># Arrow notation creates one-way (source → targets) mappings</span>
PS5 -> PlayStation 5, PS 5
AI -> Artificial Intelligence
ML -> Machine Learning, Deep Learning</code></pre>

      <h4>Elasticsearch / Solr synonyms.txt</h4>
      <pre><code><span class="comment"># Standard Elasticsearch fat-arrow notation for one-way</span>
PS5 => PlayStation 5, PS 5

<span class="comment"># Comma-separated for bidirectional (same as CSV)</span>
couch, sofa, settee</code></pre>

      <div class="callout callout-info">
        <strong>Line limit</strong>
        Imports are capped at 500 lines per file. For larger dictionaries, split the file and import in batches.
      </div>

      <h3>Import Workflow</h3>
      <ol class="step-list">
        <li><span class="step-num">1</span><div>Go to <strong>Relevance tab → Import from File</strong> and upload your CSV or .txt file</div></li>
        <li><span class="step-num">2</span><div>The system parses the file and filters entries against your content corpus — terms that don't appear in any indexed content are skipped (controlled by the <code>min_occurrences</code> threshold)</div></li>
        <li><span class="step-num">3</span><div>Matching entries are queued as recommendations in the <strong>Agent tab</strong> with an "Imported: filename" badge</div></li>
        <li><span class="step-num">4</span><div>Review each recommendation in the Agent tab and click <strong>Apply</strong> or <strong>Dismiss</strong></div></li>
        <li><span class="step-num">5</span><div>Applied entries appear in the Relevance tab synonym list and take effect immediately on the next search</div></li>
      </ol>

      <h3>Deduplication</h3>
      <p>Each synonym entry is fingerprinted on import. Re-uploading the same file will not create duplicate recommendations — already-imported entries are silently skipped. This makes it safe to re-import an updated version of a dictionary.</p>

      <h3>Where to Find Synonym Dictionaries</h3>
      <ul>
        <li><strong>Elasticsearch community synonyms</strong> — search GitHub for open-source Elasticsearch synonym files for your domain</li>
        <li><strong>OpenSearch synonym packages</strong> — the OpenSearch project maintains several domain-specific synonym sets</li>
        <li><strong>Domain-specific resources</strong> — medical, legal, and e-commerce domains have well-maintained thesaurus resources</li>
        <li><strong>Build from your own data</strong> — the Quality Agent's synonym analyzer identifies synonym candidates automatically from your search history. Run it after you have 2–3 weeks of query data.</li>
      </ul>
    </section>


    <!-- Section 6: Benchmark -->
    <section class="doc-section" id="benchmark">
      <div class="section-header">
        <span class="section-number">06</span>
        <h2>Benchmark</h2>
      </div>

      <p>The Benchmark tab lets you measure search quality against peer-reviewed <a href="https://beir.ai" style="color:var(--accent)">BEIR</a> (Benchmarking IR) datasets — the same datasets used in academic information retrieval research. This gives you objective, reproducible quality scores rather than gut-feel assessments.</p>

      <h3>Why This Matters</h3>
      <p>Most search tools have no built-in quality measurement. The BEIR benchmark lets you:</p>
      <ul>
        <li>Compare FTS5 vs AI vs Hybrid objectively before choosing a production mode</li>
        <li>Detect regressions — run the benchmark in CI to ensure a config change didn't hurt quality</li>
        <li>Justify configuration choices to stakeholders with published, verifiable scores</li>
      </ul>

      <h3>Available Datasets</h3>
      <table>
        <thead><tr><th>Dataset</th><th>Domain</th><th>Corpus size</th><th>Test queries</th></tr></thead>
        <tbody>
          <tr><td><strong>SciFact</strong></td><td>Scientific abstracts</td><td>5,183 docs</td><td>300 queries</td></tr>
          <tr><td><strong>FiQA-2018</strong></td><td>Financial Q&A</td><td>57,638 docs</td><td>648 queries</td></tr>
          <tr><td><strong>NFCorpus</strong></td><td>Biomedical</td><td>3,633 docs</td><td>323 queries</td></tr>
        </tbody>
      </table>

      <h3>Metrics Explained</h3>
      <table>
        <thead><tr><th>Metric</th><th>What it measures</th><th>Higher = ?</th></tr></thead>
        <tbody>
          <tr><td><strong>nDCG@10</strong></td><td>Ranking quality — are relevant results at the top?</td><td>Better ranking</td></tr>
          <tr><td><strong>MRR</strong></td><td>How quickly the first relevant result appears</td><td>Relevant result found sooner</td></tr>
          <tr><td><strong>Precision@10</strong></td><td>Fraction of the top 10 results that are relevant</td><td>Fewer irrelevant results</td></tr>
          <tr><td><strong>Recall@10</strong></td><td>Fraction of all relevant docs found in top 10</td><td>More relevant docs surfaced</td></tr>
        </tbody>
      </table>

      <h3>How to Run</h3>
      <ol>
        <li>Select a dataset and corpus size in the Benchmark tab</li>
        <li>Click <strong>Seed</strong> — this loads the benchmark corpus into a separate index (prefixed <code>beir-</code>) so it doesn't affect your real content</li>
        <li>Click <strong>Evaluate</strong> — runs all test queries and records scores</li>
        <li>Results appear in the table grouped by dataset and search mode</li>
        <li>Click <strong>Purge</strong> to remove benchmark content from the index when done</li>
      </ol>

      <div class="callout callout-warn">
        <strong>Known limitation (VS-2)</strong>
        Purging benchmark data currently removes evaluation results alongside the corpus. If you want to retain historical scores, export or note them before purging. A fix that persists results independently is planned.
      </div>

      <h3>Reference Results</h3>
      <p>Scores achieved during development on SciFact (20 queries, FTS5 mode):</p>
      <table>
        <thead><tr><th>Mode</th><th>nDCG@10</th><th>MRR</th><th>Recall@10</th><th>Avg latency</th></tr></thead>
        <tbody>
          <tr><td>FTS5</td><td>83.6%</td><td>81.7%</td><td>90.0%</td><td>152ms</td></tr>
          <tr><td>AI (Vectorize)</td><td>91.0%</td><td>87.9%</td><td>100.0%</td><td>258ms</td></tr>
          <tr><td>Hybrid (RRF)</td><td>88.3%</td><td>84.5%</td><td>100.0%</td><td>554ms</td></tr>
        </tbody>
      </table>
    </section>


    <!-- Section 7: Analytics -->
    <section class="doc-section" id="analytics">
      <div class="section-header">
        <span class="section-number">07</span>
        <h2>Analytics</h2>
      </div>

      <p>The Analytics tab tracks every search query and result click. Data is used to surface quality issues in the Agent tab and to measure A/B test performance.</p>

      <h3>What's Tracked</h3>
      <table>
        <thead><tr><th>Data point</th><th>Description</th></tr></thead>
        <tbody>
          <tr><td><strong>Query log</strong></td><td>Every query with timestamp, mode, result count, response time, and whether it was a cache hit</td></tr>
          <tr><td><strong>Click-through rate (CTR)</strong></td><td>Which results users click, and at what position</td></tr>
          <tr><td><strong>Zero-result queries</strong></td><td>Queries that returned no results — strong signal of content gaps or synonym needs</td></tr>
          <tr><td><strong>Popular queries</strong></td><td>Most frequent searches over the analytics window</td></tr>
          <tr><td><strong>Facet interactions</strong></td><td>Which facet filters users select and how often</td></tr>
        </tbody>
      </table>

      <h3>Dashboard Panels</h3>
      <ul>
        <li><strong>Stat cards</strong> — Total queries (30d), queries today, average response time, zero-result rate</li>
        <li><strong>Queries over time</strong> — Chart showing daily query volume</li>
        <li><strong>Mode distribution</strong> — Breakdown of which search modes are being used</li>
        <li><strong>Popular queries table</strong> — Top queries by frequency with CTR</li>
        <li><strong>Zero-result queries table</strong> — Queries that returned nothing, sorted by frequency</li>
        <li><strong>Recent queries</strong> — Live feed of the last N searches</li>
      </ul>

      <div class="known-issue">
        <span class="issue-id">AN-1</span>
        <span>Analytics are currently locked to a 30-day rolling window. Preset date range buttons (7d / 30d / 90d / all time) are planned.</span>
      </div>
    </section>


    <!-- Section 8: Quality Agent -->
    <section class="doc-section" id="quality-agent">
      <div class="section-header">
        <span class="section-number">08</span>
        <h2>Quality Agent</h2>
      </div>

      <p>The Quality Agent analyses your search history and generates actionable recommendations to improve relevance. All recommendations require explicit admin approval before taking effect — nothing is applied automatically.</p>

      <h3>Analyzers</h3>
      <div class="analyzer-grid">
        <div class="analyzer-card">
          <h4>synonym</h4>
          <p>Finds zero-result queries similar to successful ones (using Levenshtein distance and token overlap). Suggests synonym groups to bridge the gap.</p>
        </div>
        <div class="analyzer-card">
          <h4>query_rule</h4>
          <p>Identifies stop-word-heavy query patterns (e.g. "how to configure caching") and suggests prefix-stripping query rules to route them to the meaningful core.</p>
        </div>
        <div class="analyzer-card">
          <h4>low_ctr</h4>
          <p>Finds queries with ≥5 searches but under 10% CTR over 30 days — a signal that results are being shown but not clicked. Flags for manual relevance review.</p>
        </div>
        <div class="analyzer-card">
          <h4>content_gap</h4>
          <p>Identifies content that users click from positions ≥4 with ≥3 clicks — suggesting it should rank higher. Recommends a content score boost.</p>
        </div>
        <div class="analyzer-card">
          <h4>unused_facet</h4>
          <p>Finds enabled facets that have received zero clicks in 30 days. Suggests disabling them to reduce UI noise.</p>
        </div>
        <div class="analyzer-card">
          <h4>related_search</h4>
          <p>Identifies query pairs with high co-occurrence or overlapping clicked results. Suggests related search pairs to surface in the "related searches" widget.</p>
        </div>
      </div>

      <h3>Recommendation Workflow</h3>
      <ol class="step-list">
        <li><span class="step-num">1</span><div>Click <strong>Run Analysis</strong> in the Agent tab header. Analysis runs in the background (~300ms) via Cloudflare's <code>waitUntil()</code>.</div></li>
        <li><span class="step-num">2</span><div>Recommendations appear with status <strong>Pending</strong>. Each card shows the analyzer category, title, description, and the data that triggered it.</div></li>
        <li><span class="step-num">3</span><div>Click <strong>Apply</strong> to accept — this automatically creates the corresponding synonym group, query rule, related search pair, or content score boost. Click <strong>Dismiss</strong> to ignore.</div></li>
        <li><span class="step-num">4</span><div>Applied recommendations are not re-surfaced. Dismissed recommendations can re-appear if the underlying data changes significantly.</div></li>
      </ol>

      <h3>Filtering Recommendations</h3>
      <p>Use the filter bar at the top of the Agent tab to show recommendations by category (<code>synonym</code>, <code>query_rule</code>, <code>low_ctr</code>, etc.) or by status (<code>pending</code>, <code>applied</code>, <code>dismissed</code>).</p>

      <h3>Synonym Import Integration</h3>
      <p>When you import a synonym dictionary file (see <a href="#synonym-import" style="color:var(--accent)">Synonym Import</a>), the parsed entries appear in the Agent tab as recommendations tagged with "Imported: <em>filename</em>". This lets you review and selectively apply entries from a large dictionary rather than applying everything at once.</p>

      <div class="callout callout-tip">
        <strong>When to run the agent</strong>
        The agent works best with at least 2–3 weeks of real query data. Run it monthly, or whenever you notice a spike in the zero-result rate on the Analytics tab.
      </div>
    </section>


    <!-- Section 9: A/B Testing -->
    <section class="doc-section" id="ab-testing">
      <div class="section-header">
        <span class="section-number">09</span>
        <h2>A/B Testing</h2>
      </div>

      <p>The A/B Tests tab lets you compare two search configurations against each other with statistical rigour. Use it before making permanent changes to field weights, synonyms, or search mode settings.</p>

      <h3>Experiment Modes</h3>
      <table>
        <thead><tr><th>Mode</th><th>How it works</th><th>Best for</th></tr></thead>
        <tbody>
          <tr>
            <td><strong>A/B Split</strong></td>
            <td>Traffic is split — a configurable percentage of searches see variant A, the rest see variant B</td>
            <td>Large traffic volumes where you can afford to split cleanly</td>
          </tr>
          <tr>
            <td><strong>Team Draft Interleaving</strong></td>
            <td>Results from both variants are interleaved into a single list. Clicks reveal preference without users seeing different result sets</td>
            <td>Faster statistical significance — requires fewer searches to reach confidence</td>
          </tr>
        </tbody>
      </table>

      <h3>Using Templates</h3>
      <p>Eight pre-built templates are available for common experiment types:</p>
      <ul>
        <li>Hybrid vs FTS5 comparison</li>
        <li>Reranking on vs off</li>
        <li>Synonym impact (with vs without a synonym group)</li>
        <li>Field weight tuning (current weights vs proposed)</li>
        <li>Query rewriting on vs off</li>
        <li>Cache TTL comparison</li>
        <li>AI mode vs Hybrid</li>
        <li>Custom (blank template)</li>
      </ul>
      <p>Select a template when creating an experiment. Template defaults are pre-populated but fully editable in the visual settings editor.</p>

      <h3>Statistical Significance</h3>
      <p>The plugin uses chi-squared testing against a configurable confidence threshold (default 95%). The confidence bar in the active experiment panel shows progress toward the threshold. Experiments auto-complete when significance is reached — you will not accidentally act on inconclusive data.</p>

      <h3>Reading Results</h3>
      <p>The summary panel shows per-variant metrics: query count, click count, CTR, and result diversity. The recommendations panel provides plain-language guidance on which configuration to adopt based on the results.</p>

      <div class="callout callout-warn">
        <strong>Experiment lifecycle</strong>
        Experiments follow a strict status flow: <code>draft → running → completed → archived → deleted</code>. Only <code>draft</code> or <code>archived</code> experiments can be deleted. To remove a completed experiment, archive it first.
      </div>
    </section>


    <!-- Section 10: Faceted Search -->
    <section class="doc-section" id="faceted-search">
      <div class="section-header">
        <span class="section-number">10</span>
        <h2>Faceted Search</h2>
      </div>

      <p>Faceted search lets users narrow results by filtering on field values — category, status, date range, author, and so on. SonicJS generates facet options and counts dynamically at search time.</p>

      <h3>Auto-Discovery</h3>
      <p>The system inspects your collection schemas and identifies fields that are good facet candidates (low-cardinality fields like enums, booleans, and category strings). Discovered facets appear in <strong>Configuration → Facets</strong> for review and activation.</p>

      <h3>Facet Configuration</h3>
      <p>In the Configuration tab, you can:</p>
      <ul>
        <li>Enable or disable individual facets</li>
        <li>Set display labels and sort order</li>
        <li>Override auto-discovered facets with custom configuration</li>
        <li>Set a maximum number of facet values to return per field</li>
      </ul>

      <h3>Using Facets in the API</h3>
      <p>Request facets by including <code>"facets": true</code> in your search request body. Narrow results by passing <code>facet_filters</code>:</p>
      <pre><code>POST /api/search
{
  <span class="string">"q"</span>: <span class="value">"machine learning"</span>,
  <span class="string">"facets"</span>: <span class="value">true</span>,
  <span class="string">"facet_filters"</span>: {
    <span class="string">"category"</span>: [<span class="value">"tutorial"</span>, <span class="value">"guide"</span>],
    <span class="string">"status"</span>: [<span class="value">"published"</span>]
  }
}</code></pre>

      <p>The response includes a <code>facets</code> object with available values and counts for each configured facet field.</p>

      <h3>Facet Analytics</h3>
      <p>Facet interactions are tracked separately from search queries. The Analytics tab shows which facets users select most frequently. The Quality Agent's <code>unused_facet</code> analyzer uses this data to recommend disabling facets with no interaction.</p>
    </section>


    <!-- Section 11: API Reference -->
    <section class="doc-section" id="api-reference">
      <div class="section-header">
        <span class="section-number">11</span>
        <h2>API Reference</h2>
      </div>

      <p>The public search API requires no authentication by default. API key authentication can be enabled by setting <code>REQUIRE_API_KEY=true</code> in your environment.</p>

      <h3>Public Endpoints</h3>

      <div class="endpoint">
        <div class="endpoint-line">
          <span class="method method-post">POST</span>
          <span class="endpoint-path">/api/search</span>
        </div>
        <div class="endpoint-desc">Primary search endpoint. Supports all modes, facets, and filtering.</div>
        <pre style="margin-top:12px"><code>{
  <span class="string">"q"</span>: <span class="value">"your query"</span>,           <span class="comment">// required</span>
  <span class="string">"mode"</span>: <span class="value">"hybrid"</span>,           <span class="comment">// fts5 | ai | hybrid | keyword</span>
  <span class="string">"limit"</span>: <span class="value">10</span>,                <span class="comment">// max results (default: 10)</span>
  <span class="string">"offset"</span>: <span class="value">0</span>,               <span class="comment">// pagination offset</span>
  <span class="string">"collection"</span>: <span class="value">"posts"</span>,    <span class="comment">// filter to one collection</span>
  <span class="string">"facets"</span>: <span class="value">true</span>,            <span class="comment">// include facet counts in response</span>
  <span class="string">"facet_filters"</span>: { ... }   <span class="comment">// narrow by facet values</span>
}</code></pre>
      </div>

      <div class="endpoint">
        <div class="endpoint-line">
          <span class="method method-get">GET</span>
          <span class="endpoint-path">/api/search/suggest?q=term</span>
        </div>
        <div class="endpoint-desc">Autocomplete suggestions. Returns prefix-matched terms including trending searches.</div>
      </div>

      <div class="endpoint">
        <div class="endpoint-line">
          <span class="method method-post">POST</span>
          <span class="endpoint-path">/api/search/click</span>
        </div>
        <div class="endpoint-desc">Record a result click for CTR analytics. Fire-and-forget — call this when a user clicks a search result.</div>
        <pre style="margin-top:12px"><code>{
  <span class="string">"search_id"</span>: <span class="value">"uuid from search response"</span>,
  <span class="string">"content_id"</span>: <span class="value">"id of clicked result"</span>,
  <span class="string">"position"</span>: <span class="value">0</span>   <span class="comment">// 0-indexed position in results</span>
}</code></pre>
      </div>

      <div class="endpoint">
        <div class="endpoint-line">
          <span class="method method-get">GET</span>
          <span class="endpoint-path">/api/search/related?q=term</span>
        </div>
        <div class="endpoint-desc">Returns related search suggestions for a given query. Results are KV-cached.</div>
      </div>

      <div class="endpoint">
        <div class="endpoint-line">
          <span class="method method-get">GET</span>
          <span class="endpoint-path">/api/search/trending</span>
        </div>
        <div class="endpoint-desc">Returns trending searches using 5-bucket time-decay scoring. Accepts <code>limit</code> and <code>period</code> params.</div>
      </div>

      <h3>Authentication</h3>
      <p>API keys provide scoped access without requiring an admin session. Keys are created in the Configuration tab.</p>

      <table>
        <thead><tr><th>Scope</th><th>Grants access to</th></tr></thead>
        <tbody>
          <tr><td><span class="scope">search:read</span></td><td><code>POST /api/search</code></td></tr>
          <tr><td><span class="scope">search:write</span></td><td>Write operations (future use)</td></tr>
          <tr><td><span class="scope">search:analytics</span></td><td><code>GET /api/search/analytics</code></td></tr>
        </tbody>
      </table>

      <p>Pass the key in the <code>X-API-Key</code> request header. Keys are SHA-256 hashed for storage and cached in KV for fast validation.</p>

      <h3>Response Format</h3>
      <pre><code>{
  <span class="string">"search_id"</span>: <span class="value">"uuid"</span>,          <span class="comment">// pass to /click endpoint</span>
  <span class="string">"results"</span>: [
    {
      <span class="string">"id"</span>: <span class="value">"content-uuid"</span>,
      <span class="string">"title"</span>: <span class="value">"..."</span>,
      <span class="string">"slug"</span>: <span class="value">"..."</span>,
      <span class="string">"snippet"</span>: <span class="value">"...highlighted excerpt..."</span>,
      <span class="string">"score"</span>: <span class="value">0.87</span>,
      <span class="string">"collection"</span>: <span class="value">"posts"</span>
    }
  ],
  <span class="string">"total"</span>: <span class="value">42</span>,
  <span class="string">"mode"</span>: <span class="value">"hybrid"</span>,
  <span class="string">"cached"</span>: <span class="value">false</span>,
  <span class="string">"response_time_ms"</span>: <span class="value">543</span>,
  <span class="string">"facets"</span>: { ... }             <span class="comment">// only if facets:true requested</span>
}</code></pre>
    </section>


    <!-- Section 12: InstantSearch Integration -->
    <section class="doc-section" id="instantsearch">
      <div class="section-header">
        <span class="section-number">12</span>
        <h2>InstantSearch Integration</h2>
      </div>

      <p>SonicJS exposes an Algolia-compatible <code>POST /api/instantsearch</code> endpoint. This means you can use Algolia's <a href="https://www.algolia.com/doc/guides/building-search-ui/what-is-instantsearch/js/" style="color:var(--accent)">InstantSearch.js</a> widgets (React, Vue, vanilla JS, Angular) directly against SonicJS without modifying any frontend code.</p>

      <h3>Basic Setup</h3>
      <pre><code><span class="keyword">import</span> instantsearch from <span class="string">'instantsearch.js'</span>;
<span class="keyword">import</span> { searchBox, hits, refinementList } from <span class="string">'instantsearch.js/es/widgets'</span>;

<span class="keyword">const</span> search = instantsearch({
  indexName: <span class="string">'posts'</span>,
  searchClient: {
    search: <span class="keyword">async</span> (requests) => {
      <span class="keyword">const</span> res = <span class="keyword">await</span> fetch(<span class="string">'${baseUrl}/api/instantsearch'</span>, {
        method: <span class="string">'POST'</span>,
        headers: { <span class="string">'Content-Type'</span>: <span class="string">'application/json'</span> },
        body: JSON.stringify({ requests }),
      });
      <span class="keyword">return</span> res.json();
    },
  },
});

search.addWidgets([
  searchBox({ container: <span class="string">'#searchbox'</span> }),
  hits({ container: <span class="string">'#hits'</span> }),
  refinementList({ container: <span class="string">'#category'</span>, attribute: <span class="string">'category'</span> }),
]);

search.start();</code></pre>

      <div class="callout callout-info">
        <strong>See the full integration guide</strong>
        The <a href="${baseUrl}/admin/plugins/ai-search/integration-guide" style="color:var(--accent)">Integration Guide</a> page covers React InstantSearch, Vue, Next.js, vanilla JS, and headless API integration with code examples for each.
      </div>
    </section>

  </main>
</div>

<script>
  // Highlight active sidebar link on scroll
  const sections = document.querySelectorAll('.doc-section');
  const links = document.querySelectorAll('.sidebar a');

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const id = entry.target.id;
        links.forEach(l => {
          l.classList.toggle('active', l.getAttribute('href') === '#' + id);
        });
      }
    });
  }, { rootMargin: '-20% 0px -70% 0px' });

  sections.forEach(s => observer.observe(s));
</script>

</body>
</html>`;

  return c.html(html);
})

export default documentationRoutes
