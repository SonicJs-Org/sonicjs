/**
 * InstantSearch.js Test Page
 * Demonstrates the Algolia-compatible InstantSearch API with live widgets.
 * Uses the official InstantSearch.js library loaded from CDN.
 */

import { Hono } from 'hono'
import { html } from 'hono/html'
import type { Bindings } from '../../../../app'

const instantSearchTestRoutes = new Hono<{ Bindings: Bindings }>()

instantSearchTestRoutes.get('/instantsearch', async (c) => {
  // Fetch collection names for the index picker
  let collectionOptions = '<option value="*">* (All Collections)</option>'
  try {
    const { results } = await c.env.DB
      .prepare('SELECT name, display_name FROM collections WHERE is_active = 1 ORDER BY display_name')
      .all<{ name: string; display_name: string }>()
    for (const col of results || []) {
      collectionOptions += `<option value="${col.name}">${col.display_name} (${col.name})</option>`
    }
  } catch { /* ignore */ }

  return c.html(html`
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>InstantSearch.js Test - SonicJS</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/instantsearch.css@8/themes/satellite-min.css">
        <style>
          * { margin: 0; padding: 0; box-sizing: border-box; }
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f8fafc;
            color: #1e293b;
            min-height: 100vh;
          }
          .container {
            max-width: 960px;
            margin: 0 auto;
            padding: 2rem 1.5rem;
          }
          h1 { font-size: 1.5rem; font-weight: 700; margin-bottom: 0.25rem; }
          .subtitle { color: #64748b; font-size: 0.9rem; margin-bottom: 1.5rem; }
          .subtitle a { color: #6366f1; text-decoration: none; }
          .subtitle a:hover { text-decoration: underline; }

          /* Config bar */
          .config-bar {
            background: white;
            border-radius: 10px;
            padding: 1rem 1.25rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.08);
            display: flex;
            gap: 1rem;
            align-items: flex-end;
            flex-wrap: wrap;
          }
          .config-bar .field { display: flex; flex-direction: column; gap: 4px; }
          .config-bar label { font-size: 0.8rem; font-weight: 600; color: #475569; text-transform: uppercase; letter-spacing: 0.025em; }
          .config-bar select, .config-bar input[type="number"] {
            padding: 0.4rem 0.6rem;
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            font-size: 0.85rem;
            background: white;
          }
          .config-bar button {
            padding: 0.45rem 1rem;
            background: #6366f1;
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            font-size: 0.85rem;
          }
          .config-bar button:hover { background: #4f46e5; }

          /* Hits styling */
          .ais-SearchBox { margin-bottom: 1rem; }
          .ais-Hits-item {
            background: white;
            border-radius: 8px;
            padding: 1rem 1.25rem;
            margin-bottom: 0.75rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.06);
            border: 1px solid #f1f5f9;
          }
          .hit-title { font-size: 1.05rem; font-weight: 600; margin-bottom: 0.3rem; line-height: 1.3; }
          .hit-title em, .hit-snippet em {
            background: #fef08a;
            font-style: normal;
            padding: 1px 3px;
            border-radius: 2px;
          }
          .hit-snippet { color: #475569; font-size: 0.88rem; line-height: 1.55; }
          .hit-meta { margin-top: 0.5rem; font-size: 0.78rem; color: #94a3b8; display: flex; gap: 1rem; flex-wrap: wrap; }
          .badge {
            display: inline-block;
            padding: 1px 8px;
            border-radius: 9999px;
            font-size: 0.72rem;
            font-weight: 600;
          }
          .badge-published { background: #dcfce7; color: #166534; }
          .badge-draft { background: #fef9c3; color: #854d0e; }
          .badge-archived { background: #f1f5f9; color: #475569; }

          .ais-Stats { color: #64748b; font-size: 0.85rem; margin-bottom: 1rem; }
          .ais-Pagination { margin-top: 1.5rem; }

          /* Code snippet */
          .code-panel {
            background: #1e293b;
            color: #e2e8f0;
            border-radius: 10px;
            padding: 1.25rem;
            margin-top: 2rem;
            font-size: 0.82rem;
            line-height: 1.6;
            overflow-x: auto;
          }
          .code-panel summary {
            cursor: pointer;
            font-weight: 600;
            color: #94a3b8;
            margin-bottom: 0.75rem;
          }
          .code-panel code { white-space: pre; }
          .code-panel .key { color: #7dd3fc; }
          .code-panel .str { color: #86efac; }
          .code-panel .cmt { color: #64748b; }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>InstantSearch.js Test</h1>
          <p class="subtitle">
            Algolia-compatible search powered by SonicJS &mdash;
            <a href="/admin/plugins/ai-search/integration#instantsearch" target="_blank">Integration Guide</a> |
            <a href="/admin/search" target="_blank">Admin</a>
          </p>

          <div class="config-bar">
            <div class="field">
              <label for="idx">Index (Collection)</label>
              <select id="idx">${collectionOptions}</select>
            </div>
            <div class="field">
              <label for="hpp">Hits / Page</label>
              <select id="hpp">
                <option value="5">5</option>
                <option value="10" selected>10</option>
                <option value="20">20</option>
              </select>
            </div>
            <button onclick="restart()">Apply</button>
          </div>

          <div id="searchbox"></div>
          <div id="stats"></div>
          <div id="hits"></div>
          <div id="pagination"></div>

          <details class="code-panel">
            <summary>Show searchClient code (copy this into your project)</summary>
            <code><span class="cmt">// 1. Create the search client (5 lines)</span>
<span class="key">const</span> searchClient = {
  search(requests) {
    <span class="key">return</span> fetch(<span class="str">'${'{'}window.location.origin${'}'}/api/instantsearch'</span>, {
      method: <span class="str">'POST'</span>,
      headers: { <span class="str">'Content-Type'</span>: <span class="str">'application/json'</span> },
      body: JSON.stringify({ requests }),
    }).then(r => r.json());
  },
};

<span class="cmt">// 2. Use with InstantSearch.js</span>
<span class="key">import</span> instantsearch <span class="key">from</span> <span class="str">'instantsearch.js'</span>;
<span class="key">const</span> search = instantsearch({
  indexName: <span class="str">'blog_posts'</span>,  <span class="cmt">// your collection name, or "*" for all</span>
  searchClient,
});
search.addWidgets([ <span class="cmt">/* searchBox, hits, pagination ... */</span> ]);
search.start();</code>
          </details>
        </div>

        <script src="https://cdn.jsdelivr.net/npm/instantsearch.js@4/dist/instantsearch.production.min.js"></script>
        <script>
          var API = window.location.origin;
          var currentSearch = null;

          function makeClient() {
            return {
              search: function(requests) {
                return fetch(API + '/api/instantsearch', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ requests }),
                }).then(function(r) { return r.json(); });
              }
            };
          }

          function badgeClass(status) {
            if (status === 'published') return 'badge badge-published';
            if (status === 'draft') return 'badge badge-draft';
            return 'badge badge-archived';
          }

          function esc(s) {
            if (!s) return '';
            var d = document.createElement('div');
            d.appendChild(document.createTextNode(s));
            return d.innerHTML;
          }

          function restart() {
            var idx = document.getElementById('idx').value;
            var hpp = parseInt(document.getElementById('hpp').value, 10);

            if (currentSearch) {
              currentSearch.dispose();
              ['searchbox','stats','hits','pagination'].forEach(function(id) {
                document.getElementById(id).innerHTML = '';
              });
            }

            currentSearch = instantsearch({
              indexName: idx,
              searchClient: makeClient(),
              searchFunction: function(helper) {
                if (helper.state.query) {
                  helper.search();
                } else {
                  document.getElementById('hits').innerHTML =
                    '<p style="color:#94a3b8;text-align:center;padding:3rem 1rem;">Type a query above to search your content...</p>';
                  document.getElementById('stats').innerHTML = '';
                }
              },
            });

            currentSearch.addWidgets([
              instantsearch.widgets.searchBox({
                container: '#searchbox',
                placeholder: 'Search your content...',
                autofocus: true,
              }),

              instantsearch.widgets.stats({
                container: '#stats',
                templates: {
                  text: function(data) {
                    return data.nbHits + ' results in ' + data.processingTimeMS + 'ms';
                  },
                },
              }),

              instantsearch.widgets.hits({
                container: '#hits',
                templates: {
                  item: function(hit) {
                    var title = (hit._highlightResult && hit._highlightResult.title)
                      ? hit._highlightResult.title.value
                      : esc(hit.title);
                    var body = (hit._snippetResult && hit._snippetResult.body)
                      ? hit._snippetResult.body.value
                      : '';
                    var date = hit.created_at
                      ? new Date(hit.created_at * 1000).toLocaleDateString()
                      : '';
                    var score = hit.relevance_score
                      ? (hit.relevance_score * 100).toFixed(1) + '%'
                      : '';

                    return '<div>' +
                      '<div class="hit-title">' + title + '</div>' +
                      (body ? '<div class="hit-snippet">' + body + '</div>' : '') +
                      '<div class="hit-meta">' +
                        '<span>' + esc(hit.collection_name) + '</span>' +
                        '<span class="' + badgeClass(hit.status) + '">' + esc(hit.status) + '</span>' +
                        (date ? '<span>' + date + '</span>' : '') +
                        (score ? '<span>Score: ' + score + '</span>' : '') +
                        '<span>ID: ' + esc(hit.objectID).substring(0, 8) + '&hellip;</span>' +
                      '</div>' +
                    '</div>';
                  },
                  empty: function(data) {
                    return '<p style="text-align:center;color:#94a3b8;padding:3rem 1rem;">No results for &ldquo;' + esc(data.query) + '&rdquo;</p>';
                  },
                },
              }),

              instantsearch.widgets.pagination({
                container: '#pagination',
              }),

              instantsearch.widgets.configure({
                hitsPerPage: hpp,
              }),
            ]);

            currentSearch.start();
          }

          restart();
        </script>
      </body>
    </html>
  `)
})

export default instantSearchTestRoutes
