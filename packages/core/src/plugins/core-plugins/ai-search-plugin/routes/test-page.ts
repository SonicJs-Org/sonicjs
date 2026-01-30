/**
 * AI Search Test Page
 * Allows users to test search functionality and measure performance
 */

import { Hono } from 'hono'
import { html } from 'hono/html'
import type { Bindings } from '../../../../app'

const testPageRoutes = new Hono<{ Bindings: Bindings }>()

testPageRoutes.get('/test', async (c) => {
  return c.html(html`
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>AI Search Test - Performance Testing</title>
        <style>
          * { margin: 0; padding: 0; box-sizing: border-box; }
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 2rem;
          }
          .container {
            max-width: 900px;
            margin: 0 auto;
            background: white;
            border-radius: 1rem;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            padding: 2rem;
          }
          h1 {
            font-size: 2rem;
            margin-bottom: 0.5rem;
            color: #333;
          }
          .subtitle {
            color: #666;
            margin-bottom: 2rem;
          }
          .info-box {
            background: #e3f2fd;
            border-left: 4px solid #2196f3;
            padding: 1rem;
            margin-bottom: 2rem;
            border-radius: 0.5rem;
          }
          .info-box strong { color: #1976d2; }
          .search-box {
            display: flex;
            gap: 0.5rem;
            margin-bottom: 2rem;
            position: relative;
          }
          input {
            flex: 1;
            padding: 1rem;
            border: 2px solid #e0e0e0;
            border-radius: 0.5rem;
            font-size: 1rem;
          }
          input:focus {
            outline: none;
            border-color: #667eea;
          }
          button {
            padding: 1rem 2rem;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 0.5rem;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
          }
          button:hover { background: #5568d3; }
          button:disabled {
            background: #ccc;
            cursor: not-allowed;
          }
          .mode-toggle {
            display: flex;
            gap: 1rem;
            margin-bottom: 1rem;
          }
          .mode-toggle label {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            cursor: pointer;
          }
          .stats {
            background: #f8f9fa;
            padding: 1rem;
            border-radius: 0.5rem;
            margin-bottom: 2rem;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
          }
          .stat {
            text-align: center;
          }
          .stat-value {
            font-size: 2rem;
            font-weight: bold;
            color: #667eea;
          }
          .stat-label {
            font-size: 0.875rem;
            color: #666;
            margin-top: 0.25rem;
          }
          .results {
            margin-top: 1rem;
          }
          .result-item {
            padding: 1rem;
            border-left: 4px solid #667eea;
            background: #f8f9fa;
            margin-bottom: 1rem;
            border-radius: 0.5rem;
          }
          .result-title {
            font-weight: 600;
            margin-bottom: 0.5rem;
            color: #333;
          }
          .result-excerpt {
            color: #666;
            font-size: 0.875rem;
            margin-bottom: 0.5rem;
          }
          .result-meta {
            font-size: 0.75rem;
            color: #999;
          }
          .loading {
            text-align: center;
            padding: 2rem;
            color: #667eea;
          }
          .error {
            background: #fee;
            color: #c33;
            padding: 1rem;
            border-radius: 0.5rem;
            margin-bottom: 1rem;
          }
          .query-history {
            margin-top: 2rem;
            padding-top: 2rem;
            border-top: 2px solid #e0e0e0;
          }
          .history-item {
            display: flex;
            justify-content: space-between;
            padding: 0.75rem;
            background: #f8f9fa;
            margin-bottom: 0.5rem;
            border-radius: 0.5rem;
            font-size: 0.875rem;
          }
          .history-query { font-weight: 600; color: #333; }
          .history-time { color: #667eea; font-weight: 600; }
          .history-mode { color: #666; }
          .suggestions {
            position: absolute;
            top: 100%;
            left: 0;
            right: 100px;
            background: white;
            border: 2px solid #e0e0e0;
            border-top: none;
            border-radius: 0 0 0.5rem 0.5rem;
            max-height: 300px;
            overflow-y: auto;
            display: none;
            z-index: 1000;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
          }
          .suggestions.show { display: block; }
          .suggestion-item {
            padding: 0.75rem 1rem;
            cursor: pointer;
            transition: background 0.1s;
            border-bottom: 1px solid #f0f0f0;
          }
          .suggestion-item:hover {
            background: #f8f9fa;
          }
          .suggestion-item:last-child {
            border-bottom: none;
          }
          .back-link {
            display: inline-block;
            margin-bottom: 1rem;
            color: #667eea;
            text-decoration: none;
            font-weight: 600;
          }
          .back-link:hover {
            text-decoration: underline;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <a href="/admin/plugins/ai-search" class="back-link">← Back to AI Search Settings</a>
          
          <h1>🔍 AI Search Test</h1>
          <p class="subtitle">Test search performance and similarity-based caching</p>

          <div class="info-box">
            <strong>Performance Testing:</strong> Watch how similarity caching speeds up repeated queries.
            First query to a term may take 500-800ms, but similar queries should be much faster!
            <br><br>
            <strong>Autocomplete:</strong> Type 2+ characters to see instant suggestions (<50ms).
            <br><br>
            <strong>For Developers:</strong> Want to add AI search to your own frontend? 
            <a href="https://github.com/lane711/sonicjs/blob/main/packages/core/src/plugins/core-plugins/ai-search-plugin/HEADLESS_INTEGRATION.md" 
               target="_blank" 
               style="color: #2196f3; text-decoration: underline;">
              View the Headless Integration Guide
            </a> for React, Vue, Next.js examples and copy-paste code.
          </div>

          <div class="mode-toggle">
            <label>
              <input type="radio" name="mode" value="ai" checked> AI Mode (with caching)
            </label>
            <label>
              <input type="radio" name="mode" value="keyword"> Keyword Mode
            </label>
          </div>

          <div class="search-box">
            <input 
              type="text" 
              id="searchInput" 
              placeholder="Try searching for topics in your content..."
              autocomplete="off"
              autofocus
            />
            <div id="suggestions" class="suggestions"></div>
            <button id="searchBtn">Search</button>
          </div>

          <div class="stats">
            <div class="stat">
              <div class="stat-value" id="totalQueries">0</div>
              <div class="stat-label">Total Queries</div>
            </div>
            <div class="stat">
              <div class="stat-value" id="avgTime">-</div>
              <div class="stat-label">Avg Time (ms)</div>
            </div>
            <div class="stat">
              <div class="stat-value" id="lastTime">-</div>
              <div class="stat-label">Last Query (ms)</div>
            </div>
          </div>

          <div id="error"></div>
          <div id="results"></div>

          <div class="query-history">
            <h3>Query History</h3>
            <div id="history"></div>
          </div>
        </div>

        <script>
          let queryCount = 0;
          let totalTime = 0;
          const history = [];

          const searchInput = document.getElementById('searchInput');
          const searchBtn = document.getElementById('searchBtn');
          const resultsDiv = document.getElementById('results');
          const errorDiv = document.getElementById('error');
          const historyDiv = document.getElementById('history');
          const suggestionsDiv = document.getElementById('suggestions');

          let suggestionTimeout;

          // Autocomplete
          searchInput.addEventListener('input', async (e) => {
            const query = e.target.value.trim();
            
            clearTimeout(suggestionTimeout);
            
            if (query.length < 2) {
              suggestionsDiv.classList.remove('show');
              return;
            }

            suggestionTimeout = setTimeout(async () => {
              const startTime = performance.now();
              try {
                const response = await fetch(\`/api/search/suggest?q=\${encodeURIComponent(query)}\`);
                const data = await response.json();
                const endTime = performance.now();
                const duration = Math.round(endTime - startTime);
                
                if (data.success && data.data.length > 0) {
                  suggestionsDiv.innerHTML = data.data.map(s => 
                    \`<div class="suggestion-item" onclick="selectSuggestion('\${s.replace(/'/g, "\\'")}')">
                      <strong>\${s}</strong>
                    </div>\`
                  ).join('');
                  suggestionsDiv.classList.add('show');
                  console.log(\`Autocomplete: \${duration}ms for \${data.data.length} suggestions\`);
                } else {
                  suggestionsDiv.classList.remove('show');
                }
              } catch (error) {
                console.error('Autocomplete error:', error);
              }
            }, 200); // Fast debounce for instant feel
          });

          // Hide suggestions on click outside
          document.addEventListener('click', (e) => {
            if (!e.target.closest('.search-box')) {
              suggestionsDiv.classList.remove('show');
            }
          });

          function selectSuggestion(text) {
            searchInput.value = text;
            suggestionsDiv.classList.remove('show');
            search();
          }
          window.selectSuggestion = selectSuggestion;

          // Search on Enter key
          searchInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
              suggestionsDiv.classList.remove('show');
              search();
            }
          });

          searchBtn.addEventListener('click', search);

          async function search() {
            const query = searchInput.value.trim();
            if (!query) return;

            const mode = document.querySelector('input[name="mode"]:checked').value;

            errorDiv.innerHTML = '';
            resultsDiv.innerHTML = '<div class="loading">Searching...</div>';
            searchBtn.disabled = true;

            const startTime = performance.now();

            try {
              const response = await fetch('/api/search', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query, mode })
              });

              const endTime = performance.now();
              const duration = Math.round(endTime - startTime);

              const data = await response.json();

              if (data.success) {
                displayResults(data.data, duration);
                updateStats(query, mode, duration);
              } else {
                throw new Error(data.message || 'Search failed');
              }
            } catch (error) {
              errorDiv.innerHTML = \`<div class="error">Error: \${error.message}</div>\`;
              resultsDiv.innerHTML = '';
            } finally {
              searchBtn.disabled = false;
            }
          }

          function displayResults(data, duration) {
            if (!data.results || data.results.length === 0) {
              resultsDiv.innerHTML = '<div class="loading">No results found</div>';
              return;
            }

            resultsDiv.innerHTML = \`
              <div class="results">
                <h3>Found \${data.results.length} results in \${duration}ms</h3>
                \${data.results.map(result => \`
                  <div class="result-item">
                    <div class="result-title">\${result.title || 'Untitled'}</div>
                    <div class="result-excerpt">\${result.excerpt || result.content?.substring(0, 200) || ''}</div>
                    <div class="result-meta">
                      Collection: \${result.collection} | 
                      Score: \${result.score?.toFixed(3) || 'N/A'}
                    </div>
                  </div>
                \`).join('')}
              </div>
            \`;
          }

          function updateStats(query, mode, duration) {
            queryCount++;
            totalTime += duration;

            document.getElementById('totalQueries').textContent = queryCount;
            document.getElementById('avgTime').textContent = Math.round(totalTime / queryCount);
            document.getElementById('lastTime').textContent = duration;

            history.unshift({ query, mode, duration, time: new Date() });
            if (history.length > 10) history.pop();

            historyDiv.innerHTML = history.map(h => \`
              <div class="history-item">
                <span class="history-query">\${h.query}</span>
                <span class="history-mode">(\${h.mode})</span>
                <span class="history-time">\${h.duration}ms</span>
              </div>
            \`).join('');
          }
        </script>
      </body>
    </html>
  `)
})

export default testPageRoutes
