/**
 * Headless Integration Guide Page
 * Shows developers how to integrate AI search into their frontend
 */

import { Hono } from 'hono'
import { html } from 'hono/html'
import type { Bindings } from '../../../../app'

const integrationGuideRoutes = new Hono<{ Bindings: Bindings }>()

integrationGuideRoutes.get('/integration', async (c) => {
  return c.html(html`
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>AI Search - Headless Integration Guide</title>
        <style>
          * { margin: 0; padding: 0; box-sizing: border-box; }
          body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f5f5;
            line-height: 1.6;
          }
          .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            min-height: 100vh;
          }
          .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem;
            box-shadow: 0 2px 12px rgba(0,0,0,0.1);
          }
          .header h1 {
            font-size: 2rem;
            margin-bottom: 0.5rem;
          }
          .header p {
            opacity: 0.9;
          }
          .back-link {
            display: inline-block;
            color: white;
            text-decoration: none;
            margin-bottom: 1rem;
            opacity: 0.9;
            transition: opacity 0.2s;
          }
          .back-link:hover { opacity: 1; }
          .content {
            padding: 2rem;
          }
          .section {
            margin-bottom: 3rem;
          }
          h2 {
            color: #333;
            font-size: 1.75rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 3px solid #667eea;
          }
          h3 {
            color: #444;
            font-size: 1.25rem;
            margin: 2rem 0 1rem 0;
          }
          p {
            color: #666;
            margin-bottom: 1rem;
          }
          .info-box {
            background: #e3f2fd;
            border-left: 4px solid #2196f3;
            padding: 1rem;
            margin: 1rem 0;
            border-radius: 4px;
          }
          .info-box strong {
            color: #1976d2;
          }
          code {
            background: #f5f5f5;
            padding: 0.2rem 0.4rem;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            color: #c7254e;
          }
          pre {
            background: #282c34;
            color: #abb2bf;
            padding: 1.5rem;
            border-radius: 8px;
            overflow-x: auto;
            margin: 1rem 0;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            line-height: 1.5;
          }
          pre code {
            background: none;
            color: inherit;
            padding: 0;
          }
          .copy-btn {
            position: relative;
            float: right;
            background: #667eea;
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.85rem;
            margin-top: -3rem;
            margin-right: 0.5rem;
            z-index: 1;
          }
          .copy-btn:hover {
            background: #5568d3;
          }
          .tabs {
            display: flex;
            gap: 0.5rem;
            border-bottom: 2px solid #e0e0e0;
            margin-bottom: 1rem;
          }
          .tab {
            padding: 0.75rem 1.5rem;
            background: none;
            border: none;
            border-bottom: 3px solid transparent;
            cursor: pointer;
            font-size: 1rem;
            color: #666;
            transition: all 0.2s;
          }
          .tab:hover {
            color: #667eea;
          }
          .tab.active {
            color: #667eea;
            border-bottom-color: #667eea;
            font-weight: 600;
          }
          .tab-content {
            display: none;
          }
          .tab-content.active {
            display: block;
          }
          .checklist {
            list-style: none;
            padding: 0;
          }
          .checklist li {
            padding: 0.5rem 0;
            padding-left: 2rem;
            position: relative;
          }
          .checklist li:before {
            content: '□';
            position: absolute;
            left: 0;
            font-size: 1.5rem;
            color: #667eea;
          }
          .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
            margin: 1rem 0;
          }
          .card {
            background: #f8f9fa;
            padding: 1rem;
            border-radius: 8px;
            border-left: 4px solid #667eea;
          }
          .card h4 {
            margin-bottom: 0.5rem;
            color: #333;
          }
          .card p {
            margin: 0;
            font-size: 0.9rem;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <a href="/admin/plugins/ai-search" class="back-link">← Back to AI Search Settings</a>
            <h1>🚀 Headless Integration Guide</h1>
            <p>Add AI search to your React, Vue, or vanilla JS frontend in minutes</p>
          </div>

          <div class="content">
            <!-- Quick Start Section -->
            <div class="section">
              <h2>🎯 Quick Start</h2>
              <p>SonicJS provides a simple REST API. Make POST requests to <code>/api/search</code> from any frontend.</p>
              
              <div class="info-box">
                <strong>💡 Choose Your Flavor:</strong> Pick the framework below that matches your project, or use vanilla JavaScript for maximum compatibility.
              </div>

              <div class="tabs">
                <button class="tab active" onclick="showTab('vanilla')">Vanilla JS</button>
                <button class="tab" onclick="showTab('react')">React</button>
                <button class="tab" onclick="showTab('vue')">Vue</button>
                <button class="tab" onclick="showTab('astro')">Astro</button>
              </div>

              <!-- Vanilla JS Tab -->
              <div id="vanilla" class="tab-content active">
                <h3>Paste n Go - Vanilla JavaScript</h3>
                <p>Drop this into any HTML file. Just update the <code>API_URL</code> and you're done!</p>
                
                <button class="copy-btn" onclick="copyCode('vanilla-code')">Copy Code</button>
                <pre id="vanilla-code"><code>&lt;!DOCTYPE html&gt;
&lt;html&gt;
&lt;head&gt;
  &lt;title&gt;Search Demo&lt;/title&gt;
  &lt;style&gt;
    body { font-family: Arial; padding: 20px; max-width: 800px; margin: 0 auto; }
    input { width: 100%; padding: 12px; font-size: 16px; border: 2px solid #ddd; border-radius: 8px; }
    input:focus { border-color: #667eea; outline: none; }
    .result { padding: 15px; background: #f8f9fa; margin: 10px 0; border-radius: 8px; border-left: 4px solid #667eea; }
    .result h3 { margin: 0 0 8px 0; }
    .suggestions { border: 2px solid #ddd; border-top: none; border-radius: 0 0 8px 8px; max-height: 300px; overflow-y: auto; }
    .suggestion { padding: 10px; cursor: pointer; border-bottom: 1px solid #eee; }
    .suggestion:hover { background: #f8f9fa; }
  &lt;/style&gt;
&lt;/head&gt;
&lt;body&gt;
  &lt;h1&gt;🔍 Search&lt;/h1&gt;
  &lt;div style="position: relative"&gt;
    &lt;input id="search" type="text" placeholder="Type to search..." autocomplete="off"&gt;
    &lt;div id="suggestions" style="display: none"&gt;&lt;/div&gt;
  &lt;/div&gt;
  &lt;div id="results"&gt;&lt;/div&gt;

  &lt;script&gt;
    const API_URL = 'https://your-backend.com'; // ⚠️ UPDATE THIS!
    
    const searchInput = document.getElementById('search');
    const suggestionsDiv = document.getElementById('suggestions');
    const resultsDiv = document.getElementById('results');
    let timeout;

    // Autocomplete
    searchInput.addEventListener('input', async (e) =&gt; {
      const query = e.target.value.trim();
      clearTimeout(timeout);
      
      if (query.length &lt; 2) {
        suggestionsDiv.style.display = 'none';
        return;
      }

      timeout = setTimeout(async () =&gt; {
        const res = await fetch(\`\${API_URL}/api/search/suggest?q=\${encodeURIComponent(query)}\`);
        const data = await res.json();
        
        if (data.success &amp;&amp; data.data.length &gt; 0) {
          suggestionsDiv.innerHTML = \`&lt;div class="suggestions"&gt;\${
            data.data.map(s =&gt; \`&lt;div class="suggestion" onclick="search('\${s}')"&gt;\${s}&lt;/div&gt;\`).join('')
          }&lt;/div&gt;\`;
          suggestionsDiv.style.display = 'block';
        }
      }, 300);
    });

    // Search
    async function search(query) {
      if (!query) query = searchInput.value.trim();
      if (query.length &lt; 2) return;
      
      searchInput.value = query;
      suggestionsDiv.style.display = 'none';
      resultsDiv.innerHTML = 'Searching...';

      const res = await fetch(\`\${API_URL}/api/search\`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query, mode: 'ai' })
      });
      
      const data = await res.json();
      
      if (data.success &amp;&amp; data.data.results.length &gt; 0) {
        resultsDiv.innerHTML = data.data.results.map(r =&gt; \`
          &lt;div class="result"&gt;
            &lt;h3&gt;\${r.title || 'Untitled'}&lt;/h3&gt;
            &lt;p&gt;\${r.excerpt || r.content?.substring(0, 200) || ''}&lt;/p&gt;
          &lt;/div&gt;
        \`).join('');
      } else {
        resultsDiv.innerHTML = 'No results found';
      }
    }
  &lt;/script&gt;
&lt;/body&gt;
&lt;/html&gt;</code></pre>
              </div>

              <!-- React Tab -->
              <div id="react" class="tab-content">
                <h3>React / Next.js Component</h3>
                <p>Full TypeScript component with hooks, autocomplete, and error handling.</p>
                
                <button class="copy-btn" onclick="copyCode('react-code')">Copy Code</button>
                <pre id="react-code"><code>import { useState, useEffect } from 'react';

const API_URL = 'https://your-backend.com'; // ⚠️ UPDATE THIS!

export function AISearch() {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [suggestions, setSuggestions] = useState([]);
  const [loading, setLoading] = useState(false);

  // Search with debounce
  useEffect(() =&gt; {
    if (query.length &lt; 2) return;
    const timeout = setTimeout(() =&gt; performSearch(query), 500);
    return () =&gt; clearTimeout(timeout);
  }, [query]);

  // Autocomplete
  useEffect(() =&gt; {
    if (query.length &lt; 2) {
      setSuggestions([]);
      return;
    }
    
    const timeout = setTimeout(async () =&gt; {
      const res = await fetch(
        \`\${API_URL}/api/search/suggest?q=\${encodeURIComponent(query)}\`
      );
      const data = await res.json();
      if (data.success) setSuggestions(data.data);
    }, 300);
    
    return () =&gt; clearTimeout(timeout);
  }, [query]);

  const performSearch = async (q) =&gt; {
    setLoading(true);
    const res = await fetch(\`\${API_URL}/api/search\`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: q, mode: 'ai' })
    });
    const data = await res.json();
    setResults(data.success ? data.data.results : []);
    setLoading(false);
  };

  return (
    &lt;div style={{ maxWidth: '800px', margin: '2rem auto', padding: '2rem' }}&gt;
      &lt;h1&gt;🔍 Search&lt;/h1&gt;
      
      &lt;div style={{ position: 'relative', marginTop: '1.5rem' }}&gt;
        &lt;input
          type="text"
          value={query}
          onChange={(e) =&gt; setQuery(e.target.value)}
          placeholder="Type to search..."
          style={{
            width: '100%',
            padding: '1rem',
            fontSize: '1rem',
            border: '2px solid #ddd',
            borderRadius: '8px'
          }}
        /&gt;
        
        {suggestions.length &gt; 0 &amp;&amp; (
          &lt;div style={{
            position: 'absolute',
            top: '100%',
            left: 0,
            right: 0,
            background: 'white',
            border: '2px solid #ddd',
            borderRadius: '0 0 8px 8px',
            maxHeight: '300px',
            overflowY: 'auto'
          }}&gt;
            {suggestions.map((s, i) =&gt; (
              &lt;div
                key={i}
                onClick={() =&gt; { setQuery(s); setSuggestions([]); }}
                style={{ padding: '0.75rem 1rem', cursor: 'pointer' }}
              &gt;
                {s}
              &lt;/div&gt;
            ))}
          &lt;/div&gt;
        )}
      &lt;/div&gt;

      &lt;div style={{ marginTop: '2rem' }}&gt;
        {loading &amp;&amp; &lt;div&gt;Searching...&lt;/div&gt;}
        
        {results.map((r) =&gt; (
          &lt;div
            key={r.id}
            style={{
              padding: '1rem',
              background: '#f8f9fa',
              borderLeft: '4px solid #667eea',
              margin: '1rem 0',
              borderRadius: '8px'
            }}
          &gt;
            &lt;h3&gt;{r.title || 'Untitled'}&lt;/h3&gt;
            &lt;p&gt;{r.excerpt || r.content?.substring(0, 200)}&lt;/p&gt;
          &lt;/div&gt;
        ))}
      &lt;/div&gt;
    &lt;/div&gt;
  );
}</code></pre>
              </div>

              <!-- Astro Tab -->
              <div id="astro" class="tab-content">
                <h3>Astro Component</h3>
                <p>Server-side rendering with client-side interactivity for search. Perfect for content-heavy sites!</p>
                
                <button class="copy-btn" onclick="copyCode('astro-code')">Copy Code</button>
                <pre id="astro-code"><code>---
// src/components/Search.astro
const API_URL = import.meta.env.PUBLIC_API_URL || 'https://your-backend.com'; // ⚠️ UPDATE THIS!
---

&lt;div class="search-container"&gt;
  &lt;h1&gt;🔍 Search&lt;/h1&gt;
  
  &lt;div class="search-box"&gt;
    &lt;input
      id="searchInput"
      type="text"
      placeholder="Type to search..."
      autocomplete="off"
    /&gt;
    &lt;div id="suggestions" class="suggestions"&gt;&lt;/div&gt;
  &lt;/div&gt;

  &lt;div id="results"&gt;&lt;/div&gt;
&lt;/div&gt;

&lt;style&gt;
  .search-container { max-width: 800px; margin: 2rem auto; padding: 2rem; }
  .search-box { position: relative; margin-top: 1.5rem; }
  input {
    width: 100%;
    padding: 1rem;
    font-size: 1rem;
    border: 2px solid #ddd;
    border-radius: 8px;
  }
  input:focus { border-color: #667eea; outline: none; }
  .suggestions {
    position: absolute;
    top: 100%;
    left: 0;
    right: 0;
    background: white;
    border: 2px solid #ddd;
    border-top: none;
    border-radius: 0 0 8px 8px;
    max-height: 300px;
    overflow-y: auto;
    display: none;
  }
  .suggestions.show { display: block; }
  .suggestion {
    padding: 0.75rem 1rem;
    cursor: pointer;
    border-bottom: 1px solid #eee;
  }
  .suggestion:hover { background: #f8f9fa; }
  .result {
    padding: 1rem;
    background: #f8f9fa;
    border-left: 4px solid #667eea;
    margin: 1rem 0;
    border-radius: 8px;
  }
  .result h3 { margin: 0 0 0.5rem 0; }
  .loading { text-align: center; padding: 2rem; color: #667eea; }
&lt;/style&gt;

&lt;script define:vars={{ API_URL }}&gt;
  const searchInput = document.getElementById('searchInput');
  const suggestionsDiv = document.getElementById('suggestions');
  const resultsDiv = document.getElementById('results');
  
  let searchTimeout;
  let suggestTimeout;

  // Autocomplete
  searchInput.addEventListener('input', async (e) =&gt; {
    const query = e.target.value.trim();
    
    clearTimeout(suggestTimeout);
    
    if (query.length &lt; 2) {
      suggestionsDiv.classList.remove('show');
      return;
    }

    suggestTimeout = setTimeout(async () =&gt; {
      try {
        const res = await fetch(\`\${API_URL}/api/search/suggest?q=\${encodeURIComponent(query)}\`);
        const data = await res.json();
        
        if (data.success &amp;&amp; data.data.length &gt; 0) {
          suggestionsDiv.innerHTML = data.data
            .map(s =&gt; \`&lt;div class="suggestion" onclick="selectSuggestion('\${s.replace(/'/g, "\\'")}')"&gt;\${s}&lt;/div&gt;\`)
            .join('');
          suggestionsDiv.classList.add('show');
        } else {
          suggestionsDiv.classList.remove('show');
        }
      } catch (error) {
        console.error('Autocomplete error:', error);
      }
    }, 300);
  });

  // Search with debounce
  searchInput.addEventListener('input', (e) =&gt; {
    const query = e.target.value.trim();
    
    if (query.length &lt; 2) {
      resultsDiv.innerHTML = '';
      return;
    }

    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() =&gt; performSearch(query), 500);
  });

  // Hide suggestions on click outside
  document.addEventListener('click', (e) =&gt; {
    if (!e.target.closest('.search-box')) {
      suggestionsDiv.classList.remove('show');
    }
  });

  window.selectSuggestion = function(text) {
    searchInput.value = text;
    suggestionsDiv.classList.remove('show');
    performSearch(text);
  };

  async function performSearch(query) {
    resultsDiv.innerHTML = '&lt;div class="loading"&gt;Searching...&lt;/div&gt;';

    try {
      const res = await fetch(\`\${API_URL}/api/search\`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          query, 
          mode: 'ai' // or 'keyword'
        })
      });

      const data = await res.json();

      if (data.success &amp;&amp; data.data.results.length &gt; 0) {
        resultsDiv.innerHTML = data.data.results
          .map(r =&gt; \`
            &lt;div class="result"&gt;
              &lt;h3&gt;\${r.title || 'Untitled'}&lt;/h3&gt;
              &lt;p&gt;\${r.excerpt || r.content?.substring(0, 200) || ''}&lt;/p&gt;
            &lt;/div&gt;
          \`)
          .join('');
      } else {
        resultsDiv.innerHTML = '&lt;div class="loading"&gt;No results found&lt;/div&gt;';
      }
    } catch (error) {
      resultsDiv.innerHTML = '&lt;div class="loading"&gt;Search error. Please try again.&lt;/div&gt;';
      console.error('Search error:', error);
    }
  }
&lt;/script&gt;</code></pre>

                <h3>Using in a Page</h3>
                <pre><code>---
// src/pages/search.astro
import Search from '../components/Search.astro';
import Layout from '../layouts/Layout.astro';
---

&lt;Layout title="Search"&gt;
  &lt;Search /&gt;
&lt;/Layout&gt;</code></pre>

                <h3>Environment Variables</h3>
                <p>Add to your <code>.env</code> file:</p>
                <pre><code>PUBLIC_API_URL=https://your-sonicjs-backend.com</code></pre>

                <div class="info-box">
                  <strong>💡 Tip:</strong> Astro automatically handles server-side rendering and client-side hydration. 
                  The search component loads fast with minimal JavaScript, then becomes interactive on the client!
                </div>
              </div>

              <!-- Vue Tab -->
              <div id="vue" class="tab-content">
                <h3>Vue 3 Component</h3>
                <p>Composition API with reactive search and autocomplete.</p>
                
                <button class="copy-btn" onclick="copyCode('vue-code')">Copy Code</button>
                <pre id="vue-code"><code>&lt;template&gt;
  &lt;div class="search-container"&gt;
    &lt;h1&gt;🔍 Search&lt;/h1&gt;
    
    &lt;div class="search-box"&gt;
      &lt;input
        v-model="query"
        type="text"
        placeholder="Type to search..."
        @input="debouncedSearch"
      /&gt;
      
      &lt;div v-if="suggestions.length" class="suggestions"&gt;
        &lt;div
          v-for="(s, i) in suggestions"
          :key="i"
          class="suggestion"
          @click="selectSuggestion(s)"
        &gt;
          {{ s }}
        &lt;/div&gt;
      &lt;/div&gt;
    &lt;/div&gt;

    &lt;div v-if="loading"&gt;Searching...&lt;/div&gt;
    
    &lt;div
      v-for="result in results"
      :key="result.id"
      class="result"
    &gt;
      &lt;h3&gt;{{ result.title || 'Untitled' }}&lt;/h3&gt;
      &lt;p&gt;{{ result.excerpt || result.content?.substring(0, 200) }}&lt;/p&gt;
    &lt;/div&gt;
  &lt;/div&gt;
&lt;/template&gt;

&lt;script setup&gt;
import { ref, watch } from 'vue';

const API_URL = 'https://your-backend.com'; // ⚠️ UPDATE THIS!

const query = ref('');
const results = ref([]);
const suggestions = ref([]);
const loading = ref(false);

let searchTimeout;
let suggestTimeout;

watch(query, (newQuery) =&gt; {
  if (newQuery.length &lt; 2) {
    results.value = [];
    suggestions.value = [];
    return;
  }
  
  // Search
  clearTimeout(searchTimeout);
  searchTimeout = setTimeout(() =&gt; performSearch(newQuery), 500);
  
  // Autocomplete
  clearTimeout(suggestTimeout);
  suggestTimeout = setTimeout(() =&gt; getSuggestions(newQuery), 300);
});

async function performSearch(q) {
  loading.value = true;
  const res = await fetch(\`\${API_URL}/api/search\`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query: q, mode: 'ai' })
  });
  const data = await res.json();
  results.value = data.success ? data.data.results : [];
  loading.value = false;
}

async function getSuggestions(q) {
  const res = await fetch(
    \`\${API_URL}/api/search/suggest?q=\${encodeURIComponent(q)}\`
  );
  const data = await res.json();
  suggestions.value = data.success ? data.data : [];
}

function selectSuggestion(s) {
  query.value = s;
  suggestions.value = [];
}
&lt;/script&gt;

&lt;style scoped&gt;
.search-container { max-width: 800px; margin: 2rem auto; padding: 2rem; }
.search-box { position: relative; margin-top: 1.5rem; }
input { width: 100%; padding: 1rem; font-size: 1rem; border: 2px solid #ddd; border-radius: 8px; }
.suggestions { position: absolute; top: 100%; left: 0; right: 0; background: white; border: 2px solid #ddd; border-radius: 0 0 8px 8px; }
.suggestion { padding: 0.75rem 1rem; cursor: pointer; }
.suggestion:hover { background: #f8f9fa; }
.result { padding: 1rem; background: #f8f9fa; border-left: 4px solid #667eea; margin: 1rem 0; border-radius: 8px; }
&lt;/style&gt;</code></pre>
              </div>
            </div>

            <!-- API Reference Section -->
            <div class="section">
              <h2>📡 API Reference</h2>
              
              <div class="grid">
                <div class="card">
                  <h4>Search Endpoint</h4>
                  <p><strong>POST</strong> <code>/api/search</code></p>
                  <p>Execute search queries with AI or keyword mode</p>
                </div>
                <div class="card">
                  <h4>Autocomplete</h4>
                  <p><strong>GET</strong> <code>/api/search/suggest?q=query</code></p>
                  <p>Get instant suggestions (&lt;50ms)</p>
                </div>
              </div>

              <h3>Search Request</h3>
              <pre><code>{
  "query": "cloudflare workers",
  "mode": "ai",           // or "keyword"
  "filters": {
    "collections": ["blog_posts"],
    "status": "published"
  },
  "limit": 20,
  "offset": 0
}</code></pre>

              <h3>Search Response</h3>
              <pre><code>{
  "success": true,
  "data": {
    "results": [{
      "id": "123",
      "title": "Getting Started",
      "excerpt": "Learn how to...",
      "collection": "blog_posts",
      "score": 0.95
    }],
    "total": 42,
    "query_time_ms": 150
  }
}</code></pre>
            </div>

            <!-- Performance Tips Section -->
            <div class="section">
              <h2>⚡ Performance Tips</h2>
              
              <div class="grid">
                <div class="card">
                  <h4>Use Keyword Mode</h4>
                  <p>~50ms response time for simple matching</p>
                  <p><code>mode: "keyword"</code></p>
                </div>
                <div class="card">
                  <h4>Debounce Input</h4>
                  <p>Wait 300-500ms after typing stops</p>
                  <p><code>setTimeout(search, 500)</code></p>
                </div>
                <div class="card">
                  <h4>Cache Results</h4>
                  <p>Store results in Map or localStorage</p>
                  <p>Avoid redundant API calls</p>
                </div>
                <div class="card">
                  <h4>AI Mode Benefits</h4>
                  <p>First query: ~500ms</p>
                  <p>Similar queries: ~100ms (cached!)</p>
                </div>
              </div>
            </div>

            <!-- CORS Section -->
            <div class="section">
              <h2>🔐 CORS Configuration</h2>
              <p>If your frontend is on a different domain, add CORS to your SonicJS app:</p>
              
              <pre><code>// src/index.ts
import { cors } from 'hono/cors';

app.use('/api/*', cors({
  origin: ['https://your-frontend.com'],
  allowMethods: ['GET', 'POST'],
}));</code></pre>
            </div>

            <!-- Checklist Section -->
            <div class="section">
              <h2>✅ Integration Checklist</h2>
              <ul class="checklist">
                <li>Updated API_URL in code</li>
                <li>Configured CORS if needed</li>
                <li>Indexed collections in admin</li>
                <li>Tested autocomplete (&lt;50ms)</li>
                <li>Tested search (both modes)</li>
                <li>Added loading states</li>
                <li>Styled to match your design</li>
                <li>Added error handling</li>
                <li>Tested on mobile</li>
              </ul>
            </div>

            <!-- Testing Section -->
            <div class="section">
              <h2>🧪 Test Your Integration</h2>
              <div class="info-box">
                <strong>Use the test page:</strong> Go to 
                <a href="/admin/plugins/ai-search/test" target="_blank">AI Search Test Page</a>
                to verify your backend is working correctly before integrating with your frontend.
              </div>
            </div>
          </div>
        </div>

        <script>
          function showTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(el => {
              el.classList.remove('active');
            });
            document.querySelectorAll('.tab').forEach(el => {
              el.classList.remove('active');
            });
            
            // Show selected tab
            document.getElementById(tabName).classList.add('active');
            event.target.classList.add('active');
          }

          function copyCode(elementId) {
            const code = document.getElementById(elementId).textContent;
            navigator.clipboard.writeText(code).then(() => {
              const btn = event.target;
              const originalText = btn.textContent;
              btn.textContent = '✓ Copied!';
              setTimeout(() => {
                btn.textContent = originalText;
              }, 2000);
            });
          }
        </script>
      </body>
    </html>
  `)
})

export default integrationGuideRoutes
