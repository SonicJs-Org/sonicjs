/**
 * Admin Search Dashboard — Benchmark Tab
 *
 * BEIR benchmark dataset selector, seed/index/evaluate controls,
 * and results comparison table.
 */

export function renderBenchmarkTab(): string {
  return `
      <div id="tab-benchmark" class="tab-panel hidden">
        <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
          <h2 class="text-xl font-semibold text-zinc-950 dark:text-white mb-2">Search Benchmark</h2>
          <p class="text-sm text-zinc-600 dark:text-zinc-400 mb-4" id="bench-description">
            BEIR benchmark datasets with ground-truth relevance judgments.
            Seed the data, index it, then evaluate search quality with standard IR metrics (nDCG@10, Precision, Recall, MRR).
          </p>

          <!-- Dataset Selector -->
          <div class="flex flex-wrap items-center gap-3 mb-4">
            <div class="flex items-center gap-2">
              <label for="bench-dataset" class="text-sm font-medium text-zinc-700 dark:text-zinc-300">Dataset:</label>
              <select id="bench-dataset" onchange="switchBenchmarkDataset()"
                class="rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-300 dark:ring-zinc-600 focus:ring-2 focus:ring-indigo-500">
                <option value="scifact">SciFact (5,183 docs, scientific)</option>
                <option value="nfcorpus">NFCorpus (3,633 docs, biomedical)</option>
                <option value="fiqa">FiQA-2018 (57,638 docs, financial Q&amp;A)</option>
              </select>
            </div>
            <span id="bench-data-badge" class="hidden text-xs px-2 py-0.5 rounded-full bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-400">
              Data not uploaded to KV
            </span>
          </div>

          <div id="benchmark-status" class="text-sm text-zinc-500 dark:text-zinc-400 mb-4">Checking benchmark status...</div>

          <!-- Corpus Size + Seed Row -->
          <div class="flex flex-wrap items-center gap-3 mb-4">
            <div class="flex items-center gap-2">
              <label for="bench-corpus-size" class="text-sm font-medium text-zinc-700 dark:text-zinc-300">Corpus:</label>
              <select id="bench-corpus-size" onchange="updateBenchmarkStatusText()"
                class="rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-300 dark:ring-zinc-600 focus:ring-2 focus:ring-indigo-500">
                <option value="subset">Subset</option>
                <option value="full">Full corpus</option>
              </select>
            </div>
            <button onclick="seedBenchmark()" id="bench-seed-btn"
              class="px-4 py-2 text-sm font-medium text-white bg-green-600 hover:bg-green-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed">
              Seed Data
            </button>
            <button onclick="indexBenchmark()" id="bench-index-btn"
              class="px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed" disabled>
              Index (FTS5)
            </button>
            <button onclick="indexBenchmarkVectorize()" id="bench-vectorize-btn"
              class="px-4 py-2 text-sm font-medium text-white bg-cyan-600 hover:bg-cyan-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed" disabled>
              Index (Vectorize)
            </button>
            <button onclick="purgeBenchmark()" id="bench-purge-btn"
              class="px-4 py-2 text-sm font-medium text-white bg-red-600 hover:bg-red-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed" disabled>
              Purge Data
            </button>
          </div>

          <!-- Evaluate Buttons Row -->
          <div class="flex flex-wrap items-center gap-3 mb-4">
            <span class="text-sm font-medium text-zinc-700 dark:text-zinc-300">Evaluate:</span>
            <div class="flex items-center gap-2">
              <label for="bench-query-count" class="text-sm text-zinc-600 dark:text-zinc-400">Queries:</label>
              <select id="bench-query-count"
                class="rounded-lg bg-white dark:bg-zinc-800 px-2 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-300 dark:ring-zinc-600 focus:ring-2 focus:ring-indigo-500">
                <option value="15">15</option>
                <option value="50">50</option>
                <option value="100">100</option>
                <option value="0" selected>All</option>
              </select>
            </div>
            <button onclick="runBenchmark('fts5')" id="bench-fts5-btn"
              class="px-4 py-2 text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed" disabled>
              FTS5
            </button>
            <button onclick="runBenchmark('keyword')" id="bench-keyword-btn"
              class="px-4 py-2 text-sm font-medium text-white bg-zinc-600 hover:bg-zinc-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed" disabled>
              Keyword
            </button>
            <button onclick="runBenchmark('hybrid')" id="bench-hybrid-btn"
              class="px-4 py-2 text-sm font-medium text-white bg-purple-600 hover:bg-purple-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed" disabled>
              Hybrid
            </button>
            <button onclick="runBenchmark('ai')" id="bench-ai-btn"
              class="px-4 py-2 text-sm font-medium text-white bg-cyan-600 hover:bg-cyan-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed" disabled>
              AI (Vectorize)
            </button>
          </div>
          <p class="text-xs text-zinc-400 dark:text-zinc-500 mb-4">
            Hybrid and AI modes require Vectorize index binding. If unavailable, they will return an error.
          </p>

          <div id="benchmark-progress" class="hidden mb-4">
            <div class="text-sm text-zinc-600 dark:text-zinc-400 mb-1" id="benchmark-progress-text">Running...</div>
            <div class="w-full bg-zinc-200 dark:bg-zinc-700 rounded-full h-2">
              <div id="benchmark-progress-bar" class="bg-indigo-600 h-2 rounded-full transition-all duration-300" style="width: 0%"></div>
            </div>
          </div>
          <div id="benchmark-results" class="hidden">
            <div class="space-y-6">
              <h3 class="text-lg font-semibold text-zinc-950 dark:text-white" id="benchmark-results-title">Results</h3>
              <div id="benchmark-metrics"></div>
              <div class="text-xs text-zinc-500 dark:text-zinc-400" id="benchmark-details"></div>
            </div>
          </div>
        </div>
      </div>
  `
}

export function renderBenchmarkScript(): string {
  return `
      // =============================================
      // Benchmark Functions
      // =============================================

      var benchDescriptions = {
        scifact: 'BEIR SciFact — scientific abstracts with 300+ test queries and ground-truth relevance judgments.',
        nfcorpus: 'BEIR NFCorpus — biomedical IR from NutritionFacts with 323 queries and rich multi-level relevance (38 qrels/query).',
        fiqa: 'BEIR FiQA-2018 — financial opinion Q&A from StackExchange/Reddit with 648 test queries.'
      };

      function getBenchDataset() {
        return document.getElementById('bench-dataset').value;
      }

      async function switchBenchmarkDataset() {
        var dataset = getBenchDataset();
        // Update description
        document.getElementById('bench-description').textContent = benchDescriptions[dataset] ||
          'BEIR benchmark dataset. Seed, index, then evaluate with IR metrics.';
        // Reset UI
        document.getElementById('benchmark-status').textContent = 'Checking benchmark status...';
        document.getElementById('benchmark-results').classList.add('hidden');
        ['seed','index','vectorize','fts5','keyword','hybrid','ai','purge'].forEach(function(id) {
          var btn = document.getElementById('bench-' + id + '-btn');
          if (btn) btn.disabled = true;
        });
        document.getElementById('bench-seed-btn').disabled = false;
        document.getElementById('bench-seed-btn').textContent = 'Seed Data';
        document.getElementById('bench-data-badge').classList.add('hidden');
        await checkBenchmarkStatus(dataset);
        // Re-render saved results (filtered to selected dataset)
        renderAllBenchmarkRuns();
      }

      // Check benchmark status on page load
      // Cached status data for reactive UI updates
      var _lastBenchStatus = null;

      function updateBenchmarkStatusText() {
        var d = _lastBenchStatus;
        if (!d) return;
        var statusEl = document.getElementById('benchmark-status');
        var corpusSelect = document.getElementById('bench-corpus-size');
        var evalCount = d.evaluable_queries || d.query_count;
        var selectedSize = corpusSelect.value;

        if (d.seeded) {
          // Determine expected doc count for the selected corpus option
          var expectedCount = selectedSize === 'full' ? d.corpus_size : d.subset_size;
          if (expectedCount && d.seeded_count !== expectedCount) {
            statusEl.textContent = 'Seeded: ' + d.seeded_count.toLocaleString() + ' docs — selected: ' +
              corpusSelect.options[corpusSelect.selectedIndex].textContent +
              '. Click "Re-seed Data" to update.';
          } else {
            statusEl.textContent = 'Benchmark data seeded: ' + d.seeded_count.toLocaleString() + ' documents (' + evalCount + ' evaluable queries)';
          }
        } else {
          statusEl.textContent = 'Dataset: ' + d.dataset + ' (' + d.corpus_size.toLocaleString() + ' docs, ' + evalCount + ' evaluable queries) — Not yet seeded';
        }
      }

      async function checkBenchmarkStatus(dataset) {
        if (!dataset) dataset = getBenchDataset();
        try {
          var res = await fetch('/admin/plugins/ai-search/api/benchmark/status?dataset=' + dataset);
          if (res.ok) {
            var body = await res.json();
            var d = body.data;
            _lastBenchStatus = d;
            var statusEl = document.getElementById('benchmark-status');
            var corpusSelect = document.getElementById('bench-corpus-size');
            var dataBadge = document.getElementById('bench-data-badge');

            // Show/hide KV data badge
            if (d.data_available) {
              dataBadge.classList.add('hidden');
            } else {
              dataBadge.classList.remove('hidden');
              statusEl.textContent = 'Dataset data not uploaded to KV. Run: npx tsx scripts/generate-benchmark-data.ts --dataset ' + dataset;
              return;
            }

            // Update corpus size options with actual counts
            if (d.subset_size && d.corpus_size) {
              corpusSelect.options[0].textContent = 'Subset (' + d.subset_size.toLocaleString() + ' docs)';
              corpusSelect.options[1].textContent = 'Full corpus (' + d.corpus_size.toLocaleString() + ' docs)';
            } else if (d.corpus_size) {
              corpusSelect.options[1].textContent = 'Full corpus (' + d.corpus_size.toLocaleString() + ' docs)';
            }

            // Auto-select the corpus option matching what's currently seeded
            if (d.seeded && d.subset_size && d.seeded_count <= d.subset_size) {
              corpusSelect.value = 'subset';
            } else if (d.seeded) {
              corpusSelect.value = 'full';
            }

            // Update Queries dropdown "All" option with actual evaluable count
            var querySelect = document.getElementById('bench-query-count');
            var evalCount = d.evaluable_queries || d.query_count;
            var allOption = querySelect.options[querySelect.options.length - 1];
            allOption.textContent = 'All (' + evalCount.toLocaleString() + ')';

            if (d.seeded) {
              document.getElementById('bench-seed-btn').textContent = 'Re-seed Data';
              document.getElementById('bench-index-btn').disabled = false;
              document.getElementById('bench-vectorize-btn').disabled = false;
              document.getElementById('bench-fts5-btn').disabled = false;
              document.getElementById('bench-keyword-btn').disabled = false;
              document.getElementById('bench-hybrid-btn').disabled = false;
              document.getElementById('bench-ai-btn').disabled = false;
              document.getElementById('bench-purge-btn').disabled = false;
            }

            // Set status text (uses cached _lastBenchStatus)
            updateBenchmarkStatusText();
          }
        } catch (e) {
          document.getElementById('benchmark-status').textContent = 'Could not check benchmark status: ' + e.message;
        }
      }
      checkBenchmarkStatus();

      async function seedBenchmark() {
        var btn = document.getElementById('bench-seed-btn');
        var corpusSize = document.getElementById('bench-corpus-size').value;
        var dataset = getBenchDataset();
        btn.textContent = 'Seeding (' + corpusSize + ')...';
        btn.disabled = true;
        try {
          var res = await fetch('/admin/plugins/ai-search/api/benchmark/seed', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ corpus_size: corpusSize, dataset: dataset })
          });
          var data = await res.json();
          if (data.success) {
            document.getElementById('benchmark-status').textContent = data.message;
            btn.textContent = 'Re-seed Data';
            document.getElementById('bench-index-btn').disabled = false;
            document.getElementById('bench-vectorize-btn').disabled = false;
            document.getElementById('bench-fts5-btn').disabled = false;
            document.getElementById('bench-keyword-btn').disabled = false;
            document.getElementById('bench-hybrid-btn').disabled = false;
            document.getElementById('bench-ai-btn').disabled = false;
            document.getElementById('bench-purge-btn').disabled = false;
          } else {
            alert('Seed failed: ' + (data.error || 'Unknown error'));
            btn.textContent = 'Seed Data';
          }
        } catch (e) {
          alert('Error: ' + e.message);
          btn.textContent = 'Seed Data';
        }
        btn.disabled = false;
      }

      async function indexBenchmark() {
        var btn = document.getElementById('bench-index-btn');
        btn.disabled = true;
        var statusEl = document.getElementById('benchmark-status');
        var dataset = getBenchDataset();

        var totalIndexed = 0;
        var remaining = 1;
        var batchNum = 0;

        while (remaining > 0) {
          batchNum++;
          btn.textContent = 'Indexing batch ' + batchNum + '...';
          try {
            var res = await fetch('/admin/plugins/ai-search/api/benchmark/index-fts5-batch', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ batch_size: 200, dataset: dataset })
            });
            var data = await res.json();
            if (!data.success) {
              alert('FTS5 indexing failed: ' + (data.error || 'Unknown error'));
              break;
            }
            totalIndexed += data.indexed;
            remaining = data.remaining;
            var done = data.total - remaining;
            statusEl.textContent = 'FTS5 indexing: ' + done + '/' + data.total + ' docs indexed...';
            btn.textContent = 'Indexing... (' + done + '/' + data.total + ')';
          } catch (e) {
            alert('FTS5 indexing error: ' + e.message);
            break;
          }
        }

        statusEl.textContent = 'FTS5 indexing complete: ' + totalIndexed + ' docs indexed in ' + batchNum + ' batches.';
        btn.textContent = 'Index (FTS5)';
        btn.disabled = false;
      }

      async function indexBenchmarkVectorize() {
        var btn = document.getElementById('bench-vectorize-btn');
        btn.disabled = true;
        var statusEl = document.getElementById('benchmark-status');
        var dataset = getBenchDataset();

        // Reset index meta first
        try {
          await fetch('/admin/plugins/ai-search/api/benchmark/index-vectorize', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ dataset: dataset })
          });
        } catch (e) { /* continue anyway */ }

        var offset = 0;
        var remaining = 1;
        var batchNum = 0;
        var totalChunks = 0;

        while (remaining > 0) {
          batchNum++;
          btn.textContent = 'Embedding batch ' + batchNum + '...';
          try {
            var res = await fetch('/admin/plugins/ai-search/api/benchmark/index-vectorize-batch', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ batch_size: 25, offset: offset, dataset: dataset })
            });
            var data = await res.json();
            if (!data.success) {
              alert('Vectorize indexing failed: ' + (data.error || 'Unknown error'));
              break;
            }
            totalChunks += data.indexed;
            offset = data.offset;
            remaining = data.remaining;
            var done = data.total - remaining;
            statusEl.textContent = 'Vectorize: ' + done + '/' + data.total + ' docs embedded (' + totalChunks + ' chunks)...';
            btn.textContent = 'Embedding... (' + done + '/' + data.total + ')';
          } catch (e) {
            alert('Vectorize indexing error: ' + e.message);
            break;
          }
        }

        statusEl.textContent = 'Vectorize indexing complete: ' + totalChunks + ' chunks indexed in ' + batchNum + ' batches.';
        btn.textContent = 'Index (Vectorize)';
        btn.disabled = false;
      }

      async function runBenchmark(mode) {
        var btn = document.getElementById('bench-' + mode + '-btn');
        var origText = btn.textContent;
        btn.textContent = 'Running...';
        btn.disabled = true;

        var progressDiv = document.getElementById('benchmark-progress');
        var progressText = document.getElementById('benchmark-progress-text');
        var progressBar = document.getElementById('benchmark-progress-bar');
        progressDiv.classList.remove('hidden');
        progressBar.style.width = '2%';

        var maxQueries = parseInt(document.getElementById('bench-query-count').value, 10);
        var dataset = getBenchDataset();
        var BATCH_SIZE = 15;
        var startTime = Date.now();

        try {
          // Step 1: Get evaluable query IDs
          progressText.textContent = 'Fetching query list...';
          var idsRes = await fetch('/admin/plugins/ai-search/api/benchmark/query-ids?max_queries=' + maxQueries + '&dataset=' + dataset);
          var idsData = await idsRes.json();
          if (!idsData.success) {
            alert('Failed to get query IDs: ' + (idsData.error || 'Unknown error'));
            progressDiv.classList.add('hidden');
            btn.textContent = origText;
            btn.disabled = false;
            return;
          }

          var allQueryIds = idsData.query_ids;
          var totalQueries = allQueryIds.length;
          progressText.textContent = 'Evaluating ' + mode + ' mode: 0/' + totalQueries + ' queries...';

          // Step 2: Process in batches
          var allPerQuery = [];
          for (var i = 0; i < totalQueries; i += BATCH_SIZE) {
            var batchIds = allQueryIds.slice(i, i + BATCH_SIZE);
            var batchRes = await fetch('/admin/plugins/ai-search/api/benchmark/evaluate-batch', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ mode: mode, limit: 10, query_ids: batchIds, dataset: dataset })
            });
            var batchData = await batchRes.json();

            if (!batchData.success) {
              alert('Batch evaluation failed: ' + (batchData.error || 'Unknown error'));
              break;
            }

            allPerQuery = allPerQuery.concat(batchData.per_query);
            var done = Math.min(i + BATCH_SIZE, totalQueries);
            var pct = Math.round((done / totalQueries) * 100);
            progressBar.style.width = pct + '%';
            progressText.textContent = 'Evaluating ' + mode + ' mode: ' + done + '/' + totalQueries + ' queries...';
          }

          // Step 3: Compute aggregate metrics client-side
          var totalTime = Date.now() - startTime;
          var n = allPerQuery.length;
          if (n > 0) {
            var sumNDCG = 0, sumPrec = 0, sumRecall = 0, sumMRR = 0;
            for (var j = 0; j < n; j++) {
              sumNDCG += allPerQuery[j].ndcg;
              sumPrec += allPerQuery[j].precision;
              sumRecall += allPerQuery[j].recall;
              sumMRR += allPerQuery[j].mrr;
            }
            var data = {
              success: true,
              mode: mode,
              limit: 10,
              queries_evaluated: n,
              total_time_ms: totalTime,
              avg_query_time_ms: Math.round(totalTime / n),
              metrics: {
                ndcg_at_k: sumNDCG / n,
                precision_at_k: sumPrec / n,
                recall_at_k: sumRecall / n,
                mrr: sumMRR / n
              },
              per_query: allPerQuery
            };
            progressBar.style.width = '100%';
            showBenchmarkResults(data, mode);
          } else {
            alert('No queries were evaluated.');
          }
        } catch (e) {
          alert('Error: ' + e.message);
        }

        progressDiv.classList.add('hidden');
        btn.textContent = origText;
        btn.disabled = false;
      }

      // Persist benchmark results in localStorage across page refreshes
      var BENCH_STORAGE_KEY = 'sonicjs_benchmark_runs';

      function loadBenchmarkRuns() {
        try {
          var stored = localStorage.getItem(BENCH_STORAGE_KEY);
          return stored ? JSON.parse(stored) : [];
        } catch (e) { return []; }
      }

      function saveBenchmarkRuns(runs) {
        try { localStorage.setItem(BENCH_STORAGE_KEY, JSON.stringify(runs)); } catch (e) { /* ignore */ }
      }

      var benchmarkRuns = loadBenchmarkRuns();
      var benchmarkHistory = [];

      // Restore and render saved results on page load
      if (benchmarkRuns.length > 0) {
        renderAllBenchmarkRuns();
      }

      function showBenchmarkResults(data, mode) {
        var resultsDiv = document.getElementById('benchmark-results');
        var dataset = getBenchDataset();

        // Store in current session history
        benchmarkHistory = benchmarkHistory.filter(function(h) { return h.mode !== mode || h.dataset !== dataset; });
        benchmarkHistory.push({ mode: mode, dataset: dataset, data: data });

        // Also persist to localStorage with dataset + corpus label
        var corpusLabel = document.getElementById('bench-corpus-size').value;
        var runKey = dataset + '_' + corpusLabel + '_' + mode;
        var runEntry = {
          key: runKey,
          mode: mode,
          dataset: dataset,
          corpus: corpusLabel,
          corpus_size: data.corpus_size,
          metrics: data.metrics,
          limit: data.limit,
          queries_evaluated: data.queries_evaluated,
          total_time_ms: data.total_time_ms,
          avg_query_time_ms: data.avg_query_time_ms,
          timestamp: new Date().toISOString()
        };
        benchmarkRuns = benchmarkRuns.filter(function(r) { return r.key !== runKey; });
        benchmarkRuns.push(runEntry);
        saveBenchmarkRuns(benchmarkRuns);

        renderAllBenchmarkRuns();
        resultsDiv.classList.remove('hidden');
      }

      function renderAllBenchmarkRuns() {
        var resultsDiv = document.getElementById('benchmark-results');
        var titleEl = document.getElementById('benchmark-results-title');
        var metricsDiv = document.getElementById('benchmark-metrics');
        var detailsDiv = document.getElementById('benchmark-details');

        if (benchmarkRuns.length === 0) {
          resultsDiv.classList.add('hidden');
          return;
        }

        var datasetNames = { scifact: 'SciFact', nfcorpus: 'NFCorpus', fiqa: 'FiQA-2018' };
        var datasetDomains = { scifact: 'Scientific claims', nfcorpus: 'Biomedical', fiqa: 'Financial Q&A' };
        var modeOrder = ['fts5', 'hybrid', 'ai', 'keyword'];
        var modeLabels = { fts5: 'FTS5', keyword: 'Keyword', hybrid: 'Hybrid', ai: 'AI/Vectorize' };
        var modeBgClasses = {
          fts5: 'bg-indigo-50 dark:bg-indigo-500/10 text-indigo-700 dark:text-indigo-300 ring-1 ring-inset ring-indigo-600/20 dark:ring-indigo-500/20',
          ai: 'bg-cyan-50 dark:bg-cyan-500/10 text-cyan-700 dark:text-cyan-300 ring-1 ring-inset ring-cyan-600/20 dark:ring-cyan-500/20',
          hybrid: 'bg-purple-50 dark:bg-purple-500/10 text-purple-700 dark:text-purple-300 ring-1 ring-inset ring-purple-600/20 dark:ring-purple-500/20',
          keyword: 'bg-zinc-100 dark:bg-zinc-700/50 text-zinc-700 dark:text-zinc-300 ring-1 ring-inset ring-zinc-600/20 dark:ring-zinc-500/20'
        };

        titleEl.textContent = 'Benchmark Results (k=10)';

        // Group by dataset -> corpus -> mode
        var byDataset = {};
        var datasetOrder = ['scifact', 'nfcorpus', 'fiqa'];
        for (var i = 0; i < benchmarkRuns.length; i++) {
          var r = benchmarkRuns[i];
          var ds = r.dataset || 'scifact';
          if (!byDataset[ds]) byDataset[ds] = {};
          var corpus = r.corpus || 'subset';
          if (!byDataset[ds][corpus]) byDataset[ds][corpus] = [];
          byDataset[ds][corpus].push(r);
        }

        // Find best value per metric per dataset+corpus group
        function findBests(runs) {
          var bests = { ndcg: -1, precision: -1, recall: -1, mrr: -1 };
          for (var i = 0; i < runs.length; i++) {
            var m = runs[i].metrics;
            if (m.ndcg_at_k > bests.ndcg) bests.ndcg = m.ndcg_at_k;
            if (m.precision_at_k > bests.precision) bests.precision = m.precision_at_k;
            if (m.recall_at_k > bests.recall) bests.recall = m.recall_at_k;
            if (m.mrr > bests.mrr) bests.mrr = m.mrr;
          }
          return bests;
        }

        var html = '';
        for (var di = 0; di < datasetOrder.length; di++) {
          var dsKey = datasetOrder[di];
          if (!byDataset[dsKey]) continue;
          var corpusGroups = byDataset[dsKey];
          var corpusKeys = Object.keys(corpusGroups).sort();

          for (var ci = 0; ci < corpusKeys.length; ci++) {
            var corpusKey = corpusKeys[ci];
            var runs = corpusGroups[corpusKey];
            runs.sort(function(a, b) { return modeOrder.indexOf(a.mode) - modeOrder.indexOf(b.mode); });
            var sizeLabel = runs[0].corpus_size ? runs[0].corpus_size.toLocaleString() + ' docs' : '';
            var corpusDisplay = corpusKey === 'full' ? 'Full corpus' : 'Subset';
            if (sizeLabel) corpusDisplay += ' \\u00b7 ' + sizeLabel;
            var bests = findBests(runs);

            // Card wrapper per dataset+corpus
            html += '<div class="rounded-xl bg-white dark:bg-zinc-900 ring-1 ring-zinc-950/5 dark:ring-white/10 overflow-hidden">';

            // Card header
            html += '<div class="px-5 py-3 bg-zinc-50 dark:bg-zinc-800/50 border-b border-zinc-200 dark:border-zinc-700">' +
              '<div class="flex items-center justify-between">' +
                '<div class="flex items-center gap-3">' +
                  '<h4 class="text-base font-semibold text-zinc-950 dark:text-white">' + (datasetNames[dsKey] || dsKey) + '</h4>' +
                  '<span class="text-xs text-zinc-500 dark:text-zinc-400">' + (datasetDomains[dsKey] || '') + '</span>' +
                '</div>' +
                '<span class="text-xs px-2.5 py-1 rounded-full bg-zinc-100 dark:bg-zinc-700 text-zinc-600 dark:text-zinc-300 font-medium">' + corpusDisplay + '</span>' +
              '</div>' +
            '</div>';

            // Table
            html += '<div class="overflow-x-auto">' +
              '<table class="w-full text-sm">' +
              '<thead><tr class="border-b border-zinc-200 dark:border-zinc-700">' +
              '<th class="text-left px-5 py-3 text-xs font-semibold uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Mode</th>' +
              '<th class="text-right px-4 py-3 text-xs font-semibold uppercase tracking-wider text-zinc-400 dark:text-zinc-500">nDCG@10</th>' +
              '<th class="text-right px-4 py-3 text-xs font-semibold uppercase tracking-wider text-zinc-400 dark:text-zinc-500">P@10</th>' +
              '<th class="text-right px-4 py-3 text-xs font-semibold uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Recall@10</th>' +
              '<th class="text-right px-4 py-3 text-xs font-semibold uppercase tracking-wider text-zinc-400 dark:text-zinc-500">MRR</th>' +
              '<th class="text-right px-4 py-3 text-xs font-semibold uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Queries</th>' +
              '<th class="text-right px-5 py-3 text-xs font-semibold uppercase tracking-wider text-zinc-400 dark:text-zinc-500">Latency</th>' +
              '</tr></thead><tbody>';

            for (var ri = 0; ri < runs.length; ri++) {
              var run = runs[ri];
              var m = run.metrics;
              var isLast = ri === runs.length - 1;
              var rowBorder = isLast ? '' : ' border-b border-zinc-100 dark:border-zinc-800';

              // Highlight best values
              var ndcgBest = m.ndcg_at_k === bests.ndcg && runs.length > 1;
              var precBest = m.precision_at_k === bests.precision && runs.length > 1;
              var recBest = m.recall_at_k === bests.recall && runs.length > 1;
              var mrrBest = m.mrr === bests.mrr && runs.length > 1;

              function metricCell(val, isBest) {
                var pct = (val * 100).toFixed(1) + '%';
                if (isBest) {
                  return '<span class="font-semibold text-zinc-950 dark:text-white">' + pct + '</span>';
                }
                return '<span class="text-zinc-600 dark:text-zinc-400">' + pct + '</span>';
              }

              html += '<tr class="' + rowBorder + ' hover:bg-zinc-50 dark:hover:bg-zinc-800/30 transition-colors">' +
                '<td class="px-5 py-3"><span class="inline-flex items-center rounded-md px-2.5 py-1 text-xs font-semibold ' + (modeBgClasses[run.mode] || modeBgClasses.keyword) + '">' + (modeLabels[run.mode] || run.mode) + '</span></td>' +
                '<td class="px-4 py-3 text-right font-mono text-sm">' + metricCell(m.ndcg_at_k, ndcgBest) + '</td>' +
                '<td class="px-4 py-3 text-right font-mono text-sm">' + metricCell(m.precision_at_k, precBest) + '</td>' +
                '<td class="px-4 py-3 text-right font-mono text-sm">' + metricCell(m.recall_at_k, recBest) + '</td>' +
                '<td class="px-4 py-3 text-right font-mono text-sm">' + metricCell(m.mrr, mrrBest) + '</td>' +
                '<td class="px-4 py-3 text-right text-xs text-zinc-500 dark:text-zinc-400">' + run.queries_evaluated + '</td>' +
                '<td class="px-5 py-3 text-right text-xs text-zinc-500 dark:text-zinc-400">' + run.avg_query_time_ms + 'ms</td>' +
              '</tr>';
            }

            html += '</tbody></table></div></div>';
          }
        }

        // Summary + clear button
        html += '<div class="flex items-center justify-between pt-2">' +
          '<span class="text-xs text-zinc-400 dark:text-zinc-500">' + benchmarkRuns.length + ' runs across ' + Object.keys(byDataset).length + ' dataset' + (Object.keys(byDataset).length !== 1 ? 's' : '') + '</span>' +
          '<button onclick="clearBenchmarkHistory()" class="text-xs text-zinc-400 hover:text-red-500 dark:hover:text-red-400 transition-colors">Clear all results</button>' +
          '</div>';

        metricsDiv.innerHTML = html;
        detailsDiv.textContent = '';
        resultsDiv.classList.remove('hidden');
      }

      function getRelativeTime(date) {
        var now = new Date();
        var diff = Math.floor((now - date) / 1000);
        if (diff < 60) return 'just now';
        if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
        if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
        return Math.floor(diff / 86400) + 'd ago';
      }

      function clearBenchmarkHistory() {
        if (!confirm('Clear all saved benchmark results?')) return;
        benchmarkRuns = [];
        benchmarkHistory = [];
        saveBenchmarkRuns([]);
        document.getElementById('benchmark-results').classList.add('hidden');
      }

      async function purgeBenchmark() {
        var dataset = getBenchDataset();
        if (!confirm('Remove all ' + dataset + ' benchmark data? This will delete benchmark documents and index entries.')) return;
        var btn = document.getElementById('bench-purge-btn');
        btn.textContent = 'Purging...';
        btn.disabled = true;
        try {
          var res = await fetch('/admin/plugins/ai-search/api/benchmark/purge', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ dataset: dataset })
          });
          var data = await res.json();
          if (data.success) {
            document.getElementById('benchmark-status').textContent = data.message + '. Benchmark data removed.';
            document.getElementById('benchmark-results').classList.add('hidden');
            benchmarkHistory = benchmarkHistory.filter(function(h) { return h.dataset !== dataset; });
            document.getElementById('bench-seed-btn').textContent = 'Seed Data';
            document.getElementById('bench-index-btn').disabled = true;
            document.getElementById('bench-vectorize-btn').disabled = true;
            document.getElementById('bench-fts5-btn').disabled = true;
            document.getElementById('bench-keyword-btn').disabled = true;
            document.getElementById('bench-hybrid-btn').disabled = true;
            document.getElementById('bench-ai-btn').disabled = true;
            document.getElementById('bench-purge-btn').disabled = true;
          } else {
            alert('Purge failed: ' + (data.error || 'Unknown error'));
          }
        } catch (e) {
          alert('Error: ' + e.message);
        }
        btn.textContent = 'Purge Data';
        btn.disabled = false;
      }
  `
}
