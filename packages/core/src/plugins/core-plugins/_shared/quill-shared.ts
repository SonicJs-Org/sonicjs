/**
 * Shared Quill Enhancement Utilities
 *
 * Provides the common CSS, picker dropdown, Quill constructor proxy, and
 * helper functions used by both the Global Variables and Shortcodes plugins
 * for their Quill editor integrations.
 *
 * Each plugin calls getSharedQuillSetup() to get the shared <style> + <script>
 * block. At runtime, a `window.__sonicQuillShared` flag ensures these are only
 * initialized once even if both plugins inject their scripts.
 */

/**
 * Returns the shared CSS for blot chips, picker dropdown, and toolbar buttons.
 * Wrapped in a dedupe check so it's safe to include from both plugins.
 */
export function getSharedQuillStyles(): string {
  return `
    <style id="sonic-quill-shared-styles">
      /* Variable chip styles */
      .ql-variable-blot {
        display: inline-flex;
        align-items: center;
        gap: 3px;
        background: rgba(59, 130, 246, 0.15);
        border: 1px solid rgba(59, 130, 246, 0.3);
        border-radius: 4px;
        padding: 1px 6px;
        font-family: ui-monospace, monospace;
        font-size: 0.85em;
        color: #60a5fa;
        cursor: default;
        user-select: all;
        vertical-align: baseline;
        line-height: 1.4;
      }
      .ql-variable-blot::before { content: '{'; opacity: 0.5; }
      .ql-variable-blot::after { content: '}'; opacity: 0.5; }

      /* Shortcode chip styles */
      .ql-shortcode-blot {
        display: inline-flex;
        align-items: center;
        gap: 3px;
        background: rgba(168, 85, 247, 0.15);
        border: 1px solid rgba(168, 85, 247, 0.3);
        border-radius: 4px;
        padding: 1px 6px;
        font-family: ui-monospace, monospace;
        font-size: 0.85em;
        color: #c084fc;
        cursor: default;
        user-select: all;
        vertical-align: baseline;
        line-height: 1.4;
      }
      .ql-shortcode-blot::before { content: '[['; opacity: 0.5; }
      .ql-shortcode-blot::after { content: ']]'; opacity: 0.5; }

      /* Picker dropdown styles */
      .sonic-picker-dropdown {
        position: fixed;
        z-index: 10000;
        background: #18181b;
        border: 1px solid #3f3f46;
        border-radius: 8px;
        box-shadow: 0 20px 25px -5px rgba(0,0,0,0.5);
        min-width: 280px;
        max-height: 360px;
        overflow: hidden;
        display: flex;
        flex-direction: column;
      }
      .sonic-picker-dropdown .picker-header {
        padding: 10px 12px;
        border-bottom: 1px solid #27272a;
        display: flex;
        align-items: center;
        gap: 8px;
      }
      .sonic-picker-dropdown .picker-header input {
        flex: 1;
        background: #09090b;
        border: 1px solid #3f3f46;
        border-radius: 6px;
        padding: 6px 10px;
        font-size: 13px;
        color: #e4e4e7;
        outline: none;
      }
      .sonic-picker-dropdown .picker-header input:focus { border-color: #3b82f6; }
      .sonic-picker-dropdown .picker-body {
        overflow-y: auto;
        max-height: 280px;
        padding: 4px;
      }
      .sonic-picker-dropdown .picker-category {
        padding: 6px 10px 2px;
        font-size: 10px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: #71717a;
      }
      .sonic-picker-dropdown .picker-item {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 7px 10px;
        border-radius: 6px;
        cursor: pointer;
        transition: background 0.1s;
      }
      .sonic-picker-dropdown .picker-item:hover { background: #27272a; }
      .sonic-picker-dropdown .picker-item .item-key {
        font-family: ui-monospace, monospace;
        font-size: 13px;
        font-weight: 500;
      }
      .sonic-picker-dropdown .picker-item .item-value {
        font-size: 12px;
        color: #71717a;
        max-width: 140px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .sonic-picker-dropdown .picker-empty {
        padding: 20px;
        text-align: center;
        color: #52525b;
        font-size: 13px;
      }

      /* Toolbar button styles */
      .ql-toolbar .ql-insertVariable,
      .ql-toolbar .ql-insertShortcode {
        width: auto !important;
        padding: 3px 8px !important;
        font-size: 12px !important;
        font-weight: 500 !important;
      }
    </style>`;
}

/**
 * Returns the shared JavaScript that sets up:
 * - Quill constructor Proxy (injects custom formats into the whitelist)
 * - Picker dropdown component (showPicker, closePicker)
 * - insertBlot helper
 * - enhanceQuillEditors polling framework
 *
 * Idempotent: checks window.__sonicQuillShared before running.
 * Each plugin adds its own blot registration + toolbar button AFTER this.
 */
export function getSharedQuillScript(): string {
  return `
    <script>
    (function() {
      // ─── Shared setup: only runs once even if both plugins inject ──────
      if (window.__sonicQuillShared) return;

      function waitForQuill(cb) {
        if (typeof Quill !== 'undefined') return cb();
        setTimeout(function() { waitForQuill(cb); }, 50);
      }

      waitForQuill(function() {
        // ─── Patch Quill constructor to allow custom blots ─────────
        var OrigQuill = Quill;
        var handler = {
          construct: function(target, args) {
            if (args[1] && args[1].formats && Array.isArray(args[1].formats)) {
              if (!args[1].formats.includes('variable')) args[1].formats.push('variable');
              if (!args[1].formats.includes('shortcode')) args[1].formats.push('shortcode');
            }
            return Reflect.construct(target, args);
          }
        };
        if (typeof Proxy !== 'undefined') {
          window.Quill = new Proxy(OrigQuill, handler);
          Object.keys(OrigQuill).forEach(function(key) {
            if (!(key in window.Quill)) window.Quill[key] = OrigQuill[key];
          });
          window.Quill.prototype = OrigQuill.prototype;
          window.Quill.import = OrigQuill.import.bind(OrigQuill);
          window.Quill.register = OrigQuill.register.bind(OrigQuill);
          window.Quill.find = OrigQuill.find.bind(OrigQuill);
          window.Quill.sources = OrigQuill.sources;
        }

        // ─── Picker Dropdown Component ─────────────────────────────
        var activePicker = null;

        function closePicker() {
          if (activePicker) { activePicker.remove(); activePicker = null; }
          document.removeEventListener('click', onDocClick);
        }

        function onDocClick(e) {
          if (activePicker && !activePicker.contains(e.target)) closePicker();
        }

        function showPicker(opts) {
          closePicker();
          var dropdown = document.createElement('div');
          dropdown.className = 'sonic-picker-dropdown';
          var rect = opts.button.getBoundingClientRect();
          dropdown.style.top = (rect.bottom + 4) + 'px';
          dropdown.style.left = rect.left + 'px';

          var header = document.createElement('div');
          header.className = 'picker-header';
          header.innerHTML = '<span style="font-size:14px">' + opts.icon + '</span>';
          var searchInput = document.createElement('input');
          searchInput.placeholder = 'Search ' + opts.label + '...';
          searchInput.type = 'text';
          header.appendChild(searchInput);
          dropdown.appendChild(header);

          var body = document.createElement('div');
          body.className = 'picker-body';
          dropdown.appendChild(body);

          document.body.appendChild(dropdown);
          activePicker = dropdown;
          searchInput.focus();

          var allItems = [];
          fetch(opts.apiUrl)
            .then(function(r) { return r.json(); })
            .then(function(json) {
              allItems = (json.data || []).filter(function(item) {
                return opts.filterActive ? item.is_active : true;
              });
              renderItems(allItems);
            })
            .catch(function() {
              body.innerHTML = '<div class="picker-empty">Failed to load</div>';
            });

          function renderItems(items) {
            body.innerHTML = '';
            if (items.length === 0) {
              body.innerHTML = '<div class="picker-empty">No items found</div>';
              return;
            }
            var groups = {};
            items.forEach(function(item) {
              var cat = item.category || 'general';
              if (!groups[cat]) groups[cat] = [];
              groups[cat].push(item);
            });
            Object.keys(groups).sort().forEach(function(cat) {
              var catDiv = document.createElement('div');
              catDiv.className = 'picker-category';
              catDiv.textContent = cat;
              body.appendChild(catDiv);
              groups[cat].forEach(function(item) {
                var itemDiv = document.createElement('div');
                itemDiv.className = 'picker-item';
                itemDiv.innerHTML = opts.renderItem(item);
                itemDiv.addEventListener('click', function() {
                  opts.onSelect(item);
                  closePicker();
                });
                body.appendChild(itemDiv);
              });
            });
          }

          searchInput.addEventListener('input', function() {
            var q = searchInput.value.toLowerCase();
            var filtered = allItems.filter(function(item) {
              return opts.getSearchText(item).toLowerCase().indexOf(q) !== -1;
            });
            renderItems(filtered);
          });

          setTimeout(function() { document.addEventListener('click', onDocClick); }, 10);
        }

        function insertBlot(q, position, type, value) {
          q.focus();
          q.insertEmbed(position, type, value, Quill.sources.USER);
          q.setSelection(position + 1, 0, Quill.sources.SILENT);
        }

        // Expose shared utilities for plugin-specific scripts
        window.__sonicQuillShared = {
          showPicker: showPicker,
          closePicker: closePicker,
          insertBlot: insertBlot,
          ready: true
        };

        console.log('[SonicJS] Shared Quill infrastructure initialized');
      });
    })();
    </script>`;
}

/**
 * Returns the polling script that enhances Quill editors with custom buttons.
 * Each plugin registers its own enhancer function on window.__sonicQuillEnhancers[],
 * and this shared poller runs them all.
 *
 * Idempotent: only one poller runs.
 */
export function getQuillEnhancerPollerScript(): string {
  return `
    <script>
    (function() {
      if (window.__sonicQuillPollerStarted) return;
      window.__sonicQuillPollerStarted = true;
      window.__sonicQuillEnhancers = window.__sonicQuillEnhancers || [];

      function runEnhancers() {
        var enhanced = 0;
        document.querySelectorAll('.quill-editor-container').forEach(function(container) {
          var editorDiv = container.querySelector('.quill-editor');
          if (!editorDiv || !editorDiv.quillInstance) return;
          if (container.dataset.sonicEnhanced === 'true') return;

          var quill = editorDiv.quillInstance;
          var toolbar = container.querySelector('.ql-toolbar');
          if (!toolbar) return;

          // Run all registered enhancers
          window.__sonicQuillEnhancers.forEach(function(fn) {
            try { fn(container, quill, toolbar); } catch(e) { console.error('[SonicJS] Enhancer error:', e); }
          });

          // Shared: serialize blots back to token syntax on text-change
          quill.on('text-change', function() {
            var fieldId = container.getAttribute('data-field-id');
            var hiddenInput = document.getElementById(fieldId);
            if (!hiddenInput) return;
            var html = quill.root.innerHTML;
            html = html.replace(/<span[^>]*class="ql-variable-blot"[^>]*data-variable-key="([^"]*)"[^>]*>[^<]*<\/span>/g,
              function(m, key) { return '{' + key + '}'; });
            html = html.replace(/<span[^>]*class="ql-shortcode-blot"[^>]*data-shortcode-name="([^"]*)"[^>]*(?:data-shortcode-params="([^"]*)")?[^>]*>[^<]*<\/span>/g,
              function(m, name, params) { return '[[' + name + (params ? ' ' + params : '') + ']]'; });
            hiddenInput.value = html;
          });

          // Shared: convert existing {key} and [[name]] tokens to blots
          var delta = quill.getContents();
          var newOps = [];
          var changed = false;
          delta.ops.forEach(function(op) {
            if (typeof op.insert !== 'string') { newOps.push(op); return; }
            var text = op.insert;
            var regex = /(\{([a-z0-9_]+)\})|(\[\[(\w+)([^\]]*?)\]\])/g;
            var lastIndex = 0;
            var m;
            while ((m = regex.exec(text)) !== null) {
              if (m.index > lastIndex) newOps.push({ insert: text.slice(lastIndex, m.index), attributes: op.attributes });
              if (m[1]) { newOps.push({ insert: { variable: { key: m[2] } } }); changed = true; }
              else if (m[3]) { newOps.push({ insert: { shortcode: { name: m[4], params: (m[5] || '').trim() } } }); changed = true; }
              lastIndex = m.index + m[0].length;
            }
            if (lastIndex < text.length) newOps.push({ insert: text.slice(lastIndex), attributes: op.attributes });
            else if (lastIndex === 0) newOps.push(op);
          });
          if (changed) quill.setContents({ ops: newOps }, Quill.sources.SILENT);

          container.dataset.sonicEnhanced = 'true';
          enhanced++;
        });
        return enhanced;
      }

      // Poll until Quill instances appear
      var attempts = 0;
      function pollAndEnhance() {
        attempts++;
        // Wait for shared infra
        if (!window.__sonicQuillShared || !window.__sonicQuillShared.ready) {
          if (attempts < 60) setTimeout(pollAndEnhance, 200);
          return;
        }
        var count = runEnhancers();
        if (count > 0) {
          console.log('[SonicJS] Enhanced ' + count + ' Quill editor(s)');
        } else if (attempts < 30) {
          setTimeout(pollAndEnhance, 200);
        }
      }
      pollAndEnhance();

      // Re-enhance after HTMX swaps
      if (typeof htmx !== 'undefined') {
        document.body.addEventListener('htmx:afterSwap', function() {
          setTimeout(runEnhancers, 500);
        });
      }
    })();
    </script>`;
}
