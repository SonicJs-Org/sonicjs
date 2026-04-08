/**
 * TinyMCE Integration — PluginManager Approach
 *
 * Each plugin registers via `tinymce.PluginManager.add()` which is the official
 * TinyMCE way to add buttons. The plugin is registered BEFORE `tinymce.init()`
 * is called, and TinyMCE invokes it during initialization.
 *
 * The server-side HTML replacement in index.ts already:
 * 1. Adds button names (sonicInsertVar, sonicInsertSC) to the toolbar config string
 * 2. Injects the script tags BEFORE the initializeTinyMCE call
 *
 * So by the time tinymce.init() runs, PluginManager already knows our plugins,
 * the toolbar string already references our button names, and the plugins array
 * includes our plugin names. All three are handled by server-side HTML replacement.
 *
 * Each plugin also registers chip CSS + token-to-chip conversion via SetContent/GetContent.
 */

/** Picker dropdown CSS (shared, safe to duplicate) */
export function getSharedTinyMceStyles(): string {
  return `<style id="sonic-tinymce-styles">
    .sonic-picker-dropdown{position:fixed;z-index:10000;background:#18181b;border:1px solid #3f3f46;border-radius:8px;box-shadow:0 20px 25px -5px rgba(0,0,0,.5);min-width:280px;max-height:360px;overflow:hidden;display:flex;flex-direction:column}
    .sonic-picker-dropdown .picker-header{padding:10px 12px;border-bottom:1px solid #27272a;display:flex;align-items:center;gap:8px}
    .sonic-picker-dropdown .picker-header input{flex:1;background:#09090b;border:1px solid #3f3f46;border-radius:6px;padding:6px 10px;font-size:13px;color:#e4e4e7;outline:none}
    .sonic-picker-dropdown .picker-header input:focus{border-color:#3b82f6}
    .sonic-picker-dropdown .picker-body{overflow-y:auto;max-height:280px;padding:4px}
    .sonic-picker-dropdown .picker-category{padding:6px 10px 2px;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:#71717a}
    .sonic-picker-dropdown .picker-item{display:flex;align-items:center;justify-content:space-between;padding:7px 10px;border-radius:6px;cursor:pointer;transition:background .1s}
    .sonic-picker-dropdown .picker-item:hover{background:#27272a}
    .sonic-picker-dropdown .picker-item .item-key{font-family:ui-monospace,monospace;font-size:13px;font-weight:500}
    .sonic-picker-dropdown .picker-item .item-value{font-size:12px;color:#71717a;max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    .sonic-picker-dropdown .picker-empty{padding:20px;text-align:center;color:#52525b;font-size:13px}
  </style>`;
}

/**
 * Returns a SELF-CONTAINED script that:
 * - Sets up the picker dropdown (idempotent)
 * - Registers a TinyMCE plugin via PluginManager.add() (the official way)
 * - The plugin registers the toolbar button + chip CSS + token↔chip conversion
 *
 * Server-side (index.ts) handles adding button names to the toolbar string
 * and plugin names to the plugins array. This script just needs to register
 * the plugin in PluginManager before tinymce.init() is called.
 */
export function getTinyMcePluginScript(opts: {
  buttonName: string
  buttonText: string
  buttonTooltip: string
  pickerIcon: string
  pickerLabel: string
  pickerApiUrl: string
  renderItemJs: string
  getSearchTextJs: string
  onSelectJs: string
}): string {
  const chipCSS = '.sonic-var-chip{display:inline;background:rgba(59,130,246,.15);border:1px solid rgba(59,130,246,.3);border-radius:4px;padding:1px 6px;font-family:ui-monospace,monospace;font-size:.85em;color:#60a5fa;cursor:default}.sonic-var-chip::before{content:\"{\";opacity:.5}.sonic-var-chip::after{content:\"}\";opacity:.5}.sonic-sc-chip{display:inline;background:rgba(168,85,247,.15);border:1px solid rgba(168,85,247,.3);border-radius:4px;padding:1px 6px;font-family:ui-monospace,monospace;font-size:.85em;color:#c084fc;cursor:default}.sonic-sc-chip::before{content:\"[[\";opacity:.5}.sonic-sc-chip::after{content:\"]]\";opacity:.5}';

  // Each button gets its own TinyMCE plugin name (e.g., "sonicInsertVar" -> "sonicInsertVar")
  // The plugin name matches the button name for simplicity.
  const pluginName = opts.buttonName;

  return `
  <script>
  (function() {
    // ═══ 1. Picker dropdown (idempotent) ═══
    if (!window.__sonicPicker) {
      var ap = null;
      function cp() { if (ap) { ap.remove(); ap = null; } document.removeEventListener('click', odc); }
      function odc(e) { if (ap && !ap.contains(e.target)) cp(); }
      window.__sonicPicker = function(opts) {
        cp();
        var dd = document.createElement('div'); dd.className = 'sonic-picker-dropdown';
        var tb = document.querySelector('.tox-toolbar__primary');
        if (tb) { var r = tb.getBoundingClientRect(); dd.style.top = (r.bottom+4)+'px'; dd.style.right = '20px'; }
        else { dd.style.top = '60px'; dd.style.right = '20px'; }
        var hd = document.createElement('div'); hd.className = 'picker-header';
        hd.innerHTML = '<span style="font-size:14px">'+opts.icon+'</span>';
        var si = document.createElement('input'); si.placeholder = 'Search '+opts.label+'...'; si.type = 'text';
        hd.appendChild(si); dd.appendChild(hd);
        var bd = document.createElement('div'); bd.className = 'picker-body'; dd.appendChild(bd);
        document.body.appendChild(dd); ap = dd; si.focus();
        var all = [];
        fetch(opts.apiUrl).then(function(r){return r.json()}).then(function(j){
          all = j.data || []; ri(all);
        }).catch(function(){bd.innerHTML='<div class="picker-empty">Failed to load</div>'});
        function ri(items) {
          bd.innerHTML = '';
          if (!items.length) { bd.innerHTML = '<div class="picker-empty">No items found</div>'; return; }
          var g = {};
          items.forEach(function(i){ var c=i.category||'general'; if(!g[c])g[c]=[]; g[c].push(i); });
          Object.keys(g).sort().forEach(function(c){
            var cd=document.createElement('div');cd.className='picker-category';cd.textContent=c;bd.appendChild(cd);
            g[c].forEach(function(i){
              var id=document.createElement('div');id.className='picker-item';
              id.innerHTML=opts.renderItem(i);
              id.addEventListener('click',function(){opts.onSelect(i);cp()});
              bd.appendChild(id);
            });
          });
        }
        si.addEventListener('input',function(){
          var q=si.value.toLowerCase();
          ri(all.filter(function(i){return opts.getSearchText(i).toLowerCase().indexOf(q)!==-1}));
        });
        setTimeout(function(){document.addEventListener('click',odc)},10);
      };
    }

    // ═══ 2. Track registered plugin names (for init wrapper) ═══
    window.__sonicTmcePlugins = window.__sonicTmcePlugins || [];
    // Keep these for diagnostics (the test checks them)
    window.__sonicTmceButtons = window.__sonicTmceButtons || [];
    window.__sonicTmceSetups = window.__sonicTmceSetups || [];

    // ═══ 3. Register TinyMCE plugin via PluginManager (the OFFICIAL way) ═══
    // This function waits for tinymce to be defined, then registers the plugin.
    // PluginManager.add() MUST happen before tinymce.init() — the server-side
    // injection places this script before the initializeTinyMCE call, so we
    // just need to wait for the CDN to load tinymce.
    function registerSonicPlugin() {
      if (typeof tinymce === 'undefined' || !tinymce.PluginManager) return false;
      if (tinymce.PluginManager.get('${pluginName}')) return true; // Already registered

      tinymce.PluginManager.add('${pluginName}', function(editor) {
        // Register the toolbar button
        editor.ui.registry.addButton('${opts.buttonName}', {
          text: '${opts.buttonText}',
          tooltip: '${opts.buttonTooltip}',
          onAction: function() {
            window.__sonicPicker({
              icon: '${opts.pickerIcon}',
              label: '${opts.pickerLabel}',
              apiUrl: '${opts.pickerApiUrl}',
              renderItem: ${opts.renderItemJs},
              getSearchText: ${opts.getSearchTextJs},
              onSelect: function(item) { (${opts.onSelectJs})(editor, item); }
            });
          }
        });

        // Inject chip CSS into editor iframe
        editor.on('init', function() {
          var doc = editor.getDoc();
          if (doc && !doc.getElementById('sonic-chip-css')) {
            var style = doc.createElement('style');
            style.id = 'sonic-chip-css';
            style.textContent = '${chipCSS}';
            doc.head.appendChild(style);
          }
        });

        // Token→chip on content load
        editor.on('SetContent', function() {
          var b = editor.getBody(); if (!b) return;
          var h = b.innerHTML, changed = false;
          var r = h.replace(/\\{([a-z0-9_]+)\\}/g, function(m,k) {
            changed = true;
            return '<span class="sonic-var-chip" contenteditable="false" data-var-key="'+k+'">'+k+'</span>';
          });
          r = r.replace(/\\[\\[(\\w+)([^\\]]*?)\\]\\]/g, function(m,n,p) {
            changed = true;
            var pa = p.trim() ? ' data-sc-params="'+p.trim().replace(/"/g,'&amp;quot;')+'"' : '';
            return '<span class="sonic-sc-chip" contenteditable="false" data-sc-name="'+n+'"'+pa+'>'+n+(p.trim()?' '+p.trim():'')+'</span>';
          });
          if (changed) editor.undoManager.ignore(function(){ b.innerHTML = r; });
        });

        // Chip→token on save
        editor.on('GetContent', function(e) {
          if (e.format !== 'html') return;
          e.content = e.content.replace(/<span[^>]*class="[^"]*sonic-var-chip[^"]*"[^>]*data-var-key="([^"]*)"[^>]*>[^<]*<\\/span>/g,
            function(m,k){ return '{'+k+'}'; });
          e.content = e.content.replace(/<span[^>]*class="[^"]*sonic-sc-chip[^"]*"[^>]*data-sc-name="([^"]*)"[^>]*(?:data-sc-params="([^"]*)")?[^>]*>[^<]*<\\/span>/g,
            function(m,n,p){ return '[['+n+(p?' '+p:'')+']]'; });
        });

        console.log('[SonicJS] TinyMCE plugin "${pluginName}" registered via PluginManager');
      });

      window.__sonicTmcePlugins.push('${pluginName}');
      window.__sonicTmceButtons.push('${opts.buttonName}');
      console.log('[SonicJS] PluginManager.add("${pluginName}") — done');
      return true;
    }

    // Try immediately (tinymce CDN may already be loaded)
    if (!registerSonicPlugin()) {
      // Poll until tinymce is available (CDN loads async)
      // The plugin MUST be registered before tinymce.init() is called.
      // Server-side injection in index.ts adds our plugin name to the plugins array,
      // so PluginManager just needs to have it registered by that time.
      var attempts = 0;
      var iv = setInterval(function() {
        attempts++;
        if (registerSonicPlugin() || attempts > 200) {
          clearInterval(iv);
          if (attempts > 200) console.warn('[SonicJS] Gave up waiting for tinymce to register ${pluginName}');
        }
      }, 25);
    }
  })();
  </script>`;
}
