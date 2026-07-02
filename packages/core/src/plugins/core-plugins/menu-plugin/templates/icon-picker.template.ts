import { escapeHtml } from '../../../../utils/sanitize'

const ICONS: Array<{ name: string; svg: string }> = [
  {
    name: 'puzzle-piece',
    svg: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 4a2 2 0 114 0v1a1 1 0 001 1h3a1 1 0 011 1v3a1 1 0 01-1 1h-1a2 2 0 100 4h1a1 1 0 011 1v3a1 1 0 01-1 1h-3a1 1 0 01-1-1v-1a2 2 0 10-4 0v1a1 1 0 01-1 1H7a1 1 0 01-1-1v-3a1 1 0 00-1-1H4a2 2 0 110-4h1a1 1 0 001-1V7a1 1 0 011-1h3a1 1 0 001-1V4z"/>'
  },
  {
    name: 'document',
    svg: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z"/>'
  },
  {
    name: 'collection',
    svg: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/>'
  },
  {
    name: 'users',
    svg: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z"/>'
  },
  {
    name: 'cog',
    svg: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/>'
  },
  {
    name: 'envelope',
    svg: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/>'
  },
  {
    name: 'chart',
    svg: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/>'
  },
  {
    name: 'bolt',
    svg: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/>'
  },
  {
    name: 'sparkles',
    svg: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 3v4M3 5h4M6 17v4m-2-2h4m5-16l2.286 6.857L21 12l-5.714 2.143L13 21l-2.286-6.857L5 12l5.714-2.143L13 3z"/>'
  },
  {
    name: 'photo',
    svg: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"/>'
  },
  {
    name: 'lock',
    svg: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>'
  },
  {
    name: 'magnifying-glass',
    svg: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/>'
  },
  {
    name: 'chart-bar',
    svg: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/>'
  },
  {
    name: 'image',
    svg: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"/>'
  },
  {
    name: 'key',
    svg: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"/>'
  },
  {
    name: 'shield-check',
    svg: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>'
  },
  {
    name: 'credit-card',
    svg: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z"/>'
  },
  {
    name: 'document-text',
    svg: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>'
  },
  {
    name: 'pencil-square',
    svg: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/>'
  },
  {
    name: 'server',
    svg: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01"/>'
  },
  {
    name: 'building-office',
    svg: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"/>'
  },
  {
    name: 'home',
    svg: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"/>'
  },
  {
    name: 'star',
    svg: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z"/>'
  },
  {
    name: 'tag',
    svg: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A1.994 1.994 0 013 12V7a4 4 0 014-4z"/>'
  },
  {
    name: 'link',
    svg: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/>'
  },
  {
    name: 'external-link',
    svg: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/>'
  },
  {
    name: 'eye',
    svg: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"/>'
  },
  {
    name: 'bars-3',
    svg: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/>'
  },
  {
    name: 'arrow-right',
    svg: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14 5l7 7m0 0l-7 7m7-7H3"/>'
  }
]

export function renderIconPicker(selectedIcon: string): string {
  const safeSelected = escapeHtml(selectedIcon)

  const iconButtons = ICONS.map(({ name, svg }) => {
    const isSelected = name === selectedIcon
    const selectedClasses = isSelected
      ? 'ring-2 ring-cyan-500 bg-cyan-50 dark:bg-cyan-900/30'
      : 'ring-1 ring-zinc-200 dark:ring-zinc-700 hover:ring-cyan-300 dark:hover:ring-cyan-600 hover:bg-zinc-50 dark:hover:bg-zinc-800'
    return `
      <button
        type="button"
        data-icon-name="${name}"
        onclick="selectIcon('${name}')"
        class="icon-btn flex flex-col items-center gap-1 p-2 rounded-lg transition-all duration-150 ${selectedClasses}"
        title="${name}"
      >
        <svg class="w-6 h-6 text-zinc-700 dark:text-zinc-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          ${svg}
        </svg>
        <span class="text-[10px] text-zinc-500 dark:text-zinc-400 truncate max-w-[56px] text-center leading-tight">${name}</span>
      </button>`
  }).join('\n')

  return `
    <div class="space-y-4">
      <input type="hidden" name="icon" id="icon-input" value="${safeSelected}">

      <div>
        <p class="text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-2">Choose an icon</p>
        <div class="grid grid-cols-6 sm:grid-cols-8 md:grid-cols-10 gap-2 max-h-64 overflow-y-auto p-1 rounded-lg border border-zinc-200 dark:border-zinc-700 bg-white dark:bg-zinc-900">
          ${iconButtons}
        </div>
      </div>

      <div>
        <label class="text-sm font-medium text-zinc-700 dark:text-zinc-300 block mb-1">Custom SVG (overrides selection above)</label>
        <textarea
          id="custom-svg-input"
          rows="3"
          placeholder='<svg xmlns="http://www.w3.org/2000/svg" ...>...</svg>'
          oninput="handleCustomSvg(this.value)"
          class="w-full rounded-lg border border-zinc-300 dark:border-zinc-600 bg-white dark:bg-zinc-800 px-3 py-2 text-sm text-zinc-900 dark:text-zinc-100 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 font-mono"
        ></textarea>
        <p class="mt-1 text-xs text-zinc-400 dark:text-zinc-500">Paste raw SVG markup to use a custom icon.</p>
      </div>
    </div>

    <script>
      (function () {
        function selectIcon(name) {
          document.getElementById('icon-input').value = name;
          document.getElementById('custom-svg-input').value = '';
          document.querySelectorAll('.icon-btn').forEach(function (btn) {
            var isSelected = btn.getAttribute('data-icon-name') === name;
            btn.className = btn.className
              .replace(/ring-2 ring-cyan-500 bg-cyan-50 dark:bg-cyan-900\\/30/g, '')
              .replace(/ring-1 ring-zinc-200 dark:ring-zinc-700 hover:ring-cyan-300 dark:hover:ring-cyan-600 hover:bg-zinc-50 dark:hover:bg-zinc-800/g, '')
              .trim();
            if (isSelected) {
              btn.className += ' ring-2 ring-cyan-500 bg-cyan-50 dark:bg-cyan-900/30';
            } else {
              btn.className += ' ring-1 ring-zinc-200 dark:ring-zinc-700 hover:ring-cyan-300 dark:hover:ring-cyan-600 hover:bg-zinc-50 dark:hover:bg-zinc-800';
            }
          });
        }

        function handleCustomSvg(value) {
          var trimmed = value.trim();
          if (trimmed) {
            document.getElementById('icon-input').value = trimmed;
            document.querySelectorAll('.icon-btn').forEach(function (btn) {
              btn.className = btn.className
                .replace(/ring-2 ring-cyan-500 bg-cyan-50 dark:bg-cyan-900\\/30/g, '')
                .replace(/ring-1 ring-zinc-200 dark:ring-zinc-700 hover:ring-cyan-300 dark:hover:ring-cyan-600 hover:bg-zinc-50 dark:hover:bg-zinc-800/g, '')
                .trim();
              btn.className += ' ring-1 ring-zinc-200 dark:ring-zinc-700 hover:ring-cyan-300 dark:hover:ring-cyan-600 hover:bg-zinc-50 dark:hover:bg-zinc-800';
            });
          }
        }

        window.selectIcon = selectIcon;
        window.handleCustomSvg = handleCustomSvg;
      })();
    </script>
  `
}
