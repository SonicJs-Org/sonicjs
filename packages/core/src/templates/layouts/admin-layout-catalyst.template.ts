import { HtmlEscapedString } from "hono/utils/html";
import { renderLogo } from "../components/logo.template";

// Catalyst Checkbox Component (HTML implementation)
export interface CatalystCheckboxProps {
  id: string;
  name: string;
  checked?: boolean;
  disabled?: boolean;
  label?: string;
  description?: string;
  color?:
    | "dark/zinc"
    | "dark/white"
    | "white"
    | "dark"
    | "zinc"
    | "blue"
    | "green"
    | "red";
  className?: string;
}

export function renderCatalystCheckbox(props: CatalystCheckboxProps): string {
  const {
    id,
    name,
    checked = false,
    disabled = false,
    label,
    description,
    color = "dark/zinc",
    className = "",
  } = props;

  const colorConfig = {
    "dark/zinc": {
      bg: "#18181b",
      border: "#09090b",
      check: "#ffffff",
      darkBg: "#52525b",
    },
    "dark/white": {
      bg: "#18181b",
      border: "#09090b",
      check: "#ffffff",
      darkBg: "#ffffff",
      darkCheck: "#18181b",
    },
    white: { bg: "#ffffff", border: "#09090b", check: "#18181b" },
    dark: { bg: "#18181b", border: "#09090b", check: "#ffffff" },
    zinc: { bg: "#52525b", border: "#3f3f46", check: "#ffffff" },
    blue: { bg: "#2563eb", border: "#1d4ed8", check: "#ffffff" },
    green: { bg: "#16a34a", border: "#15803d", check: "#ffffff" },
    red: { bg: "#dc2626", border: "#b91c1c", check: "#ffffff" },
  };

  const _config = colorConfig[color] || colorConfig["dark/zinc"];

  const colorClasses = {
    "dark/zinc":
      "peer-checked:bg-zinc-900 peer-checked:before:bg-zinc-900 dark:peer-checked:bg-zinc-600",
    "dark/white":
      "peer-checked:bg-zinc-900 peer-checked:before:bg-zinc-900 dark:peer-checked:bg-white",
    white: "peer-checked:bg-white peer-checked:before:bg-white",
    dark: "peer-checked:bg-zinc-900 peer-checked:before:bg-zinc-900",
    zinc: "peer-checked:bg-zinc-600 peer-checked:before:bg-zinc-600",
    blue: "peer-checked:bg-blue-600 peer-checked:before:bg-blue-600",
    green: "peer-checked:bg-green-600 peer-checked:before:bg-green-600",
    red: "peer-checked:bg-red-600 peer-checked:before:bg-red-600",
  };

  const checkColor =
    color === "dark/white" ? "dark:text-zinc-900" : "text-white";

  const baseClasses = `
    relative isolate flex w-4 h-4 items-center justify-center rounded-[0.3125rem]
    before:absolute before:inset-0 before:-z-10 before:rounded-[calc(0.3125rem-1px)] before:bg-white before:shadow-sm
    dark:before:hidden
    dark:bg-white/5
    border border-zinc-950/15 peer-checked:border-transparent
    dark:border-white/15 dark:peer-checked:border-white/5
    peer-focus:outline peer-focus:outline-2 peer-focus:outline-offset-2 peer-focus:outline-blue-500
    peer-disabled:opacity-50
    peer-disabled:border-zinc-950/25 peer-disabled:bg-zinc-950/5
    dark:peer-disabled:border-white/20 dark:peer-disabled:bg-white/2.5
  `
    .trim()
    .replace(/\s+/g, " ");

  const checkIconClasses = `
    w-4 h-4 opacity-0 peer-checked:opacity-100 pointer-events-none
  `
    .trim()
    .replace(/\s+/g, " ");

  if (description) {
    // Field layout with description
    return `
      <div class="grid grid-cols-[1.125rem_1fr] gap-x-4 gap-y-1 sm:grid-cols-[1rem_1fr] ${className}">
        <div class="col-start-1 row-start-1 mt-0.75 sm:mt-1">
          <input
            type="checkbox"
            id="${id}"
            name="${name}"
            ${checked ? "checked" : ""}
            ${disabled ? "disabled" : ""}
            class="peer sr-only"
          />
          <label for="${id}" class="inline-flex cursor-pointer">
            <span class="${baseClasses} ${colorClasses[color] || colorClasses["dark/zinc"]}">
              <svg class="${checkIconClasses} ${checkColor}" viewBox="0 0 14 14" fill="none" stroke="currentColor">
                <path d="M3 8L6 11L11 3.5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
              </svg>
            </span>
          </label>
        </div>
        ${label ? `<label for="${id}" class="col-start-2 row-start-1 text-sm/6 font-medium text-zinc-950 dark:text-white cursor-pointer">${label}</label>` : ""}
        ${description ? `<p class="col-start-2 row-start-2 text-sm/6 text-zinc-500 dark:text-zinc-400">${description}</p>` : ""}
      </div>
    `;
  } else {
    // Simple checkbox with optional label
    return `
      <label class="inline-flex items-center gap-3 cursor-pointer ${className}">
        <input
          type="checkbox"
          id="${id}"
          name="${name}"
          ${checked ? "checked" : ""}
          ${disabled ? "disabled" : ""}
          class="peer sr-only"
        />
        <span class="${baseClasses} ${colorClasses[color] || colorClasses["dark/zinc"]}">
          <svg class="${checkIconClasses} ${checkColor}" viewBox="0 0 14 14" fill="none" stroke="currentColor">
            <path d="M3 8L6 11L11 3.5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
        </span>
        ${label ? `<span class="text-sm/6 font-medium text-zinc-950 dark:text-white">${label}</span>` : ""}
      </label>
    `;
  }
}

export interface AdminLayoutCatalystData {
  title: string;
  pageTitle?: string;
  currentPath?: string;
  version?: string;
  enableExperimentalFeatures?: boolean;
  user?: {
    name: string;
    email: string;
    role: string;
  };
  scripts?: string[];
  styles?: string[];
  content: string | HtmlEscapedString;
  dynamicMenuItems?: Array<{
    label: string;
    path: string;
    icon: string;
  }>;
}

export function renderAdminLayoutCatalyst(
  data: AdminLayoutCatalystData
): string {
  return `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${data.title} - SonicJS AI Admin</title>
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">

  <!-- Tailwind CSS -->
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          colors: {
            zinc: {
              50: '#fafafa',
              100: '#f4f4f5',
              200: '#e4e4e7',
              300: '#d4d4d8',
              400: '#a1a1aa',
              500: '#71717a',
              600: '#52525b',
              700: '#3f3f46',
              800: '#27272a',
              900: '#18181b',
              950: '#09090b'
            }
          }
        }
      }
    }
  </script>

  <!-- Additional Styles -->
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    body {
      font-family: 'Inter', system-ui, -apple-system, sans-serif;
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
    }

    /* Custom scrollbar */
    ::-webkit-scrollbar {
      width: 8px;
      height: 8px;
    }

    ::-webkit-scrollbar-track {
      background: #27272a;
    }

    ::-webkit-scrollbar-thumb {
      background: #52525b;
      border-radius: 4px;
    }

    ::-webkit-scrollbar-thumb:hover {
      background: #71717a;
    }

    /* Smooth transitions */
    * {
      transition-property: color, background-color, border-color, text-decoration-color, fill, stroke;
      transition-timing-function: cubic-bezier(0.4, 0, 0.2, 1);
      transition-duration: 150ms;
    }
  </style>

  <!-- Scripts -->
  <script src="https://unpkg.com/htmx.org@2.0.3"></script>
  <script src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js" defer></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>

  <!-- CSRF: Auto-attach token to all HTMX and fetch requests -->
  <script>
    function getCsrfToken() {
      var cookie = document.cookie.split('; ')
        .find(function(row) { return row.startsWith('csrf_token='); });
      return cookie ? cookie.substring(cookie.indexOf('=') + 1) : '';
    }

    document.addEventListener('htmx:configRequest', function(event) {
      var token = getCsrfToken();
      if (token) {
        event.detail.headers['X-CSRF-Token'] = token;
      }
    });

    (function() {
      var originalFetch = window.fetch;
      window.fetch = function(url, options) {
        options = options || {};
        var method = (options.method || 'GET').toUpperCase();
        if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
          options.headers = options.headers || {};
          if (options.headers instanceof Headers) {
            if (!options.headers.has('X-CSRF-Token')) {
              options.headers.set('X-CSRF-Token', getCsrfToken());
            }
          } else if (!Array.isArray(options.headers) && !options.headers['X-CSRF-Token']) {
            options.headers['X-CSRF-Token'] = getCsrfToken();
          }
        }
        return originalFetch.call(this, url, options);
      };
    })();

    // Inject _csrf hidden field into regular form submissions (non-HTMX)
    document.addEventListener('submit', function(event) {
      var form = event.target;
      if (!form || !form.tagName || form.tagName !== 'FORM') return;
      var method = (form.method || 'GET').toUpperCase();
      if (method === 'GET') return;
      if (form.hasAttribute('hx-post') || form.hasAttribute('hx-put') ||
          form.hasAttribute('hx-delete') || form.hasAttribute('hx-patch')) return;
      if (!form.querySelector('input[name="_csrf"]')) {
        var input = document.createElement('input');
        input.type = 'hidden';
        input.name = '_csrf';
        input.value = getCsrfToken();
        form.appendChild(input);
      }
    });
  </script>

  ${
    data.styles
      ? data.styles
          .map((style) => `<link rel="stylesheet" href="${style}">`)
          .join("\n  ")
      : ""
  }
  ${
    data.scripts
      ? data.scripts
          .map((script) => `<script src="${script}"></script>`)
          .join("\n  ")
      : ""
  }
</head>
<body class="min-h-screen bg-white dark:bg-zinc-900">
  <div class="relative isolate flex min-h-svh w-full max-lg:flex-col lg:bg-zinc-100 dark:lg:bg-zinc-950">
    <!-- Sidebar on desktop -->
    <div class="fixed inset-y-0 left-0 w-64 max-lg:hidden">
      ${renderCatalystSidebar(
        data.currentPath,
        data.user,
        data.dynamicMenuItems,
        false,
        data.version,
        data.enableExperimentalFeatures
      )}
    </div>

    <!-- Mobile sidebar (hidden by default) -->
    <div id="mobile-sidebar-overlay" class="fixed inset-0 bg-black/30 lg:hidden hidden z-40" onclick="closeMobileSidebar()"></div>
    <div id="mobile-sidebar" class="fixed inset-y-0 left-0 w-80 transform -translate-x-full transition-transform duration-300 ease-in-out lg:hidden z-50">
      ${renderCatalystSidebar(
        data.currentPath,
        data.user,
        data.dynamicMenuItems,
        true,
        data.version,
        data.enableExperimentalFeatures
      )}
    </div>

    <!-- Main content area -->
    <main class="flex flex-1 flex-col pb-2 lg:min-w-0 lg:pr-2 lg:pl-64">
      <!-- Mobile header with menu toggle -->
      <header class="flex items-center px-4 py-2.5 lg:hidden border-b border-zinc-950/5 dark:border-white/5">
        <button onclick="openMobileSidebar()" class="relative flex items-center justify-center rounded-lg p-2 text-zinc-950 hover:bg-zinc-950/5 dark:text-white dark:hover:bg-white/5" aria-label="Open navigation">
          <svg class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
            <path d="M2 6.75C2 6.33579 2.33579 6 2.75 6H17.25C17.6642 6 18 6.33579 18 6.75C18 7.16421 17.6642 7.5 17.25 7.5H2.75C2.33579 7.5 2 7.16421 2 6.75ZM2 13.25C2 12.8358 2.33579 12.5 2.75 12.5H17.25C17.6642 12.5 18 12.8358 18 13.25C18 13.6642 17.6642 14 17.25 14H2.75C2.33579 14 2 13.6642 2 13.25Z" />
          </svg>
        </button>
        <div class="ml-4 flex-1">
          ${renderLogo({ size: "sm", showText: true, variant: "white", version: data.version, href: "/admin" })}
        </div>
      </header>

      <!-- Content -->
      <div class="grow p-6 lg:rounded-lg lg:bg-white lg:p-10 lg:shadow-sm lg:ring-1 lg:ring-zinc-950/5 dark:lg:bg-zinc-900 dark:lg:ring-white/10">
        ${data.content}
      </div>
    </main>
  </div>

  <!-- Notification Container -->
  <div id="notification-container" class="fixed top-4 right-4 z-50 space-y-2"></div>

  <!-- Migration Warning Banner (hidden by default) -->
  <div id="migration-banner" class="hidden fixed top-0 left-0 right-0 z-50 bg-amber-500 dark:bg-amber-600 shadow-lg">
    <div class="max-w-7xl mx-auto px-4 py-3 sm:px-6 lg:px-8">
      <div class="flex items-center justify-between flex-wrap">
        <div class="flex items-center flex-1">
          <span class="flex p-2 rounded-lg bg-amber-600 dark:bg-amber-700">
            <svg class="h-5 w-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
            </svg>
          </span>
          <div class="ml-3">
            <p class="text-sm font-medium text-white">
              <span id="migration-count"></span> pending database migration(s) detected
            </p>
            <p class="text-xs text-amber-100 dark:text-amber-200 mt-1">
              Run: <code class="bg-amber-700 dark:bg-amber-800 px-2 py-0.5 rounded font-mono text-white">wrangler d1 migrations apply DB --local</code>
            </p>
          </div>
        </div>
        <div class="flex items-center gap-2">
          <a href="/admin/settings/migrations" class="text-xs font-semibold text-white hover:text-amber-100 underline">
            View Details
          </a>
          <button onclick="closeMigrationBanner()" class="p-1 rounded-md text-white hover:bg-amber-600 dark:hover:bg-amber-700 focus:outline-none focus:ring-2 focus:ring-white">
            <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
            </svg>
          </button>
        </div>
      </div>
    </div>
  </div>

  <script>
    // Mobile sidebar toggle
    function openMobileSidebar() {
      const sidebar = document.getElementById('mobile-sidebar');
      const overlay = document.getElementById('mobile-sidebar-overlay');
      sidebar.classList.remove('-translate-x-full');
      overlay.classList.remove('hidden');
    }

    function closeMobileSidebar() {
      const sidebar = document.getElementById('mobile-sidebar');
      const overlay = document.getElementById('mobile-sidebar-overlay');
      sidebar.classList.add('-translate-x-full');
      overlay.classList.add('hidden');
    }

    // User dropdown toggle
    function toggleUserDropdown() {
      const dropDowns = document.querySelectorAll('.userDropdown');
      dropDowns.forEach(dropdown => {
        dropdown.classList.toggle('hidden');
      });
    }

    // Close dropdown when clicking outside
    document.addEventListener('click', function(event) {
      const dropdown = document.getElementById('userDropdown');
      const button = event.target.closest('[data-user-menu]');
      if (!button && dropdown && !dropdown.contains(event.target)) {
        dropdown.classList.add('hidden');
      }
    });

    // Show notification
    function showNotification(message, type = 'info') {
      const container = document.getElementById('notification-container');
      const notification = document.createElement('div');
      const colors = {
        success: 'bg-green-50 dark:bg-green-500/10 text-green-700 dark:text-green-400 ring-green-600/20 dark:ring-green-500/20',
        error: 'bg-red-50 dark:bg-red-500/10 text-red-700 dark:text-red-400 ring-red-600/20 dark:ring-red-500/20',
        warning: 'bg-amber-50 dark:bg-amber-500/10 text-amber-700 dark:text-amber-400 ring-amber-600/20 dark:ring-amber-500/20',
        info: 'bg-blue-50 dark:bg-blue-500/10 text-blue-700 dark:text-blue-400 ring-blue-600/20 dark:ring-blue-500/20'
      };

      notification.className = \`rounded-lg p-4 ring-1 \${colors[type] || colors.info} max-w-sm shadow-lg\`;
      notification.innerHTML = \`
        <div class="flex items-center justify-between">
          <span class="text-sm">\${message}</span>
          <button onclick="this.parentElement.parentElement.remove()" class="ml-4 hover:opacity-70">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
            </svg>
          </button>
        </div>
      \`;

      container.appendChild(notification);

      // Auto remove after 5 seconds
      setTimeout(() => {
        if (notification.parentElement) {
          notification.remove();
        }
      }, 5000);
    }

    // Initialize dark mode
    if (localStorage.getItem('darkMode') === 'false') {
      document.documentElement.classList.remove('dark');
    }

    // Migration banner functions
    function closeMigrationBanner() {
      const banner = document.getElementById('migration-banner');
      if (banner) {
        banner.classList.add('hidden');
        // Store in session storage so it doesn't show again during this session
        sessionStorage.setItem('migrationBannerDismissed', 'true');
      }
    }

    // Check for pending migrations on page load
    async function checkPendingMigrations() {
      // Don't check if user dismissed the banner in this session
      if (sessionStorage.getItem('migrationBannerDismissed') === 'true') {
        return;
      }

      try {
        const response = await fetch('/admin/api/migrations/status');
        if (response.ok) {
          const data = await response.json();
          if (data.success && data.data && data.data.pendingMigrations > 0) {
            const banner = document.getElementById('migration-banner');
            const countElement = document.getElementById('migration-count');
            if (banner && countElement) {
              countElement.textContent = data.data.pendingMigrations;
              banner.classList.remove('hidden');
            }
          }
        }
      } catch (error) {
        console.error('Failed to check migration status:', error);
      }
    }

    // Check for pending migrations when the page loads
    document.addEventListener('DOMContentLoaded', checkPendingMigrations);
  </script>
</body>
</html>`;
}

function renderCatalystSidebar(
  currentPath: string = "",
  user?: any,
  dynamicMenuItems?: Array<{ label: string; path: string; icon: string }>,
  isMobile: boolean = false,
  version?: string,
  enableExperimentalFeatures?: boolean
): string {
  let baseMenuItems = [
    {
      label: "Dashboard",
      path: "/admin",
      icon: `<svg class="h-5 w-5" fill="currentColor" viewBox="0 0 20 20">
        <path d="M3 4a1 1 0 011-1h12a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1V4zM3 10a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H4a1 1 0 01-1-1v-6zM14 9a1 1 0 00-1 1v6a1 1 0 001 1h2a1 1 0 001-1v-6a1 1 0 00-1-1h-2z"/>
      </svg>`,
    },
    {
      label: "Collections",
      path: "/admin/collections",
      icon: `<svg class="h-5 w-5" fill="currentColor" viewBox="0 0 20 20">
        <path d="M7 3a1 1 0 000 2h6a1 1 0 100-2H7zM4 7a1 1 0 011-1h10a1 1 0 110 2H5a1 1 0 01-1-1zM2 11a2 2 0 012-2h12a2 2 0 012 2v4a2 2 0 01-2 2H4a2 2 0 01-2-2v-4z"/>
      </svg>`,
    },
    {
      label: "Forms",
      path: "/admin/forms",
      icon: `<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
      </svg>`,
    },
    {
      label: "Content",
      path: "/admin/content",
      icon: `<svg class="h-5 w-5" fill="currentColor" viewBox="0 0 20 20">
        <path fill-rule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4zm2 6a1 1 0 011-1h6a1 1 0 110 2H7a1 1 0 01-1-1zm1 3a1 1 0 100 2h6a1 1 0 100-2H7z" clip-rule="evenodd"/>
      </svg>`,
    },
    {
      label: "Media",
      path: "/admin/media",
      icon: `<svg class="h-5 w-5" fill="currentColor" viewBox="0 0 20 20">
        <path fill-rule="evenodd" d="M4 3a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V5a2 2 0 00-2-2H4zm12 12H4l4-8 3 6 2-4 3 6z" clip-rule="evenodd"/>
      </svg>`,
    },
    {
      label: "Users",
      path: "/admin/users",
      icon: `<svg class="h-5 w-5" fill="currentColor" viewBox="0 0 20 20">
        <path d="M9 6a3 3 0 11-6 0 3 3 0 016 0zM17 6a3 3 0 11-6 0 3 3 0 016 0zM12.93 17c.046-.327.07-.66.07-1a6.97 6.97 0 00-1.5-4.33A5 5 0 0119 16v1h-6.07zM6 11a5 5 0 015 5v1H1v-1a5 5 0 015-5z"/>
      </svg>`,
    },
    {
      label: "Plugins",
      path: "/admin/plugins",
      icon: `<svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/>
      </svg>`,
    },
    {
      label: "Cache",
      path: "/admin/cache",
      icon: `<svg class="h-5 w-5" fill="currentColor" viewBox="0 0 20 20">
        <path fill-rule="evenodd" d="M2 5a2 2 0 012-2h12a2 2 0 012 2v2a2 2 0 01-2 2H4a2 2 0 01-2-2V5zm14 1a1 1 0 11-2 0 1 1 0 012 0zM2 13a2 2 0 012-2h12a2 2 0 012 2v2a2 2 0 01-2 2H4a2 2 0 01-2-2v-2zm14 1a1 1 0 11-2 0 1 1 0 012 0z" clip-rule="evenodd"/>
      </svg>`,
    },
  ];

  const settingsMenuItem = {
    label: "Settings",
    path: "/admin/settings",
    icon: `<svg class="h-5 w-5" fill="currentColor" viewBox="0 0 20 20">
      <path fill-rule="evenodd" d="M11.49 3.17c-.38-1.56-2.6-1.56-2.98 0a1.532 1.532 0 01-2.286.948c-1.372-.836-2.942.734-2.106 2.106.54.886.061 2.042-.947 2.287-1.561.379-1.561 2.6 0 2.978a1.532 1.532 0 01.947 2.287c-.836 1.372.734 2.942 2.106 2.106a1.532 1.532 0 012.287.947c.379 1.561 2.6 1.561 2.978 0a1.533 1.533 0 012.287-.947c1.372.836 2.942-.734 2.106-2.106a1.533 1.533 0 01.947-2.287c1.561-.379 1.561-2.6 0-2.978a1.532 1.532 0 01-.947-2.287c.836-1.372-.734-2.942-2.106-2.106a1.532 1.532 0 01-2.287-.947zM10 13a3 3 0 100-6 3 3 0 000 6z" clip-rule="evenodd"/>
    </svg>`,
  };

  // Combine base menu items with dynamic menu items
  const allMenuItems = [...baseMenuItems];
  if (dynamicMenuItems && dynamicMenuItems.length > 0) {
    // Insert dynamic menu items after Users menu item
    const usersIndex = allMenuItems.findIndex(
      (item) => item.path === "/admin/users"
    );
    if (usersIndex !== -1) {
      allMenuItems.splice(usersIndex + 1, 0, ...dynamicMenuItems);
    } else {
      // Fallback: add to end if Users not found
      allMenuItems.push(...dynamicMenuItems);
    }
  }

  const closeButton = isMobile
    ? `
    <div class="-mb-3 px-4 pt-3">
      <button onclick="closeMobileSidebar()" class="relative flex w-full items-center gap-3 rounded-lg p-2 text-left text-base/6 font-medium text-zinc-950 hover:bg-zinc-950/5 dark:text-white dark:hover:bg-white/5 sm:text-sm/5" aria-label="Close navigation">
        <svg class="h-5 w-5 shrink-0 fill-zinc-500 dark:fill-zinc-400" viewBox="0 0 20 20">
          <path d="M6.28 5.22a.75.75 0 0 0-1.06 1.06L8.94 10l-3.72 3.72a.75.75 0 1 0 1.06 1.06L10 11.06l3.72 3.72a.75.75 0 1 0 1.06-1.06L11.06 10l3.72-3.72a.75.75 0 0 0-1.06-1.06L10 8.94 6.28 5.22Z" />
        </svg>
        <span>Close menu</span>
      </button>
    </div>
  `
    : "";

  return `
    <nav class="flex h-full min-h-0 flex-col bg-white shadow-sm ring-1 ring-zinc-950/5 dark:bg-zinc-900 dark:ring-white/10 ${
      isMobile ? "is-mobile rounded-lg p-2 m-2" : ""
    }">
      ${closeButton}

      <!-- Sidebar Header -->
      <div class="flex flex-col border-b border-zinc-950/5 p-4 dark:border-white/5">
        ${renderLogo({ size: "md", showText: true, variant: "white", version, href: "/admin" })}
      </div>

      <!-- Sidebar Body -->
      <div class="flex flex-1 flex-col overflow-y-auto p-4">
        <div class="flex flex-col gap-0.5">
          ${allMenuItems
            .map((item) => {
              const isActive =
                currentPath === item.path ||
                (item.path !== "/admin" && currentPath?.startsWith(item.path));
              return `
              <span class="relative">
                ${
                  isActive
                    ? `
                  <span class="absolute inset-y-2 -left-4 w-0.5 rounded-full bg-cyan-500 dark:bg-cyan-400"></span>
                `
                    : ""
                }
                <a
                  href="${item.path}"
                  class="flex w-full items-center gap-3 rounded-lg px-2 py-2.5 text-left text-sm/5 font-medium ${
                    isActive
                      ? "text-zinc-950 dark:text-white"
                      : "text-zinc-950 hover:bg-zinc-950/5 dark:text-white dark:hover:bg-white/5"
                  }"
                  ${isActive ? 'data-current="true"' : ""}
                >
                  <span class="shrink-0 ${
                    isActive
                      ? "fill-zinc-950 dark:fill-white"
                      : "fill-zinc-500 dark:fill-zinc-400"
                  }">
                    ${item.icon}
                  </span>
                  <span class="truncate">${item.label}</span>
                </a>
              </span>
            `;
            })
            .join("")}
        </div>
      </div>

      <!-- Settings Menu Item (Bottom) -->
      <div class="border-t border-zinc-950/5 p-4 dark:border-white/5">
        ${(() => {
          const isActive =
            currentPath === settingsMenuItem.path ||
            currentPath?.startsWith(settingsMenuItem.path);
          return `
            <span class="relative">
              ${
                isActive
                  ? `
                <span class="absolute inset-y-2 -left-4 w-0.5 rounded-full bg-cyan-500 dark:bg-cyan-400"></span>
              `
                  : ""
              }
              <a
                href="${settingsMenuItem.path}"
                class="flex w-full items-center gap-3 rounded-lg px-2 py-2.5 text-left text-sm/5 font-medium ${
                  isActive
                    ? "text-zinc-950 dark:text-white"
                    : "text-zinc-950 hover:bg-zinc-950/5 dark:text-white dark:hover:bg-white/5"
                }"
                ${isActive ? 'data-current="true"' : ""}
              >
                <span class="shrink-0 ${
                  isActive
                    ? "fill-zinc-950 dark:fill-white"
                    : "fill-zinc-500 dark:fill-zinc-400"
                }">
                  ${settingsMenuItem.icon}
                </span>
                <span class="truncate">${settingsMenuItem.label}</span>
              </a>
            </span>
          `;
        })()}
      </div>

      <!-- Sidebar Footer (User) -->
      ${
        user
          ? `
        <div class="flex flex-col border-t border-zinc-950/5 p-4 dark:border-white/5">
          <div class="relative">
            <button
              data-user-menu
              onclick="toggleUserDropdown()"
              class="flex w-full items-center gap-3 rounded-lg px-2 py-2.5 text-left text-sm/5 font-medium text-zinc-950 hover:bg-zinc-950/5 dark:text-white dark:hover:bg-white/5"
            >
              <div class="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-zinc-950 text-white dark:bg-white dark:text-zinc-950">
                <span class="text-xs font-semibold">${(
                  user.name ||
                  user.email ||
                  "U"
                )
                  .charAt(0)
                  .toUpperCase()}</span>
              </div>
              <span class="flex-1 truncate">${
                user.name || user.email || "User"
              }</span>
              <svg class="h-4 w-4 shrink-0 fill-zinc-500 dark:fill-zinc-400" viewBox="0 0 20 20">
                <path d="M5.22 8.22a.75.75 0 0 1 1.06 0L10 11.94l3.72-3.72a.75.75 0 1 1 1.06 1.06l-4.25 4.25a.75.75 0 0 1-1.06 0L5.22 9.28a.75.75 0 0 1 0-1.06Z" />
              </svg>
            </button>

            <!-- User Dropdown -->
            <div class="userDropdown hidden absolute bottom-full mb-2 left-0 right-0 mx-2 rounded-xl bg-white shadow-lg ring-1 ring-zinc-950/10 dark:bg-zinc-800 dark:ring-white/10 z-50">
              <div class="p-2">
                <div class="px-3 py-2 border-b border-zinc-950/5 dark:border-white/5">
                  <p class="text-sm font-medium text-zinc-950 dark:text-white">${
                    user.name || user.email || "User"
                  }</p>
                  <p class="text-xs text-zinc-500 dark:text-zinc-400">${
                    user.email || ""
                  }</p>
                </div>
                <a href="/admin/profile" class="flex items-center gap-2 rounded-lg px-3 py-2 text-sm text-zinc-950 hover:bg-zinc-950/5 dark:text-white dark:hover:bg-white/5">
                  <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/>
                  </svg>
                  My Profile
                </a>
                <a href="/auth/logout" class="flex items-center gap-2 rounded-lg px-3 py-2 text-sm text-red-600 hover:bg-red-50 dark:text-red-400 dark:hover:bg-red-500/10">
                  <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/>
                  </svg>
                  Sign Out
                </a>
              </div>
            </div>
          </div>
        </div>
      `
          : ""
      }
    </nav>
  `;
}
