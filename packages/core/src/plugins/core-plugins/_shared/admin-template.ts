/**
 * Shared Admin Page Template
 *
 * Provides the HTML wrapper for plugin admin pages with:
 * - Tailwind CSS (CDN) with dark mode
 * - HTMX for AJAX operations
 * - CSRF token auto-injection (matches core admin layout pattern)
 * - Inter font
 */

export function wrapAdminPage(opts: {
  title: string
  body: string
}): string {
  return `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${opts.title} - SonicJS</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script>tailwind.config = { darkMode: 'class' }</script>
  <script src="https://unpkg.com/htmx.org@2.0.3"></script>
  <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap">
  <style>body { font-family: 'Inter', system-ui, sans-serif; }</style>

  <!-- CSRF: Auto-attach token to all HTMX and fetch requests (matches core admin pattern) -->
  <script>
    function getCsrfToken() {
      var cookie = document.cookie.split('; ')
        .find(function(row) { return row.startsWith('csrf_token='); });
      return cookie ? cookie.substring(cookie.indexOf('=') + 1) : '';
    }

    // HTMX: attach CSRF token to all requests
    document.addEventListener('htmx:configRequest', function(event) {
      var token = getCsrfToken();
      if (token) {
        event.detail.headers['X-CSRF-Token'] = token;
      }
    });

    // fetch(): attach CSRF token to mutating requests
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
  </script>
</head>
<body class="bg-zinc-50 dark:bg-zinc-950 text-zinc-900 dark:text-zinc-100 min-h-screen">
  ${opts.body}
</body>
</html>`
}
