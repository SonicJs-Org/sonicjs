import {
  renderAdminLayoutCatalyst,
  type AdminLayoutCatalystData,
} from '../../../../templates/layouts/admin-layout-catalyst.template'
import { escapeHtml } from '../../../../utils/sanitize'
import type { ResolvedMcpType } from '../config'
import type { McpToolDescriptor } from '../tools/registry'

export interface McpDashboardPageData {
  endpointUrl: string
  types: ResolvedMcpType[]
  tools: McpToolDescriptor[]
  user?: { name: string; email: string; role: string }
  version?: string
  dynamicMenuItems?: Array<{ label: string; path: string; icon: string }>
}

function accessBadge(ok: boolean): string {
  return ok
    ? `<span class="inline-flex items-center rounded-full bg-emerald-50 dark:bg-emerald-900/20 px-2 py-0.5 text-xs font-medium text-emerald-700 dark:text-emerald-400 ring-1 ring-emerald-600/20 dark:ring-emerald-400/20">Yes</span>`
    : `<span class="inline-flex items-center rounded-full bg-zinc-100 dark:bg-zinc-800 px-2 py-0.5 text-xs font-medium text-zinc-500 dark:text-zinc-400 ring-1 ring-zinc-200 dark:ring-zinc-700">No</span>`
}

function toolNamesForType(typeId: string, tools: McpToolDescriptor[]): string {
  const names = tools
    .filter((t) => t.typeId === typeId)
    .map((t) => `<code class="text-xs font-mono text-zinc-500 dark:text-zinc-400">${escapeHtml(t.name)}</code>`)
  return names.length ? names.join('<span class="text-zinc-300 dark:text-zinc-600 mx-1">,</span>') : '—'
}

function buildClaudeJson(endpointUrl: string): string {
  return JSON.stringify(
    {
      mcpServers: {
        sonicjs: {
          type: 'http',
          url: endpointUrl,
          headers: { Authorization: 'Bearer sk_YOUR_API_KEY' },
        },
      },
    },
    null,
    2,
  )
}

function buildCursorJson(endpointUrl: string): string {
  return JSON.stringify(
    {
      mcpServers: {
        sonicjs: {
          url: endpointUrl,
          headers: { Authorization: 'Bearer sk_YOUR_API_KEY' },
        },
      },
    },
    null,
    2,
  )
}

export function renderMcpDashboardPage(data: McpDashboardPageData): string {
  const { endpointUrl, types, tools, user, version, dynamicMenuItems } = data
  const safeEndpoint = escapeHtml(endpointUrl)
  const typeCount = types.length
  const toolCount = tools.length

  const typeRows = types.length
    ? types
        .map(
          (t) => `
      <tr class="border-t border-zinc-950/5 dark:border-white/10">
        <td class="py-3 pr-4 text-sm font-mono text-zinc-950 dark:text-white">${escapeHtml(t.typeId)}</td>
        <td class="py-3 pr-4 text-sm text-zinc-500 dark:text-zinc-400">${escapeHtml(t.displayName)}</td>
        <td class="py-3 pr-4">${accessBadge(t.read)}</td>
        <td class="py-3 pr-4">${accessBadge(t.write)}</td>
        <td class="py-3 text-sm">${toolNamesForType(t.typeId, tools)}</td>
      </tr>`,
        )
        .join('')
    : `<tr><td colspan="5" class="py-8 text-center text-sm text-zinc-500 dark:text-zinc-400">No collections exposed. Register collections via <code class="font-mono">registerCollections()</code> in your app entry point.</td></tr>`

  const claudeJson = escapeHtml(buildClaudeJson(endpointUrl))
  const cursorJson = escapeHtml(buildCursorJson(endpointUrl))

  const content = `
    <div class="space-y-8">

      <!-- Header -->
      <div class="sm:flex sm:items-center sm:justify-between">
        <div class="sm:flex-auto">
          <h1 class="text-2xl/8 font-semibold text-zinc-950 dark:text-white sm:text-xl/8">MCP Server</h1>
          <p class="mt-2 text-sm/6 text-zinc-500 dark:text-zinc-400">
            Model Context Protocol endpoint for AI agents (Claude Code, Cursor, VS Code). Requests are authenticated with API keys.
          </p>
        </div>
        <div class="mt-4 sm:mt-0 sm:ml-16">
          <a href="/admin/plugins/api-keys"
            class="inline-flex items-center justify-center rounded-lg bg-cyan-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-cyan-500 transition-colors shadow-sm">
            Mint API Key
          </a>
        </div>
      </div>

      <!-- Status -->
      <div class="rounded-xl bg-white/80 dark:bg-zinc-900/80 backdrop-blur-xl p-6 ring-1 ring-zinc-950/5 dark:ring-white/10 shadow-sm">
        <h2 class="text-sm font-semibold text-zinc-950 dark:text-white mb-4">Endpoint</h2>
        <div class="flex items-center gap-3">
          <code id="endpoint-url" class="flex-1 rounded-lg bg-zinc-50 dark:bg-zinc-800 px-3 py-2 text-sm font-mono text-zinc-950 dark:text-white ring-1 ring-zinc-950/5 dark:ring-white/5 break-all">${safeEndpoint}</code>
          <button type="button" onclick="copyEndpoint()"
            class="shrink-0 rounded-lg bg-zinc-100 dark:bg-zinc-800 px-3 py-2 text-sm font-medium text-zinc-700 dark:text-zinc-300 hover:bg-zinc-200 dark:hover:bg-zinc-700 ring-1 ring-zinc-950/5 dark:ring-white/10 transition-colors">
            Copy
          </button>
        </div>
        <div class="mt-4 flex flex-wrap gap-4 text-sm text-zinc-500 dark:text-zinc-400">
          <span>
            <span class="font-semibold text-zinc-950 dark:text-white">${typeCount}</span>
            collection${typeCount === 1 ? '' : 's'} exposed
          </span>
          <span class="text-zinc-300 dark:text-zinc-600">&middot;</span>
          <span>
            <span class="font-semibold text-zinc-950 dark:text-white">${toolCount}</span>
            tool${toolCount === 1 ? '' : 's'} available
          </span>
          <span class="text-zinc-300 dark:text-zinc-600">&middot;</span>
          <span>Auth via <a href="/admin/plugins/api-keys" class="text-cyan-600 dark:text-cyan-400 hover:underline">API Keys</a></span>
        </div>
      </div>

      <!-- Exposed collections table -->
      <div class="rounded-xl bg-white/80 dark:bg-zinc-900/80 backdrop-blur-xl p-6 ring-1 ring-zinc-950/5 dark:ring-white/10 shadow-sm overflow-x-auto">
        <h2 class="text-sm font-semibold text-zinc-950 dark:text-white mb-4">Exposed collections</h2>
        <table class="w-full text-left">
          <thead>
            <tr class="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
              <th class="pb-2 pr-4">ID</th>
              <th class="pb-2 pr-4">Display name</th>
              <th class="pb-2 pr-4">Read</th>
              <th class="pb-2 pr-4">Write</th>
              <th class="pb-2">Tools</th>
            </tr>
          </thead>
          <tbody>${typeRows}</tbody>
        </table>
      </div>

      <!-- Integration guide -->
      <div class="rounded-xl bg-white/80 dark:bg-zinc-900/80 backdrop-blur-xl p-6 ring-1 ring-zinc-950/5 dark:ring-white/10 shadow-sm space-y-6">
        <div>
          <h2 class="text-sm font-semibold text-zinc-950 dark:text-white mb-1">Integration guide</h2>
          <p class="text-sm text-zinc-500 dark:text-zinc-400">
            <a href="/admin/plugins/api-keys" class="text-cyan-600 dark:text-cyan-400 hover:underline">Mint an API key</a>,
            then paste one of the configs below into your MCP client.
            Replace <code class="font-mono text-xs">sk_YOUR_API_KEY</code> with the key.
          </p>
        </div>

        <!-- Claude Code -->
        <div>
          <div class="flex items-center justify-between mb-2">
            <h3 class="text-sm font-medium text-zinc-700 dark:text-zinc-300">
              Claude Code &mdash; <code class="font-mono text-xs">~/.claude/mcp.json</code>
            </h3>
            <button type="button" onclick="copyConfig('claude-config')"
              class="text-xs text-zinc-500 dark:text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200 transition-colors">
              Copy
            </button>
          </div>
          <pre id="claude-config" class="rounded-lg bg-zinc-950 dark:bg-zinc-800 px-4 py-3 text-sm font-mono text-zinc-100 overflow-x-auto ring-1 ring-zinc-700 dark:ring-zinc-600 whitespace-pre">${claudeJson}</pre>
        </div>

        <!-- Cursor -->
        <div>
          <div class="flex items-center justify-between mb-2">
            <h3 class="text-sm font-medium text-zinc-700 dark:text-zinc-300">
              Cursor &mdash; <code class="font-mono text-xs">~/.cursor/mcp.json</code>
            </h3>
            <button type="button" onclick="copyConfig('cursor-config')"
              class="text-xs text-zinc-500 dark:text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200 transition-colors">
              Copy
            </button>
          </div>
          <pre id="cursor-config" class="rounded-lg bg-zinc-950 dark:bg-zinc-800 px-4 py-3 text-sm font-mono text-zinc-100 overflow-x-auto ring-1 ring-zinc-700 dark:ring-zinc-600 whitespace-pre">${cursorJson}</pre>
        </div>

        <p class="text-xs text-zinc-400 dark:text-zinc-500">
          MCP v1 = HTTP POST only (no SSE stream). Clients that require stdio transport can use
          <code class="font-mono">npx mcp-remote ${safeEndpoint}</code> as a local bridge.
        </p>
      </div>

    </div>

    <script>
      function copyEndpoint() {
        navigator.clipboard.writeText(document.getElementById('endpoint-url').textContent.trim()).then(() => {
          window.showNotification && window.showNotification('Endpoint URL copied', 'success')
        })
      }
      function copyConfig(id) {
        navigator.clipboard.writeText(document.getElementById(id).textContent).then(() => {
          window.showNotification && window.showNotification('Config copied', 'success')
        })
      }
    </script>`

  const layoutData: AdminLayoutCatalystData = {
    title: 'MCP Server',
    pageTitle: 'MCP Server',
    currentPath: '/admin/mcp',
    user,
    content,
    version,
    dynamicMenuItems,
  }

  return renderAdminLayoutCatalyst(layoutData)
}
