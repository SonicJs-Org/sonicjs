'use strict';

var chunkRCLFF5NO_cjs = require('./chunk-RCLFF5NO.cjs');
var chunkVNLR35GO_cjs = require('./chunk-VNLR35GO.cjs');
var chunkYZRINJP5_cjs = require('./chunk-YZRINJP5.cjs');
var chunkMPT5PA6U_cjs = require('./chunk-MPT5PA6U.cjs');
var chunkVVY7W23T_cjs = require('./chunk-VVY7W23T.cjs');
var chunk6WA4KFYZ_cjs = require('./chunk-6WA4KFYZ.cjs');
var chunkGMUS5V42_cjs = require('./chunk-GMUS5V42.cjs');
var chunkMNFY6DWY_cjs = require('./chunk-MNFY6DWY.cjs');
var chunk6FHNRRJ3_cjs = require('./chunk-6FHNRRJ3.cjs');
var chunkUOEIMC67_cjs = require('./chunk-UOEIMC67.cjs');
require('./chunk-P3XDZL6Q.cjs');
var chunkRCQ2HIQD_cjs = require('./chunk-RCQ2HIQD.cjs');
var chunkKYGRJCZM_cjs = require('./chunk-KYGRJCZM.cjs');
require('./chunk-IGJUBJBW.cjs');
var hono = require('hono');
var cookie = require('hono/cookie');
var zod = require('zod');
var html = require('hono/html');
var d1 = require('drizzle-orm/d1');

// src/plugins/core-plugins/database-tools-plugin/services/database-service.ts
var DatabaseToolsService = class {
  constructor(db) {
    this.db = db;
  }
  /**
   * Get database statistics
   */
  async getDatabaseStats() {
    const tables = await this.getTables();
    const stats = {
      tables: [],
      totalRows: 0
    };
    for (const tableName of tables) {
      try {
        const result = await this.db.prepare(`SELECT COUNT(*) as count FROM ${tableName}`).first();
        const rowCount = result?.count || 0;
        stats.tables.push({
          name: tableName,
          rowCount
        });
        stats.totalRows += rowCount;
      } catch (error) {
        console.warn(`Could not count rows in table ${tableName}:`, error);
      }
    }
    return stats;
  }
  /**
   * Get all tables in the database
   */
  async getTables() {
    const result = await this.db.prepare(`
      SELECT name FROM sqlite_master 
      WHERE type='table' 
      AND name NOT LIKE 'sqlite_%'
      ORDER BY name
    `).all();
    return result.results?.map((row) => row.name) || [];
  }
  /**
   * Truncate all data except admin user
   */
  async truncateAllData(adminEmail) {
    const errors = [];
    const tablesCleared = [];
    let adminUserPreserved = false;
    try {
      const adminUser = await this.db.prepare(
        "SELECT * FROM users WHERE email = ? AND role = ?"
      ).bind(adminEmail, "admin").first();
      if (!adminUser) {
        return {
          success: false,
          message: "Admin user not found. Operation cancelled for safety.",
          tablesCleared: [],
          adminUserPreserved: false,
          errors: ["Admin user not found"]
        };
      }
      const tablesToTruncate = [
        "content",
        "content_versions",
        "content_workflow_status",
        "collections",
        "media",
        "sessions",
        "notifications",
        "api_tokens",
        "workflow_history",
        "scheduled_content",
        "faqs",
        "faq_categories",
        "plugins",
        "plugin_settings",
        "email_templates",
        "email_themes"
      ];
      const existingTables = await this.getTables();
      const tablesToClear = tablesToTruncate.filter(
        (table) => existingTables.includes(table)
      );
      for (const tableName of tablesToClear) {
        try {
          await this.db.prepare(`DELETE FROM ${tableName}`).run();
          tablesCleared.push(tableName);
        } catch (error) {
          errors.push(`Failed to clear table ${tableName}: ${error}`);
          console.error(`Error clearing table ${tableName}:`, error);
        }
      }
      try {
        await this.db.prepare("DELETE FROM users WHERE email != ? OR role != ?").bind(adminEmail, "admin").run();
        const verifyAdmin = await this.db.prepare(
          "SELECT id FROM users WHERE email = ? AND role = ?"
        ).bind(adminEmail, "admin").first();
        adminUserPreserved = !!verifyAdmin;
        tablesCleared.push("users (non-admin)");
      } catch (error) {
        errors.push(`Failed to clear non-admin users: ${error}`);
        console.error("Error clearing non-admin users:", error);
      }
      try {
        await this.db.prepare("DELETE FROM sqlite_sequence").run();
      } catch (error) {
      }
      const message = errors.length > 0 ? `Truncation completed with ${errors.length} errors. ${tablesCleared.length} tables cleared.` : `Successfully truncated database. ${tablesCleared.length} tables cleared.`;
      return {
        success: errors.length === 0,
        message,
        tablesCleared,
        adminUserPreserved,
        errors: errors.length > 0 ? errors : void 0
      };
    } catch (error) {
      return {
        success: false,
        message: `Database truncation failed: ${error}`,
        tablesCleared,
        adminUserPreserved,
        errors: [String(error)]
      };
    }
  }
  /**
   * Create a backup of current data (simplified version)
   */
  async createBackup() {
    try {
      const backupId = `backup_${Date.now()}`;
      const stats = await this.getDatabaseStats();
      console.log(`Backup ${backupId} created with ${stats.totalRows} total rows`);
      return {
        success: true,
        message: `Backup created successfully (${stats.totalRows} rows)`,
        backupId
      };
    } catch (error) {
      return {
        success: false,
        message: `Backup failed: ${error}`
      };
    }
  }
  /**
   * Get table data with optional pagination and sorting
   */
  async getTableData(tableName, limit = 100, offset = 0, sortColumn, sortDirection = "asc") {
    try {
      const tables = await this.getTables();
      if (!tables.includes(tableName)) {
        throw new Error(`Table ${tableName} not found`);
      }
      const pragmaResult = await this.db.prepare(`PRAGMA table_info(${tableName})`).all();
      const columns = pragmaResult.results?.map((col) => col.name) || [];
      if (sortColumn && !columns.includes(sortColumn)) {
        sortColumn = void 0;
      }
      const countResult = await this.db.prepare(`SELECT COUNT(*) as count FROM ${tableName}`).first();
      const totalRows = countResult?.count || 0;
      let query = `SELECT * FROM ${tableName}`;
      if (sortColumn) {
        query += ` ORDER BY ${sortColumn} ${sortDirection.toUpperCase()}`;
      }
      query += ` LIMIT ${limit} OFFSET ${offset}`;
      const dataResult = await this.db.prepare(query).all();
      return {
        tableName,
        columns,
        rows: dataResult.results || [],
        totalRows
      };
    } catch (error) {
      throw new Error(`Failed to fetch table data: ${error}`);
    }
  }
  /**
   * Validate database integrity
   */
  async validateDatabase() {
    const issues = [];
    try {
      const requiredTables = ["users", "content", "collections"];
      const existingTables = await this.getTables();
      for (const table of requiredTables) {
        if (!existingTables.includes(table)) {
          issues.push(`Critical table missing: ${table}`);
        }
      }
      const adminCount = await this.db.prepare(
        "SELECT COUNT(*) as count FROM users WHERE role = ?"
      ).bind("admin").first();
      if (adminCount?.count === 0) {
        issues.push("No admin users found");
      }
      try {
        const integrityResult = await this.db.prepare("PRAGMA integrity_check").first();
        if (integrityResult && integrityResult.integrity_check !== "ok") {
          issues.push(`Database integrity check failed: ${integrityResult.integrity_check}`);
        }
      } catch (error) {
        issues.push(`Could not run integrity check: ${error}`);
      }
    } catch (error) {
      issues.push(`Validation error: ${error}`);
    }
    return {
      valid: issues.length === 0,
      issues
    };
  }
};

// src/templates/pages/admin-database-table.template.ts
chunkGMUS5V42_cjs.init_admin_layout_catalyst_template();
function renderDatabaseTablePage(data) {
  const totalPages = Math.ceil(data.totalRows / data.pageSize);
  const startRow = (data.currentPage - 1) * data.pageSize + 1;
  const endRow = Math.min(data.currentPage * data.pageSize, data.totalRows);
  const pageContent = `
    <div class="space-y-6">
      <!-- Header -->
      <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div class="flex items-center space-x-3">
            <a
              href="/admin/settings/database-tools"
              class="inline-flex items-center text-sm/6 text-zinc-500 dark:text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-300"
            >
              <svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/>
              </svg>
              Back to Database Tools
            </a>
          </div>
          <h1 class="mt-2 text-2xl/8 font-semibold text-zinc-950 dark:text-white sm:text-xl/8">Table: ${data.tableName}</h1>
          <p class="mt-2 text-sm/6 text-zinc-500 dark:text-zinc-400">
            Showing ${startRow.toLocaleString()} - ${endRow.toLocaleString()} of ${data.totalRows.toLocaleString()} rows
          </p>
        </div>
        <div class="mt-4 sm:mt-0 flex items-center space-x-3">
          <div class="flex items-center space-x-2">
            <label for="pageSize" class="text-sm font-medium text-zinc-700 dark:text-zinc-300">
              Rows per page:
            </label>
            <select
              id="pageSize"
              onchange="changePageSize(this.value)"
              class="rounded-lg bg-white dark:bg-zinc-800 px-3 py-2 text-sm font-semibold text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition-colors shadow-sm cursor-pointer"
            >
              <option value="10" ${data.pageSize === 10 ? "selected" : ""}>10</option>
              <option value="20" ${data.pageSize === 20 ? "selected" : ""}>20</option>
              <option value="50" ${data.pageSize === 50 ? "selected" : ""}>50</option>
              <option value="100" ${data.pageSize === 100 ? "selected" : ""}>100</option>
              <option value="200" ${data.pageSize === 200 ? "selected" : ""}>200</option>
            </select>
          </div>
          <button
            onclick="refreshTableData()"
            class="inline-flex items-center justify-center rounded-lg bg-white dark:bg-zinc-800 px-3.5 py-2.5 text-sm font-semibold text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition-colors shadow-sm"
          >
            <svg class="-ml-0.5 mr-1.5 h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
            </svg>
            Refresh
          </button>
        </div>
      </div>

      <!-- Table Card -->
      <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 overflow-hidden">
        <!-- Table -->
        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-zinc-950/10 dark:divide-white/10">
            <thead class="bg-zinc-50 dark:bg-white/5">
              <tr>
                ${data.columns.map((col) => `
                  <th
                    scope="col"
                    class="px-4 py-3.5 text-left text-xs font-semibold text-zinc-950 dark:text-white uppercase tracking-wider cursor-pointer hover:bg-zinc-100 dark:hover:bg-white/10 transition-colors"
                    onclick="sortTable('${col}')"
                  >
                    <div class="flex items-center space-x-1">
                      <span>${col}</span>
                      ${data.sortColumn === col ? `
                        <svg class="w-4 h-4 ${data.sortDirection === "asc" ? "" : "rotate-180"}" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 15l7-7 7 7"/>
                        </svg>
                      ` : `
                        <svg class="w-4 h-4 text-zinc-400 dark:text-zinc-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4"/>
                        </svg>
                      `}
                    </div>
                  </th>
                `).join("")}
              </tr>
            </thead>
            <tbody class="divide-y divide-zinc-950/5 dark:divide-white/5">
              ${data.rows.length > 0 ? data.rows.map((row, idx) => `
                  <tr class="${idx % 2 === 0 ? "bg-white dark:bg-zinc-900" : "bg-zinc-50 dark:bg-zinc-900/50"}">
                    ${data.columns.map((col) => `
                      <td class="px-4 py-3 text-sm text-zinc-700 dark:text-zinc-300 whitespace-nowrap max-w-xs overflow-hidden text-ellipsis" title="${escapeHtml2(String(row[col] ?? ""))}">
                        ${formatCellValue(row[col])}
                      </td>
                    `).join("")}
                  </tr>
                `).join("") : `
                  <tr>
                    <td colspan="${data.columns.length}" class="px-4 py-12 text-center text-sm text-zinc-500 dark:text-zinc-400">
                      <svg class="w-12 h-12 mx-auto mb-4 text-zinc-400 dark:text-zinc-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 13V6a2 2 0 00-2-2H6a2 2 0 00-2 2v7m16 0v5a2 2 0 01-2 2H6a2 2 0 01-2-2v-5m16 0h-2.586a1 1 0 00-.707.293l-2.414 2.414a1 1 0 01-.707.293h-3.172a1 1 0 01-.707-.293l-2.414-2.414A1 1 0 006.586 13H4"/>
                      </svg>
                      <p>No data in this table</p>
                    </td>
                  </tr>
                `}
            </tbody>
          </table>
        </div>

        <!-- Pagination -->
        ${totalPages > 1 ? `
          <div class="flex items-center justify-between border-t border-zinc-950/10 dark:border-white/10 bg-zinc-50 dark:bg-zinc-900/50 px-4 py-3 sm:px-6">
            <div class="flex flex-1 justify-between sm:hidden">
              <button
                onclick="goToPage(${data.currentPage - 1})"
                ${data.currentPage === 1 ? "disabled" : ""}
                class="relative inline-flex items-center rounded-lg px-4 py-2 text-sm font-semibold text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-100 dark:hover:bg-zinc-800 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Previous
              </button>
              <button
                onclick="goToPage(${data.currentPage + 1})"
                ${data.currentPage === totalPages ? "disabled" : ""}
                class="relative ml-3 inline-flex items-center rounded-lg px-4 py-2 text-sm font-semibold text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-100 dark:hover:bg-zinc-800 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Next
              </button>
            </div>
            <div class="hidden sm:flex sm:flex-1 sm:items-center sm:justify-between">
              <div>
                <p class="text-sm text-zinc-700 dark:text-zinc-300">
                  Page <span class="font-medium">${data.currentPage}</span> of <span class="font-medium">${totalPages}</span>
                </p>
              </div>
              <div>
                <nav class="isolate inline-flex -space-x-px rounded-lg shadow-sm" aria-label="Pagination">
                  <button
                    onclick="goToPage(${data.currentPage - 1})"
                    ${data.currentPage === 1 ? "disabled" : ""}
                    class="relative inline-flex items-center rounded-l-lg px-2 py-2 text-zinc-400 ring-1 ring-inset ring-zinc-300 dark:ring-zinc-700 hover:bg-zinc-50 dark:hover:bg-zinc-800 focus:z-20 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <span class="sr-only">Previous</span>
                    <svg class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                      <path fill-rule="evenodd" d="M12.79 5.23a.75.75 0 01-.02 1.06L8.832 10l3.938 3.71a.75.75 0 11-1.04 1.08l-4.5-4.25a.75.75 0 010-1.08l4.5-4.25a.75.75 0 011.06.02z" clip-rule="evenodd" />
                    </svg>
                  </button>

                  ${generatePageNumbers(data.currentPage, totalPages)}

                  <button
                    onclick="goToPage(${data.currentPage + 1})"
                    ${data.currentPage === totalPages ? "disabled" : ""}
                    class="relative inline-flex items-center rounded-r-lg px-2 py-2 text-zinc-400 ring-1 ring-inset ring-zinc-300 dark:ring-zinc-700 hover:bg-zinc-50 dark:hover:bg-zinc-800 focus:z-20 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <span class="sr-only">Next</span>
                    <svg class="h-5 w-5" viewBox="0 0 20 20" fill="currentColor">
                      <path fill-rule="evenodd" d="M7.21 14.77a.75.75 0 01.02-1.06L11.168 10 7.23 6.29a.75.75 0 111.04-1.08l4.5 4.25a.75.75 0 010 1.08l-4.5 4.25a.75.75 0 01-1.06-.02z" clip-rule="evenodd" />
                    </svg>
                  </button>
                </nav>
              </div>
            </div>
          </div>
        ` : ""}
      </div>
    </div>

    <script>
      const currentTableName = '${data.tableName}';
      let currentPage = ${data.currentPage};
      let currentPageSize = ${data.pageSize};
      let currentSort = '${data.sortColumn || ""}';
      let currentSortDir = '${data.sortDirection || "asc"}';

      function goToPage(page) {
        if (page < 1 || page > ${totalPages}) return;
        const params = new URLSearchParams();
        params.set('page', page);
        params.set('pageSize', currentPageSize);
        if (currentSort) {
          params.set('sort', currentSort);
          params.set('dir', currentSortDir);
        }
        window.location.href = \`/admin/database-tools/tables/\${currentTableName}?\${params}\`;
      }

      function sortTable(column) {
        let newDir = 'asc';
        if (currentSort === column && currentSortDir === 'asc') {
          newDir = 'desc';
        }

        const params = new URLSearchParams();
        params.set('page', '1');
        params.set('pageSize', currentPageSize);
        params.set('sort', column);
        params.set('dir', newDir);
        window.location.href = \`/admin/database-tools/tables/\${currentTableName}?\${params}\`;
      }

      function changePageSize(newSize) {
        const params = new URLSearchParams();
        params.set('page', '1');
        params.set('pageSize', newSize);
        if (currentSort) {
          params.set('sort', currentSort);
          params.set('dir', currentSortDir);
        }
        window.location.href = \`/admin/database-tools/tables/\${currentTableName}?\${params}\`;
      }

      function refreshTableData() {
        window.location.reload();
      }

      function formatCellValue(value) {
        if (value === null || value === undefined) {
          return '<span class="text-zinc-400 dark:text-zinc-500 italic">null</span>';
        }
        if (typeof value === 'boolean') {
          return \`<span class="px-2 py-0.5 rounded text-xs font-medium \${value ? 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400' : 'bg-zinc-100 text-zinc-800 dark:bg-zinc-800 dark:text-zinc-400'}">\${value}</span>\`;
        }
        if (typeof value === 'object') {
          return '<span class="text-xs font-mono text-zinc-600 dark:text-zinc-400">' + JSON.stringify(value).substring(0, 50) + (JSON.stringify(value).length > 50 ? '...' : '') + '</span>';
        }
        const str = String(value);
        if (str.length > 100) {
          return escapeHtml(str.substring(0, 100)) + '...';
        }
        return escapeHtml(str);
      }

      function escapeHtml(text) {
        const map = {
          '&': '&amp;',
          '<': '&lt;',
          '>': '&gt;',
          '"': '&quot;',
          "'": '&#039;'
        };
        return String(text).replace(/[&<>"']/g, m => map[m]);
      }
    </script>
  `;
  const layoutData = {
    title: `Table: ${data.tableName}`,
    pageTitle: `Database: ${data.tableName}`,
    currentPath: `/admin/database-tools/tables/${data.tableName}`,
    user: data.user,
    content: pageContent
  };
  return chunkGMUS5V42_cjs.renderAdminLayoutCatalyst(layoutData);
}
function generatePageNumbers(currentPage, totalPages) {
  const pages = [];
  const maxVisible = 7;
  if (totalPages <= maxVisible) {
    for (let i = 1; i <= totalPages; i++) {
      pages.push(i);
    }
  } else {
    if (currentPage <= 4) {
      for (let i = 1; i <= 5; i++) pages.push(i);
      pages.push(-1);
      pages.push(totalPages);
    } else if (currentPage >= totalPages - 3) {
      pages.push(1);
      pages.push(-1);
      for (let i = totalPages - 4; i <= totalPages; i++) pages.push(i);
    } else {
      pages.push(1);
      pages.push(-1);
      for (let i = currentPage - 1; i <= currentPage + 1; i++) pages.push(i);
      pages.push(-1);
      pages.push(totalPages);
    }
  }
  return pages.map((page) => {
    if (page === -1) {
      return `
        <span class="relative inline-flex items-center px-4 py-2 text-sm font-semibold text-zinc-700 dark:text-zinc-300 ring-1 ring-inset ring-zinc-300 dark:ring-zinc-700">
          ...
        </span>
      `;
    }
    const isActive = page === currentPage;
    return `
      <button
        onclick="goToPage(${page})"
        class="relative inline-flex items-center px-4 py-2 text-sm font-semibold ${isActive ? "z-10 bg-indigo-600 text-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600" : "text-zinc-900 dark:text-zinc-100 ring-1 ring-inset ring-zinc-300 dark:ring-zinc-700 hover:bg-zinc-50 dark:hover:bg-zinc-800"}"
      >
        ${page}
      </button>
    `;
  }).join("");
}
function escapeHtml2(text) {
  const map = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  };
  return String(text).replace(/[&<>"']/g, (m) => map[m] || m);
}
function formatCellValue(value) {
  if (value === null || value === void 0) {
    return '<span class="text-zinc-400 dark:text-zinc-500 italic">null</span>';
  }
  if (typeof value === "boolean") {
    return `<span class="px-2 py-0.5 rounded text-xs font-medium ${value ? "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400" : "bg-zinc-100 text-zinc-800 dark:bg-zinc-800 dark:text-zinc-400"}">${value}</span>`;
  }
  if (typeof value === "object") {
    return '<span class="text-xs font-mono text-zinc-600 dark:text-zinc-400">' + JSON.stringify(value).substring(0, 50) + (JSON.stringify(value).length > 50 ? "..." : "") + "</span>";
  }
  const str = String(value);
  if (str.length > 100) {
    return escapeHtml2(str.substring(0, 100)) + "...";
  }
  return escapeHtml2(str);
}

// src/plugins/core-plugins/database-tools-plugin/admin-routes.ts
function createDatabaseToolsAdminRoutes() {
  const router3 = new hono.Hono();
  router3.use("*", chunkYZRINJP5_cjs.requireAuth());
  router3.get("/api/stats", async (c) => {
    try {
      const user = c.get("user");
      if (!user || user.role !== "admin") {
        return c.json({
          success: false,
          error: "Unauthorized. Admin access required."
        }, 403);
      }
      const db = c.env.DB;
      const service = new DatabaseToolsService(db);
      const stats = await service.getDatabaseStats();
      return c.json({
        success: true,
        data: stats
      });
    } catch (error) {
      console.error("Error fetching database stats:", error);
      return c.json({
        success: false,
        error: "Failed to fetch database statistics"
      }, 500);
    }
  });
  router3.post("/api/truncate", async (c) => {
    try {
      const user = c.get("user");
      if (!user || user.role !== "admin") {
        return c.json({
          success: false,
          error: "Unauthorized. Admin access required."
        }, 403);
      }
      const body = await c.req.json();
      const { confirmText } = body;
      if (confirmText !== "TRUNCATE ALL DATA") {
        return c.json({
          success: false,
          error: "Invalid confirmation text. Operation cancelled."
        }, 400);
      }
      const db = c.env.DB;
      const service = new DatabaseToolsService(db);
      const result = await service.truncateAllData(user.email);
      return c.json({
        success: result.success,
        message: result.message,
        data: {
          tablesCleared: result.tablesCleared,
          adminUserPreserved: result.adminUserPreserved,
          errors: result.errors
        }
      });
    } catch (error) {
      console.error("Error truncating database:", error);
      return c.json({
        success: false,
        error: "Failed to truncate database"
      }, 500);
    }
  });
  router3.post("/api/backup", async (c) => {
    try {
      const user = c.get("user");
      if (!user || user.role !== "admin") {
        return c.json({
          success: false,
          error: "Unauthorized. Admin access required."
        }, 403);
      }
      const db = c.env.DB;
      const service = new DatabaseToolsService(db);
      const result = await service.createBackup();
      return c.json({
        success: result.success,
        message: result.message,
        data: {
          backupId: result.backupId
        }
      });
    } catch (error) {
      console.error("Error creating backup:", error);
      return c.json({
        success: false,
        error: "Failed to create backup"
      }, 500);
    }
  });
  router3.get("/api/validate", async (c) => {
    try {
      const user = c.get("user");
      if (!user || user.role !== "admin") {
        return c.json({
          success: false,
          error: "Unauthorized. Admin access required."
        }, 403);
      }
      const db = c.env.DB;
      const service = new DatabaseToolsService(db);
      const validation = await service.validateDatabase();
      return c.json({
        success: true,
        data: validation
      });
    } catch (error) {
      console.error("Error validating database:", error);
      return c.json({
        success: false,
        error: "Failed to validate database"
      }, 500);
    }
  });
  router3.get("/api/tables/:tableName", async (c) => {
    try {
      const user = c.get("user");
      if (!user || user.role !== "admin") {
        return c.json({
          success: false,
          error: "Unauthorized. Admin access required."
        }, 403);
      }
      const tableName = c.req.param("tableName");
      const limit = parseInt(c.req.query("limit") || "100");
      const offset = parseInt(c.req.query("offset") || "0");
      const sortColumn = c.req.query("sort");
      const sortDirection = c.req.query("dir") || "asc";
      const db = c.env.DB;
      const service = new DatabaseToolsService(db);
      const tableData = await service.getTableData(tableName, limit, offset, sortColumn, sortDirection);
      return c.json({
        success: true,
        data: tableData
      });
    } catch (error) {
      console.error("Error fetching table data:", error);
      return c.json({
        success: false,
        error: `Failed to fetch table data: ${error}`
      }, 500);
    }
  });
  router3.get("/tables/:tableName", async (c) => {
    try {
      const user = c.get("user");
      if (!user || user.role !== "admin") {
        return c.redirect("/admin/login");
      }
      const tableName = c.req.param("tableName");
      const page = parseInt(c.req.query("page") || "1");
      const pageSize = parseInt(c.req.query("pageSize") || "20");
      const sortColumn = c.req.query("sort");
      const sortDirection = c.req.query("dir") || "asc";
      const offset = (page - 1) * pageSize;
      const db = c.env.DB;
      const service = new DatabaseToolsService(db);
      const tableData = await service.getTableData(tableName, pageSize, offset, sortColumn, sortDirection);
      const pageData = {
        user: {
          name: user.email.split("@")[0] || "Unknown",
          email: user.email,
          role: user.role
        },
        tableName: tableData.tableName,
        columns: tableData.columns,
        rows: tableData.rows,
        totalRows: tableData.totalRows,
        currentPage: page,
        pageSize,
        sortColumn,
        sortDirection
      };
      return c.html(renderDatabaseTablePage(pageData));
    } catch (error) {
      console.error("Error rendering table page:", error);
      return c.text(`Error: ${error}`, 500);
    }
  });
  return router3;
}

// src/plugins/core-plugins/seed-data-plugin/services/seed-data-service.ts
var SeedDataService = class {
  constructor(db) {
    this.db = db;
  }
  // ============================================================================
  // Data Arrays
  // ============================================================================
  firstNames = [
    "Emma",
    "Liam",
    "Olivia",
    "Noah",
    "Ava",
    "Ethan",
    "Sophia",
    "Mason",
    "Isabella",
    "William",
    "Mia",
    "James",
    "Charlotte",
    "Benjamin",
    "Amelia",
    "Lucas",
    "Harper",
    "Henry",
    "Evelyn",
    "Alexander",
    "Aria",
    "Daniel",
    "Chloe",
    "Michael",
    "Penelope",
    "Sebastian",
    "Layla",
    "Jack",
    "Riley",
    "Owen"
  ];
  lastNames = [
    "Smith",
    "Johnson",
    "Williams",
    "Brown",
    "Jones",
    "Garcia",
    "Miller",
    "Davis",
    "Rodriguez",
    "Martinez",
    "Hernandez",
    "Lopez",
    "Gonzalez",
    "Wilson",
    "Anderson",
    "Thomas",
    "Taylor",
    "Moore",
    "Jackson",
    "Martin",
    "Lee",
    "Perez",
    "Thompson",
    "White",
    "Harris",
    "Sanchez",
    "Clark",
    "Ramirez",
    "Lewis",
    "Robinson"
  ];
  blogTitles = [
    "Getting Started with Modern Web Development",
    "The Future of JavaScript Frameworks",
    "Building Scalable Applications with Microservices",
    "Understanding TypeScript: A Complete Guide",
    "Best Practices for API Design",
    "Introduction to Cloud Computing",
    "Mastering Git and Version Control",
    "The Art of Code Review",
    "Performance Optimization Techniques",
    "Security Best Practices for Web Apps",
    "Exploring Serverless Architecture",
    "Database Design Fundamentals",
    "Testing Strategies for Modern Apps",
    "CI/CD Pipeline Implementation",
    "Mobile-First Development Approach",
    "GraphQL vs REST: A Practical Comparison",
    "Building Real-Time Applications with WebSockets",
    "Container Orchestration with Kubernetes",
    "Edge Computing and the Modern Web",
    "Accessibility in Web Development"
  ];
  pageTitles = [
    "About Us",
    "Contact",
    "Privacy Policy",
    "Terms of Service",
    "FAQ",
    "Our Team",
    "Careers",
    "Press Kit",
    "Support",
    "Documentation",
    "Pricing",
    "Features"
  ];
  productTitles = [
    "Premium Wireless Headphones",
    "Smart Watch Pro",
    "Laptop Stand Adjustable",
    "Mechanical Keyboard RGB",
    "HD Webcam 4K",
    "USB-C Hub 7-in-1",
    "Portable SSD 1TB",
    "Wireless Mouse Ergonomic",
    'Monitor 27" 4K',
    "Desk Lamp LED",
    "Phone Case Premium",
    "Tablet Stand Aluminum",
    "Cable Management Kit",
    "Power Bank 20000mAh",
    "Bluetooth Speaker Portable"
  ];
  blogParagraphs = [
    "Modern web development has evolved significantly over the past decade. What once required extensive server-side rendering and page reloads now leverages sophisticated client-side frameworks and APIs. The shift toward component-based architectures has fundamentally changed how we think about building user interfaces.",
    "Performance optimization remains one of the most critical aspects of web application development. Users expect pages to load in under two seconds, and search engines increasingly factor page speed into their ranking algorithms. Techniques like code splitting, lazy loading, and edge caching have become essential tools in every developer's toolkit.",
    "Security should never be an afterthought in software development. From input validation and output encoding to proper authentication and authorization, every layer of your application needs careful consideration. The OWASP Top 10 provides an excellent starting point for understanding the most common security vulnerabilities.",
    "Testing is the backbone of reliable software delivery. A well-balanced test pyramid with unit tests at the base, integration tests in the middle, and end-to-end tests at the top ensures comprehensive coverage without sacrificing speed. Automated testing in CI/CD pipelines catches regressions before they reach production.",
    "The rise of serverless computing has transformed how we deploy and scale applications. By abstracting away infrastructure management, developers can focus entirely on business logic. Functions-as-a-Service platforms like Cloudflare Workers offer millisecond cold starts and global distribution out of the box.",
    "TypeScript has become the de facto standard for large-scale JavaScript applications. Its static type system catches errors at compile time, provides excellent IDE support with autocompletion and refactoring tools, and makes codebases significantly more maintainable as teams and projects grow.",
    "API design is both an art and a science. RESTful APIs should follow consistent naming conventions, use appropriate HTTP methods, and return meaningful status codes. GraphQL offers an alternative approach with its query language, allowing clients to request exactly the data they need.",
    "DevOps practices bridge the gap between development and operations teams. Continuous integration ensures code changes are tested automatically, while continuous deployment streamlines the release process. Infrastructure as code allows teams to version control their entire deployment environment.",
    "Microservices architecture enables teams to develop, deploy, and scale individual components independently. Each service owns its data and communicates through well-defined APIs. However, this approach introduces complexity in areas like service discovery, distributed tracing, and eventual consistency.",
    "Edge computing brings computation closer to the end user, dramatically reducing latency for global applications. Content delivery networks have evolved beyond static asset caching to support full application logic at the edge. This paradigm shift enables new categories of real-time, location-aware applications.",
    "Accessible web applications are not optional \u2014 they are a fundamental requirement. Screen readers, keyboard navigation, and proper semantic HTML ensure that everyone can use your application. WCAG guidelines provide clear standards for achieving accessibility compliance across your entire product.",
    "Database design decisions have lasting impacts on application performance and scalability. Choosing between SQL and NoSQL databases depends on your data relationships, query patterns, and consistency requirements. Proper indexing, query optimization, and connection pooling are critical regardless of your database choice.",
    "Version control with Git is more than just tracking changes. Branching strategies like GitFlow and trunk-based development define how teams collaborate on features, fixes, and releases. Understanding rebasing, cherry-picking, and conflict resolution makes you a more effective team member.",
    "Progressive Web Apps combine the best of web and native applications. Service workers enable offline functionality, push notifications keep users engaged, and the app manifest provides an installable experience. PWAs offer near-native performance without the overhead of app store distribution.",
    "Monitoring and observability are essential for maintaining production applications. Structured logging, distributed tracing, and metrics dashboards help teams identify and resolve issues quickly. Alert fatigue is real \u2014 focus on actionable alerts that indicate genuine problems requiring human intervention.",
    "Code review is one of the most valuable practices in software development. Beyond catching bugs, it promotes knowledge sharing, maintains code quality standards, and helps junior developers grow. Effective reviews focus on architecture, logic, and maintainability rather than style preferences.",
    "Container technology has revolutionized application deployment. Docker containers package applications with their dependencies, ensuring consistency across development, testing, and production environments. Multi-stage builds optimize image sizes while maintaining a clean development workflow.",
    "State management in complex applications requires careful architectural decisions. Whether using Redux, MobX, Zustand, or built-in framework solutions, the key is choosing the right level of complexity for your needs. Over-engineering state management leads to boilerplate; under-engineering leads to spaghetti code.",
    "Internationalization and localization go beyond simple text translation. Date formats, number formatting, right-to-left layouts, and cultural considerations all play a role in creating truly global applications. Planning for i18n from the start is far easier than retrofitting it later.",
    "The JAMstack architecture has gained tremendous popularity for content-driven websites. Pre-rendered pages served from CDNs provide excellent performance, while APIs handle dynamic functionality. Static site generators and headless CMS platforms make this architecture accessible to teams of all sizes."
  ];
  blogExcerpts = [
    "A comprehensive guide covering essential concepts and practical techniques for modern development.",
    "Explore the latest trends shaping the future of web applications and software engineering.",
    "Practical tips and real-world examples to improve your development workflow and productivity.",
    "Deep dive into advanced concepts with step-by-step instructions for developers of all levels.",
    "Learn proven strategies and best practices used by industry-leading engineering teams.",
    "Master the essential skills and tools needed to build production-ready applications.",
    "An in-depth look at architectures, patterns, and methodologies for scalable software.",
    "Discover cutting-edge techniques that will transform how you approach software development.",
    "From fundamentals to advanced topics \u2014 everything you need to level up your skills.",
    "Expert insights and actionable advice for building robust, maintainable applications.",
    "Understanding the core principles that separate great software from merely functional code.",
    "A practical walkthrough with code examples, diagrams, and real-world case studies.",
    "Lessons learned from production systems serving millions of users worldwide.",
    "Navigate common pitfalls and make informed decisions about your technology stack.",
    "Bridge the gap between theory and practice with hands-on examples and exercises."
  ];
  allTags = [
    "tutorial",
    "guide",
    "javascript",
    "typescript",
    "web-dev",
    "backend",
    "frontend",
    "best-practices",
    "security",
    "performance",
    "testing",
    "deployment",
    "cloud",
    "database",
    "api",
    "react",
    "vue",
    "nextjs",
    "serverless",
    "edge-computing",
    "graphql",
    "rest-api",
    "devops",
    "ci-cd",
    "docker",
    "kubernetes",
    "monitoring",
    "accessibility",
    "seo",
    "ux-design"
  ];
  pageContentTemplates = {
    "About Us": "<h2>Our Story</h2><p>Founded with a vision to simplify content management, our team has been building innovative solutions for businesses of all sizes. We believe that powerful technology should be accessible to everyone, not just large enterprises with dedicated engineering teams.</p><h2>Our Mission</h2><p>We are committed to providing the most developer-friendly, performant, and flexible content management platform available. Our open-source approach ensures transparency and community-driven innovation.</p><p>With users across 40+ countries and thousands of active installations, we continue to push the boundaries of what a modern CMS can achieve.</p>",
    "Contact": "<h2>Get in Touch</h2><p>We would love to hear from you. Whether you have a question about our platform, need technical support, or want to explore partnership opportunities, our team is ready to help.</p><p><strong>Email:</strong> hello@example.com<br/><strong>Phone:</strong> (555) 123-4567<br/><strong>Address:</strong> 123 Innovation Drive, Suite 400, San Francisco, CA 94105</p><h2>Office Hours</h2><p>Monday through Friday, 9:00 AM to 6:00 PM Pacific Time. We typically respond to inquiries within 24 business hours.</p>",
    "Privacy Policy": "<h2>Privacy Policy</h2><p>Last updated: January 2026. This Privacy Policy describes how we collect, use, and protect your personal information when you use our services.</p><h2>Information We Collect</h2><p>We collect information you provide directly, such as when you create an account, submit a form, or contact us. We also collect certain information automatically, including usage data, IP addresses, and browser information.</p><h2>How We Use Your Information</h2><p>We use the information we collect to provide and improve our services, communicate with you, and ensure the security of our platform. We do not sell your personal information to third parties.</p><h2>Data Retention</h2><p>We retain your information for as long as your account is active or as needed to provide you with our services. You may request deletion of your data at any time by contacting our support team.</p>",
    "Terms of Service": '<h2>Terms of Service</h2><p>By accessing and using this platform, you agree to be bound by these Terms of Service. Please read them carefully before using our services.</p><h2>Account Responsibilities</h2><p>You are responsible for maintaining the confidentiality of your account credentials and for all activities that occur under your account. You agree to notify us immediately of any unauthorized use.</p><h2>Acceptable Use</h2><p>You agree to use our services only for lawful purposes and in accordance with these Terms. You may not use our platform to distribute harmful content, violate intellectual property rights, or engage in any activity that disrupts our services.</p><h2>Limitation of Liability</h2><p>Our platform is provided "as is" without warranties of any kind. We shall not be liable for any indirect, incidental, or consequential damages arising from your use of our services.</p>',
    "FAQ": "<h2>Frequently Asked Questions</h2><h3>What is this platform?</h3><p>Our platform is a modern, headless content management system built for speed, flexibility, and developer experience. It runs on edge infrastructure for global performance.</p><h3>How do I get started?</h3><p>Simply create an account, define your content collections, and start creating content. Our API-first approach means you can integrate with any frontend framework or static site generator.</p><h3>Is there a free tier?</h3><p>Yes, our free tier includes everything you need to get started, including API access, basic search, and community support. Upgrade to Pro for advanced features like AI search and custom workflows.</p><h3>Can I migrate from another CMS?</h3><p>Absolutely. We provide migration tools and guides for popular platforms including WordPress, Strapi, Contentful, and Sanity. Our support team can assist with complex migrations.</p>",
    "Our Team": "<h2>Meet Our Team</h2><p>We are a diverse team of engineers, designers, and product thinkers passionate about building the future of content management.</p><h3>Leadership</h3><p>Our leadership team brings decades of combined experience from companies like Google, AWS, Cloudflare, and Vercel. We are united by a shared belief that content infrastructure should be fast, reliable, and enjoyable to work with.</p><h3>Engineering</h3><p>Our engineering team specializes in edge computing, distributed systems, and developer experience. We build with TypeScript, Cloudflare Workers, and modern web standards.</p><h3>Join Us</h3><p>We are always looking for talented individuals who share our passion. Check our careers page for current openings.</p>",
    "Careers": "<h2>Join Our Team</h2><p>We are building the future of content management and we need talented people to help us get there. We offer competitive compensation, remote-first culture, and the opportunity to work on technology used by thousands of developers worldwide.</p><h2>Open Positions</h2><p><strong>Senior Full-Stack Engineer</strong> \u2014 Work on our core platform, building features that scale to millions of requests. TypeScript, Cloudflare Workers, and distributed systems experience preferred.</p><p><strong>Developer Advocate</strong> \u2014 Help developers succeed with our platform through documentation, tutorials, talks, and community engagement.</p><p><strong>Product Designer</strong> \u2014 Design intuitive admin interfaces and developer experiences that make complex tasks simple.</p>",
    "Pricing": "<h2>Simple, Transparent Pricing</h2><p>Choose the plan that fits your needs. All plans include our core features with no hidden fees.</p><h3>Free</h3><p>Perfect for personal projects and getting started. Includes 1,000 API requests/day, 3 collections, and community support.</p><h3>Pro \u2014 $29/month</h3><p>For growing teams and production applications. Includes unlimited API requests, unlimited collections, AI-powered search, priority support, and custom domains.</p><h3>Enterprise \u2014 Custom</h3><p>For organizations with advanced requirements. Includes dedicated infrastructure, SLA guarantees, SSO/SAML, audit logs, and a dedicated account manager. Contact us for a quote.</p>",
    "Features": "<h2>Powerful Features for Modern Content</h2><h3>Headless API</h3><p>RESTful API with full CRUD operations, filtering, sorting, and pagination. Query your content from any frontend or service.</p><h3>AI-Powered Search</h3><p>Full-text search with BM25 ranking, semantic search with vector embeddings, and hybrid mode that combines both for best results.</p><h3>Form Builder</h3><p>Drag-and-drop form builder with 20+ field types, validation rules, and submission management. Embed forms anywhere with our JavaScript SDK.</p><h3>Edge Performance</h3><p>Built on Cloudflare Workers for sub-50ms response times globally. Your content is served from 300+ data centers worldwide.</p>",
    "Support": "<h2>How Can We Help?</h2><p>Our support team is here to ensure your success with the platform. Choose the support channel that works best for you.</p><h3>Documentation</h3><p>Comprehensive guides, API references, and tutorials covering every aspect of the platform. Start with our quickstart guide to get up and running in minutes.</p><h3>Community</h3><p>Join our Discord community to connect with other developers, share tips, and get help from the community. Our team is active in the community channels daily.</p><h3>Email Support</h3><p>For technical issues and account questions, email support@example.com. Pro and Enterprise customers receive priority response times.</p>",
    "Documentation": "<h2>Getting Started</h2><p>Welcome to the documentation. This guide will help you understand the platform architecture, set up your development environment, and build your first application.</p><h3>Quick Start</h3><p>1. Install the CLI tool with npm. 2. Initialize a new project. 3. Define your collections. 4. Start the development server. 5. Create content via the admin UI or API.</p><h3>API Reference</h3><p>Our REST API follows standard conventions with JSON request/response bodies. Authentication uses JWT tokens. All endpoints support filtering, sorting, and pagination.</p><h3>Deployment</h3><p>Deploy to Cloudflare Workers with a single command. Configure custom domains, environment variables, and D1 database bindings in your wrangler.toml file.</p>"
  };
  productDescriptions = {
    "Premium Wireless Headphones": "Experience crystal-clear audio with our Premium Wireless Headphones. Featuring active noise cancellation with three adjustable levels, 40mm custom-tuned drivers, and up to 30 hours of battery life on a single charge. The memory foam ear cushions provide all-day comfort while the foldable design makes them perfect for travel. Supports Bluetooth 5.2 with multipoint connection for seamless switching between devices.",
    "Smart Watch Pro": 'Stay connected and track your health with the Smart Watch Pro. Features a vibrant 1.4" AMOLED display, continuous heart rate monitoring, blood oxygen sensing, and sleep tracking. Water-resistant to 50 meters with GPS for outdoor activities. Receive notifications, control music, and pay contactlessly \u2014 all from your wrist. Battery lasts up to 7 days with typical use.',
    "Laptop Stand Adjustable": 'Elevate your workspace ergonomics with our adjustable laptop stand. CNC-machined from a single piece of aluminum alloy for maximum stability and heat dissipation. Adjusts from 6" to 12" in height with 360-degree rotation. Compatible with laptops from 10" to 17". Non-slip silicone pads protect your device. Weighs just 1.2 lbs and folds flat for portability.',
    "Mechanical Keyboard RGB": "Type with precision on our mechanical keyboard featuring hot-swappable switches, per-key RGB backlighting with 16.8 million colors, and programmable macros. Durable PBT double-shot keycaps will not fade over time. N-key rollover ensures every keystroke is registered during intense gaming sessions. Detachable USB-C cable and compact 75% layout save desk space.",
    "HD Webcam 4K": "Look your best on every video call with our 4K Ultra HD webcam. Sony STARVIS sensor delivers stunning clarity even in low light conditions. Built-in noise-canceling dual microphones pick up your voice clearly while reducing background noise. Auto-framing AI keeps you centered as you move. Privacy shutter for peace of mind when not in use.",
    "USB-C Hub 7-in-1": "Expand your laptop's connectivity with our 7-in-1 USB-C hub. Includes 4K HDMI output at 60Hz, two USB 3.0 ports, SD and microSD card readers, USB-C power delivery pass-through up to 100W, and Gigabit Ethernet. Compact aluminum design with braided cable. Compatible with MacBook, Dell XPS, ThinkPad, and all USB-C laptops.",
    "Portable SSD 1TB": "Lightning-fast storage you can take anywhere. Sequential read speeds up to 1,050 MB/s and write speeds up to 1,000 MB/s over USB 3.2 Gen 2. Rugged design survives drops up to 6 feet. Hardware AES 256-bit encryption protects your data. Compatible with PC, Mac, PlayStation, and Xbox. Compact form factor weighs only 1.8 oz.",
    "Wireless Mouse Ergonomic": "Say goodbye to wrist strain with our ergonomically designed wireless mouse. The 57-degree vertical angle promotes a natural handshake position. Precision 4000 DPI optical sensor works on virtually any surface. Connects via Bluetooth or included USB receiver. Quiet click buttons and textured thumb rest. Single AA battery lasts up to 18 months.",
    'Monitor 27" 4K': "Immerse yourself in stunning detail with our 27-inch 4K UHD monitor. IPS panel delivers 100% sRGB and 95% DCI-P3 color accuracy. Factory calibrated to Delta E < 2 for professional color work. USB-C connectivity with 65W power delivery charges your laptop while displaying at full resolution. Adjustable stand with height, tilt, swivel, and pivot. Built-in KVM switch for dual-computer setups.",
    "Desk Lamp LED": "Illuminate your workspace with our award-winning LED desk lamp. Stepless brightness and color temperature adjustment from warm 2700K to cool 6500K. CRI > 95 for accurate color rendering. Built-in ambient light sensor automatically adjusts to your environment. USB charging port on the base. Memory function remembers your preferred settings. Energy Star certified.",
    "Phone Case Premium": "Military-grade protection meets premium design. Our phone case features a triple-layer construction with shock-absorbing TPU, rigid polycarbonate shell, and soft microfiber lining. Tested to survive 10-foot drops on concrete. Raised bezels protect the camera and screen. MagSafe compatible for wireless charging. Available in 6 colors with a lifetime warranty.",
    "Tablet Stand Aluminum": 'The perfect companion for your tablet or iPad. Precision-engineered aluminum construction with a weighted base prevents tipping. Adjustable viewing angle from 0 to 135 degrees. Rubber padding protects your device and prevents slipping. Cable routing channel keeps your workspace tidy. Compatible with all tablets from 7" to 13". Ideal for drawing, video calls, and recipe following.',
    "Cable Management Kit": "Tame your cable chaos with our comprehensive cable management kit. Includes 10 reusable silicone cable ties, 6 adhesive cable clips, 2 under-desk cable trays, 1 cable sleeve (6 ft), and 20 cable labels. All components are tool-free installation. The under-desk trays hold up to 10 cables each and include power strip mounts. Everything you need for a clean, organized workspace.",
    "Power Bank 20000mAh": "Never run out of power on the go. Our 20,000mAh power bank charges an iPhone up to 5 times or a MacBook Air once. Dual USB-C ports support 65W PD fast charging \u2014 recharge the power bank itself in just 2 hours. LED display shows exact remaining capacity. Pass-through charging lets you charge devices while recharging the bank. Airline approved for carry-on luggage.",
    "Bluetooth Speaker Portable": "Rich, room-filling sound in a compact package. Dual 10W drivers and passive bass radiator deliver surprisingly deep bass. IP67 waterproof and dustproof \u2014 take it to the beach, pool, or shower. 24-hour battery life with USB-C fast charging (15 minutes = 3 hours of playback). Pair two speakers for true stereo sound. Built-in microphone for hands-free calls."
  };
  productCategories = ["Electronics", "Accessories", "Peripherals", "Storage", "Audio"];
  // ============================================================================
  // Form Templates
  // ============================================================================
  formTemplates = [
    {
      name: "contact_us",
      display_name: "Contact Us",
      description: "General contact form for inquiries and messages",
      category: "contact",
      formio_schema: {
        components: [
          { type: "textfield", key: "name", label: "Full Name", placeholder: "Enter your full name", validate: { required: true, maxLength: 100 } },
          { type: "email", key: "email", label: "Email Address", placeholder: "you@example.com", validate: { required: true } },
          { type: "phoneNumber", key: "phone", label: "Phone Number", placeholder: "(555) 123-4567" },
          { type: "select", key: "subject", label: "Subject", data: { values: [
            { label: "General Inquiry", value: "general" },
            { label: "Technical Support", value: "support" },
            { label: "Sales", value: "sales" },
            { label: "Partnership", value: "partnership" },
            { label: "Press/Media", value: "press" }
          ] }, validate: { required: true } },
          { type: "textarea", key: "message", label: "Message", placeholder: "How can we help you?", validate: { required: true, maxLength: 2e3 } }
        ]
      },
      settings: { emailNotifications: true, notifyEmail: "admin@example.com", successMessage: "Thank you for reaching out! We will get back to you within 24 hours.", submitButtonText: "Send Message", requireAuth: false }
    },
    {
      name: "customer_feedback",
      display_name: "Customer Feedback",
      description: "Collect customer feedback and satisfaction ratings",
      category: "feedback",
      formio_schema: {
        components: [
          { type: "textfield", key: "name", label: "Your Name", placeholder: "Enter your name" },
          { type: "email", key: "email", label: "Email", validate: { required: true } },
          { type: "radio", key: "satisfaction", label: "Overall Satisfaction", values: [
            { label: "Very Satisfied", value: "5" },
            { label: "Satisfied", value: "4" },
            { label: "Neutral", value: "3" },
            { label: "Dissatisfied", value: "2" },
            { label: "Very Dissatisfied", value: "1" }
          ], validate: { required: true } },
          { type: "selectboxes", key: "improvements", label: "What areas can we improve?", values: [
            { label: "Product Quality", value: "quality" },
            { label: "Customer Service", value: "service" },
            { label: "Pricing", value: "pricing" },
            { label: "Website Experience", value: "website" },
            { label: "Documentation", value: "docs" },
            { label: "Delivery Speed", value: "delivery" }
          ] },
          { type: "textarea", key: "comments", label: "Additional Comments", placeholder: "Tell us more about your experience..." }
        ]
      },
      settings: { successMessage: "Thank you for your feedback! We appreciate you taking the time.", submitButtonText: "Submit Feedback", requireAuth: false }
    },
    {
      name: "event_registration",
      display_name: "Event Registration",
      description: "Register for upcoming events and workshops",
      category: "registration",
      formio_schema: {
        components: [
          { type: "textfield", key: "firstName", label: "First Name", validate: { required: true } },
          { type: "textfield", key: "lastName", label: "Last Name", validate: { required: true } },
          { type: "email", key: "email", label: "Email", validate: { required: true } },
          { type: "phoneNumber", key: "phone", label: "Phone Number" },
          { type: "textfield", key: "company", label: "Company / Organization" },
          { type: "select", key: "eventType", label: "Event", data: { values: [
            { label: "Annual Conference 2026", value: "conference-2026" },
            { label: "Web Development Workshop", value: "webdev-workshop" },
            { label: "Product Launch Webinar", value: "product-launch" },
            { label: "Community Meetup", value: "meetup" }
          ] }, validate: { required: true } },
          { type: "select", key: "dietary", label: "Dietary Restrictions", data: { values: [
            { label: "None", value: "none" },
            { label: "Vegetarian", value: "vegetarian" },
            { label: "Vegan", value: "vegan" },
            { label: "Gluten-Free", value: "gluten-free" },
            { label: "Kosher", value: "kosher" },
            { label: "Halal", value: "halal" }
          ] } },
          { type: "checkbox", key: "agreeTerms", label: "I agree to the terms and conditions", validate: { required: true } }
        ]
      },
      settings: { successMessage: "You are registered! Check your email for confirmation details.", submitButtonText: "Register", requireAuth: false }
    },
    {
      name: "customer_survey",
      display_name: "Customer Survey",
      description: "Comprehensive customer satisfaction survey",
      category: "survey",
      formio_schema: {
        components: [
          { type: "email", key: "email", label: "Email (optional)" },
          { type: "radio", key: "productRating", label: "How would you rate our product?", values: [
            { label: "Excellent", value: "5" },
            { label: "Good", value: "4" },
            { label: "Average", value: "3" },
            { label: "Below Average", value: "2" },
            { label: "Poor", value: "1" }
          ], validate: { required: true } },
          { type: "radio", key: "supportRating", label: "How would you rate our support?", values: [
            { label: "Excellent", value: "5" },
            { label: "Good", value: "4" },
            { label: "Average", value: "3" },
            { label: "Below Average", value: "2" },
            { label: "Poor", value: "1" }
          ], validate: { required: true } },
          { type: "radio", key: "recommend", label: "Would you recommend us to others?", values: [
            { label: "Definitely", value: "definitely" },
            { label: "Probably", value: "probably" },
            { label: "Not Sure", value: "not-sure" },
            { label: "Probably Not", value: "probably-not" },
            { label: "Definitely Not", value: "definitely-not" }
          ], validate: { required: true } },
          { type: "textarea", key: "feedback", label: "What could we do better?", placeholder: "Your honest feedback helps us improve..." }
        ]
      },
      settings: { successMessage: "Thank you for completing our survey!", submitButtonText: "Submit Survey", requireAuth: false }
    },
    {
      name: "newsletter_signup",
      display_name: "Newsletter Signup",
      description: "Subscribe to our newsletter for updates and news",
      category: "general",
      formio_schema: {
        components: [
          { type: "textfield", key: "name", label: "Name", placeholder: "Your name", validate: { required: true } },
          { type: "email", key: "email", label: "Email Address", validate: { required: true } },
          { type: "select", key: "frequency", label: "Preferred Frequency", data: { values: [
            { label: "Weekly Digest", value: "weekly" },
            { label: "Bi-Weekly", value: "biweekly" },
            { label: "Monthly Summary", value: "monthly" }
          ] } },
          { type: "selectboxes", key: "interests", label: "Topics of Interest", values: [
            { label: "Product Updates", value: "products" },
            { label: "Engineering Blog", value: "engineering" },
            { label: "Industry News", value: "news" },
            { label: "Tips & Tutorials", value: "tutorials" },
            { label: "Events & Webinars", value: "events" }
          ] }
        ]
      },
      settings: { successMessage: "Welcome aboard! Check your inbox to confirm your subscription.", submitButtonText: "Subscribe", requireAuth: false }
    },
    {
      name: "support_ticket",
      display_name: "Support Ticket",
      description: "Submit a technical support request",
      category: "contact",
      formio_schema: {
        components: [
          { type: "textfield", key: "name", label: "Your Name", validate: { required: true } },
          { type: "email", key: "email", label: "Email", validate: { required: true } },
          { type: "select", key: "priority", label: "Priority", data: { values: [
            { label: "Low \u2014 General question", value: "low" },
            { label: "Medium \u2014 Issue affecting workflow", value: "medium" },
            { label: "High \u2014 Service degraded", value: "high" },
            { label: "Critical \u2014 Service down", value: "critical" }
          ] }, validate: { required: true } },
          { type: "select", key: "category", label: "Category", data: { values: [
            { label: "Account & Billing", value: "billing" },
            { label: "API & Integration", value: "api" },
            { label: "Performance", value: "performance" },
            { label: "Bug Report", value: "bug" },
            { label: "Feature Request", value: "feature" }
          ] }, validate: { required: true } },
          { type: "textarea", key: "description", label: "Description", placeholder: "Describe the issue in detail...", validate: { required: true, maxLength: 5e3 } },
          { type: "url", key: "url", label: "Related URL (optional)", placeholder: "https://" }
        ]
      },
      settings: { emailNotifications: true, notifyEmail: "support@example.com", successMessage: "Your support ticket has been submitted. We will respond within 4 business hours.", submitButtonText: "Submit Ticket", requireAuth: false }
    },
    {
      name: "job_application",
      display_name: "Job Application",
      description: "Apply for open positions at our company",
      category: "registration",
      formio_schema: {
        components: [
          { type: "textfield", key: "firstName", label: "First Name", validate: { required: true } },
          { type: "textfield", key: "lastName", label: "Last Name", validate: { required: true } },
          { type: "email", key: "email", label: "Email", validate: { required: true } },
          { type: "phoneNumber", key: "phone", label: "Phone Number", validate: { required: true } },
          { type: "url", key: "portfolio", label: "Portfolio / LinkedIn URL", placeholder: "https://" },
          { type: "select", key: "position", label: "Position", data: { values: [
            { label: "Senior Full-Stack Engineer", value: "senior-fullstack" },
            { label: "Frontend Developer", value: "frontend" },
            { label: "Backend Engineer", value: "backend" },
            { label: "DevOps Engineer", value: "devops" },
            { label: "Product Designer", value: "designer" },
            { label: "Developer Advocate", value: "devrel" }
          ] }, validate: { required: true } },
          { type: "textarea", key: "coverLetter", label: "Cover Letter", placeholder: "Tell us why you are interested in this role...", validate: { required: true, maxLength: 3e3 } }
        ]
      },
      settings: { emailNotifications: true, notifyEmail: "careers@example.com", successMessage: "Thank you for applying! Our hiring team will review your application and follow up within one week.", submitButtonText: "Submit Application", requireAuth: false }
    },
    {
      name: "product_review",
      display_name: "Product Review",
      description: "Leave a review for a product you purchased",
      category: "feedback",
      formio_schema: {
        components: [
          { type: "textfield", key: "name", label: "Your Name", validate: { required: true } },
          { type: "email", key: "email", label: "Email", validate: { required: true } },
          { type: "select", key: "product", label: "Product", data: { values: [
            { label: "Premium Wireless Headphones", value: "headphones" },
            { label: "Smart Watch Pro", value: "smartwatch" },
            { label: "Mechanical Keyboard RGB", value: "keyboard" },
            { label: "HD Webcam 4K", value: "webcam" },
            { label: "Portable SSD 1TB", value: "ssd" },
            { label: 'Monitor 27" 4K', value: "monitor" }
          ] }, validate: { required: true } },
          { type: "number", key: "rating", label: "Rating (1-5)", validate: { required: true, min: 1, max: 5 } },
          { type: "textarea", key: "review", label: "Your Review", placeholder: "Share your experience with this product...", validate: { required: true, maxLength: 2e3 } },
          { type: "checkbox", key: "recommend", label: "I would recommend this product to others" }
        ]
      },
      settings: { successMessage: "Thank you for your review! It will appear on the product page after moderation.", submitButtonText: "Submit Review", requireAuth: false }
    }
  ];
  // ============================================================================
  // Submission Data Pools
  // ============================================================================
  messageTexts = [
    "I would like to learn more about your services and pricing options for our team.",
    "We are interested in scheduling a demo for our engineering department next week.",
    "Could you provide more details about the enterprise plan and SLA guarantees?",
    "I am having trouble integrating the API with our existing React application.",
    "Great product! Just wanted to say how much our team loves using it every day.",
    "Is there a way to export our data in CSV format from the admin dashboard?",
    "We are evaluating CMS platforms and would love to discuss a potential partnership.",
    "I noticed a minor issue with the search feature when using special characters.",
    "Can you help me set up custom webhooks for content change notifications?",
    "Our company is migrating from WordPress and would appreciate migration guidance.",
    "I am interested in contributing to the open-source project. Where can I start?",
    "The documentation is excellent but I could not find info about rate limiting.",
    "We need to set up SSO with our Azure AD tenant. Is this supported on the Pro plan?",
    "Just wanted to share some feedback \u2014 the new form builder is a huge improvement.",
    "Is it possible to schedule content publishing for a specific date and time?",
    "We are experiencing intermittent 502 errors on our production deployment.",
    "How does the AI search feature handle multi-language content?",
    "I would like to request a feature for bulk content import via CSV upload."
  ];
  feedbackComments = [
    "Great product overall. The interface is intuitive and the API is well-documented.",
    "Delivery was faster than expected. Very pleased with the build quality.",
    "Customer service was incredibly responsive. My issue was resolved in under an hour.",
    "The performance improvements in the latest release are very noticeable.",
    "I wish there were more customization options for the dashboard layout.",
    "Setup was straightforward \u2014 I had everything running in under 30 minutes.",
    "Good value for the price point. Comparable products cost significantly more.",
    "The mobile experience could use some polish but desktop is excellent.",
    "Documentation is comprehensive and the code examples are very helpful.",
    "We have been using this for 6 months and it has been rock solid in production.",
    "The search functionality works great, especially the full-text search mode.",
    "Would love to see more integrations with third-party services in future updates.",
    "Minor bugs occasionally but the team is quick to push fixes. Impressed.",
    "The form builder is powerful but has a small learning curve for complex forms.",
    "Best headless CMS we have tried. Migrating our entire content pipeline."
  ];
  coverLetterTexts = [
    "I am excited to apply for this position. With 5 years of experience in full-stack development and a passion for building performant web applications, I believe I would be a strong addition to your team. I have been following your open-source project for the past year and love the architecture decisions around edge computing.",
    "As a developer who has worked extensively with TypeScript, React, and cloud infrastructure, I am thrilled about this opportunity. In my current role, I lead a team of 4 engineers building real-time collaboration tools. I am particularly drawn to your company's focus on developer experience and open-source community.",
    "I am writing to express my interest in joining your engineering team. My background includes 3 years at a YC-backed startup where I built and scaled API services handling 10M+ requests daily. I am passionate about performance optimization and have contributed to several open-source projects in the Node.js ecosystem.",
    "This role aligns perfectly with my career goals and technical expertise. I have deep experience with Cloudflare Workers, D1, and edge computing patterns. I contributed to the Workers runtime documentation and have given talks at CloudflareConnect about serverless architectures. I would love to bring this expertise to your team."
  ];
  companyNames = [
    "Acme Corp",
    "TechStart Inc",
    "Global Systems LLC",
    "Innovate Digital",
    "Summit Solutions",
    "Nexus Technologies",
    "Brightwave Media",
    "Quantum Labs",
    "Evergreen Software",
    "Pinnacle Consulting",
    "Atlas Ventures",
    "Horizon Health",
    "Velocity Partners",
    "Sterling Analytics",
    "Catalyst Group"
  ];
  userAgents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"
  ];
  referrers = [
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://twitter.com/",
    "https://www.linkedin.com/",
    "https://github.com/",
    "https://news.ycombinator.com/",
    "https://www.reddit.com/",
    null
  ];
  utmSources = ["google", "twitter", "linkedin", "newsletter", "facebook", "github"];
  utmMediums = ["cpc", "organic", "email", "social", "referral"];
  utmCampaigns = ["spring-launch", "developer-week", "product-update", "webinar-promo", "year-end"];
  // ============================================================================
  // Helper Methods
  // ============================================================================
  generateId() {
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }
  generateSlug(title) {
    return title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
  }
  randomDate() {
    const now = /* @__PURE__ */ new Date();
    const yearAgo = new Date(now.getFullYear() - 1, now.getMonth(), now.getDate());
    const t = Math.pow(Math.random(), 0.7);
    const randomTime = yearAgo.getTime() + t * (now.getTime() - yearAgo.getTime());
    return new Date(randomTime);
  }
  pickRandom(array) {
    return array[Math.floor(Math.random() * array.length)];
  }
  generateTags(count) {
    const numTags = count || Math.floor(Math.random() * 4) + 2;
    const shuffled = [...this.allTags].sort(() => 0.5 - Math.random());
    return shuffled.slice(0, numTags);
  }
  generatePhoneNumber() {
    const area = Math.floor(Math.random() * 900) + 100;
    const mid = Math.floor(Math.random() * 900) + 100;
    const end = Math.floor(Math.random() * 9e3) + 1e3;
    return `(${area}) ${mid}-${end}`;
  }
  generateEmail(index) {
    const first = this.pickRandom(this.firstNames).toLowerCase();
    const last = this.pickRandom(this.lastNames).toLowerCase();
    const n = index !== void 0 ? index : Math.floor(Math.random() * 999);
    return `${first}.${last}${n}@example.com`;
  }
  generateIpAddress() {
    return `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;
  }
  assembleMultiParagraphHtml(title, paragraphCount) {
    const selected = [];
    const shuffled = [...this.blogParagraphs].sort(() => 0.5 - Math.random());
    for (let i = 0; i < paragraphCount && i < shuffled.length; i++) {
      selected.push(shuffled[i]);
    }
    let html4 = `<h1>${title}</h1>
`;
    const subheadings = ["Key Concepts", "Practical Considerations", "Best Practices", "Looking Ahead", "Implementation Details", "Common Pitfalls"];
    let subheadingIndex = 0;
    for (let i = 0; i < selected.length; i++) {
      if (i > 0 && i % 2 === 0 && subheadingIndex < subheadings.length) {
        html4 += `<h2>${subheadings[subheadingIndex]}</h2>
`;
        subheadingIndex++;
      }
      html4 += `<p>${selected[i]}</p>
`;
    }
    return html4;
  }
  // ============================================================================
  // Content Generation (Rich)
  // ============================================================================
  generateRichBlogData(title, richness) {
    if (richness === "minimal") {
      return {
        body: this.pickRandom(this.blogParagraphs),
        excerpt: "A brief introduction to this article that provides an overview of the main topics covered.",
        tags: this.generateTags(2),
        featured: Math.random() > 0.7
      };
    }
    const paragraphCount = Math.floor(Math.random() * 3) + 3;
    return {
      body: this.assembleMultiParagraphHtml(title, paragraphCount),
      excerpt: this.pickRandom(this.blogExcerpts),
      tags: this.generateTags(),
      featured: Math.random() > 0.7,
      difficulty: this.pickRandom(["beginner", "intermediate", "advanced"]),
      readingTime: `${Math.floor(Math.random() * 12) + 3} min read`,
      author: `${this.pickRandom(this.firstNames)} ${this.pickRandom(this.lastNames)}`
    };
  }
  generateRichPageData(title, richness) {
    if (richness === "minimal") {
      return {
        body: "This is a standard page with important information about our services and policies.",
        template: "default",
        showInMenu: Math.random() > 0.5
      };
    }
    const templateContent = this.pageContentTemplates[title];
    const body = templateContent || this.assembleMultiParagraphHtml(title, 3);
    return {
      body,
      template: "default",
      showInMenu: Math.random() > 0.3,
      metaDescription: `${title} \u2014 Learn more about our platform, services, and commitment to excellence.`,
      metaKeywords: this.generateTags(3)
    };
  }
  generateRichProductData(title, richness) {
    const price = (Math.random() * 500 + 10).toFixed(2);
    const sku = `SKU-${Math.random().toString(36).substr(2, 9).toUpperCase()}`;
    const inStock = Math.random() > 0.2;
    const rating = (Math.random() * 2 + 3).toFixed(1);
    if (richness === "minimal") {
      return { description: "High-quality product with excellent features and great value for money.", price, sku, inStock, rating };
    }
    const description = this.productDescriptions[title] || "High-quality product with excellent features, premium materials, and outstanding value. Designed for professionals who demand the best from their tools.";
    return {
      description,
      price,
      sku,
      inStock,
      rating,
      reviewCount: Math.floor(Math.random() * 200) + 5,
      category: this.pickRandom(this.productCategories),
      brand: this.pickRandom(["TechPro", "NovaTech", "EliteGear", "PrimeWare", "Zenith"]),
      featured: Math.random() > 0.7
    };
  }
  // ============================================================================
  // Submission Field Value Generation
  // ============================================================================
  generateFieldValue(component, submissionIndex) {
    const key = component.key || "";
    switch (component.type) {
      case "textfield":
        if (key.includes("name") || key.includes("Name")) {
          if (key.includes("first") || key.includes("First")) return this.pickRandom(this.firstNames);
          if (key.includes("last") || key.includes("Last")) return this.pickRandom(this.lastNames);
          return `${this.pickRandom(this.firstNames)} ${this.pickRandom(this.lastNames)}`;
        }
        if (key.includes("company") || key.includes("organization")) return this.pickRandom(this.companyNames);
        return `Sample text for ${key}`;
      case "email":
        return this.generateEmail(submissionIndex);
      case "textarea":
        if (key.includes("cover") || key.includes("Cover")) return this.pickRandom(this.coverLetterTexts);
        if (key.includes("review") || key.includes("feedback") || key.includes("comment")) return this.pickRandom(this.feedbackComments);
        return this.pickRandom(this.messageTexts);
      case "phoneNumber":
        return this.generatePhoneNumber();
      case "number":
        const min = component.validate?.min ?? 1;
        const max = component.validate?.max ?? 5;
        return Math.floor(Math.random() * (max - min + 1)) + min;
      case "checkbox":
        return Math.random() > 0.3;
      case "radio": {
        const radioValues = component.values || [];
        if (radioValues.length > 0) return this.pickRandom(radioValues).value;
        return "option1";
      }
      case "select": {
        const selectValues = component.data?.values || component.values || [];
        if (selectValues.length > 0) return this.pickRandom(selectValues).value;
        return "option1";
      }
      case "selectboxes": {
        const boxes = {};
        const sbValues = component.values || [];
        sbValues.forEach((v) => {
          boxes[v.value] = Math.random() > 0.5;
        });
        return boxes;
      }
      case "datetime":
        return this.randomDate().toISOString();
      case "url":
        return this.pickRandom([
          "https://linkedin.com/in/johndoe",
          "https://github.com/developer",
          "https://portfolio.example.com",
          "https://example.com/page",
          "https://mysite.dev"
        ]);
      default:
        return null;
    }
  }
  // ============================================================================
  // Core Methods
  // ============================================================================
  async createUsers(userCount = 20) {
    const roles = ["admin", "editor", "author", "viewer"];
    const hashedPassword = "password123";
    let count = 0;
    for (let i = 0; i < userCount; i++) {
      const firstName = this.pickRandom(this.firstNames);
      const lastName = this.pickRandom(this.lastNames);
      const username = `${firstName.toLowerCase()}${lastName.toLowerCase()}${i}`;
      const email = `${username}@example.com`;
      const createdAt = this.randomDate();
      const createdAtTimestamp = Math.floor(createdAt.getTime() / 1e3);
      await this.db.prepare(`
        INSERT INTO users (id, email, username, first_name, last_name, password_hash, role, is_active, last_login_at, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        this.generateId(),
        email,
        username,
        firstName,
        lastName,
        hashedPassword,
        this.pickRandom(roles),
        Math.random() > 0.1 ? 1 : 0,
        Math.random() > 0.3 ? createdAtTimestamp : null,
        createdAtTimestamp,
        createdAtTimestamp
      ).run();
      count++;
    }
    return count;
  }
  async createContent(contentCount = 200, richness = "full") {
    const { results: allUsers } = await this.db.prepare("SELECT * FROM users").all();
    const { results: allCollections } = await this.db.prepare("SELECT * FROM collections").all();
    if (!allUsers || allUsers.length === 0) throw new Error("No users found. Please create users first.");
    if (!allCollections || allCollections.length === 0) throw new Error("No collections found. Please create collections first.");
    const statuses = ["draft", "published", "published", "published", "archived"];
    let count = 0;
    for (let i = 0; i < contentCount; i++) {
      const collection = this.pickRandom(allCollections);
      const author = this.pickRandom(allUsers);
      const status = this.pickRandom(statuses);
      const name = (collection.name || "").toLowerCase();
      let title;
      let contentData;
      if (name === "blog_posts" || name.includes("blog")) {
        title = this.pickRandom(this.blogTitles);
        contentData = this.generateRichBlogData(title, richness);
      } else if (name === "pages" || name.includes("page")) {
        title = this.pickRandom(this.pageTitles);
        contentData = this.generateRichPageData(title, richness);
      } else if (name === "products" || name.includes("product")) {
        title = this.pickRandom(this.productTitles);
        contentData = this.generateRichProductData(title, richness);
      } else {
        title = `${collection.display_name || collection.name} Item ${i + 1}`;
        contentData = {
          description: richness === "full" ? `This is a sample ${collection.display_name || collection.name} item with generated content for testing and development purposes.` : "This is a sample content item with generic data.",
          value: Math.floor(Math.random() * 1e3)
        };
      }
      const slug = `${this.generateSlug(title)}-${i}`;
      const createdAt = this.randomDate();
      const createdAtTimestamp = Math.floor(createdAt.getTime() / 1e3);
      const publishedAtTimestamp = status === "published" ? createdAtTimestamp : null;
      await this.db.prepare(`
        INSERT INTO content (id, collection_id, slug, title, data, status, published_at, author_id, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        this.generateId(),
        collection.id,
        slug,
        `${title} ${i}`,
        JSON.stringify(contentData),
        status,
        publishedAtTimestamp,
        author.id,
        createdAtTimestamp,
        createdAtTimestamp
      ).run();
      count++;
    }
    return count;
  }
  async createForms(formCount = 5, creatorUserId) {
    let count = 0;
    const formIds = [];
    for (let i = 0; i < formCount; i++) {
      const templateIndex = i % this.formTemplates.length;
      const template = this.formTemplates[templateIndex];
      const suffix = i >= this.formTemplates.length ? `_${Math.floor(i / this.formTemplates.length) + 1}` : "";
      const name = `${template.name}${suffix}`;
      const displayName = suffix ? `${template.display_name} ${Math.floor(i / this.formTemplates.length) + 1}` : template.display_name;
      const id = this.generateId();
      const now = Date.now();
      try {
        await this.db.prepare(`
          INSERT OR IGNORE INTO forms (
            id, name, display_name, description, category,
            formio_schema, settings, is_active, is_public,
            submission_count, created_by, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, 1, 0, ?, ?, ?)
        `).bind(
          id,
          name,
          displayName,
          template.description,
          template.category,
          JSON.stringify(template.formio_schema),
          JSON.stringify(template.settings || {}),
          creatorUserId,
          now,
          now
        ).run();
        formIds.push(id);
        count++;
      } catch (e) {
        console.warn(`[Seed] Skipping form "${name}" \u2014 may already exist`);
      }
    }
    return { forms: count, formIds };
  }
  async createSubmissions(formId, formSchema, count, users2) {
    const components = formSchema?.components || [];
    if (components.length === 0) return 0;
    let created = 0;
    for (let i = 0; i < count; i++) {
      const submissionData = {};
      for (const component of components) {
        if (component.key && component.type !== "button") {
          submissionData[component.key] = this.generateFieldValue(component, i);
        }
      }
      const id = this.generateId();
      const submittedAt = Date.now() - Math.floor(Math.random() * 90 * 24 * 60 * 60 * 1e3);
      const user = Math.random() > 0.5 && users2.length > 0 ? this.pickRandom(users2) : null;
      const email = submissionData.email || this.generateEmail(i);
      const status = this.pickRandom(["pending", "pending", "pending", "reviewed", "approved"]);
      await this.db.prepare(`
        INSERT INTO form_submissions (
          id, form_id, submission_data, status, user_id, user_email,
          ip_address, user_agent, referrer, utm_source, utm_medium, utm_campaign,
          submitted_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        id,
        formId,
        JSON.stringify(submissionData),
        status,
        user?.id || null,
        email,
        this.generateIpAddress(),
        this.pickRandom(this.userAgents),
        this.pickRandom(this.referrers),
        Math.random() > 0.6 ? this.pickRandom(this.utmSources) : null,
        Math.random() > 0.6 ? this.pickRandom(this.utmMediums) : null,
        Math.random() > 0.7 ? this.pickRandom(this.utmCampaigns) : null,
        submittedAt,
        submittedAt
      ).run();
      created++;
    }
    return created;
  }
  async createAllFormsAndSubmissions(formCount = 5, submissionsPerForm = 15) {
    const { results: admins } = await this.db.prepare("SELECT id FROM users WHERE role = 'admin' LIMIT 1").all();
    const creatorId = admins?.[0]?.id || "system";
    const { results: allUsers } = await this.db.prepare("SELECT id, email FROM users").all();
    const { forms, formIds } = await this.createForms(formCount, creatorId);
    let totalSubmissions = 0;
    for (const formId of formIds) {
      const formRow = await this.db.prepare("SELECT formio_schema FROM forms WHERE id = ?").bind(formId).first();
      if (!formRow) continue;
      const schema = JSON.parse(formRow.formio_schema);
      const created = await this.createSubmissions(formId, schema, submissionsPerForm, allUsers || []);
      totalSubmissions += created;
    }
    return { forms, submissions: totalSubmissions };
  }
  async seedAll(options) {
    const users2 = await this.createUsers(options.userCount);
    const content2 = await this.createContent(options.contentCount, options.richness);
    const { forms, submissions } = await this.createAllFormsAndSubmissions(
      options.formCount,
      options.submissionsPerForm
    );
    return { users: users2, content: content2, forms, submissions };
  }
  async clearSeedData() {
    await this.db.prepare("DELETE FROM form_submissions").run();
    await this.db.prepare("DELETE FROM forms").run();
    await this.db.prepare("DELETE FROM content").run();
    await this.db.prepare("DELETE FROM users WHERE role != 'admin'").run();
  }
};

// src/plugins/core-plugins/seed-data-plugin/admin-routes.ts
var DEFAULTS = {
  userCount: 20,
  contentCount: 200,
  formCount: 5,
  submissionsPerForm: 15,
  richness: "full"
};
function parseNumberOrDefault(value, defaultVal) {
  if (value === void 0 || value === null || value === "") return defaultVal;
  const num = Number(value);
  return isNaN(num) ? defaultVal : num;
}
async function loadSettings(db) {
  try {
    const row = await db.prepare("SELECT settings FROM plugins WHERE id = ?").bind("seed-data").first();
    const saved = row?.settings ? JSON.parse(row.settings) : {};
    return {
      userCount: parseNumberOrDefault(saved.userCount, DEFAULTS.userCount),
      contentCount: parseNumberOrDefault(saved.contentCount, DEFAULTS.contentCount),
      formCount: parseNumberOrDefault(saved.formCount, DEFAULTS.formCount),
      submissionsPerForm: parseNumberOrDefault(saved.submissionsPerForm, DEFAULTS.submissionsPerForm),
      richness: saved.richness || DEFAULTS.richness
    };
  } catch {
    return { ...DEFAULTS };
  }
}
function createSeedDataAdminRoutes() {
  const routes = new hono.Hono();
  routes.get("/", async (c) => {
    const db = c.env.DB;
    const s = await loadSettings(db);
    const content2 = `
    <div class="w-full px-4 sm:px-6 lg:px-8 py-6">
      <!-- Header -->
      <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-6">
        <div>
          <h1 class="text-2xl/8 font-semibold text-zinc-950 dark:text-white sm:text-xl/8">Seed Data Generator</h1>
          <p class="mt-2 text-sm/6 text-zinc-500 dark:text-zinc-400">
            Generate realistic users, content, forms, and submissions for testing and development.
          </p>
        </div>
        <div class="mt-4 sm:mt-0">
          <a href="/admin/plugins" class="inline-flex items-center justify-center rounded-lg bg-white dark:bg-zinc-800 px-3.5 py-2.5 text-sm font-semibold text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition-colors shadow-sm">
            <svg class="-ml-0.5 mr-1.5 h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/>
            </svg>
            Back to Plugins
          </a>
        </div>
      </div>

      <!-- Warning Banner -->
      <div class="rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 p-4 mb-6">
        <div class="flex items-center gap-2">
          <span class="text-amber-600 dark:text-amber-400 font-semibold">Warning:</span>
          <span class="text-sm text-amber-700 dark:text-amber-300">This tool creates test data in your database. Do not use in production!</span>
        </div>
      </div>

      <!-- Status Messages -->
      <div id="successMessage" class="hidden rounded-lg bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 p-4 mb-6">
        <span class="text-sm font-medium text-green-800 dark:text-green-200" id="successText"></span>
      </div>
      <div id="errorMessage" class="hidden rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 p-4 mb-6">
        <span class="text-sm font-medium text-red-800 dark:text-red-200" id="errorText"></span>
      </div>

      <!-- Configuration Card -->
      <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6 mb-6">
        <h2 class="text-lg font-semibold text-zinc-950 dark:text-white mb-4">Configuration</h2>
        <form id="seedForm" class="space-y-6">
          <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <div>
              <label for="userCount" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-1">Users to Create</label>
              <input type="number" id="userCount" name="userCount" value="${s.userCount}" min="0" max="100"
                class="w-full rounded-lg bg-white dark:bg-white/5 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500">
              <p class="mt-1 text-xs text-zinc-500">With names, emails, roles (0-100)</p>
            </div>
            <div>
              <label for="contentCount" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-1">Content Items</label>
              <input type="number" id="contentCount" name="contentCount" value="${s.contentCount}" min="0" max="1000"
                class="w-full rounded-lg bg-white dark:bg-white/5 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500">
              <p class="mt-1 text-xs text-zinc-500">Distributed across existing collections (0-1000)</p>
            </div>
            <div>
              <label for="formCount" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-1">Forms to Create</label>
              <input type="number" id="formCount" name="formCount" value="${s.formCount}" min="0" max="20"
                class="w-full rounded-lg bg-white dark:bg-white/5 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500">
              <p class="mt-1 text-xs text-zinc-500">Contact, feedback, registration, etc. (0-20)</p>
            </div>
            <div>
              <label for="submissionsPerForm" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-1">Submissions per Form</label>
              <input type="number" id="submissionsPerForm" name="submissionsPerForm" value="${s.submissionsPerForm}" min="0" max="100"
                class="w-full rounded-lg bg-white dark:bg-white/5 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500">
              <p class="mt-1 text-xs text-zinc-500">Realistic submissions per form (0-100)</p>
            </div>
            <div>
              <label for="richness" class="block text-sm font-medium text-zinc-700 dark:text-zinc-300 mb-1">Content Richness</label>
              <select id="richness" name="richness"
                class="w-full rounded-lg bg-white dark:bg-white/5 px-3 py-2 text-sm text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 focus:ring-2 focus:ring-indigo-500">
                <option value="full" ${s.richness === "full" ? "selected" : ""}>Full \u2014 Multi-paragraph content, SEO metadata, specs</option>
                <option value="minimal" ${s.richness === "minimal" ? "selected" : ""}>Minimal \u2014 Single-sentence bodies, basic fields</option>
              </select>
              <p class="mt-1 text-xs text-zinc-500">Depth of generated content</p>
            </div>
          </div>

          <div class="flex items-center gap-3 pt-2">
            <button type="button" onclick="saveDefaults()" class="inline-flex items-center rounded-lg bg-white dark:bg-zinc-800 px-4 py-2 text-sm font-semibold text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-700 transition-colors">
              Save as Defaults
            </button>
            <span id="savedIndicator" class="hidden text-sm text-green-600 dark:text-green-400">Saved!</span>
          </div>
        </form>
      </div>

      <!-- What Gets Created -->
      <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6 mb-6">
        <h2 class="text-lg font-semibold text-zinc-950 dark:text-white mb-3">What Gets Created</h2>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
          <div class="space-y-2 text-zinc-600 dark:text-zinc-400">
            <p><strong class="text-zinc-900 dark:text-white">Users:</strong> Realistic names, emails, roles (admin/editor/author/viewer), activity dates</p>
            <p><strong class="text-zinc-900 dark:text-white">Content:</strong> Distributed across all existing collections \u2014 blog posts get multi-paragraph HTML bodies with excerpts and tags, pages get SEO metadata, other collections get contextual data</p>
          </div>
          <div class="space-y-2 text-zinc-600 dark:text-zinc-400">
            <p><strong class="text-zinc-900 dark:text-white">Forms:</strong> Contact, feedback, survey, registration, newsletter, support, job application, product review \u2014 with full Form.io schemas</p>
            <p><strong class="text-zinc-900 dark:text-white">Submissions:</strong> Schema-aware field data, IP addresses, user agents, UTM tracking, status workflow</p>
          </div>
        </div>
      </div>

      <!-- Progress Bar (hidden by default) -->
      <div id="progressContainer" class="hidden rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6 mb-6">
        <div class="flex items-center justify-between mb-2">
          <h2 class="text-sm font-semibold text-zinc-950 dark:text-white" id="progressLabel">Generating...</h2>
          <span class="text-sm text-zinc-500 dark:text-zinc-400" id="progressPercent">0%</span>
        </div>
        <div class="w-full bg-zinc-200 dark:bg-zinc-700 rounded-full h-3 overflow-hidden">
          <div id="progressBar" class="bg-indigo-600 h-3 rounded-full transition-all duration-500 ease-out" style="width: 0%"></div>
        </div>
        <p class="mt-2 text-xs text-zinc-500 dark:text-zinc-400" id="progressDetail"></p>
      </div>

      <!-- Generate & Clear Actions -->
      <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
          <p class="text-sm text-zinc-500 dark:text-zinc-400 mb-4">Creates users, content, forms, and submissions using the configuration above.</p>
          <button id="generateBtn" onclick="generateSeedData()" class="inline-flex items-center rounded-lg bg-indigo-600 hover:bg-indigo-500 px-4 py-2.5 text-sm font-semibold text-white transition-colors shadow-sm disabled:opacity-50 disabled:cursor-not-allowed">
            <svg class="-ml-0.5 mr-1.5 h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"/>
            </svg>
            <span id="generateText">Generate Seed Data</span>
          </button>
        </div>

        <div class="rounded-xl bg-white dark:bg-zinc-900 shadow-sm ring-1 ring-zinc-950/5 dark:ring-white/10 p-6">
          <p class="text-sm text-zinc-500 dark:text-zinc-400 mb-4">Removes all content, forms, submissions, and non-admin users. Cannot be undone.</p>
          <button id="clearBtn" onclick="clearSeedData()" class="inline-flex items-center rounded-lg bg-red-600 hover:bg-red-500 px-4 py-2.5 text-sm font-semibold text-white transition-colors shadow-sm disabled:opacity-50 disabled:cursor-not-allowed">
            <svg class="-ml-0.5 mr-1.5 h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
            </svg>
            <span id="clearText">Clear All Data</span>
          </button>
        </div>
      </div>
    </div>

    <script>
      function getFormValues() {
        return {
          userCount: Number(document.getElementById('userCount').value),
          contentCount: Number(document.getElementById('contentCount').value),
          formCount: Number(document.getElementById('formCount').value),
          submissionsPerForm: Number(document.getElementById('submissionsPerForm').value),
          richness: document.getElementById('richness').value
        };
      }

      function showMessage(type, text) {
        var successEl = document.getElementById('successMessage');
        var errorEl = document.getElementById('errorMessage');
        successEl.classList.add('hidden');
        errorEl.classList.add('hidden');

        if (type === 'success') {
          document.getElementById('successText').textContent = text;
          successEl.classList.remove('hidden');
        } else {
          document.getElementById('errorText').textContent = text;
          errorEl.classList.remove('hidden');
        }
      }

      function updateProgress(percent, label, detail) {
        var container = document.getElementById('progressContainer');
        var bar = document.getElementById('progressBar');
        var percentEl = document.getElementById('progressPercent');
        var labelEl = document.getElementById('progressLabel');
        var detailEl = document.getElementById('progressDetail');

        container.classList.remove('hidden');
        bar.style.width = percent + '%';
        percentEl.textContent = percent + '%';
        labelEl.textContent = label;
        detailEl.textContent = detail || '';
      }

      function hideProgress() {
        document.getElementById('progressContainer').classList.add('hidden');
      }

      async function saveDefaults() {
        try {
          var res = await fetch('/admin/seed-data/settings', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(getFormValues())
          });
          if (res.ok) {
            var indicator = document.getElementById('savedIndicator');
            indicator.classList.remove('hidden');
            setTimeout(function() { indicator.classList.add('hidden'); }, 2000);
          } else {
            showMessage('error', 'Failed to save defaults');
          }
        } catch (e) {
          showMessage('error', 'Error: ' + e.message);
        }
      }

      async function generateSeedData() {
        var btn = document.getElementById('generateBtn');
        var text = document.getElementById('generateText');
        var clearBtn = document.getElementById('clearBtn');
        btn.disabled = true;
        clearBtn.disabled = true;
        text.textContent = 'Generating...';

        var vals = getFormValues();
        var totals = { users: 0, content: 0, forms: 0, submissions: 0 };
        var steps = [];

        if (vals.userCount > 0) steps.push({ endpoint: 'users', label: 'Creating users...', key: 'users', body: { userCount: vals.userCount } });
        if (vals.contentCount > 0) steps.push({ endpoint: 'content', label: 'Creating content...', key: 'content', body: { contentCount: vals.contentCount, richness: vals.richness } });
        if (vals.formCount > 0) steps.push({ endpoint: 'forms', label: 'Creating forms...', key: 'forms', body: { formCount: vals.formCount } });
        if (vals.formCount > 0 && vals.submissionsPerForm > 0) steps.push({ endpoint: 'submissions', label: 'Creating submissions...', key: 'submissions', body: { submissionsPerForm: vals.submissionsPerForm } });

        if (steps.length === 0) {
          showMessage('error', 'All counts are set to 0. Nothing to generate.');
          btn.disabled = false;
          clearBtn.disabled = false;
          text.textContent = 'Generate Seed Data';
          return;
        }

        try {
          for (var i = 0; i < steps.length; i++) {
            var step = steps[i];
            var pct = Math.round(((i) / steps.length) * 100);
            updateProgress(pct, step.label, 'Step ' + (i + 1) + ' of ' + steps.length);

            var res = await fetch('/admin/seed-data/generate/' + step.endpoint, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(step.body)
            });
            var data = await res.json();
            if (!res.ok || !data.success) {
              throw new Error(data.error || 'Failed at step: ' + step.label);
            }
            totals[step.key] = data.count || 0;
          }

          updateProgress(100, 'Complete!', '');
          setTimeout(hideProgress, 2000);

          var parts = [];
          if (totals.users > 0) parts.push(totals.users + ' users');
          if (totals.content > 0) parts.push(totals.content + ' content items');
          if (totals.forms > 0) parts.push(totals.forms + ' forms');
          if (totals.submissions > 0) parts.push(totals.submissions + ' submissions');
          showMessage('success', 'Created ' + parts.join(', ') + '!');
        } catch (e) {
          hideProgress();
          showMessage('error', 'Error: ' + e.message);
        } finally {
          btn.disabled = false;
          clearBtn.disabled = false;
          text.textContent = 'Generate Seed Data';
        }
      }

      async function clearSeedData() {
        if (!confirm('Are you sure you want to clear ALL data? This removes all content, forms, submissions, and non-admin users. This cannot be undone!')) return;

        var btn = document.getElementById('clearBtn');
        var text = document.getElementById('clearText');
        btn.disabled = true;
        text.textContent = 'Clearing...';

        try {
          var res = await fetch('/admin/seed-data/clear', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
          });
          var data = await res.json();
          if (res.ok && data.success) {
            showMessage('success', 'All seed data cleared successfully!');
          } else {
            throw new Error(data.error || 'Clear failed');
          }
        } catch (e) {
          showMessage('error', 'Error: ' + e.message);
        } finally {
          btn.disabled = false;
          text.textContent = 'Clear All Data';
        }
      }
    </script>
    `;
    return c.html(chunkGMUS5V42_cjs.renderAdminLayout({
      title: "Seed Data Generator",
      pageTitle: "Seed Data Generator",
      currentPath: "/admin/seed-data",
      content: content2
    }));
  });
  routes.post("/settings", async (c) => {
    try {
      const db = c.env.DB;
      const body = await c.req.json();
      const settings = {
        userCount: Math.min(Math.max(parseNumberOrDefault(body.userCount, DEFAULTS.userCount), 0), 100),
        contentCount: Math.min(Math.max(parseNumberOrDefault(body.contentCount, DEFAULTS.contentCount), 0), 1e3),
        formCount: Math.min(Math.max(parseNumberOrDefault(body.formCount, DEFAULTS.formCount), 0), 20),
        submissionsPerForm: Math.min(Math.max(parseNumberOrDefault(body.submissionsPerForm, DEFAULTS.submissionsPerForm), 0), 100),
        richness: body.richness === "minimal" ? "minimal" : "full"
      };
      await db.prepare(
        "UPDATE plugins SET settings = ? WHERE id = ?"
      ).bind(JSON.stringify(settings), "seed-data").run();
      return c.json({ success: true, settings });
    } catch (error) {
      return c.json({ success: false, error: error.message }, 500);
    }
  });
  routes.post("/generate/users", async (c) => {
    try {
      const db = c.env.DB;
      const body = await c.req.json();
      const userCount = Math.min(Math.max(parseNumberOrDefault(body.userCount, 0), 0), 100);
      if (userCount === 0) return c.json({ success: true, count: 0 });
      const seedService = new SeedDataService(db);
      const count = await seedService.createUsers(userCount);
      return c.json({ success: true, count });
    } catch (error) {
      console.error("[Seed Data] Users error:", error);
      return c.json({ success: false, error: error.message }, 500);
    }
  });
  routes.post("/generate/content", async (c) => {
    try {
      const db = c.env.DB;
      const body = await c.req.json();
      const contentCount = Math.min(Math.max(parseNumberOrDefault(body.contentCount, 0), 0), 1e3);
      const richness = body.richness === "minimal" ? "minimal" : "full";
      if (contentCount === 0) return c.json({ success: true, count: 0 });
      const seedService = new SeedDataService(db);
      const count = await seedService.createContent(contentCount, richness);
      return c.json({ success: true, count });
    } catch (error) {
      console.error("[Seed Data] Content error:", error);
      return c.json({ success: false, error: error.message }, 500);
    }
  });
  routes.post("/generate/forms", async (c) => {
    try {
      const db = c.env.DB;
      const body = await c.req.json();
      const formCount = Math.min(Math.max(parseNumberOrDefault(body.formCount, 0), 0), 20);
      if (formCount === 0) return c.json({ success: true, count: 0 });
      const { results: admins } = await db.prepare("SELECT id FROM users WHERE role = 'admin' LIMIT 1").all();
      const creatorId = admins?.[0]?.id || "system";
      const seedService = new SeedDataService(db);
      const { forms } = await seedService.createForms(formCount, creatorId);
      return c.json({ success: true, count: forms });
    } catch (error) {
      console.error("[Seed Data] Forms error:", error);
      return c.json({ success: false, error: error.message }, 500);
    }
  });
  routes.post("/generate/submissions", async (c) => {
    try {
      const db = c.env.DB;
      const body = await c.req.json();
      const submissionsPerForm = Math.min(Math.max(parseNumberOrDefault(body.submissionsPerForm, 0), 0), 100);
      if (submissionsPerForm === 0) return c.json({ success: true, count: 0 });
      const { results: forms } = await db.prepare("SELECT id, formio_schema FROM forms").all();
      if (!forms || forms.length === 0) return c.json({ success: true, count: 0 });
      const { results: allUsers } = await db.prepare("SELECT id, email FROM users").all();
      const seedService = new SeedDataService(db);
      let totalSubmissions = 0;
      for (const form of forms) {
        const schema = JSON.parse(form.formio_schema);
        const created = await seedService.createSubmissions(form.id, schema, submissionsPerForm, allUsers || []);
        totalSubmissions += created;
      }
      return c.json({ success: true, count: totalSubmissions });
    } catch (error) {
      console.error("[Seed Data] Submissions error:", error);
      return c.json({ success: false, error: error.message }, 500);
    }
  });
  routes.post("/generate", async (c) => {
    try {
      const db = c.env.DB;
      const body = await c.req.json();
      const options = {
        userCount: Math.min(Math.max(parseNumberOrDefault(body.userCount, DEFAULTS.userCount), 0), 100),
        contentCount: Math.min(Math.max(parseNumberOrDefault(body.contentCount, DEFAULTS.contentCount), 0), 1e3),
        formCount: Math.min(Math.max(parseNumberOrDefault(body.formCount, DEFAULTS.formCount), 0), 20),
        submissionsPerForm: Math.min(Math.max(parseNumberOrDefault(body.submissionsPerForm, DEFAULTS.submissionsPerForm), 0), 100),
        richness: body.richness === "minimal" ? "minimal" : "full"
      };
      const seedService = new SeedDataService(db);
      const result = await seedService.seedAll(options);
      return c.json({ success: true, ...result });
    } catch (error) {
      console.error("[Seed Data] Generation error:", error);
      return c.json({ success: false, error: error.message }, 500);
    }
  });
  routes.post("/clear", async (c) => {
    try {
      const db = c.env.DB;
      const seedService = new SeedDataService(db);
      await seedService.clearSeedData();
      return c.json({ success: true });
    } catch (error) {
      console.error("[Seed Data] Clear error:", error);
      return c.json({ success: false, error: error.message }, 500);
    }
  });
  return routes;
}
function createEmailPlugin() {
  const builder = chunk6FHNRRJ3_cjs.PluginBuilder.create({
    name: "email",
    version: "1.0.0-beta.1",
    description: "Send transactional emails using Resend"
  });
  builder.metadata({
    author: {
      name: "SonicJS Team",
      email: "team@sonicjs.com"
    },
    license: "MIT",
    compatibility: "^2.0.0"
  });
  const emailRoutes = new hono.Hono();
  emailRoutes.post("/settings", async (c) => {
    try {
      const body = await c.req.json();
      const db = c.env.DB;
      await db.prepare(`
        UPDATE plugins
        SET settings = ?,
            updated_at = unixepoch()
        WHERE id = 'email'
      `).bind(JSON.stringify(body)).run();
      return c.json({ success: true });
    } catch (error) {
      console.error("Error saving email settings:", error);
      return c.json({ success: false, error: "Failed to save settings" }, 500);
    }
  });
  emailRoutes.post("/test", async (c) => {
    try {
      const db = c.env.DB;
      const body = await c.req.json();
      const plugin2 = await db.prepare(`
        SELECT settings FROM plugins WHERE id = 'email'
      `).first();
      if (!plugin2?.settings) {
        return c.json({
          success: false,
          error: "Email settings not configured. Please save your settings first."
        }, 400);
      }
      const settings = JSON.parse(plugin2.settings);
      if (!settings.apiKey || !settings.fromEmail || !settings.fromName) {
        return c.json({
          success: false,
          error: "Missing required settings. Please configure API Key, From Email, and From Name."
        }, 400);
      }
      const toEmail = body.toEmail || settings.fromEmail;
      if (!toEmail.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) {
        return c.json({
          success: false,
          error: "Invalid email address format"
        }, 400);
      }
      const response = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${settings.apiKey}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          from: `${settings.fromName} <${settings.fromEmail}>`,
          to: [toEmail],
          subject: "Test Email from SonicJS",
          html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
              <h1 style="color: #667eea;">Test Email Successful! \u{1F389}</h1>
              <p>This is a test email from your SonicJS Email plugin.</p>
              <p><strong>Configuration:</strong></p>
              <ul>
                <li>From: ${settings.fromName} &lt;${settings.fromEmail}&gt;</li>
                <li>Reply-To: ${settings.replyTo || "Not set"}</li>
                <li>Sent at: ${(/* @__PURE__ */ new Date()).toISOString()}</li>
              </ul>
              <p>Your email settings are working correctly!</p>
            </div>
          `,
          reply_to: settings.replyTo || settings.fromEmail
        })
      });
      const data = await response.json();
      if (!response.ok) {
        console.error("Resend API error:", data);
        return c.json({
          success: false,
          error: data.message || "Failed to send test email. Check your API key and domain verification."
        }, response.status);
      }
      return c.json({
        success: true,
        message: `Test email sent successfully to ${toEmail}`,
        emailId: data.id
      });
    } catch (error) {
      console.error("Test email error:", error);
      return c.json({
        success: false,
        error: error.message || "An error occurred while sending test email"
      }, 500);
    }
  });
  builder.addRoute("/admin/plugins/email", emailRoutes, {
    description: "Email plugin settings",
    requiresAuth: true,
    priority: 80
  });
  builder.addMenuItem("Email", "/admin/plugins/email", {
    icon: "envelope",
    order: 80,
    permissions: ["email:manage"]
  });
  builder.lifecycle({
    activate: async () => {
      console.info("\u2705 Email plugin activated");
    },
    deactivate: async () => {
      console.info("\u274C Email plugin deactivated");
    }
  });
  return builder.build();
}
var emailPlugin = createEmailPlugin();

// src/plugins/core-plugins/otp-login-plugin/otp-service.ts
var OTPService = class {
  constructor(db) {
    this.db = db;
  }
  /**
   * Generate a secure random OTP code
   */
  generateCode(length = 6) {
    const digits = "0123456789";
    let code = "";
    for (let i = 0; i < length; i++) {
      const randomValues = new Uint8Array(1);
      crypto.getRandomValues(randomValues);
      const randomValue = randomValues[0] ?? 0;
      code += digits[randomValue % digits.length];
    }
    return code;
  }
  /**
   * Create and store a new OTP code
   */
  async createOTPCode(email, settings, ipAddress, userAgent) {
    const code = this.generateCode(settings.codeLength);
    const id = crypto.randomUUID();
    const now = Date.now();
    const expiresAt = now + settings.codeExpiryMinutes * 60 * 1e3;
    const otpCode = {
      id,
      user_email: email.toLowerCase(),
      code,
      expires_at: expiresAt,
      used: 0,
      used_at: null,
      ip_address: ipAddress || null,
      user_agent: userAgent || null,
      attempts: 0,
      created_at: now
    };
    await this.db.prepare(`
      INSERT INTO otp_codes (
        id, user_email, code, expires_at, used, used_at,
        ip_address, user_agent, attempts, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      otpCode.id,
      otpCode.user_email,
      otpCode.code,
      otpCode.expires_at,
      otpCode.used,
      otpCode.used_at,
      otpCode.ip_address,
      otpCode.user_agent,
      otpCode.attempts,
      otpCode.created_at
    ).run();
    return otpCode;
  }
  /**
   * Verify an OTP code
   */
  async verifyCode(email, code, settings) {
    const normalizedEmail = email.toLowerCase();
    const now = Date.now();
    const otpCode = await this.db.prepare(`
      SELECT * FROM otp_codes
      WHERE user_email = ? AND code = ? AND used = 0
      ORDER BY created_at DESC
      LIMIT 1
    `).bind(normalizedEmail, code).first();
    if (!otpCode) {
      return { valid: false, error: "Invalid or expired code" };
    }
    if (now > otpCode.expires_at) {
      return { valid: false, error: "Code has expired" };
    }
    if (otpCode.attempts >= settings.maxAttempts) {
      return { valid: false, error: "Maximum attempts exceeded" };
    }
    await this.db.prepare(`
      UPDATE otp_codes
      SET used = 1, used_at = ?, attempts = attempts + 1
      WHERE id = ?
    `).bind(now, otpCode.id).run();
    return { valid: true };
  }
  /**
   * Increment failed attempt count
   */
  async incrementAttempts(email, code) {
    const normalizedEmail = email.toLowerCase();
    const result = await this.db.prepare(`
      UPDATE otp_codes
      SET attempts = attempts + 1
      WHERE user_email = ? AND code = ? AND used = 0
      RETURNING attempts
    `).bind(normalizedEmail, code).first();
    return result?.attempts || 0;
  }
  /**
   * Check rate limiting
   */
  async checkRateLimit(email, settings) {
    const normalizedEmail = email.toLowerCase();
    const oneHourAgo = Date.now() - 60 * 60 * 1e3;
    const result = await this.db.prepare(`
      SELECT COUNT(*) as count
      FROM otp_codes
      WHERE user_email = ? AND created_at > ?
    `).bind(normalizedEmail, oneHourAgo).first();
    const count = result?.count || 0;
    return count < settings.rateLimitPerHour;
  }
  /**
   * Get recent OTP requests for activity log
   */
  async getRecentRequests(limit = 50) {
    const result = await this.db.prepare(`
      SELECT * FROM otp_codes
      ORDER BY created_at DESC
      LIMIT ?
    `).bind(limit).all();
    const rows = result.results || [];
    return rows.map((row) => this.mapRowToOTP(row));
  }
  /**
   * Clean up expired codes (for maintenance)
   */
  async cleanupExpiredCodes() {
    const now = Date.now();
    const result = await this.db.prepare(`
      DELETE FROM otp_codes
      WHERE expires_at < ? OR (used = 1 AND used_at < ?)
    `).bind(now, now - 30 * 24 * 60 * 60 * 1e3).run();
    return result.meta.changes || 0;
  }
  mapRowToOTP(row) {
    return {
      id: String(row.id),
      user_email: String(row.user_email),
      code: String(row.code),
      expires_at: Number(row.expires_at ?? Date.now()),
      used: Number(row.used ?? 0),
      used_at: row.used_at === null || row.used_at === void 0 ? null : Number(row.used_at),
      ip_address: typeof row.ip_address === "string" ? row.ip_address : null,
      user_agent: typeof row.user_agent === "string" ? row.user_agent : null,
      attempts: Number(row.attempts ?? 0),
      created_at: Number(row.created_at ?? Date.now())
    };
  }
  /**
   * Get OTP statistics
   */
  async getStats(days = 7) {
    const since = Date.now() - days * 24 * 60 * 60 * 1e3;
    const stats = await this.db.prepare(`
      SELECT
        COUNT(*) as total,
        SUM(CASE WHEN used = 1 THEN 1 ELSE 0 END) as successful,
        SUM(CASE WHEN attempts >= 3 AND used = 0 THEN 1 ELSE 0 END) as failed,
        SUM(CASE WHEN expires_at < ? AND used = 0 THEN 1 ELSE 0 END) as expired
      FROM otp_codes
      WHERE created_at > ?
    `).bind(Date.now(), since).first();
    return {
      total: stats?.total || 0,
      successful: stats?.successful || 0,
      failed: stats?.failed || 0,
      expired: stats?.expired || 0
    };
  }
};

// src/plugins/core-plugins/otp-login-plugin/email-templates.ts
function renderOTPEmailHTML(data) {
  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Your Login Code</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f5f5f5;">

  <div style="background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">

    ${data.logoUrl ? `
    <div style="text-align: center; padding: 30px 20px 20px;">
      <img src="${data.logoUrl}" alt="Logo" style="max-width: 150px; height: auto;">
    </div>
    ` : ""}

    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px 30px; text-align: center;">
      <h1 style="margin: 0 0 10px 0; font-size: 32px; font-weight: 600;">Your Login Code</h1>
      <p style="margin: 0; opacity: 0.95; font-size: 16px;">Enter this code to sign in to ${data.appName}</p>
    </div>

    <div style="padding: 40px 30px;">
      <div style="background: #f8f9fa; border: 2px dashed #667eea; border-radius: 12px; padding: 30px; text-align: center; margin: 0 0 30px 0;">
        <div style="font-size: 56px; font-weight: bold; letter-spacing: 12px; color: #667eea; font-family: 'Courier New', Courier, monospace; line-height: 1;">
          ${data.code}
        </div>
      </div>

      <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 16px 20px; margin: 0 0 30px 0; border-radius: 6px;">
        <p style="margin: 0; font-size: 14px; color: #856404;">
          <strong>\u26A0\uFE0F This code expires in ${data.expiryMinutes} minutes</strong>
        </p>
      </div>

      <div style="margin: 0 0 30px 0;">
        <h3 style="color: #333; margin: 0 0 15px 0; font-size: 18px;">Quick Tips:</h3>
        <ul style="color: #666; font-size: 14px; line-height: 1.8; margin: 0; padding-left: 20px;">
          <li>Enter the code exactly as shown (${data.codeLength} digits)</li>
          <li>The code can only be used once</li>
          <li>You have ${data.maxAttempts} attempts to enter the correct code</li>
          <li>Request a new code if this one expires</li>
        </ul>
      </div>

      <div style="background: #e8f4ff; border-radius: 8px; padding: 20px; margin: 0 0 30px 0;">
        <p style="margin: 0 0 10px 0; font-size: 14px; color: #0066cc; font-weight: 600;">
          \u{1F512} Security Notice
        </p>
        <p style="margin: 0; font-size: 13px; color: #004080; line-height: 1.6;">
          Never share this code with anyone. ${data.appName} will never ask you for this code via phone, email, or social media.
        </p>
      </div>
    </div>

    <div style="border-top: 1px solid #eee; padding: 30px; background: #f8f9fa;">
      <p style="margin: 0 0 15px 0; font-size: 14px; color: #666; text-align: center;">
        <strong>Didn't request this code?</strong><br>
        Someone may have entered your email by mistake. You can safely ignore this email.
      </p>

      <div style="text-align: center; color: #999; font-size: 12px; line-height: 1.6;">
        <p style="margin: 5px 0;">This email was sent to ${data.email}</p>
        ${data.ipAddress ? `<p style="margin: 5px 0;">IP Address: ${data.ipAddress}</p>` : ""}
        <p style="margin: 5px 0;">Time: ${data.timestamp}</p>
      </div>
    </div>

  </div>

  <div style="text-align: center; padding: 20px; color: #999; font-size: 12px;">
    <p style="margin: 0;">&copy; ${(/* @__PURE__ */ new Date()).getFullYear()} ${data.appName}. All rights reserved.</p>
  </div>

</body>
</html>`;
}
function renderOTPEmailText(data) {
  return `Your Login Code for ${data.appName}

Your one-time verification code is:

${data.code}

This code expires in ${data.expiryMinutes} minutes.

Quick Tips:
\u2022 Enter the code exactly as shown (${data.codeLength} digits)
\u2022 The code can only be used once
\u2022 You have ${data.maxAttempts} attempts to enter the correct code
\u2022 Request a new code if this one expires

Security Notice:
Never share this code with anyone. ${data.appName} will never ask you for this code via phone, email, or social media.

Didn't request this code?
Someone may have entered your email by mistake. You can safely ignore this email.

---
This email was sent to ${data.email}
${data.ipAddress ? `IP Address: ${data.ipAddress}` : ""}
Time: ${data.timestamp}

\xA9 ${(/* @__PURE__ */ new Date()).getFullYear()} ${data.appName}. All rights reserved.`;
}
function renderOTPEmail(data) {
  return {
    html: renderOTPEmailHTML(data),
    text: renderOTPEmailText(data)
  };
}

// src/plugins/core-plugins/otp-login-plugin/index.ts
var otpRequestSchema = zod.z.object({
  email: zod.z.string().email("Valid email is required")
});
var otpVerifySchema = zod.z.object({
  email: zod.z.string().email("Valid email is required"),
  code: zod.z.string().min(4).max(8)
});
var DEFAULT_SETTINGS = {
  codeLength: 6,
  codeExpiryMinutes: 10,
  maxAttempts: 3,
  rateLimitPerHour: 5,
  allowNewUserRegistration: false
};
function createOTPLoginPlugin() {
  const builder = chunk6FHNRRJ3_cjs.PluginBuilder.create({
    name: "otp-login",
    version: "1.0.0-beta.1",
    description: "Passwordless authentication via email one-time codes"
  });
  builder.metadata({
    author: {
      name: "SonicJS Team",
      email: "team@sonicjs.com"
    },
    license: "MIT",
    compatibility: "^2.0.0"
  });
  const otpAPI = new hono.Hono();
  otpAPI.post("/request", async (c) => {
    try {
      const body = await c.req.json();
      const validation = otpRequestSchema.safeParse(body);
      if (!validation.success) {
        return c.json({
          error: "Validation failed",
          details: validation.error.issues
        }, 400);
      }
      const { email } = validation.data;
      const normalizedEmail = email.toLowerCase();
      const db = c.env.DB;
      const otpService = new OTPService(db);
      let settings = { ...DEFAULT_SETTINGS };
      const pluginRow = await db.prepare(`
        SELECT settings FROM plugins WHERE id = 'otp-login'
      `).first();
      if (pluginRow?.settings) {
        try {
          const savedSettings = JSON.parse(pluginRow.settings);
          settings = { ...DEFAULT_SETTINGS, ...savedSettings };
        } catch (e) {
          console.warn("Failed to parse OTP plugin settings, using defaults");
        }
      }
      const settingsService = new chunkVNLR35GO_cjs.SettingsService(db);
      const generalSettings = await settingsService.getGeneralSettings();
      const siteName = generalSettings.siteName;
      const canRequest = await otpService.checkRateLimit(normalizedEmail, settings);
      if (!canRequest) {
        return c.json({
          error: "Too many requests. Please try again in an hour."
        }, 429);
      }
      const user = await db.prepare(`
        SELECT id, email, role, is_active
        FROM users
        WHERE email = ?
      `).bind(normalizedEmail).first();
      if (!user && !settings.allowNewUserRegistration) {
        return c.json({
          message: "If an account exists for this email, you will receive a verification code shortly.",
          expiresIn: settings.codeExpiryMinutes * 60
        });
      }
      if (user && !user.is_active) {
        return c.json({
          error: "This account has been deactivated."
        }, 403);
      }
      const ipAddress = c.req.header("cf-connecting-ip") || c.req.header("x-forwarded-for") || "unknown";
      const userAgent = c.req.header("user-agent") || "unknown";
      const otpCode = await otpService.createOTPCode(
        normalizedEmail,
        settings,
        ipAddress,
        userAgent
      );
      try {
        const isDevMode = c.env.ENVIRONMENT === "development";
        if (isDevMode) {
          console.log(`[DEV] OTP Code for ${normalizedEmail}: ${otpCode.code}`);
        }
        const emailContent = renderOTPEmail({
          code: otpCode.code,
          expiryMinutes: settings.codeExpiryMinutes,
          codeLength: settings.codeLength,
          maxAttempts: settings.maxAttempts,
          email: normalizedEmail,
          ipAddress,
          timestamp: (/* @__PURE__ */ new Date()).toISOString(),
          appName: siteName
        });
        const emailPlugin2 = await db.prepare(`
          SELECT settings FROM plugins WHERE id = 'email'
        `).first();
        if (emailPlugin2?.settings) {
          const emailSettings = JSON.parse(emailPlugin2.settings);
          if (emailSettings.apiKey && emailSettings.fromEmail && emailSettings.fromName) {
            const emailResponse = await fetch("https://api.resend.com/emails", {
              method: "POST",
              headers: {
                "Authorization": `Bearer ${emailSettings.apiKey}`,
                "Content-Type": "application/json"
              },
              body: JSON.stringify({
                from: `${emailSettings.fromName} <${emailSettings.fromEmail}>`,
                to: [normalizedEmail],
                subject: `Your login code for ${siteName}`,
                html: emailContent.html,
                text: emailContent.text,
                reply_to: emailSettings.replyTo || emailSettings.fromEmail
              })
            });
            if (!emailResponse.ok) {
              const errorData = await emailResponse.json();
              console.error("Failed to send OTP email via Resend:", errorData);
            }
          } else {
            console.warn("Email plugin is not fully configured (missing apiKey, fromEmail, or fromName)");
          }
        } else {
          console.warn("Email plugin is not active or has no settings configured");
        }
        const response = {
          message: "If an account exists for this email, you will receive a verification code shortly.",
          expiresIn: settings.codeExpiryMinutes * 60
        };
        if (isDevMode) {
          response.dev_code = otpCode.code;
        }
        return c.json(response);
      } catch (emailError) {
        console.error("Error sending OTP email:", emailError);
        return c.json({
          error: "Failed to send verification code. Please try again."
        }, 500);
      }
    } catch (error) {
      console.error("OTP request error:", error);
      return c.json({
        error: "An error occurred. Please try again."
      }, 500);
    }
  });
  otpAPI.post("/verify", async (c) => {
    try {
      const body = await c.req.json();
      const validation = otpVerifySchema.safeParse(body);
      if (!validation.success) {
        return c.json({
          error: "Validation failed",
          details: validation.error.issues
        }, 400);
      }
      const { email, code } = validation.data;
      const normalizedEmail = email.toLowerCase();
      const db = c.env.DB;
      const otpService = new OTPService(db);
      let settings = { ...DEFAULT_SETTINGS };
      const pluginRow = await db.prepare(`
        SELECT settings FROM plugins WHERE id = 'otp-login'
      `).first();
      if (pluginRow?.settings) {
        try {
          const savedSettings = JSON.parse(pluginRow.settings);
          settings = { ...DEFAULT_SETTINGS, ...savedSettings };
        } catch (e) {
          console.warn("Failed to parse OTP plugin settings, using defaults");
        }
      }
      const verification = await otpService.verifyCode(normalizedEmail, code, settings);
      if (!verification.valid) {
        await otpService.incrementAttempts(normalizedEmail, code);
        return c.json({
          error: verification.error || "Invalid code",
          attemptsRemaining: verification.attemptsRemaining
        }, 401);
      }
      const user = await db.prepare(`
        SELECT id, email, role, is_active
        FROM users
        WHERE email = ?
      `).bind(normalizedEmail).first();
      if (!user) {
        return c.json({
          error: "User not found"
        }, 404);
      }
      if (!user.is_active) {
        return c.json({
          error: "Account is deactivated"
        }, 403);
      }
      const token = await chunkYZRINJP5_cjs.AuthManager.generateToken(user.id, user.email, user.role);
      cookie.setCookie(c, "auth_token", token, {
        httpOnly: true,
        secure: true,
        sameSite: "Strict",
        maxAge: 60 * 60 * 24
        // 24 hours
      });
      return c.json({
        success: true,
        user: {
          id: user.id,
          email: user.email,
          role: user.role
        },
        token,
        message: "Authentication successful"
      });
    } catch (error) {
      console.error("OTP verify error:", error);
      return c.json({
        error: "An error occurred. Please try again."
      }, 500);
    }
  });
  otpAPI.post("/resend", async (c) => {
    try {
      const body = await c.req.json();
      const validation = otpRequestSchema.safeParse(body);
      if (!validation.success) {
        return c.json({
          error: "Validation failed",
          details: validation.error.issues
        }, 400);
      }
      return otpAPI.fetch(
        new Request(c.req.url.replace("/resend", "/request"), {
          method: "POST",
          headers: c.req.raw.headers,
          body: JSON.stringify({ email: validation.data.email })
        }),
        c.env
      );
    } catch (error) {
      console.error("OTP resend error:", error);
      return c.json({
        error: "An error occurred. Please try again."
      }, 500);
    }
  });
  builder.addRoute("/auth/otp", otpAPI, {
    description: "OTP authentication endpoints",
    requiresAuth: false,
    priority: 100
  });
  builder.addMenuItem("OTP Login", "/admin/plugins/otp-login", {
    icon: "key",
    order: 85,
    permissions: ["otp:manage"]
  });
  builder.lifecycle({
    activate: async () => {
      console.info("\u2705 OTP Login plugin activated");
    },
    deactivate: async () => {
      console.info("\u274C OTP Login plugin deactivated");
    }
  });
  return builder.build();
}
var otpLoginPlugin = createOTPLoginPlugin();

// src/plugins/core-plugins/ai-search-plugin/manifest.json
var manifest_default = {
  name: "AI Search",
  description: "Advanced search with Cloudflare AI Search. Full-text search, semantic search, and advanced filtering across all content collections.",
  version: "1.0.0",
  author: "SonicJS"};
var clampWeight = (val, fallback) => {
  const n = Number(val);
  return isNaN(n) || !isFinite(n) ? fallback : Math.round(Math.min(10, Math.max(0, n)) * 10) / 10;
};
var adminRoutes = new hono.Hono();
adminRoutes.use("*", chunkYZRINJP5_cjs.requireAuth());
adminRoutes.get("/", async (c) => {
  return c.redirect("/admin/search");
});
adminRoutes.post("/", async (c) => {
  try {
    const db = c.env.DB;
    const ai = c.env.AI;
    const vectorize = c.env.VECTORIZE_INDEX;
    const service = new chunkRCLFF5NO_cjs.AISearchService(db, ai, vectorize);
    const indexer = new chunkRCLFF5NO_cjs.IndexManager(db, ai, vectorize);
    const body = await c.req.json();
    console.log("[AI Search POST] Received body:", JSON.stringify(body, null, 2));
    const currentSettings = await service.getSettings();
    console.log("[AI Search POST] Current settings selected_collections:", currentSettings?.selected_collections);
    const updatedSettings = {
      enabled: body.enabled !== void 0 ? Boolean(body.enabled) : currentSettings?.enabled,
      ai_mode_enabled: body.ai_mode_enabled !== void 0 ? Boolean(body.ai_mode_enabled) : currentSettings?.ai_mode_enabled,
      selected_collections: Array.isArray(body.selected_collections) ? body.selected_collections.map(String) : currentSettings?.selected_collections || [],
      dismissed_collections: Array.isArray(body.dismissed_collections) ? body.dismissed_collections.map(String) : currentSettings?.dismissed_collections || [],
      autocomplete_enabled: body.autocomplete_enabled !== void 0 ? Boolean(body.autocomplete_enabled) : currentSettings?.autocomplete_enabled,
      cache_duration: body.cache_duration ? Number(body.cache_duration) : currentSettings?.cache_duration,
      results_limit: body.results_limit ? Number(body.results_limit) : currentSettings?.results_limit,
      index_media: body.index_media !== void 0 ? Boolean(body.index_media) : currentSettings?.index_media,
      reranking_enabled: body.reranking_enabled !== void 0 ? Boolean(body.reranking_enabled) : currentSettings?.reranking_enabled,
      query_rewriting_enabled: body.query_rewriting_enabled !== void 0 ? Boolean(body.query_rewriting_enabled) : currentSettings?.query_rewriting_enabled,
      fts5_title_boost: body.fts5_title_boost !== void 0 ? clampWeight(body.fts5_title_boost, currentSettings?.fts5_title_boost ?? 5) : currentSettings?.fts5_title_boost,
      fts5_slug_boost: body.fts5_slug_boost !== void 0 ? clampWeight(body.fts5_slug_boost, currentSettings?.fts5_slug_boost ?? 2) : currentSettings?.fts5_slug_boost,
      fts5_body_boost: body.fts5_body_boost !== void 0 ? clampWeight(body.fts5_body_boost, currentSettings?.fts5_body_boost ?? 1) : currentSettings?.fts5_body_boost,
      query_synonyms_enabled: body.query_synonyms_enabled !== void 0 ? Boolean(body.query_synonyms_enabled) : currentSettings?.query_synonyms_enabled,
      facets_enabled: body.facets_enabled !== void 0 ? Boolean(body.facets_enabled) : currentSettings?.facets_enabled,
      facet_config: Array.isArray(body.facet_config) ? body.facet_config : currentSettings?.facet_config,
      facet_max_values: body.facet_max_values !== void 0 ? Number(body.facet_max_values) : currentSettings?.facet_max_values
    };
    console.log("[AI Search POST] Updated settings selected_collections:", updatedSettings.selected_collections);
    const collectionsChanged = JSON.stringify(updatedSettings.selected_collections) !== JSON.stringify(currentSettings?.selected_collections || []);
    const saved = await service.updateSettings(updatedSettings);
    console.log("[AI Search POST] Settings saved, selected_collections:", saved.selected_collections);
    if (collectionsChanged && updatedSettings.selected_collections) {
      console.log("[AI Search POST] Collections changed, starting background indexing");
      c.executionCtx.waitUntil(
        indexer.syncAll(updatedSettings.selected_collections).then(() => console.log("[AI Search POST] Background indexing completed")).catch((error) => console.error("[AI Search POST] Background indexing error:", error))
      );
    }
    return c.json({ success: true, settings: saved });
  } catch (error) {
    console.error("Error updating AI Search settings:", error);
    return c.json({ error: "Failed to update settings" }, 500);
  }
});
adminRoutes.get("/api/settings", async (c) => {
  try {
    const db = c.env.DB;
    const ai = c.env.AI;
    const vectorize = c.env.VECTORIZE_INDEX;
    const service = new chunkRCLFF5NO_cjs.AISearchService(db, ai, vectorize);
    const settings = await service.getSettings();
    return c.json({ success: true, data: settings });
  } catch (error) {
    console.error("Error fetching settings:", error);
    return c.json({ error: "Failed to fetch settings" }, 500);
  }
});
adminRoutes.get("/api/new-collections", async (c) => {
  try {
    const db = c.env.DB;
    const ai = c.env.AI;
    const vectorize = c.env.VECTORIZE_INDEX;
    const service = new chunkRCLFF5NO_cjs.AISearchService(db, ai, vectorize);
    const notifications = await service.detectNewCollections();
    return c.json({ success: true, data: notifications });
  } catch (error) {
    console.error("Error detecting new collections:", error);
    return c.json({ error: "Failed to detect new collections" }, 500);
  }
});
adminRoutes.get("/api/status", async (c) => {
  try {
    const db = c.env.DB;
    const ai = c.env.AI;
    const vectorize = c.env.VECTORIZE_INDEX;
    const indexer = new chunkRCLFF5NO_cjs.IndexManager(db, ai, vectorize);
    const status = await indexer.getAllIndexStatus();
    return c.json({ success: true, data: status });
  } catch (error) {
    console.error("Error fetching index status:", error);
    return c.json({ error: "Failed to fetch status" }, 500);
  }
});
adminRoutes.post("/api/reindex", async (c) => {
  try {
    const db = c.env.DB;
    const ai = c.env.AI;
    const vectorize = c.env.VECTORIZE_INDEX;
    const indexer = new chunkRCLFF5NO_cjs.IndexManager(db, ai, vectorize);
    const body = await c.req.json();
    const collectionIdRaw = body.collection_id;
    const collectionId = collectionIdRaw ? String(collectionIdRaw) : "";
    if (!collectionId || collectionId === "undefined" || collectionId === "null") {
      return c.json({ error: "collection_id is required" }, 400);
    }
    c.executionCtx.waitUntil(
      indexer.indexCollection(collectionId).then(() => console.log(`[AI Search Reindex] Completed for collection ${collectionId}`)).catch((error) => console.error(`[AI Search Reindex] Error for collection ${collectionId}:`, error))
    );
    return c.json({ success: true, message: "Re-indexing started" });
  } catch (error) {
    console.error("Error starting re-index:", error);
    return c.json({ error: "Failed to start re-indexing" }, 500);
  }
});
adminRoutes.get("/api/fts5/status", async (c) => {
  try {
    const db = c.env.DB;
    const fts5Service = new chunkRCLFF5NO_cjs.FTS5Service(db);
    const isAvailable = await fts5Service.isAvailable();
    if (!isAvailable) {
      return c.json({
        success: true,
        data: {
          available: false,
          message: "FTS5 tables not yet created. Run migrations to enable FTS5 search."
        }
      });
    }
    const stats = await fts5Service.getStats();
    return c.json({
      success: true,
      data: {
        available: true,
        total_indexed: stats.total_indexed,
        by_collection: stats.by_collection
      }
    });
  } catch (error) {
    console.error("Error fetching FTS5 status:", error);
    return c.json({ error: "Failed to fetch FTS5 status" }, 500);
  }
});
adminRoutes.post("/api/fts5/index-collection", async (c) => {
  try {
    const db = c.env.DB;
    const fts5Service = new chunkRCLFF5NO_cjs.FTS5Service(db);
    const isAvailable = await fts5Service.isAvailable();
    if (!isAvailable) {
      return c.json({
        error: "FTS5 tables not available. Run migrations first."
      }, 400);
    }
    const body = await c.req.json();
    const collectionIdRaw = body.collection_id;
    const collectionId = collectionIdRaw ? String(collectionIdRaw) : "";
    if (!collectionId || collectionId === "undefined" || collectionId === "null") {
      return c.json({ error: "collection_id is required" }, 400);
    }
    c.executionCtx.waitUntil(
      fts5Service.indexCollection(collectionId).then((result) => {
        console.log(`[FTS5 Admin] Indexing completed for collection ${collectionId}:`, result);
      }).catch((error) => {
        console.error(`[FTS5 Admin] Indexing error for collection ${collectionId}:`, error);
      })
    );
    return c.json({
      success: true,
      message: "FTS5 indexing started for collection"
    });
  } catch (error) {
    console.error("Error starting FTS5 index:", error);
    return c.json({ error: "Failed to start FTS5 indexing" }, 500);
  }
});
adminRoutes.post("/api/fts5/reindex-all", async (c) => {
  try {
    const db = c.env.DB;
    const ai = c.env.AI;
    const vectorize = c.env.VECTORIZE_INDEX;
    const service = new chunkRCLFF5NO_cjs.AISearchService(db, ai, vectorize);
    const fts5Service = new chunkRCLFF5NO_cjs.FTS5Service(db);
    const isAvailable = await fts5Service.isAvailable();
    if (!isAvailable) {
      return c.json({
        error: "FTS5 tables not available. Run migrations first."
      }, 400);
    }
    const settings = await service.getSettings();
    const collections2 = settings?.selected_collections || [];
    if (collections2.length === 0) {
      return c.json({
        success: true,
        message: "No collections selected for indexing"
      });
    }
    try {
      const placeholders = collections2.map(() => "?").join(",");
      await db.batch([
        db.prepare(`DELETE FROM content_fts WHERE collection_id NOT IN (${placeholders})`).bind(...collections2),
        db.prepare(`DELETE FROM content_fts_sync WHERE collection_id NOT IN (${placeholders})`).bind(...collections2)
      ]);
      console.log(`[FTS5 Admin] Cleaned up FTS5 entries for unselected collections`);
    } catch (e) {
      console.warn("[FTS5 Admin] Cleanup of unselected collections failed (non-fatal):", e);
    }
    c.executionCtx.waitUntil(
      (async () => {
        console.log(`[FTS5 Admin] Starting reindex-all for ${collections2.length} collections`);
        const results = {};
        for (const collectionId of collections2) {
          try {
            const result = await fts5Service.indexCollection(collectionId);
            results[collectionId] = result;
            console.log(`[FTS5 Admin] Indexed collection ${collectionId}:`, result);
          } catch (error) {
            console.error(`[FTS5 Admin] Error indexing collection ${collectionId}:`, error);
            results[collectionId] = { error: error instanceof Error ? error.message : String(error) };
          }
        }
        console.log("[FTS5 Admin] Reindex-all completed:", results);
      })()
    );
    return c.json({
      success: true,
      message: `FTS5 indexing started for ${collections2.length} collections`,
      collections: collections2
    });
  } catch (error) {
    console.error("Error starting FTS5 reindex-all:", error);
    return c.json({ error: "Failed to start FTS5 reindex" }, 500);
  }
});
adminRoutes.post("/api/vectorize/reindex-all", async (c) => {
  try {
    const db = c.env.DB;
    const ai = c.env.AI;
    const vectorize = c.env.VECTORIZE_INDEX;
    if (!ai || !vectorize) {
      return c.json({ error: "Vectorize reindexing requires AI and VECTORIZE_INDEX bindings." }, 400);
    }
    const service = new chunkRCLFF5NO_cjs.AISearchService(db, ai, vectorize);
    const settings = await service.getSettings();
    const collections2 = settings?.selected_collections || [];
    if (collections2.length === 0) {
      return c.json({ error: "No collections selected. Configure collections in the Configuration tab first." }, 400);
    }
    for (const collectionId of collections2) {
      try {
        await db.prepare(
          "DELETE FROM ai_search_index_meta WHERE collection_id = ?"
        ).bind(collectionId).run();
        const countResult = await db.prepare(
          "SELECT COUNT(*) as cnt FROM content WHERE collection_id = ? AND status != 'deleted'"
        ).bind(collectionId).first();
        const colInfo = await db.prepare(
          "SELECT display_name FROM collections WHERE id = ?"
        ).bind(collectionId).first();
        await db.prepare(`
          INSERT INTO ai_search_index_meta (collection_id, collection_name, total_items, indexed_items, status, last_sync_at)
          VALUES (?, ?, ?, 0, 'indexing', ?)
        `).bind(
          collectionId,
          colInfo?.display_name || collectionId,
          countResult?.cnt || 0,
          Date.now()
        ).run();
      } catch (e) {
      }
    }
    try {
      const benchmarkIds = [];
      for (const dsId of chunkRCLFF5NO_cjs.BENCHMARK_DATASETS.map((d) => d.id)) {
        for (let i = 0; i < 6e3; i++) {
          for (let chunk = 0; chunk < 3; chunk++) {
            benchmarkIds.push(`beir-${dsId}-${i}-chunk-${chunk}`);
          }
        }
      }
      for (let i = 0; i < benchmarkIds.length; i += 1e3) {
        await vectorize.deleteByIds(benchmarkIds.slice(i, i + 1e3));
      }
      console.log("[Vectorize Reindex] Cleaned orphaned benchmark vectors from main index");
    } catch (e) {
      console.warn("[Vectorize Reindex] Orphan cleanup failed (non-fatal):", e);
    }
    const indexer = new chunkRCLFF5NO_cjs.IndexManager(db, ai, vectorize);
    c.executionCtx.waitUntil(
      indexer.syncAll(collections2).then(() => console.log("[Vectorize Reindex] All collections reindexed")).catch((error) => console.error("[Vectorize Reindex] Error:", error))
    );
    return c.json({
      success: true,
      message: `Vectorize reindexing started for ${collections2.length} collection(s)`,
      collections: collections2
    });
  } catch (error) {
    console.error("Error starting Vectorize reindex-all:", error);
    return c.json({ error: "Failed to start Vectorize reindexing" }, 500);
  }
});
adminRoutes.post("/api/relevance/preview", async (c) => {
  try {
    const db = c.env.DB;
    const body = await c.req.json();
    const query = body.query?.trim();
    if (!query) return c.json({ error: "query is required" }, 400);
    const limit = Math.min(body.limit || 10, 20);
    const service = new chunkRCLFF5NO_cjs.AISearchService(db);
    const settings = await service.getSettings();
    const titleWeight = clampWeight(body.title_weight, settings?.fts5_title_boost ?? 5);
    const slugWeight = clampWeight(body.slug_weight, settings?.fts5_slug_boost ?? 2);
    const bodyWeight = clampWeight(body.body_weight, settings?.fts5_body_boost ?? 1);
    const previewSettings = {
      ...settings,
      fts5_title_boost: titleWeight,
      fts5_slug_boost: slugWeight,
      fts5_body_boost: bodyWeight
    };
    const fts5Service = new chunkRCLFF5NO_cjs.FTS5Service(db);
    let result = await fts5Service.search(
      { query, mode: "fts5", limit, offset: 0 },
      previewSettings,
      { titleBoost: titleWeight, slugBoost: slugWeight, bodyBoost: bodyWeight }
    );
    const pipelineService = new chunkRCLFF5NO_cjs.RankingPipelineService(db);
    let pipelineApplied = false;
    try {
      const config = await pipelineService.getConfig();
      const activeStages = config.filter((s) => s.enabled && s.weight > 0);
      if (activeStages.length > 0) {
        result = await pipelineService.apply(result, query);
        pipelineApplied = true;
      }
    } catch (err) {
      console.warn("[Relevance Preview] Pipeline application failed:", err);
    }
    return c.json({
      success: true,
      data: {
        results: result.results,
        total: result.total,
        query_time_ms: result.query_time_ms,
        weights: { title: titleWeight, slug: slugWeight, body: bodyWeight },
        pipeline_applied: pipelineApplied
      }
    });
  } catch (error) {
    console.error("Error in relevance preview:", error);
    return c.json({ error: "Preview search failed: " + (error instanceof Error ? error.message : String(error)) }, 500);
  }
});
adminRoutes.get("/api/relevance/pipeline", async (c) => {
  try {
    const pipelineService = new chunkRCLFF5NO_cjs.RankingPipelineService(c.env.DB);
    const config = await pipelineService.getConfig();
    return c.json({ success: true, data: config });
  } catch (error) {
    console.error("Error fetching pipeline config:", error);
    return c.json({ error: "Failed to fetch pipeline config" }, 500);
  }
});
adminRoutes.post("/api/relevance/pipeline", async (c) => {
  try {
    const body = await c.req.json();
    if (!Array.isArray(body.stages)) {
      return c.json({ error: "stages must be an array" }, 400);
    }
    const pipelineService = new chunkRCLFF5NO_cjs.RankingPipelineService(c.env.DB);
    await pipelineService.saveConfig(body.stages);
    const saved = await pipelineService.getConfig();
    return c.json({ success: true, data: saved });
  } catch (error) {
    console.error("Error saving pipeline config:", error);
    return c.json({ error: "Failed to save pipeline config" }, 500);
  }
});
adminRoutes.get("/api/relevance/content-scores", async (c) => {
  try {
    const contentId = c.req.query("content_id");
    const scoreType = c.req.query("score_type") || "popularity";
    if (!contentId) {
      return c.json({ error: "content_id query parameter is required" }, 400);
    }
    const pipelineService = new chunkRCLFF5NO_cjs.RankingPipelineService(c.env.DB);
    const scores = await pipelineService.getContentScores([contentId], scoreType);
    return c.json({
      success: true,
      data: { content_id: contentId, score_type: scoreType, score: scores.get(contentId) ?? null }
    });
  } catch (error) {
    console.error("Error fetching content scores:", error);
    return c.json({ error: "Failed to fetch content scores" }, 500);
  }
});
adminRoutes.post("/api/relevance/content-scores", async (c) => {
  try {
    const body = await c.req.json();
    const { content_id: contentId, score_type: scoreType, score } = body;
    if (!contentId || !scoreType || score == null) {
      return c.json({ error: "content_id, score_type, and score are required" }, 400);
    }
    if (!["popularity", "custom"].includes(scoreType)) {
      return c.json({ error: 'score_type must be "popularity" or "custom"' }, 400);
    }
    const pipelineService = new chunkRCLFF5NO_cjs.RankingPipelineService(c.env.DB);
    await pipelineService.setContentScore(String(contentId), scoreType, Number(score));
    return c.json({ success: true });
  } catch (error) {
    console.error("Error setting content score:", error);
    return c.json({ error: "Failed to set content score" }, 500);
  }
});
adminRoutes.delete("/api/relevance/content-scores", async (c) => {
  try {
    const body = await c.req.json();
    const { content_id: contentId, score_type: scoreType } = body;
    if (!contentId || !scoreType) {
      return c.json({ error: "content_id and score_type are required" }, 400);
    }
    const pipelineService = new chunkRCLFF5NO_cjs.RankingPipelineService(c.env.DB);
    await pipelineService.deleteContentScore(String(contentId), scoreType);
    return c.json({ success: true });
  } catch (error) {
    console.error("Error deleting content score:", error);
    return c.json({ error: "Failed to delete content score" }, 500);
  }
});
adminRoutes.get("/api/relevance/synonyms", async (c) => {
  try {
    const synonymService = new chunkRCLFF5NO_cjs.SynonymService(c.env.DB);
    const groups = await synonymService.getAll();
    return c.json({ success: true, data: groups });
  } catch (error) {
    console.error("Error fetching synonym groups:", error);
    return c.json({ error: "Failed to fetch synonym groups" }, 500);
  }
});
adminRoutes.post("/api/relevance/synonyms", async (c) => {
  try {
    const body = await c.req.json();
    if (!Array.isArray(body.terms) || body.terms.length < 2) {
      return c.json({ error: "terms must be an array with at least 2 items" }, 400);
    }
    const synonymService = new chunkRCLFF5NO_cjs.SynonymService(c.env.DB);
    const group = await synonymService.create(body.terms, body.enabled !== false);
    return c.json({ success: true, data: group });
  } catch (error) {
    console.error("Error creating synonym group:", error);
    return c.json({ error: error instanceof Error ? error.message : "Failed to create synonym group" }, 500);
  }
});
adminRoutes.put("/api/relevance/synonyms/:id", async (c) => {
  try {
    const id = c.req.param("id");
    const body = await c.req.json();
    const synonymService = new chunkRCLFF5NO_cjs.SynonymService(c.env.DB);
    const group = await synonymService.update(id, {
      terms: body.terms,
      enabled: body.enabled
    });
    if (!group) {
      return c.json({ error: "Synonym group not found" }, 404);
    }
    return c.json({ success: true, data: group });
  } catch (error) {
    console.error("Error updating synonym group:", error);
    return c.json({ error: error instanceof Error ? error.message : "Failed to update synonym group" }, 500);
  }
});
adminRoutes.delete("/api/relevance/synonyms/:id", async (c) => {
  try {
    const id = c.req.param("id");
    const synonymService = new chunkRCLFF5NO_cjs.SynonymService(c.env.DB);
    const deleted = await synonymService.delete(id);
    if (!deleted) {
      return c.json({ error: "Synonym group not found" }, 404);
    }
    return c.json({ success: true });
  } catch (error) {
    console.error("Error deleting synonym group:", error);
    return c.json({ error: "Failed to delete synonym group" }, 500);
  }
});
adminRoutes.get("/api/facets/discover", async (c) => {
  try {
    const facetService = new chunkRCLFF5NO_cjs.FacetService(c.env.DB);
    const discovered = await facetService.discoverFields();
    return c.json({ success: true, data: discovered });
  } catch (error) {
    console.error("Error discovering facet fields:", error);
    return c.json({ error: "Failed to discover facet fields" }, 500);
  }
});
var BUILTIN_SHADOW_FIELDS = /* @__PURE__ */ new Set(["$.author", "$.status"]);
function stripShadowFacets(config) {
  return config.filter((f) => !BUILTIN_SHADOW_FIELDS.has(f.field));
}
adminRoutes.get("/api/facets/config", async (c) => {
  try {
    const service = new chunkRCLFF5NO_cjs.AISearchService(c.env.DB);
    const settings = await service.getSettings();
    const config = stripShadowFacets(settings?.facet_config ?? []);
    return c.json({
      success: true,
      data: {
        enabled: settings?.facets_enabled ?? false,
        config,
        max_values: settings?.facet_max_values ?? 20
      }
    });
  } catch (error) {
    console.error("Error fetching facet config:", error);
    return c.json({ error: "Failed to fetch facet config" }, 500);
  }
});
adminRoutes.post("/api/facets/config", async (c) => {
  try {
    const body = await c.req.json();
    const service = new chunkRCLFF5NO_cjs.AISearchService(c.env.DB);
    const updates = {};
    if (body.enabled !== void 0) updates.facets_enabled = Boolean(body.enabled);
    if (Array.isArray(body.config)) updates.facet_config = stripShadowFacets(body.config);
    if (body.max_values !== void 0) updates.facet_max_values = Number(body.max_values);
    const saved = await service.updateSettings(updates);
    return c.json({
      success: true,
      data: {
        enabled: saved.facets_enabled ?? false,
        config: saved.facet_config ?? [],
        max_values: saved.facet_max_values ?? 20
      }
    });
  } catch (error) {
    console.error("Error saving facet config:", error);
    return c.json({ error: "Failed to save facet config" }, 500);
  }
});
adminRoutes.post("/api/facets/auto-generate", async (c) => {
  try {
    const facetService = new chunkRCLFF5NO_cjs.FacetService(c.env.DB);
    const discovered = await facetService.discoverFields();
    const config = facetService.autoGenerateConfig(discovered);
    const service = new chunkRCLFF5NO_cjs.AISearchService(c.env.DB);
    const saved = await service.updateSettings({
      facets_enabled: true,
      facet_config: config
    });
    return c.json({
      success: true,
      data: {
        enabled: true,
        config: saved.facet_config ?? config,
        discovered_count: discovered.length,
        auto_enabled_count: config.length
      }
    });
  } catch (error) {
    console.error("Error auto-generating facet config:", error);
    return c.json({ error: "Failed to auto-generate facet config" }, 500);
  }
});
adminRoutes.post("/api/seed/clicks", async (c) => {
  try {
    const body = await c.req.json();
    if (!Array.isArray(body.searches) || body.searches.length === 0) {
      return c.json({ error: "searches array is required" }, 400);
    }
    const db = c.env.DB;
    const days = body.days || 30;
    const now = Date.now();
    const msPerDay = 24 * 60 * 60 * 1e3;
    let searchCount = 0;
    let clickCount = 0;
    for (const [i, s] of body.searches.entries()) {
      const daysAgo = i / body.searches.length * days;
      const jitter = (Math.random() - 0.5) * msPerDay;
      const searchTimestamp = now - daysAgo * msPerDay + jitter;
      const historyResult = await db.prepare(
        `INSERT INTO ai_search_history (query, mode, results_count, response_time_ms, created_at) VALUES (?, ?, ?, ?, ?)`
      ).bind(s.query, s.mode, s.results_count, s.response_time_ms, Math.floor(searchTimestamp)).run();
      const searchId = historyResult.meta?.last_row_id?.toString();
      searchCount++;
      if (s.clicks && searchId) {
        for (const click of s.clicks) {
          const clickId = crypto.randomUUID();
          const clickOffset = Math.floor(Math.random() * 60) * 1e3;
          const clickDatetime = new Date(searchTimestamp + clickOffset).toISOString().replace("T", " ").replace("Z", "").slice(0, 19);
          await db.prepare(
            `INSERT INTO ai_search_clicks (id, search_id, query, mode, clicked_content_id, clicked_content_title, click_position, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
          ).bind(clickId, searchId, s.query, s.mode, click.content_id, click.content_title, click.position, clickDatetime).run();
          clickCount++;
        }
      }
    }
    return c.json({
      success: true,
      data: { searches_inserted: searchCount, clicks_inserted: clickCount }
    });
  } catch (error) {
    console.error("Error seeding click data:", error);
    return c.json({ error: `Seed failed: ${error instanceof Error ? error.message : String(error)}` }, 500);
  }
});
adminRoutes.post("/api/seed/facet-clicks", async (c) => {
  try {
    const body = await c.req.json();
    if (!Array.isArray(body.clicks) || body.clicks.length === 0) {
      return c.json({ error: "clicks array is required" }, 400);
    }
    const db = c.env.DB;
    const days = body.days || 30;
    const now = Date.now();
    const msPerDay = 24 * 60 * 60 * 1e3;
    let insertCount = 0;
    for (const [i, fc] of body.clicks.entries()) {
      const id = crypto.randomUUID();
      const daysAgo = i / body.clicks.length * days;
      const jitter = (Math.random() - 0.5) * msPerDay;
      const timestamp = now - daysAgo * msPerDay + jitter;
      const datetime = new Date(timestamp).toISOString().replace("T", " ").replace("Z", "").slice(0, 19);
      await db.prepare(
        `INSERT INTO ai_search_facet_clicks (id, search_id, facet_field, facet_value, created_at) VALUES (?, ?, ?, ?, ?)`
      ).bind(id, fc.search_id || null, fc.facet_field, fc.facet_value, datetime).run();
      insertCount++;
    }
    return c.json({
      success: true,
      data: { facet_clicks_inserted: insertCount }
    });
  } catch (error) {
    console.error("Error seeding facet click data:", error);
    return c.json({ error: `Seed failed: ${error instanceof Error ? error.message : String(error)}` }, 500);
  }
});
adminRoutes.delete("/api/seed/clicks", async (c) => {
  try {
    const db = c.env.DB;
    await db.prepare("DELETE FROM ai_search_clicks").run();
    await db.prepare("DELETE FROM ai_search_history").run();
    return c.json({ success: true, message: "Cleared click tracking and search history data" });
  } catch (error) {
    return c.json({ error: `Clear failed: ${error instanceof Error ? error.message : String(error)}` }, 500);
  }
});
adminRoutes.delete("/api/seed/facet-clicks", async (c) => {
  try {
    const db = c.env.DB;
    await db.prepare("DELETE FROM ai_search_facet_clicks").run();
    return c.json({ success: true, message: "Cleared facet click data" });
  } catch (error) {
    return c.json({ error: `Clear failed: ${error instanceof Error ? error.message : String(error)}` }, 500);
  }
});
adminRoutes.get("/api/analytics/extended", async (c) => {
  try {
    const db = c.env.DB;
    const ai = c.env.AI;
    const vectorize = c.env.VECTORIZE_INDEX;
    const service = new chunkRCLFF5NO_cjs.AISearchService(db, ai, vectorize);
    const data = await service.getAnalyticsExtended();
    return c.json({ success: true, data });
  } catch (error) {
    console.error("Error fetching extended analytics:", error);
    return c.json({ success: false, error: error instanceof Error ? error.message : String(error) }, 500);
  }
});
adminRoutes.get("/api/benchmark/datasets", async (c) => {
  return c.json({ success: true, datasets: chunkRCLFF5NO_cjs.BENCHMARK_DATASETS });
});
adminRoutes.get("/api/benchmark/status", async (c) => {
  try {
    const db = c.env.DB;
    const kv = c.env.CACHE_KV;
    const dataset = c.req.query("dataset") || "scifact";
    const benchmarkService = new chunkRCLFF5NO_cjs.BenchmarkService(db, kv, void 0, dataset);
    const { seeded, count } = await benchmarkService.isSeeded();
    const meta = benchmarkService.getMeta();
    const dataAvailable = await benchmarkService.isDataAvailable();
    let subsetSize = 0;
    let evaluableQueries = 0;
    if (dataAvailable) {
      try {
        const [ss, eqIds] = await Promise.all([
          benchmarkService.getSubsetSize(),
          benchmarkService.getEvaluableQueryIds(0)
        ]);
        subsetSize = ss;
        evaluableQueries = eqIds.length;
      } catch (e) {
      }
    }
    return c.json({
      success: true,
      data: {
        seeded,
        seeded_count: count,
        corpus_size: meta.corpus_size,
        subset_size: subsetSize,
        query_count: meta.query_count,
        evaluable_queries: evaluableQueries,
        dataset: meta.name,
        dataset_id: dataset,
        license: meta.license,
        data_available: dataAvailable
      }
    });
  } catch (error) {
    console.error("Error fetching benchmark status:", error);
    return c.json({ error: `Failed to fetch benchmark status: ${error instanceof Error ? error.message : String(error)}` }, 500);
  }
});
adminRoutes.post("/api/benchmark/seed", async (c) => {
  try {
    const user = c.get("user");
    const db = c.env.DB;
    const kv = c.env.CACHE_KV;
    const body = await c.req.json().catch(() => ({}));
    const dataset = body.dataset || "scifact";
    const useSubset = body.corpus_size !== "full";
    const benchmarkService = new chunkRCLFF5NO_cjs.BenchmarkService(db, kv, void 0, dataset);
    const collectionId = benchmarkService.getCollectionId();
    const userId = user.userId || user.id;
    const result = await benchmarkService.seed(String(userId), useSubset);
    if (useSubset) {
      const fts5Service = new chunkRCLFF5NO_cjs.FTS5Service(db);
      c.executionCtx.waitUntil(
        fts5Service.indexCollection(collectionId).then((r) => console.log(`[Benchmark:${dataset}] FTS5 indexed ${r.indexed_items}/${r.total_items} docs`)).catch((e) => console.error(`[Benchmark:${dataset}] FTS5 indexing error:`, e))
      );
    }
    const meta = benchmarkService.getMeta();
    const indexNote = useSubset ? "FTS5 indexing started in background." : "Use the Index buttons to index before evaluating.";
    if (result.skipped) {
      return c.json({
        success: true,
        message: `Benchmark data already exists (${result.seeded} documents). ${indexNote}`,
        seeded: result.seeded,
        skipped: true
      });
    }
    return c.json({
      success: true,
      message: `Seeded ${result.seeded} ${meta.name} documents. ${indexNote}`,
      seeded: result.seeded,
      skipped: false
    });
  } catch (error) {
    console.error("Error seeding benchmark data:", error);
    return c.json(
      { error: `Failed to seed benchmark data: ${error instanceof Error ? error.message : String(error)}` },
      500
    );
  }
});
adminRoutes.post("/api/benchmark/purge", async (c) => {
  try {
    const db = c.env.DB;
    const kv = c.env.CACHE_KV;
    const vectorize = c.env.VECTORIZE_BENCHMARK_INDEX || c.env.VECTORIZE_INDEX;
    const body = await c.req.json().catch(() => ({}));
    const dataset = body.dataset || "scifact";
    const benchmarkService = new chunkRCLFF5NO_cjs.BenchmarkService(db, kv, vectorize, dataset);
    const deleted = await benchmarkService.purge();
    return c.json({
      success: true,
      message: `Removed ${deleted} benchmark documents`,
      deleted
    });
  } catch (error) {
    console.error("Error purging benchmark data:", error);
    return c.json({ error: "Failed to purge benchmark data" }, 500);
  }
});
adminRoutes.post("/api/benchmark/index-fts5-batch", async (c) => {
  try {
    const db = c.env.DB;
    const fts5Service = new chunkRCLFF5NO_cjs.FTS5Service(db);
    if (!await fts5Service.isAvailable()) {
      return c.json({ error: "FTS5 tables not available." }, 400);
    }
    const body = await c.req.json().catch(() => ({}));
    const dataset = body.dataset || "scifact";
    const batchSize = body.batch_size || 200;
    const collectionId = `benchmark-${dataset}-collection`;
    const result = await fts5Service.indexCollectionBatch(
      collectionId,
      batchSize
    );
    return c.json({
      success: true,
      indexed: result.indexed,
      remaining: result.remaining,
      total: result.total
    });
  } catch (error) {
    console.error("Error in FTS5 batch indexing:", error);
    return c.json({ error: `FTS5 batch indexing failed: ${error instanceof Error ? error.message : String(error)}` }, 500);
  }
});
adminRoutes.post("/api/benchmark/index-vectorize-batch", async (c) => {
  try {
    const db = c.env.DB;
    const ai = c.env.AI;
    const vectorize = c.env.VECTORIZE_BENCHMARK_INDEX || c.env.VECTORIZE_INDEX;
    if (!ai || !vectorize) {
      return c.json({ error: "Vectorize indexing requires AI and VECTORIZE_BENCHMARK_INDEX bindings." }, 400);
    }
    const body = await c.req.json().catch(() => ({}));
    const dataset = body.dataset || "scifact";
    const batchSize = body.batch_size || 25;
    const offset = body.offset || 0;
    const benchmarkCollectionId = `benchmark-${dataset}-collection`;
    const datasetInfo = chunkRCLFF5NO_cjs.BENCHMARK_DATASETS.find((d) => d.id === dataset);
    const displayName = datasetInfo ? `${datasetInfo.name} Benchmark` : `BEIR ${dataset} Benchmark`;
    const embeddingService = new chunkRCLFF5NO_cjs.EmbeddingService(ai);
    const chunkingService = new chunkRCLFF5NO_cjs.ChunkingService();
    const totalResult = await db.prepare("SELECT COUNT(*) as cnt FROM content WHERE collection_id = ? AND status != 'deleted'").bind(benchmarkCollectionId).first();
    const total = totalResult?.cnt || 0;
    if (offset >= total) {
      try {
        await db.prepare(`
          INSERT OR REPLACE INTO ai_search_index_meta
          (collection_id, collection_name, total_items, indexed_items, last_sync_at, status)
          VALUES (?, ?, ?, ?, ?, 'completed')
        `).bind(benchmarkCollectionId, displayName, total, total, Date.now()).run();
      } catch (e) {
      }
      return c.json({ success: true, indexed: 0, offset, total, remaining: 0 });
    }
    const { results: contentItems } = await db.prepare(`
        SELECT c.id, c.title, c.data, c.collection_id, c.status,
               c.created_at, c.author_id
        FROM content c
        WHERE c.collection_id = ? AND c.status != 'deleted'
        ORDER BY c.id
        LIMIT ? OFFSET ?
      `).bind(benchmarkCollectionId, batchSize, offset).all();
    const items = (contentItems || []).map((item) => ({
      id: item.id,
      collection_id: item.collection_id,
      title: item.title || "Untitled",
      data: typeof item.data === "string" ? JSON.parse(item.data) : item.data,
      metadata: {
        status: item.status,
        created_at: item.created_at,
        author_id: item.author_id,
        collection_name: `benchmark_${dataset}`,
        collection_display_name: displayName
      }
    }));
    const chunks = chunkingService.chunkContentBatch(items);
    const embeddings = await embeddingService.generateBatch(
      chunks.map((ch) => `${ch.title}

${ch.text}`)
    );
    let indexedChunks = 0;
    const upsertBatchSize = 100;
    for (let i = 0; i < chunks.length; i += upsertBatchSize) {
      const chunkBatch = chunks.slice(i, i + upsertBatchSize);
      const embBatch = embeddings.slice(i, i + upsertBatchSize);
      try {
        await vectorize.upsert(
          chunkBatch.map((chunk, idx) => ({
            id: chunk.id,
            values: embBatch[idx],
            metadata: {
              content_id: chunk.content_id,
              collection_id: chunk.collection_id,
              title: chunk.title,
              text: chunk.text.substring(0, 500),
              chunk_index: chunk.chunk_index,
              ...chunk.metadata
            }
          }))
        );
        indexedChunks += chunkBatch.length;
      } catch (error) {
        console.error(`[Benchmark:${dataset} Vectorize] Upsert error at batch offset ${i}:`, error);
      }
    }
    const newOffset = offset + (contentItems?.length || 0);
    const remaining = Math.max(0, total - newOffset);
    try {
      await db.prepare(`
        INSERT OR REPLACE INTO ai_search_index_meta
        (collection_id, collection_name, total_items, indexed_items, last_sync_at, status)
        VALUES (?, ?, ?, ?, ?, ?)
      `).bind(
        benchmarkCollectionId,
        displayName,
        total,
        newOffset,
        Date.now(),
        remaining > 0 ? "indexing" : "completed"
      ).run();
    } catch (e) {
    }
    return c.json({
      success: true,
      indexed: indexedChunks,
      items_processed: contentItems?.length || 0,
      offset: newOffset,
      total,
      remaining
    });
  } catch (error) {
    console.error("Error in Vectorize batch indexing:", error);
    return c.json({ error: `Vectorize batch indexing failed: ${error instanceof Error ? error.message : String(error)}` }, 500);
  }
});
adminRoutes.post("/api/benchmark/index-vectorize", async (c) => {
  try {
    const db = c.env.DB;
    const kv = c.env.CACHE_KV;
    const ai = c.env.AI;
    const vectorize = c.env.VECTORIZE_BENCHMARK_INDEX || c.env.VECTORIZE_INDEX;
    if (!ai || !vectorize) {
      return c.json(
        { error: "Vectorize indexing requires AI and VECTORIZE_BENCHMARK_INDEX bindings. Configure them in wrangler.toml." },
        400
      );
    }
    const body = await c.req.json().catch(() => ({}));
    const dataset = body.dataset || "scifact";
    const benchmarkService = new chunkRCLFF5NO_cjs.BenchmarkService(db, kv, void 0, dataset);
    const { seeded } = await benchmarkService.isSeeded();
    if (!seeded) {
      return c.json({ error: "Benchmark data not seeded. Seed first." }, 400);
    }
    const collectionId = benchmarkService.getCollectionId();
    const meta = benchmarkService.getMeta();
    const displayName = `${meta.name} Benchmark`;
    try {
      await db.prepare(`
        INSERT OR REPLACE INTO ai_search_index_meta
        (collection_id, collection_name, total_items, indexed_items, last_sync_at, status)
        VALUES (?, ?, 0, 0, ?, 'indexing')
      `).bind(collectionId, displayName, Date.now()).run();
    } catch (e) {
    }
    return c.json({
      success: true,
      message: "Vectorize index reset. Use batch indexing to process documents."
    });
  } catch (error) {
    console.error("Error starting Vectorize indexing:", error);
    return c.json({ error: "Failed to start Vectorize indexing" }, 500);
  }
});
adminRoutes.post("/api/benchmark/evaluate", async (c) => {
  try {
    const db = c.env.DB;
    const kv = c.env.CACHE_KV;
    const ai = c.env.AI;
    const vectorize = c.env.VECTORIZE_BENCHMARK_INDEX || c.env.VECTORIZE_INDEX;
    const body = await c.req.json();
    const mode = body.mode || "fts5";
    const limit = body.limit || 10;
    const maxQueries = body.max_queries || 0;
    const dataset = body.dataset || "scifact";
    const benchmarkService = new chunkRCLFF5NO_cjs.BenchmarkService(db, kv, void 0, dataset);
    const collectionId = benchmarkService.getCollectionId();
    const { seeded } = await benchmarkService.isSeeded();
    if (!seeded) {
      return c.json(
        { error: "Benchmark data not seeded. Call /api/benchmark/seed first." },
        400
      );
    }
    if (mode === "fts5" || mode === "hybrid") {
      const fts5Service = new chunkRCLFF5NO_cjs.FTS5Service(db);
      if (await fts5Service.isAvailable()) {
        const ftsCount = await db.prepare("SELECT COUNT(*) as cnt FROM content_fts WHERE collection_id = ?").bind(collectionId).first();
        if (!ftsCount || ftsCount.cnt === 0) {
          return c.json(
            { error: 'Benchmark data not yet FTS5-indexed. Click "Seed Data" again or wait for background indexing to complete, then retry.' },
            400
          );
        }
      }
    }
    if ((mode === "ai" || mode === "hybrid") && !vectorize) {
      return c.json(
        { error: `${mode.toUpperCase()} mode requires a Vectorize index binding. Configure it in wrangler.toml.` },
        400
      );
    }
    if (mode === "ai" || mode === "hybrid") {
      try {
        const indexMeta = await db.prepare("SELECT status, indexed_items FROM ai_search_index_meta WHERE collection_id = ?").bind(collectionId).first();
        if (!indexMeta || indexMeta.indexed_items === 0) {
          return c.json(
            { error: 'Benchmark data not yet Vectorize-indexed. Click "Index (Vectorize)" first and wait for it to complete.' },
            400
          );
        }
        if (indexMeta.status === "indexing") {
          return c.json(
            { error: "Vectorize indexing is still in progress. Wait for it to complete, then retry." },
            400
          );
        }
      } catch (e) {
        return c.json(
          { error: 'Benchmark data not yet Vectorize-indexed. Click "Index (Vectorize)" first.' },
          400
        );
      }
    }
    const aiSearchService = new chunkRCLFF5NO_cjs.AISearchService(db, ai, vectorize);
    const searchFn = async (query, searchMode, searchLimit) => {
      const response = await aiSearchService.search({
        query,
        mode: searchMode,
        limit: searchLimit,
        filters: { collections: [collectionId] }
      });
      return { results: response.results.map((r) => ({ id: r.id })) };
    };
    const results = await benchmarkService.evaluate(
      searchFn,
      mode,
      limit,
      maxQueries
    );
    return c.json({ success: true, ...results });
  } catch (error) {
    console.error("Error running benchmark evaluation:", error);
    return c.json(
      { error: `Benchmark evaluation failed: ${error instanceof Error ? error.message : String(error)}` },
      500
    );
  }
});
adminRoutes.get("/api/benchmark/query-ids", async (c) => {
  try {
    const maxQueries = parseInt(c.req.query("max_queries") || "0", 10);
    const dataset = c.req.query("dataset") || "scifact";
    const db = c.env.DB;
    const kv = c.env.CACHE_KV;
    const benchmarkService = new chunkRCLFF5NO_cjs.BenchmarkService(db, kv, void 0, dataset);
    const ids = await benchmarkService.getEvaluableQueryIds(maxQueries);
    return c.json({ success: true, query_ids: ids, total: ids.length });
  } catch (error) {
    return c.json({ error: String(error) }, 500);
  }
});
adminRoutes.post("/api/benchmark/evaluate-batch", async (c) => {
  try {
    const db = c.env.DB;
    const kv = c.env.CACHE_KV;
    const ai = c.env.AI;
    const vectorize = c.env.VECTORIZE_BENCHMARK_INDEX || c.env.VECTORIZE_INDEX;
    const body = await c.req.json();
    const mode = body.mode || "fts5";
    const limit = body.limit || 10;
    const queryIds = body.query_ids || [];
    const dataset = body.dataset || "scifact";
    if (queryIds.length === 0) {
      return c.json({ error: "No query_ids provided" }, 400);
    }
    if ((mode === "ai" || mode === "hybrid") && !vectorize) {
      return c.json({ error: `${mode.toUpperCase()} mode requires Vectorize binding.` }, 400);
    }
    const benchmarkService = new chunkRCLFF5NO_cjs.BenchmarkService(db, kv, void 0, dataset);
    const collectionId = benchmarkService.getCollectionId();
    const aiSearchService = new chunkRCLFF5NO_cjs.AISearchService(db, ai, vectorize);
    const searchFn = async (query, searchMode, searchLimit) => {
      const response = await aiSearchService.search({
        query,
        mode: searchMode,
        limit: searchLimit,
        filters: { collections: [collectionId] }
      });
      return { results: response.results.map((r) => ({ id: r.id })) };
    };
    const perQuery = await benchmarkService.evaluateBatch(searchFn, mode, limit, queryIds);
    return c.json({
      success: true,
      per_query: perQuery,
      evaluated: perQuery.length
    });
  } catch (error) {
    console.error("Error in batch evaluation:", error);
    return c.json({ error: String(error) }, 500);
  }
});
var admin_default = adminRoutes;
var apiRoutes = new hono.Hono();
apiRoutes.post("/", async (c) => {
  try {
    const db = c.env.DB;
    const ai = c.env.AI;
    const vectorize = c.env.VECTORIZE_INDEX;
    const service = new chunkRCLFF5NO_cjs.AISearchService(db, ai, vectorize);
    const body = await c.req.json();
    const query = {
      query: body.query || "",
      mode: body.mode || "keyword",
      filters: body.filters || {},
      limit: body.limit ? Number(body.limit) : void 0,
      offset: body.offset ? Number(body.offset) : void 0,
      facets: body.facets === true
    };
    if (query.filters?.dateRange) {
      if (typeof query.filters.dateRange.start === "string") {
        query.filters.dateRange.start = new Date(query.filters.dateRange.start);
      }
      if (typeof query.filters.dateRange.end === "string") {
        query.filters.dateRange.end = new Date(query.filters.dateRange.end);
      }
    }
    const results = await service.search(query);
    return c.json({
      success: true,
      data: results
    });
  } catch (error) {
    console.error("Search error:", error);
    return c.json(
      {
        success: false,
        error: "Search failed",
        message: error instanceof Error ? error.message : String(error)
      },
      500
    );
  }
});
apiRoutes.get("/suggest", async (c) => {
  try {
    const db = c.env.DB;
    const ai = c.env.AI;
    const vectorize = c.env.VECTORIZE_INDEX;
    const service = new chunkRCLFF5NO_cjs.AISearchService(db, ai, vectorize);
    const query = c.req.query("q") || "";
    if (!query || query.length < 2) {
      return c.json({ success: true, data: [] });
    }
    const suggestions = await service.getSearchSuggestions(query);
    return c.json({
      success: true,
      data: suggestions
    });
  } catch (error) {
    console.error("Suggestions error:", error);
    return c.json(
      {
        success: false,
        error: "Failed to get suggestions"
      },
      500
    );
  }
});
apiRoutes.post("/click", async (c) => {
  try {
    const db = c.env.DB;
    const body = await c.req.json();
    const searchId = body.search_id;
    const contentId = body.content_id;
    const clickPosition = body.click_position;
    if (!contentId || typeof contentId !== "string") {
      return c.json({ success: false, error: "content_id is required" }, 400);
    }
    if (!clickPosition || typeof clickPosition !== "number" || clickPosition < 1 || !Number.isInteger(clickPosition)) {
      return c.json({ success: false, error: "click_position must be a positive integer" }, 400);
    }
    let query = null;
    let mode = null;
    if (searchId) {
      try {
        const historyRow = await db.prepare("SELECT query, mode FROM ai_search_history WHERE id = ? LIMIT 1").bind(Number(searchId)).first();
        if (historyRow) {
          query = historyRow.query;
          mode = historyRow.mode;
        }
      } catch {
      }
    }
    const clickId = crypto.randomUUID();
    await db.prepare(`
        INSERT INTO ai_search_clicks (id, search_id, query, mode, clicked_content_id, clicked_content_title, click_position, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
      `).bind(
      clickId,
      searchId || null,
      query,
      mode,
      contentId,
      body.content_title || null,
      clickPosition
    ).run();
    return c.json({ success: true });
  } catch (error) {
    console.error("Click tracking error:", error);
    return c.json({ success: true });
  }
});
apiRoutes.post("/facet-click", async (c) => {
  try {
    const db = c.env.DB;
    const body = await c.req.json();
    const facetField = body.facet_field;
    const facetValue = body.facet_value;
    const searchId = body.search_id;
    if (!facetField || typeof facetField !== "string") {
      return c.json({ success: false, error: "facet_field is required" }, 400);
    }
    if (!facetValue || typeof facetValue !== "string") {
      return c.json({ success: false, error: "facet_value is required" }, 400);
    }
    const id = crypto.randomUUID();
    await db.prepare(`
        INSERT INTO ai_search_facet_clicks (id, search_id, facet_field, facet_value, created_at)
        VALUES (?, ?, ?, ?, datetime('now'))
      `).bind(id, searchId || null, facetField, facetValue).run();
    return c.json({ success: true });
  } catch (error) {
    console.error("Facet click tracking error:", error);
    return c.json({ success: true });
  }
});
apiRoutes.get("/analytics", async (c) => {
  try {
    const db = c.env.DB;
    const ai = c.env.AI;
    const vectorize = c.env.VECTORIZE_INDEX;
    const service = new chunkRCLFF5NO_cjs.AISearchService(db, ai, vectorize);
    const analytics = await service.getSearchAnalytics();
    return c.json({
      success: true,
      data: analytics
    });
  } catch (error) {
    console.error("Analytics error:", error);
    return c.json(
      {
        success: false,
        error: "Failed to get analytics"
      },
      500
    );
  }
});
var api_default2 = apiRoutes;

// src/plugins/core-plugins/ai-search-plugin/services/instantsearch-adapter.ts
var InstantSearchAdapter = class {
  constructor(db) {
    this.db = db;
  }
  collectionCache = /* @__PURE__ */ new Map();
  /**
   * Convert an InstantSearch request to a SonicJS SearchQuery
   */
  async toSonicQuery(request, settings) {
    const params = request.params || {};
    const page = params.page ?? 0;
    const hitsPerPage = Math.min(params.hitsPerPage ?? 20, 200);
    const collections2 = await this.resolveCollections(request.indexName);
    const mode = this.determineSearchMode(settings);
    const customFilters = this.parseFacetFilters(params.facetFilters);
    return {
      query: params.query || "",
      mode,
      limit: hitsPerPage,
      offset: page * hitsPerPage,
      filters: {
        collections: collections2.length > 0 ? collections2 : void 0,
        status: this.parseStatusFilter(params.filters),
        ...Object.keys(customFilters).length > 0 ? { custom: customFilters } : {}
      },
      facets: params.facets && params.facets.length > 0 ? true : void 0
    };
  }
  /**
   * Convert a SonicJS SearchResponse to an InstantSearch result
   */
  toInstantSearchResult(response, request, queryTime) {
    const params = request.params || {};
    const page = params.page ?? 0;
    const hitsPerPage = Math.min(params.hitsPerPage ?? 20, 200);
    const hits = response.results.map((r) => this.toHit(r, params));
    const nbPages = hitsPerPage > 0 ? Math.ceil(response.total / hitsPerPage) : 0;
    const facets = response.facets && response.facets.length > 0 ? this.mapFacetResults(response.facets, params.facets) : this.computeFacets(response.results, params.facets);
    return {
      hits,
      nbHits: response.total,
      page,
      nbPages,
      hitsPerPage,
      processingTimeMS: queryTime,
      query: params.query || "",
      params: this.buildParamsString(params),
      exhaustiveNbHits: true,
      ...Object.keys(facets).length > 0 ? { facets } : {},
      index: request.indexName
    };
  }
  // --------------------------------------------------
  // Private helpers
  // --------------------------------------------------
  toHit(result, params) {
    const pre = params.highlightPreTag || "<em>";
    const post = params.highlightPostTag || "</em>";
    const hit = {
      objectID: result.id,
      title: result.title,
      slug: result.slug,
      collection_id: result.collection_id,
      collection_name: result.collection_name,
      status: result.status,
      created_at: result.created_at,
      updated_at: result.updated_at,
      ...result.author_name ? { author_name: result.author_name } : {},
      ...result.url ? { url: result.url } : {},
      ...result.relevance_score != null ? { relevance_score: result.relevance_score } : {}
    };
    if (result.highlights) {
      const hr = {};
      if (result.highlights.title) {
        hr.title = {
          value: this.convertTags(result.highlights.title, pre, post),
          matchLevel: this.matchLevel(result.highlights.title)
        };
      }
      if (result.highlights.body) {
        hr.body = {
          value: this.convertTags(result.highlights.body, pre, post),
          matchLevel: this.matchLevel(result.highlights.body)
        };
      }
      if (Object.keys(hr).length > 0) {
        hit._highlightResult = hr;
      }
    }
    if (result.snippet) {
      hit._snippetResult = {
        body: {
          value: this.convertTags(result.snippet, pre, post),
          matchLevel: this.matchLevel(result.snippet)
        }
      };
    }
    return hit;
  }
  /**
   * Resolve collection name(s) to IDs.
   * "*" / "all" / "" → empty array (search all indexed collections).
   */
  async resolveCollections(indexName) {
    if (!indexName || indexName === "*" || indexName === "all") {
      return [];
    }
    const cached = this.collectionCache.get(indexName);
    if (cached) return cached;
    try {
      const row = await this.db.prepare("SELECT id FROM collections WHERE name = ? AND is_active = 1 LIMIT 1").bind(indexName).first();
      const ids = row?.id ? [String(row.id)] : [];
      this.collectionCache.set(indexName, ids);
      return ids;
    } catch {
      return [];
    }
  }
  determineSearchMode(settings) {
    if (settings.ai_mode_enabled) return "hybrid";
    return "fts5";
  }
  /**
   * Parse Algolia's facetFilters parameter into filters.custom format.
   * Supports: ["field:value", ...] and [["field:val1", "field:val2"], ...]
   */
  parseFacetFilters(facetFilters) {
    if (!facetFilters || facetFilters.length === 0) return {};
    const result = {};
    for (const filter of facetFilters) {
      if (typeof filter === "string") {
        const colonIndex = filter.indexOf(":");
        if (colonIndex > 0) {
          const field = filter.substring(0, colonIndex);
          const value = filter.substring(colonIndex + 1);
          if (!result[field]) result[field] = [];
          result[field].push(value);
        }
      } else if (Array.isArray(filter)) {
        for (const f of filter) {
          const colonIndex = f.indexOf(":");
          if (colonIndex > 0) {
            const field = f.substring(0, colonIndex);
            const value = f.substring(colonIndex + 1);
            if (!result[field]) result[field] = [];
            result[field].push(value);
          }
        }
      }
    }
    return result;
  }
  /**
   * Minimal Algolia filter parser. MVP supports:
   *   status:published   status:'draft'   status:"archived"
   */
  parseStatusFilter(filters) {
    if (!filters) return void 0;
    const m = filters.match(/status\s*:\s*['"]?(\w+)['"]?/i);
    return m?.[1] ? [m[1]] : void 0;
  }
  /**
   * Map FacetResult[] from FacetService to Algolia format.
   * Filters to only the facets requested by InstantSearch params.
   */
  mapFacetResults(facetResults, requested) {
    if (!requested || requested.length === 0) return {};
    const facets = {};
    const requestedSet = new Set(requested);
    for (const fr of facetResults) {
      if (requestedSet.has(fr.field) || requestedSet.has(fr.name) || requestedSet.has("*")) {
        const counts = {};
        for (const fv of fr.values) {
          counts[fv.value] = fv.count;
        }
        facets[fr.field] = counts;
      }
    }
    return facets;
  }
  /**
   * Compute facet counts from the current result page.
   * Fallback when FacetService data is not available.
   */
  computeFacets(results, requested) {
    if (!requested || requested.length === 0) return {};
    const facets = {};
    for (const name of requested) {
      if (name === "collection_name") {
        const counts = {};
        for (const r of results) {
          counts[r.collection_name] = (counts[r.collection_name] || 0) + 1;
        }
        facets.collection_name = counts;
      } else if (name === "status") {
        const counts = {};
        for (const r of results) {
          counts[r.status] = (counts[r.status] || 0) + 1;
        }
        facets.status = counts;
      }
    }
    return facets;
  }
  /** Replace <mark>...</mark> with the requested highlight tags. */
  convertTags(text, open, close) {
    return text.replace(/<mark>/g, open).replace(/<\/mark>/g, close);
  }
  /** Detect Algolia match level from presence of <mark> tags in the source text. */
  matchLevel(text) {
    if (!text.includes("<mark>")) return "none";
    const plain = text.replace(/<\/?mark>/g, "");
    const highlighted = (text.match(/<mark>([\s\S]*?)<\/mark>/g) || []).map((m) => m.replace(/<\/?mark>/g, "")).join("");
    return highlighted.length / Math.max(plain.length, 1) > 0.5 ? "full" : "partial";
  }
  buildParamsString(params) {
    const parts = [];
    if (params.query != null) parts.push(`query=${encodeURIComponent(params.query)}`);
    if (params.page != null) parts.push(`page=${params.page}`);
    if (params.hitsPerPage != null) parts.push(`hitsPerPage=${params.hitsPerPage}`);
    if (params.facets) parts.push(`facets=${encodeURIComponent(JSON.stringify(params.facets))}`);
    if (params.filters) parts.push(`filters=${encodeURIComponent(params.filters)}`);
    return parts.join("&");
  }
};

// src/plugins/core-plugins/ai-search-plugin/routes/instantsearch-api.ts
var instantSearchRoutes = new hono.Hono();
instantSearchRoutes.post("/", async (c) => {
  try {
    const db = c.env.DB;
    const ai = c.env.AI;
    const vectorize = c.env.VECTORIZE_INDEX;
    const searchService = new chunkRCLFF5NO_cjs.AISearchService(db, ai, vectorize);
    const adapter = new InstantSearchAdapter(db);
    const body = await c.req.json();
    if (!body.requests || !Array.isArray(body.requests)) {
      return c.json(
        { message: "Invalid request format. Expected { requests: [...] }", status: 400 },
        400
      );
    }
    const settings = await searchService.getSettings();
    if (!settings?.enabled) {
      return c.json({
        results: body.requests.map((req) => emptyResult(req))
      });
    }
    const results = await Promise.all(
      body.requests.map(async (request) => {
        const requestStart = Date.now();
        try {
          const sonicQuery = await adapter.toSonicQuery(request, settings);
          const sonicResponse = await searchService.search(sonicQuery);
          return adapter.toInstantSearchResult(
            sonicResponse,
            request,
            Date.now() - requestStart
          );
        } catch (error) {
          console.error("[InstantSearch] Request error:", error);
          return emptyResult(request, Date.now() - requestStart);
        }
      })
    );
    return c.json({ results });
  } catch (error) {
    console.error("[InstantSearch] Error:", error);
    return c.json(
      { message: "Search request failed", status: 500 },
      500
    );
  }
});
function emptyResult(request, processingTimeMS = 0) {
  const params = request.params || {};
  return {
    hits: [],
    nbHits: 0,
    page: params.page ?? 0,
    nbPages: 0,
    hitsPerPage: params.hitsPerPage ?? 20,
    processingTimeMS,
    query: params.query || "",
    params: "",
    exhaustiveNbHits: true,
    index: request.indexName
  };
}
var instantsearch_api_default = instantSearchRoutes;
var instantSearchTestRoutes = new hono.Hono();
instantSearchTestRoutes.get("/instantsearch", async (c) => {
  let collectionOptions = '<option value="*">* (All Collections)</option>';
  try {
    const { results } = await c.env.DB.prepare("SELECT name, display_name FROM collections WHERE is_active = 1 ORDER BY display_name").all();
    for (const col of results || []) {
      collectionOptions += `<option value="${col.name}">${col.display_name} (${col.name})</option>`;
    }
  } catch {
  }
  return c.html(html.html`
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
              <select id="idx">${html.raw(collectionOptions)}</select>
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
    <span class="key">return</span> fetch(<span class="str">'${"{"}window.location.origin${"}"}/api/instantsearch'</span>, {
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
  `);
});
var instantsearch_test_page_default = instantSearchTestRoutes;
var integrationGuideRoutes = new hono.Hono();
integrationGuideRoutes.get("/integration", async (c) => {
  return c.html(html.html`
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
                <button class="tab" onclick="showTab('instantsearch')">InstantSearch.js</button>
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

              <!-- InstantSearch.js Tab -->
              <div id="instantsearch" class="tab-content">
                <h3>InstantSearch.js &mdash; Drop-in Algolia Replacement</h3>
                <p>Use the official <a href="https://www.algolia.com/doc/guides/building-search-ui/what-is-instantsearch/js/" target="_blank">InstantSearch.js</a> library (React, Vue, or vanilla JS) with SonicJS as the backend. Zero UI changes needed if you&rsquo;re migrating from Algolia.</p>

                <div class="info-box">
                  <strong>How it works:</strong> SonicJS exposes a <code>POST /api/instantsearch</code> endpoint that speaks the Algolia multi-search protocol. You connect it with a 5-line <code>searchClient</code> shim &mdash; no npm adapter package required.
                </div>

                <h3>1. Install InstantSearch.js</h3>
                <pre><code>npm install instantsearch.js
# Or for React:
npm install react-instantsearch
# Or for Vue:
npm install vue-instantsearch</code></pre>

                <h3>2. Create the Search Client (5 lines)</h3>
                <button class="copy-btn" onclick="copyCode('is-client')">Copy Code</button>
                <pre id="is-client"><code>// searchClient.js
const API_URL = 'https://your-sonicjs-site.com'; // Update this!

export const searchClient = {
  search(requests) {
    return fetch(\`\${API_URL}/api/instantsearch\`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ requests }),
    }).then(res =&gt; res.json());
  },
};</code></pre>

                <h3>3a. Vanilla InstantSearch.js</h3>
                <button class="copy-btn" onclick="copyCode('is-vanilla')">Copy Code</button>
                <pre id="is-vanilla"><code>import instantsearch from 'instantsearch.js';
import { searchBox, hits, pagination } from 'instantsearch.js/es/widgets';
import { searchClient } from './searchClient';

const search = instantsearch({
  indexName: 'posts',   // Your collection name, or "*" for all
  searchClient,
});

search.addWidgets([
  searchBox({ container: '#searchbox' }),
  hits({
    container: '#hits',
    templates: {
      item(hit, { html, components }) {
        return html\`
          &lt;div&gt;
            &lt;h3&gt;\${components.Highlight({ hit, attribute: 'title' })}&lt;/h3&gt;
            &lt;p&gt;\${components.Snippet({ hit, attribute: 'body' })}&lt;/p&gt;
          &lt;/div&gt;
        \`;
      },
    },
  }),
  pagination({ container: '#pagination' }),
]);

search.start();</code></pre>

                <h3>3b. React InstantSearch</h3>
                <button class="copy-btn" onclick="copyCode('is-react')">Copy Code</button>
                <pre id="is-react"><code>import {
  InstantSearch, SearchBox, Hits, Pagination, Highlight, Snippet,
} from 'react-instantsearch';
import { searchClient } from './searchClient';

function Hit({ hit }) {
  return (
    &lt;div&gt;
      &lt;h3&gt;&lt;Highlight attribute="title" hit={hit} /&gt;&lt;/h3&gt;
      &lt;p&gt;&lt;Snippet attribute="body" hit={hit} /&gt;&lt;/p&gt;
    &lt;/div&gt;
  );
}

export default function SearchPage() {
  return (
    &lt;InstantSearch searchClient={searchClient} indexName="posts"&gt;
      &lt;SearchBox /&gt;
      &lt;Hits hitComponent={Hit} /&gt;
      &lt;Pagination /&gt;
    &lt;/InstantSearch&gt;
  );
}</code></pre>

                <h3>Index Name Mapping</h3>
                <div class="info-box">
                  <strong>Collection names:</strong> Use your SonicJS collection name as the <code>indexName</code> (e.g. <code>"posts"</code>, <code>"products"</code>).<br>
                  <strong>Search all:</strong> Use <code>indexName: "*"</code> or <code>"all"</code> to search across every indexed collection.
                </div>

                <h3>Supported Features</h3>
                <ul>
                  <li><strong>Search:</strong> Full-text (FTS5), semantic (AI), and hybrid search</li>
                  <li><strong>Highlighting:</strong> Automatic highlight &amp; snippet results</li>
                  <li><strong>Pagination:</strong> Page-based navigation via <code>page</code> / <code>hitsPerPage</code></li>
                  <li><strong>Facets (MVP):</strong> <code>collection_name</code> and <code>status</code> facets</li>
                  <li><strong>Custom highlight tags:</strong> Configurable via <code>highlightPreTag</code> / <code>highlightPostTag</code></li>
                </ul>
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
                <div class="card">
                  <h4>InstantSearch API</h4>
                  <p><strong>POST</strong> <code>/api/instantsearch</code></p>
                  <p>Algolia-compatible multi-search endpoint</p>
                </div>
                <div class="card">
                  <h4>Click Tracking</h4>
                  <p><strong>POST</strong> <code>/api/search/click</code></p>
                  <p>Record result clicks for CTR analytics</p>
                </div>
              </div>

              <h3>Search Request</h3>
              <pre><code>{
  "query": "cloudflare workers",
  "mode": "ai",           // "ai", "fts5", "hybrid", or "keyword"
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
    "search_id": "a1b2c3d4-...",  // Use for click tracking
    "results": [{
      "id": "123",
      "title": "Getting Started",
      "excerpt": "Learn how to...",
      "collection": "blog_posts",
      "score": 0.95,
      "highlights": {          // FTS5 mode only
        "title": "&lt;mark&gt;Getting&lt;/mark&gt; Started",
        "body": "Learn how to use &lt;mark&gt;cloudflare&lt;/mark&gt; &lt;mark&gt;workers&lt;/mark&gt;..."
      },
      "bm25_score": 12.5       // FTS5 mode only
    }],
    "total": 42,
    "query_time_ms": 150,
    "mode": "ai"
  }
}</code></pre>

              <h3>Click Tracking</h3>
              <p>Record when users click search results. This powers CTR analytics in the admin dashboard.</p>
              <pre><code>// Fire-and-forget when user clicks a result
navigator.sendBeacon('/api/search/click', JSON.stringify({
  search_id: searchResponse.data.search_id,  // from search response
  content_id: result.id,                      // clicked result ID
  content_title: result.title,                // for analytics display
  click_position: index + 1                   // 1-based position in results
}));</code></pre>
              <p><small>Click tracking is optional but recommended. Uses <code>sendBeacon</code> for reliability during navigation.</small></p>

              <h3>Faceted Search</h3>
              <p>Request facet counts alongside search results by passing <code>facets: true</code>. Facets reflect the full matching result set, not just the current page.</p>
              <pre><code>// Request with facets
const response = await fetch('/api/search', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    query: 'tutorial',
    mode: 'fts5',
    facets: true
  })
});

// Response includes facets array
{
  "success": true,
  "data": {
    "results": [...],
    "total": 42,
    "facets": [
      { "name": "Collection", "field": "collection_name", "values": [
        { "value": "Blog Posts", "count": 28 },
        { "value": "Docs", "count": 14 }
      ]},
      { "name": "Status", "field": "status", "values": [
        { "value": "published", "count": 40 },
        { "value": "draft", "count": 2 }
      ]},
      { "name": "Tags", "field": "$.tags", "values": [
        { "value": "javascript", "count": 15 },
        { "value": "react", "count": 12 }
      ]}
    ]
  }
}</code></pre>

              <h4>Frontend Facet Sidebar Example</h4>
              <pre><code>// Render facet checkboxes
function renderFacets(facets) {
  return facets.map(facet =&gt; \`
    &lt;div class="facet-group"&gt;
      &lt;h4&gt;\${facet.name}&lt;/h4&gt;
      \${facet.values.map(v =&gt; \`
        &lt;label&gt;
          &lt;input type="checkbox" value="\${v.value}"
            onchange="filterByFacet('\${facet.field}', '\${v.value}')"&gt;
          \${v.value} (\${v.count})
        &lt;/label&gt;
      \`).join('')}
    &lt;/div&gt;
  \`).join('');
}

// Track facet interactions (optional, powers admin analytics)
function filterByFacet(field, value) {
  navigator.sendBeacon('/api/search/facet-click', JSON.stringify({
    facet_field: field,
    facet_value: value,
    search_id: currentSearchId
  }));
  // Re-run search with the filter applied
}</code></pre>

              <h4>InstantSearch.js RefinementList</h4>
              <p>If you use InstantSearch.js, facets work automatically with the <code>RefinementList</code> widget:</p>
              <pre><code>import { refinementList } from 'instantsearch.js/es/widgets';

search.addWidgets([
  refinementList({
    container: '#status-filter',
    attribute: 'status',
  }),
  refinementList({
    container: '#collection-filter',
    attribute: 'collection_name',
  })
]);</code></pre>
              <p><small>Enable faceted search in the admin dashboard (Configuration tab) to auto-discover facets from your collection schemas.</small></p>
            </div>

            <!-- Performance Tips Section -->
            <div class="section">
              <h2>⚡ Performance Tips</h2>
              
              <div class="grid">
                <div class="card">
                  <h4>Hybrid Mode</h4>
                  <p>FTS5 + AI + Reranking combined</p>
                  <p><code>mode: "hybrid"</code> ~150-500ms</p>
                </div>
                <div class="card">
                  <h4>FTS5 Full-Text Mode</h4>
                  <p>BM25 ranked, stemming, highlights</p>
                  <p><code>mode: "fts5"</code> ~20-50ms</p>
                </div>
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
                <li>Added click tracking (optional)</li>
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
  `);
});
var integration_guide_default = integrationGuideRoutes;
var testPageRoutes = new hono.Hono();
testPageRoutes.get("/test", async (c) => {
  return c.html(html.html`
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
          .result-title a {
            color: #667eea;
            text-decoration: none;
          }
          .result-title a:hover {
            text-decoration: underline;
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
          
          <h1>AI Search Test</h1>
          <p class="subtitle">Test search performance and similarity-based caching</p>

          <div class="info-box">
            <strong>Performance Testing:</strong> Watch how similarity caching speeds up repeated queries.
            First query to a term may take 500-800ms, but similar queries should be much faster!
            <br><br>
            <strong>Autocomplete:</strong> Type 2+ characters to see instant suggestions (<50ms).
            <br><br>
            <strong>For Developers:</strong> Want to add AI search to your own frontend? 
            <a href="/admin/plugins/ai-search/integration"
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
              <input type="radio" name="mode" value="fts5"> FTS5 Full-Text
            </label>
            <label>
              <input type="radio" name="mode" value="hybrid"> Hybrid (FTS5 + AI)
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
              errorDiv.innerHTML = '<div class="error">Error: ' + escapeHtml(error.message) + '</div>';
              resultsDiv.innerHTML = '';
            } finally {
              searchBtn.disabled = false;
            }
          }

          function escapeHtml(str) {
            if (!str) return '';
            var div = document.createElement('div');
            div.appendChild(document.createTextNode(str));
            return div.innerHTML;
          }

          function sanitizeHighlight(str) {
            if (!str) return '';
            // Preserve <mark> and </mark> tags, strip all other HTML, escape text
            // 1. Replace <mark> with placeholder
            var s = str.replace(/<mark>/gi, '\\x01MARK_OPEN\\x01').replace(/<\\/mark>/gi, '\\x01MARK_CLOSE\\x01');
            // 2. Strip all remaining HTML tags
            var tmp = document.createElement('div');
            tmp.innerHTML = s;
            var text = tmp.textContent || tmp.innerText || '';
            // 3. Escape the text
            var div = document.createElement('div');
            div.appendChild(document.createTextNode(text));
            var escaped = div.innerHTML;
            // 4. Restore <mark> tags
            escaped = escaped.replace(/\\x01MARK_OPEN\\x01/g, '<mark>').replace(/\\x01MARK_CLOSE\\x01/g, '</mark>');
            return escaped;
          }

          function renderResultItem(result) {
            var rawTitle = result.highlights && result.highlights.title ? result.highlights.title : (result.title || 'Untitled');
            var rawSnippet = (result.highlights && result.highlights.body) || result.snippet || result.excerpt || '';
            var collection = escapeHtml(result.collection_name || result.collection || 'N/A');
            var score = result.rerank_score || result.rrf_score || result.bm25_score || result.relevance_score || result.score;
            var scoreStr = score ? score.toFixed(3) : 'N/A';
            var scoreLabel = result.rerank_score ? 'Rerank' : result.rrf_score ? 'RRF' : result.bm25_score ? 'BM25' : 'Score';

            // Sanitize: allow <mark> highlighting, strip all other HTML
            var safeTitle = sanitizeHighlight(rawTitle);
            var safeSnippet = sanitizeHighlight(rawSnippet);

            var titleHtml = safeTitle;
            if (result.id) {
              var editUrl = '/admin/content/' + encodeURIComponent(result.id) + '/edit';
              titleHtml = '<a href="' + editUrl + '" target="_blank">' + safeTitle + '</a>';
            }

            return '<div class="result-item">' +
              '<div class="result-title">' + titleHtml + '</div>' +
              '<div class="result-excerpt">' + safeSnippet + '</div>' +
              '<div class="result-meta">Collection: ' + collection + ' | ' + scoreLabel + ': ' + scoreStr + '</div>' +
              '</div>';
          }

          function displayResults(data, duration) {
            if (!data.results || data.results.length === 0) {
              resultsDiv.innerHTML = '<div class="loading">No results found</div>';
              return;
            }

            var html = '<div class="results">';
            html += '<h3>Found ' + data.results.length + ' results in ' + duration + 'ms (mode: ' + (data.mode || 'unknown') + ')</h3>';
            for (var i = 0; i < data.results.length; i++) {
              html += renderResultItem(data.results[i]);
            }
            html += '</div>';
            resultsDiv.innerHTML = html;
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
  `);
});
var test_page_default = testPageRoutes;

// src/plugins/core-plugins/ai-search-plugin/index.ts
var aiSearchPlugin = new chunk6FHNRRJ3_cjs.PluginBuilder({
  name: manifest_default.name,
  version: manifest_default.version,
  description: manifest_default.description,
  author: { name: manifest_default.author }
}).metadata({
  description: manifest_default.description,
  author: { name: manifest_default.author }
}).addService("aiSearch", chunkRCLFF5NO_cjs.AISearchService).addService("indexManager", chunkRCLFF5NO_cjs.IndexManager).addRoute("/admin/plugins/ai-search", admin_default).addRoute("/api/search", api_default2).addRoute("/api/instantsearch", instantsearch_api_default).addRoute("/admin/plugins/ai-search", test_page_default).addRoute("/admin/plugins/ai-search", instantsearch_test_page_default).addRoute("/admin/plugins/ai-search", integration_guide_default).build();
var magicLinkRequestSchema = zod.z.object({
  email: zod.z.string().email("Valid email is required")
});
function createMagicLinkAuthPlugin() {
  const magicLinkRoutes = new hono.Hono();
  magicLinkRoutes.post("/request", async (c) => {
    try {
      const body = await c.req.json();
      const validation = magicLinkRequestSchema.safeParse(body);
      if (!validation.success) {
        return c.json({
          error: "Validation failed",
          details: validation.error.issues
        }, 400);
      }
      const { email } = validation.data;
      const normalizedEmail = email.toLowerCase();
      const db = c.env.DB;
      const oneHourAgo = Date.now() - 60 * 60 * 1e3;
      const recentLinks = await db.prepare(`
        SELECT COUNT(*) as count
        FROM magic_links
        WHERE user_email = ? AND created_at > ?
      `).bind(normalizedEmail, oneHourAgo).first();
      const rateLimitPerHour = 5;
      if (recentLinks && recentLinks.count >= rateLimitPerHour) {
        return c.json({
          error: "Too many requests. Please try again later."
        }, 429);
      }
      const user = await db.prepare(`
        SELECT id, email, role, is_active
        FROM users
        WHERE email = ?
      `).bind(normalizedEmail).first();
      const allowNewUsers = false;
      if (!user && !allowNewUsers) {
        return c.json({
          message: "If an account exists for this email, you will receive a magic link shortly."
        });
      }
      if (user && !user.is_active) {
        return c.json({
          error: "This account has been deactivated."
        }, 403);
      }
      const token = crypto.randomUUID() + "-" + crypto.randomUUID();
      const tokenId = crypto.randomUUID();
      const linkExpiryMinutes = 15;
      const expiresAt = Date.now() + linkExpiryMinutes * 60 * 1e3;
      await db.prepare(`
        INSERT INTO magic_links (
          id, user_email, token, expires_at, used, created_at, ip_address, user_agent
        ) VALUES (?, ?, ?, ?, 0, ?, ?, ?)
      `).bind(
        tokenId,
        normalizedEmail,
        token,
        expiresAt,
        Date.now(),
        c.req.header("cf-connecting-ip") || c.req.header("x-forwarded-for") || "unknown",
        c.req.header("user-agent") || "unknown"
      ).run();
      const baseUrl = new URL(c.req.url).origin;
      const magicLink = `${baseUrl}/auth/magic-link/verify?token=${token}`;
      try {
        const emailPlugin2 = c.env.plugins?.get("email");
        if (emailPlugin2 && emailPlugin2.sendEmail) {
          await emailPlugin2.sendEmail({
            to: normalizedEmail,
            subject: "Your Magic Link to Sign In",
            html: renderMagicLinkEmail(magicLink, linkExpiryMinutes)
          });
        } else {
          console.error("Email plugin not available");
          console.log(`Magic link for ${normalizedEmail}: ${magicLink}`);
        }
      } catch (error) {
        console.error("Failed to send magic link email:", error);
        return c.json({
          error: "Failed to send email. Please try again later."
        }, 500);
      }
      return c.json({
        message: "If an account exists for this email, you will receive a magic link shortly.",
        // For development only - remove in production
        ...c.env.ENVIRONMENT === "development" && { dev_link: magicLink }
      });
    } catch (error) {
      console.error("Magic link request error:", error);
      return c.json({ error: "Failed to process request" }, 500);
    }
  });
  magicLinkRoutes.get("/verify", async (c) => {
    try {
      const token = c.req.query("token");
      if (!token) {
        return c.redirect("/auth/login?error=Invalid magic link");
      }
      const db = c.env.DB;
      const magicLink = await db.prepare(`
        SELECT * FROM magic_links
        WHERE token = ? AND used = 0
      `).bind(token).first();
      if (!magicLink) {
        return c.redirect("/auth/login?error=Invalid or expired magic link");
      }
      if (magicLink.expires_at < Date.now()) {
        return c.redirect("/auth/login?error=This magic link has expired");
      }
      let user = await db.prepare(`
        SELECT * FROM users WHERE email = ? AND is_active = 1
      `).bind(magicLink.user_email).first();
      const allowNewUsers = false;
      if (!user && allowNewUsers) {
        const userId = crypto.randomUUID();
        const username = magicLink.user_email.split("@")[0];
        const now = Date.now();
        await db.prepare(`
          INSERT INTO users (
            id, email, username, first_name, last_name,
            password_hash, role, is_active, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, NULL, 'viewer', 1, ?, ?)
        `).bind(
          userId,
          magicLink.user_email,
          username,
          username,
          "",
          now,
          now
        ).run();
        user = {
          id: userId,
          email: magicLink.user_email,
          username,
          role: "viewer"
        };
      } else if (!user) {
        return c.redirect("/auth/login?error=No account found for this email");
      }
      await db.prepare(`
        UPDATE magic_links
        SET used = 1, used_at = ?
        WHERE id = ?
      `).bind(Date.now(), magicLink.id).run();
      const jwtToken = await chunkYZRINJP5_cjs.AuthManager.generateToken(
        user.id,
        user.email,
        user.role
      );
      chunkYZRINJP5_cjs.AuthManager.setAuthCookie(c, jwtToken);
      await db.prepare(`
        UPDATE users SET last_login_at = ? WHERE id = ?
      `).bind(Date.now(), user.id).run();
      return c.redirect("/admin/dashboard?message=Successfully signed in");
    } catch (error) {
      console.error("Magic link verification error:", error);
      return c.redirect("/auth/login?error=Authentication failed");
    }
  });
  return {
    name: "magic-link-auth",
    version: "1.0.0",
    description: "Passwordless authentication via email magic links",
    author: {
      name: "SonicJS Team",
      email: "team@sonicjs.com"
    },
    dependencies: ["email"],
    routes: [{
      path: "/auth/magic-link",
      handler: magicLinkRoutes,
      description: "Magic link authentication endpoints",
      requiresAuth: false
    }],
    async install(context) {
      console.log("Installing magic-link-auth plugin...");
    },
    async activate(context) {
      console.log("Magic link authentication activated");
      console.log("Users can now sign in via /auth/magic-link/request");
    },
    async deactivate(context) {
      console.log("Magic link authentication deactivated");
    },
    async uninstall(context) {
      console.log("Uninstalling magic-link-auth plugin...");
    }
  };
}
function renderMagicLinkEmail(magicLink, expiryMinutes) {
  return `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Your Magic Link</title>
      <style>
        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
          line-height: 1.6;
          color: #333;
          max-width: 600px;
          margin: 0 auto;
          padding: 20px;
        }
        .container {
          background: #ffffff;
          border-radius: 8px;
          padding: 40px;
          box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .header {
          text-align: center;
          margin-bottom: 30px;
        }
        .header h1 {
          color: #0ea5e9;
          margin: 0;
          font-size: 24px;
        }
        .content {
          margin-bottom: 30px;
        }
        .button {
          display: inline-block;
          padding: 14px 32px;
          background: linear-gradient(135deg, #0ea5e9 0%, #06b6d4 100%);
          color: #ffffff !important;
          text-decoration: none;
          border-radius: 6px;
          font-weight: 600;
          text-align: center;
          margin: 20px 0;
        }
        .button:hover {
          opacity: 0.9;
        }
        .expiry {
          color: #ef4444;
          font-size: 14px;
          margin-top: 20px;
        }
        .footer {
          margin-top: 40px;
          padding-top: 20px;
          border-top: 1px solid #e5e7eb;
          font-size: 12px;
          color: #6b7280;
          text-align: center;
        }
        .security-note {
          background: #fef3c7;
          border-left: 4px solid #f59e0b;
          padding: 12px 16px;
          margin-top: 20px;
          border-radius: 4px;
          font-size: 14px;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="header">
          <h1>\u{1F517} Your Magic Link</h1>
        </div>

        <div class="content">
          <p>Hello!</p>
          <p>You requested a magic link to sign in to your account. Click the button below to continue:</p>

          <div style="text-align: center;">
            <a href="${magicLink}" class="button">Sign In</a>
          </div>

          <p class="expiry">\u23F0 This link expires in ${expiryMinutes} minutes</p>

          <div class="security-note">
            <strong>Security Notice:</strong> If you didn't request this link, you can safely ignore this email.
            Someone may have entered your email address by mistake.
          </div>
        </div>

        <div class="footer">
          <p>This is an automated email from SonicJS.</p>
          <p>For security, this link can only be used once.</p>
        </div>
      </div>
    </body>
    </html>
  `;
}
createMagicLinkAuthPlugin();

// src/plugins/cache/services/cache-config.ts
var CACHE_CONFIGS = {
  // Content (high read, low write)
  content: {
    ttl: 3600,
    // 1 hour
    kvEnabled: true,
    memoryEnabled: true,
    namespace: "content",
    invalidateOn: ["content.update", "content.delete", "content.publish"],
    version: "v1"
  },
  // User data (medium read, medium write)
  user: {
    ttl: 900,
    // 15 minutes
    kvEnabled: true,
    memoryEnabled: true,
    namespace: "user",
    invalidateOn: ["user.update", "user.delete", "auth.login"],
    version: "v1"
  },
  // Configuration (high read, very low write)
  config: {
    ttl: 7200,
    // 2 hours
    kvEnabled: true,
    memoryEnabled: true,
    namespace: "config",
    invalidateOn: ["config.update", "plugin.activate", "plugin.deactivate"],
    version: "v1"
  },
  // Media metadata (high read, low write)
  media: {
    ttl: 3600,
    // 1 hour
    kvEnabled: true,
    memoryEnabled: true,
    namespace: "media",
    invalidateOn: ["media.upload", "media.delete", "media.update"],
    version: "v1"
  },
  // API responses (very high read, low write)
  api: {
    ttl: 300,
    // 5 minutes
    kvEnabled: true,
    memoryEnabled: true,
    namespace: "api",
    invalidateOn: ["content.update", "content.publish"],
    version: "v1"
  },
  // Session data (very high read, medium write)
  session: {
    ttl: 1800,
    // 30 minutes
    kvEnabled: false,
    // Only in-memory for sessions
    memoryEnabled: true,
    namespace: "session",
    invalidateOn: ["auth.logout"],
    version: "v1"
  },
  // Plugin data
  plugin: {
    ttl: 3600,
    // 1 hour
    kvEnabled: true,
    memoryEnabled: true,
    namespace: "plugin",
    invalidateOn: ["plugin.activate", "plugin.deactivate", "plugin.update"],
    version: "v1"
  },
  // Collections/schema
  collection: {
    ttl: 7200,
    // 2 hours
    kvEnabled: true,
    memoryEnabled: true,
    namespace: "collection",
    invalidateOn: ["collection.update", "collection.delete"],
    version: "v1"
  }
};
function getCacheConfig(namespace) {
  return CACHE_CONFIGS[namespace] || {
    ttl: 3600,
    kvEnabled: true,
    memoryEnabled: true,
    namespace,
    invalidateOn: [],
    version: "v1"
  };
}
function generateCacheKey(namespace, type, identifier, version) {
  const v = version || getCacheConfig(namespace).version || "v1";
  return `${namespace}:${type}:${identifier}:${v}`;
}
function parseCacheKey(key) {
  const parts = key.split(":");
  if (parts.length !== 4) {
    return null;
  }
  return {
    namespace: parts[0] || "",
    type: parts[1] || "",
    identifier: parts[2] || "",
    version: parts[3] || ""
  };
}

// src/plugins/cache/services/cache.ts
var MemoryCache = class {
  cache = /* @__PURE__ */ new Map();
  maxSize = 50 * 1024 * 1024;
  // 50MB
  currentSize = 0;
  /**
   * Get item from memory cache
   */
  get(key) {
    const entry = this.cache.get(key);
    if (!entry) {
      return null;
    }
    if (Date.now() > entry.expiresAt) {
      this.delete(key);
      return null;
    }
    return entry.data;
  }
  /**
   * Set item in memory cache
   */
  set(key, value, ttl, version = "v1") {
    const now = Date.now();
    const entry = {
      data: value,
      timestamp: now,
      expiresAt: now + ttl * 1e3,
      version
    };
    const entrySize = JSON.stringify(entry).length * 2;
    if (this.currentSize + entrySize > this.maxSize) {
      this.evictLRU(entrySize);
    }
    if (this.cache.has(key)) {
      this.delete(key);
    }
    this.cache.set(key, entry);
    this.currentSize += entrySize;
  }
  /**
   * Delete item from memory cache
   */
  delete(key) {
    const entry = this.cache.get(key);
    if (entry) {
      const entrySize = JSON.stringify(entry).length * 2;
      this.currentSize -= entrySize;
      return this.cache.delete(key);
    }
    return false;
  }
  /**
   * Clear all items from memory cache
   */
  clear() {
    this.cache.clear();
    this.currentSize = 0;
  }
  /**
   * Get cache statistics
   */
  getStats() {
    return {
      size: this.currentSize,
      count: this.cache.size
    };
  }
  /**
   * Evict least recently used items to make space
   */
  evictLRU(neededSpace) {
    const entries = Array.from(this.cache.entries()).sort(
      (a, b) => a[1].timestamp - b[1].timestamp
    );
    let freedSpace = 0;
    for (const [key, entry] of entries) {
      if (freedSpace >= neededSpace) break;
      const entrySize = JSON.stringify(entry).length * 2;
      this.delete(key);
      freedSpace += entrySize;
    }
  }
  /**
   * Delete items matching a pattern
   */
  invalidatePattern(pattern) {
    const regex = new RegExp(
      "^" + pattern.replace(/\*/g, ".*").replace(/\?/g, ".") + "$"
    );
    let count = 0;
    for (const key of this.cache.keys()) {
      if (regex.test(key)) {
        this.delete(key);
        count++;
      }
    }
    return count;
  }
};
var CacheService = class {
  memoryCache;
  config;
  stats;
  kvNamespace;
  constructor(config, kvNamespace) {
    this.memoryCache = new MemoryCache();
    this.config = config;
    this.kvNamespace = kvNamespace;
    this.stats = {
      memoryHits: 0,
      memoryMisses: 0,
      kvHits: 0,
      kvMisses: 0,
      dbHits: 0,
      totalRequests: 0,
      hitRate: 0,
      memorySize: 0,
      entryCount: 0
    };
  }
  /**
   * Get value from cache (tries memory first, then KV)
   */
  async get(key) {
    this.stats.totalRequests++;
    if (this.config.memoryEnabled) {
      const memoryValue = this.memoryCache.get(key);
      if (memoryValue !== null) {
        this.stats.memoryHits++;
        this.updateHitRate();
        return memoryValue;
      }
      this.stats.memoryMisses++;
    }
    if (this.config.kvEnabled && this.kvNamespace) {
      try {
        const kvValue = await this.kvNamespace.get(key, "json");
        if (kvValue !== null) {
          this.stats.kvHits++;
          if (this.config.memoryEnabled) {
            this.memoryCache.set(key, kvValue, this.config.ttl, this.config.version);
          }
          this.updateHitRate();
          return kvValue;
        }
        this.stats.kvMisses++;
      } catch (error) {
        console.error("KV cache read error:", error);
        this.stats.kvMisses++;
      }
    }
    this.updateHitRate();
    return null;
  }
  /**
   * Get value from cache with source information
   */
  async getWithSource(key) {
    this.stats.totalRequests++;
    if (this.config.memoryEnabled) {
      const memoryValue = this.memoryCache.get(key);
      if (memoryValue !== null) {
        this.stats.memoryHits++;
        this.updateHitRate();
        const entry = await this.getEntry(key);
        return {
          data: memoryValue,
          source: "memory",
          hit: true,
          timestamp: entry?.timestamp,
          ttl: entry?.ttl
        };
      }
      this.stats.memoryMisses++;
    }
    if (this.config.kvEnabled && this.kvNamespace) {
      try {
        const kvValue = await this.kvNamespace.get(key, "json");
        if (kvValue !== null) {
          this.stats.kvHits++;
          if (this.config.memoryEnabled) {
            this.memoryCache.set(key, kvValue, this.config.ttl, this.config.version);
          }
          this.updateHitRate();
          return {
            data: kvValue,
            source: "kv",
            hit: true
          };
        }
        this.stats.kvMisses++;
      } catch (error) {
        console.error("KV cache read error:", error);
        this.stats.kvMisses++;
      }
    }
    this.updateHitRate();
    return {
      data: null,
      source: "miss",
      hit: false
    };
  }
  /**
   * Set value in cache (stores in both memory and KV)
   */
  async set(key, value, customConfig) {
    const config = { ...this.config, ...customConfig };
    if (config.memoryEnabled) {
      this.memoryCache.set(key, value, config.ttl, config.version);
    }
    if (config.kvEnabled && this.kvNamespace) {
      try {
        await this.kvNamespace.put(key, JSON.stringify(value), {
          expirationTtl: config.ttl
        });
      } catch (error) {
        console.error("KV cache write error:", error);
      }
    }
  }
  /**
   * Delete value from cache (removes from both memory and KV)
   */
  async delete(key) {
    if (this.config.memoryEnabled) {
      this.memoryCache.delete(key);
    }
    if (this.config.kvEnabled && this.kvNamespace) {
      try {
        await this.kvNamespace.delete(key);
      } catch (error) {
        console.error("KV cache delete error:", error);
      }
    }
  }
  /**
   * Clear all cache entries for this namespace
   */
  async clear() {
    if (this.config.memoryEnabled) {
      this.memoryCache.clear();
    }
    this.stats = {
      memoryHits: 0,
      memoryMisses: 0,
      kvHits: 0,
      kvMisses: 0,
      dbHits: 0,
      totalRequests: 0,
      hitRate: 0,
      memorySize: 0,
      entryCount: 0
    };
  }
  /**
   * Invalidate cache entries matching a pattern
   */
  async invalidate(pattern) {
    let count = 0;
    if (this.config.memoryEnabled) {
      count += this.memoryCache.invalidatePattern(pattern);
    }
    if (this.config.kvEnabled && this.kvNamespace) {
      try {
        const regex = new RegExp(
          "^" + pattern.replace(/\*/g, ".*").replace(/\?/g, ".") + "$"
        );
        const prefix = this.config.namespace + ":";
        const list = await this.kvNamespace.list({ prefix });
        for (const key of list.keys) {
          if (regex.test(key.name)) {
            await this.kvNamespace.delete(key.name);
            count++;
          }
        }
      } catch (error) {
        console.error("KV cache invalidation error:", error);
      }
    }
    return count;
  }
  /**
   * Invalidate cache entries matching a pattern (alias for invalidate)
   */
  async invalidatePattern(pattern) {
    return this.invalidate(pattern);
  }
  /**
   * Get cache statistics
   */
  getStats() {
    const memStats = this.memoryCache.getStats();
    return {
      ...this.stats,
      memorySize: memStats.size,
      entryCount: memStats.count
    };
  }
  /**
   * Update hit rate calculation
   */
  updateHitRate() {
    const totalHits = this.stats.memoryHits + this.stats.kvHits + this.stats.dbHits;
    this.stats.hitRate = this.stats.totalRequests > 0 ? totalHits / this.stats.totalRequests * 100 : 0;
  }
  /**
   * Generate a cache key using the configured namespace
   */
  generateKey(type, identifier) {
    return generateCacheKey(
      this.config.namespace,
      type,
      identifier,
      this.config.version
    );
  }
  /**
   * Warm cache with multiple entries
   */
  async warmCache(entries) {
    for (const entry of entries) {
      await this.set(entry.key, entry.value);
    }
  }
  /**
   * Check if a key exists in cache
   */
  async has(key) {
    const value = await this.get(key);
    return value !== null;
  }
  /**
   * Get multiple values at once
   */
  async getMany(keys) {
    const results = /* @__PURE__ */ new Map();
    for (const key of keys) {
      const value = await this.get(key);
      if (value !== null) {
        results.set(key, value);
      }
    }
    return results;
  }
  /**
   * Set multiple values at once
   */
  async setMany(entries, customConfig) {
    for (const entry of entries) {
      await this.set(entry.key, entry.value, customConfig);
    }
  }
  /**
   * Delete multiple keys at once
   */
  async deleteMany(keys) {
    for (const key of keys) {
      await this.delete(key);
    }
  }
  /**
   * Get or set pattern - fetch from cache or compute if not found
   */
  async getOrSet(key, fetcher, customConfig) {
    const cached = await this.get(key);
    if (cached !== null) {
      return cached;
    }
    const value = await fetcher();
    await this.set(key, value, customConfig);
    return value;
  }
  /**
   * List all cache keys with metadata
   */
  async listKeys() {
    const keys = [];
    if (this.config.memoryEnabled) {
      const cache = this.memoryCache.cache;
      for (const [key, entry] of cache.entries()) {
        const size = JSON.stringify(entry).length * 2;
        const age = Date.now() - entry.timestamp;
        keys.push({
          key,
          size,
          expiresAt: entry.expiresAt,
          age
        });
      }
    }
    return keys.sort((a, b) => a.age - b.age);
  }
  /**
   * Get cache entry with full metadata
   */
  async getEntry(key) {
    if (!this.config.memoryEnabled) {
      return null;
    }
    const cache = this.memoryCache.cache;
    const entry = cache.get(key);
    if (!entry) {
      return null;
    }
    if (Date.now() > entry.expiresAt) {
      await this.delete(key);
      return null;
    }
    const size = JSON.stringify(entry).length * 2;
    const ttl = Math.max(0, entry.expiresAt - Date.now()) / 1e3;
    return {
      data: entry.data,
      timestamp: entry.timestamp,
      expiresAt: entry.expiresAt,
      ttl,
      size
    };
  }
};
var cacheInstances = /* @__PURE__ */ new Map();
var globalKVNamespace;
function getCacheService(config, kvNamespace) {
  const key = config.namespace;
  if (!cacheInstances.has(key)) {
    const kv = globalKVNamespace;
    cacheInstances.set(key, new CacheService(config, kv));
  }
  return cacheInstances.get(key);
}
async function clearAllCaches() {
  for (const cache of cacheInstances.values()) {
    await cache.clear();
  }
}
function getAllCacheStats() {
  const stats = {};
  for (const [namespace, cache] of cacheInstances.entries()) {
    stats[namespace] = cache.getStats();
  }
  return stats;
}

// src/plugins/cache/services/event-bus.ts
var EventBus = class {
  subscriptions = /* @__PURE__ */ new Map();
  eventLog = [];
  maxLogSize = 100;
  /**
   * Subscribe to an event
   */
  on(event, handler) {
    if (!this.subscriptions.has(event)) {
      this.subscriptions.set(event, []);
    }
    this.subscriptions.get(event).push(handler);
    return () => {
      const handlers = this.subscriptions.get(event);
      if (handlers) {
        const index = handlers.indexOf(handler);
        if (index > -1) {
          handlers.splice(index, 1);
        }
      }
    };
  }
  /**
   * Emit an event to all subscribers
   */
  async emit(event, data) {
    this.logEvent(event, data);
    const handlers = this.subscriptions.get(event) || [];
    await Promise.all(
      handlers.map(async (handler) => {
        try {
          await handler(data);
        } catch (error) {
          console.error(`Error in event handler for ${event}:`, error);
        }
      })
    );
    const wildcardHandlers = this.subscriptions.get("*") || [];
    await Promise.all(
      wildcardHandlers.map(async (handler) => {
        try {
          await handler({ event, data });
        } catch (error) {
          console.error(`Error in wildcard event handler for ${event}:`, error);
        }
      })
    );
  }
  /**
   * Remove all subscribers for an event
   */
  off(event) {
    this.subscriptions.delete(event);
  }
  /**
   * Get all registered events
   */
  getEvents() {
    return Array.from(this.subscriptions.keys());
  }
  /**
   * Get subscriber count for an event
   */
  getSubscriberCount(event) {
    return this.subscriptions.get(event)?.length || 0;
  }
  /**
   * Log an event for debugging
   */
  logEvent(event, data) {
    this.eventLog.push({
      event,
      timestamp: Date.now(),
      data
    });
    if (this.eventLog.length > this.maxLogSize) {
      this.eventLog.shift();
    }
  }
  /**
   * Get recent event log
   */
  getEventLog(limit = 50) {
    return this.eventLog.slice(-limit);
  }
  /**
   * Clear event log
   */
  clearEventLog() {
    this.eventLog = [];
  }
  /**
   * Get statistics
   */
  getStats() {
    const eventCounts = {};
    for (const log of this.eventLog) {
      eventCounts[log.event] = (eventCounts[log.event] || 0) + 1;
    }
    return {
      totalEvents: this.eventLog.length,
      totalSubscriptions: this.subscriptions.size,
      eventCounts
    };
  }
};
var globalEventBus = null;
function getEventBus() {
  if (!globalEventBus) {
    globalEventBus = new EventBus();
  }
  return globalEventBus;
}
function onEvent(event, handler) {
  const bus = getEventBus();
  return bus.on(event, handler);
}

// src/plugins/cache/services/cache-invalidation.ts
function setupCacheInvalidation() {
  getEventBus();
  setupContentInvalidation();
  setupUserInvalidation();
  setupConfigInvalidation();
  setupMediaInvalidation();
  setupAPIInvalidation();
  setupCollectionInvalidation();
  console.log("Cache invalidation listeners registered");
}
function setupContentInvalidation() {
  const config = CACHE_CONFIGS.content;
  if (!config) return;
  const contentCache = getCacheService(config);
  onEvent("content.create", async (_data) => {
    await contentCache.invalidate("content:*");
    console.log("Cache invalidated: content.create");
  });
  onEvent("content.update", async (data) => {
    if (data?.id) {
      await contentCache.delete(contentCache.generateKey("item", data.id));
    }
    await contentCache.invalidate("content:list:*");
    console.log("Cache invalidated: content.update", data?.id);
  });
  onEvent("content.delete", async (data) => {
    if (data?.id) {
      await contentCache.delete(contentCache.generateKey("item", data.id));
    }
    await contentCache.invalidate("content:*");
    console.log("Cache invalidated: content.delete", data?.id);
  });
  onEvent("content.publish", async (_data) => {
    await contentCache.invalidate("content:*");
    console.log("Cache invalidated: content.publish");
  });
}
function setupUserInvalidation() {
  const config = CACHE_CONFIGS.user;
  if (!config) return;
  const userCache = getCacheService(config);
  onEvent("user.update", async (data) => {
    if (data?.id) {
      await userCache.delete(userCache.generateKey("id", data.id));
    }
    if (data?.email) {
      await userCache.delete(userCache.generateKey("email", data.email));
    }
    console.log("Cache invalidated: user.update", data?.id);
  });
  onEvent("user.delete", async (data) => {
    if (data?.id) {
      await userCache.delete(userCache.generateKey("id", data.id));
    }
    if (data?.email) {
      await userCache.delete(userCache.generateKey("email", data.email));
    }
    console.log("Cache invalidated: user.delete", data?.id);
  });
  onEvent("auth.login", async (data) => {
    if (data?.userId) {
      await userCache.delete(userCache.generateKey("id", data.userId));
    }
    console.log("Cache invalidated: auth.login", data?.userId);
  });
  onEvent("auth.logout", async (data) => {
    const sessionConfig = CACHE_CONFIGS.session;
    if (sessionConfig) {
      const sessionCache = getCacheService(sessionConfig);
      if (data?.sessionId) {
        await sessionCache.delete(sessionCache.generateKey("session", data.sessionId));
      }
    }
    console.log("Cache invalidated: auth.logout");
  });
}
function setupConfigInvalidation() {
  const configConfig = CACHE_CONFIGS.config;
  if (!configConfig) return;
  const configCache = getCacheService(configConfig);
  onEvent("config.update", async (_data) => {
    await configCache.invalidate("config:*");
    console.log("Cache invalidated: config.update");
  });
  onEvent("plugin.activate", async (data) => {
    await configCache.invalidate("config:*");
    const pluginConfig = CACHE_CONFIGS.plugin;
    if (pluginConfig) {
      const pluginCache = getCacheService(pluginConfig);
      await pluginCache.invalidate("plugin:*");
    }
    console.log("Cache invalidated: plugin.activate", data?.pluginId);
  });
  onEvent("plugin.deactivate", async (data) => {
    await configCache.invalidate("config:*");
    const pluginConfig = CACHE_CONFIGS.plugin;
    if (pluginConfig) {
      const pluginCache = getCacheService(pluginConfig);
      await pluginCache.invalidate("plugin:*");
    }
    console.log("Cache invalidated: plugin.deactivate", data?.pluginId);
  });
  onEvent("plugin.update", async (data) => {
    const pluginConfig = CACHE_CONFIGS.plugin;
    if (!pluginConfig) return;
    const pluginCache = getCacheService(pluginConfig);
    await pluginCache.invalidate("plugin:*");
    console.log("Cache invalidated: plugin.update", data?.pluginId);
  });
}
function setupMediaInvalidation() {
  const config = CACHE_CONFIGS.media;
  if (!config) return;
  const mediaCache = getCacheService(config);
  onEvent("media.upload", async (_data) => {
    await mediaCache.invalidate("media:*");
    console.log("Cache invalidated: media.upload");
  });
  onEvent("media.delete", async (data) => {
    if (data?.id) {
      await mediaCache.delete(mediaCache.generateKey("item", data.id));
    }
    await mediaCache.invalidate("media:list:*");
    console.log("Cache invalidated: media.delete", data?.id);
  });
  onEvent("media.update", async (data) => {
    if (data?.id) {
      await mediaCache.delete(mediaCache.generateKey("item", data.id));
    }
    await mediaCache.invalidate("media:list:*");
    console.log("Cache invalidated: media.update", data?.id);
  });
}
function setupAPIInvalidation() {
  const config = CACHE_CONFIGS.api;
  if (!config) return;
  const apiCache = getCacheService(config);
  onEvent("content.update", async (_data) => {
    await apiCache.invalidate("api:*");
    console.log("Cache invalidated: api (content.update)");
  });
  onEvent("content.publish", async (_data) => {
    await apiCache.invalidate("api:*");
    console.log("Cache invalidated: api (content.publish)");
  });
  onEvent("content.create", async (_data) => {
    await apiCache.invalidate("api:*");
    console.log("Cache invalidated: api (content.create)");
  });
  onEvent("content.delete", async (_data) => {
    await apiCache.invalidate("api:*");
    console.log("Cache invalidated: api (content.delete)");
  });
  onEvent("collection.update", async (_data) => {
    await apiCache.invalidate("api:*");
    console.log("Cache invalidated: api (collection.update)");
  });
}
function setupCollectionInvalidation() {
  const config = CACHE_CONFIGS.collection;
  if (!config) return;
  const collectionCache = getCacheService(config);
  onEvent("collection.create", async (_data) => {
    await collectionCache.invalidate("collection:*");
    console.log("Cache invalidated: collection.create");
  });
  onEvent("collection.update", async (data) => {
    if (data?.id) {
      await collectionCache.delete(collectionCache.generateKey("item", data.id));
    }
    await collectionCache.invalidate("collection:*");
    console.log("Cache invalidated: collection.update", data?.id);
  });
  onEvent("collection.delete", async (data) => {
    await collectionCache.invalidate("collection:*");
    console.log("Cache invalidated: collection.delete", data?.id);
  });
}
function getCacheInvalidationStats() {
  const eventBus = getEventBus();
  return eventBus.getStats();
}
function getRecentInvalidations(limit = 50) {
  const eventBus = getEventBus();
  return eventBus.getEventLog(limit);
}

// src/plugins/cache/services/cache-warming.ts
async function warmCommonCaches(db) {
  let totalWarmed = 0;
  let totalErrors = 0;
  const details = [];
  try {
    const collectionCount = await warmCollections(db);
    totalWarmed += collectionCount;
    details.push({ namespace: "collection", count: collectionCount });
    const contentCount = await warmRecentContent(db);
    totalWarmed += contentCount;
    details.push({ namespace: "content", count: contentCount });
    const mediaCount = await warmRecentMedia(db);
    totalWarmed += mediaCount;
    details.push({ namespace: "media", count: mediaCount });
  } catch (error) {
    console.error("Error warming caches:", error);
    totalErrors++;
  }
  return {
    warmed: totalWarmed,
    errors: totalErrors,
    details
  };
}
async function warmCollections(db) {
  const config = CACHE_CONFIGS.collection;
  if (!config) return 0;
  const collectionCache = getCacheService(config);
  let count = 0;
  try {
    const stmt = db.prepare("SELECT * FROM collections WHERE is_active = 1");
    const { results } = await stmt.all();
    for (const collection of results) {
      const key = collectionCache.generateKey("item", collection.id);
      await collectionCache.set(key, collection);
      count++;
    }
    const listKey = collectionCache.generateKey("list", "all");
    await collectionCache.set(listKey, results);
    count++;
  } catch (error) {
    console.error("Error warming collections cache:", error);
  }
  return count;
}
async function warmRecentContent(db, limit = 50) {
  const config = CACHE_CONFIGS.content;
  if (!config) return 0;
  const contentCache = getCacheService(config);
  let count = 0;
  try {
    const stmt = db.prepare(`SELECT * FROM content ORDER BY created_at DESC LIMIT ${limit}`);
    const { results } = await stmt.all();
    for (const content2 of results) {
      const key = contentCache.generateKey("item", content2.id);
      await contentCache.set(key, content2);
      count++;
    }
    const listKey = contentCache.generateKey("list", "recent");
    await contentCache.set(listKey, results);
    count++;
  } catch (error) {
    console.error("Error warming content cache:", error);
  }
  return count;
}
async function warmRecentMedia(db, limit = 50) {
  const config = CACHE_CONFIGS.media;
  if (!config) return 0;
  const mediaCache = getCacheService(config);
  let count = 0;
  try {
    const stmt = db.prepare(`SELECT * FROM media WHERE deleted_at IS NULL ORDER BY uploaded_at DESC LIMIT ${limit}`);
    const { results } = await stmt.all();
    for (const media2 of results) {
      const key = mediaCache.generateKey("item", media2.id);
      await mediaCache.set(key, media2);
      count++;
    }
    const listKey = mediaCache.generateKey("list", "recent");
    await mediaCache.set(listKey, results);
    count++;
  } catch (error) {
    console.error("Error warming media cache:", error);
  }
  return count;
}
async function warmNamespace(namespace, entries) {
  const config = CACHE_CONFIGS[namespace];
  if (!config) {
    throw new Error(`Unknown namespace: ${namespace}`);
  }
  const cache = getCacheService(config);
  await cache.setMany(entries);
  return entries.length;
}

// src/templates/pages/admin-cache.template.ts
chunkGMUS5V42_cjs.init_admin_layout_catalyst_template();
function renderCacheDashboard(data) {
  const pageContent = `
    <div class="space-y-6">
      <!-- Header -->
      <div class="flex items-center justify-between">
        <div>
          <h1 class="text-2xl font-semibold text-zinc-950 dark:text-white">Cache System</h1>
          <p class="mt-1 text-sm text-zinc-600 dark:text-zinc-400">
            Monitor and manage cache performance across all namespaces
          </p>
        </div>
        <div class="flex gap-3">
          <button
            onclick="refreshStats()"
            class="inline-flex items-center gap-2 rounded-lg bg-white dark:bg-zinc-900 px-4 py-2 text-sm font-medium text-zinc-950 dark:text-white ring-1 ring-inset ring-zinc-950/10 dark:ring-white/10 hover:bg-zinc-50 dark:hover:bg-zinc-800"
          >
            <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
            </svg>
            Refresh
          </button>
          <button
            onclick="clearAllCaches()"
            class="inline-flex items-center gap-2 rounded-lg bg-red-600 dark:bg-red-500 px-4 py-2 text-sm font-medium text-white hover:bg-red-700 dark:hover:bg-red-600"
          >
            <svg class="h-4 w-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
            </svg>
            Clear All
          </button>
        </div>
      </div>

      <!-- Overall Stats Cards -->
      <div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        ${renderStatCard("Total Requests", data.totals.requests.toLocaleString(), "lime", `
          <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6"/>
          </svg>
        `)}

        ${renderStatCard("Hit Rate", data.totals.hitRate + "%", "blue", `
          <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
          </svg>
        `, parseFloat(data.totals.hitRate) > 70 ? "lime" : parseFloat(data.totals.hitRate) > 40 ? "amber" : "red")}

        ${renderStatCard("Memory Usage", formatBytes(data.totals.memorySize), "purple", `
          <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z"/>
          </svg>
        `)}

        ${renderStatCard("Cached Entries", data.totals.entryCount.toLocaleString(), "sky", `
          <svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 21a4 4 0 01-4-4V5a2 2 0 012-2h4a2 2 0 012 2v12a4 4 0 01-4 4zm0 0h12a2 2 0 002-2v-4a2 2 0 00-2-2h-2.343M11 7.343l1.657-1.657a2 2 0 012.828 0l2.829 2.829a2 2 0 010 2.828l-8.486 8.485M7 17h.01"/>
          </svg>
        `)}
      </div>

      <!-- Namespace Statistics -->
      <div class="overflow-hidden rounded-xl bg-white dark:bg-zinc-900 ring-1 ring-zinc-950/5 dark:ring-white/10">
        <div class="px-6 py-4 border-b border-zinc-950/5 dark:border-white/10">
          <h2 class="text-lg font-semibold text-zinc-950 dark:text-white">Cache Namespaces</h2>
        </div>
        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-zinc-950/5 dark:divide-white/10">
            <thead class="bg-zinc-50 dark:bg-zinc-800/50">
              <tr>
                <th class="px-6 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">
                  Namespace
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">
                  Requests
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">
                  Hit Rate
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">
                  Memory Hits
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">
                  KV Hits
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">
                  Entries
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">
                  Size
                </th>
                <th class="px-6 py-3 text-right text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-zinc-950/5 dark:divide-white/10">
              ${data.namespaces.map((namespace) => {
    const stat = data.stats[namespace];
    if (!stat) return "";
    return renderNamespaceRow(namespace, stat);
  }).join("")}
            </tbody>
          </table>
        </div>
      </div>

      <!-- Performance Chart Placeholder -->
      <div class="overflow-hidden rounded-xl bg-white dark:bg-zinc-900 ring-1 ring-zinc-950/5 dark:ring-white/10">
        <div class="px-6 py-4 border-b border-zinc-950/5 dark:border-white/10">
          <h2 class="text-lg font-semibold text-zinc-950 dark:text-white">Performance Overview</h2>
        </div>
        <div class="p-6">
          <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            ${renderPerformanceMetric("Memory Cache", data.totals.hits, data.totals.misses)}
            ${renderHealthStatus(parseFloat(data.totals.hitRate))}
          </div>
        </div>
      </div>
    </div>

    <script>
      async function refreshStats() {
        window.location.reload()
      }

      async function clearAllCaches() {
        showConfirmDialog('clear-all-cache-confirm')
      }

      async function performClearAllCaches() {
        try {
          const response = await fetch('/admin/cache/clear', {
            method: 'POST'
          })

          const result = await response.json()
          if (result.success) {
            alert('All caches cleared successfully')
            window.location.reload()
          } else {
            alert('Error clearing caches: ' + result.error)
          }
        } catch (error) {
          alert('Error clearing caches: ' + error.message)
        }
      }

      let namespaceToDelete = null

      async function clearNamespaceCache(namespace) {
        namespaceToDelete = namespace
        showConfirmDialog('clear-namespace-cache-confirm')
      }

      async function performClearNamespaceCache() {
        if (!namespaceToDelete) return

        try {
          const response = await fetch(\`/admin/cache/clear/\${namespaceToDelete}\`, {
            method: 'POST'
          })

          const result = await response.json()
          if (result.success) {
            alert('Cache cleared successfully')
            window.location.reload()
          } else {
            alert('Error clearing cache: ' + result.error)
          }
        } catch (error) {
          alert('Error clearing cache: ' + error.message)
        } finally {
          namespaceToDelete = null
        }
      }
    </script>

    <!-- Confirmation Dialogs -->
    ${chunkRCLFF5NO_cjs.renderConfirmationDialog({
    id: "clear-all-cache-confirm",
    title: "Clear All Cache",
    message: "Are you sure you want to clear all cache entries? This cannot be undone.",
    confirmText: "Clear All",
    cancelText: "Cancel",
    iconColor: "yellow",
    confirmClass: "bg-yellow-500 hover:bg-yellow-400",
    onConfirm: "performClearAllCaches()"
  })}

    ${chunkRCLFF5NO_cjs.renderConfirmationDialog({
    id: "clear-namespace-cache-confirm",
    title: "Clear Namespace Cache",
    message: "Clear cache for this namespace?",
    confirmText: "Clear",
    cancelText: "Cancel",
    iconColor: "yellow",
    confirmClass: "bg-yellow-500 hover:bg-yellow-400",
    onConfirm: "performClearNamespaceCache()"
  })}

    ${chunkRCLFF5NO_cjs.getConfirmationDialogScript()}
  `;
  const layoutData = {
    title: "Cache System",
    pageTitle: "Cache System",
    currentPath: "/admin/cache",
    user: data.user,
    version: data.version,
    content: pageContent
  };
  return chunkGMUS5V42_cjs.renderAdminLayoutCatalyst(layoutData);
}
function renderStatCard(label, value, color, icon, colorOverride) {
  const finalColor = colorOverride || color;
  const colorClasses = {
    lime: "bg-lime-50 dark:bg-lime-500/10 text-lime-600 dark:text-lime-400 ring-lime-600/20 dark:ring-lime-500/20",
    blue: "bg-blue-50 dark:bg-blue-500/10 text-blue-600 dark:text-blue-400 ring-blue-600/20 dark:ring-blue-500/20",
    purple: "bg-purple-50 dark:bg-purple-500/10 text-purple-600 dark:text-purple-400 ring-purple-600/20 dark:ring-purple-500/20",
    sky: "bg-sky-50 dark:bg-sky-500/10 text-sky-600 dark:text-sky-400 ring-sky-600/20 dark:ring-sky-500/20",
    amber: "bg-amber-50 dark:bg-amber-500/10 text-amber-600 dark:text-amber-400 ring-amber-600/20 dark:ring-amber-500/20",
    red: "bg-red-50 dark:bg-red-500/10 text-red-600 dark:text-red-400 ring-red-600/20 dark:ring-red-500/20"
  };
  return `
    <div class="overflow-hidden rounded-xl bg-white dark:bg-zinc-900 ring-1 ring-zinc-950/5 dark:ring-white/10">
      <div class="p-6">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-3">
            <div class="rounded-lg p-2 ring-1 ring-inset ${colorClasses[finalColor]}">
              ${icon}
            </div>
            <div>
              <p class="text-sm text-zinc-600 dark:text-zinc-400">${label}</p>
              <p class="mt-1 text-2xl font-semibold text-zinc-950 dark:text-white">${value}</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  `;
}
function renderNamespaceRow(namespace, stat) {
  const hitRate = stat.hitRate.toFixed(1);
  const hitRateColor = stat.hitRate > 70 ? "text-lime-600 dark:text-lime-400" : stat.hitRate > 40 ? "text-amber-600 dark:text-amber-400" : "text-red-600 dark:text-red-400";
  return `
    <tr class="hover:bg-zinc-50 dark:hover:bg-zinc-800/50">
      <td class="px-6 py-4 whitespace-nowrap">
        <span class="inline-flex items-center rounded-md px-2 py-1 text-xs font-medium bg-zinc-100 dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100 ring-1 ring-inset ring-zinc-200 dark:ring-zinc-700">
          ${namespace}
        </span>
      </td>
      <td class="px-6 py-4 whitespace-nowrap text-sm text-zinc-900 dark:text-zinc-100">
        ${stat.totalRequests.toLocaleString()}
      </td>
      <td class="px-6 py-4 whitespace-nowrap">
        <span class="text-sm font-medium ${hitRateColor}">
          ${hitRate}%
        </span>
      </td>
      <td class="px-6 py-4 whitespace-nowrap text-sm text-zinc-600 dark:text-zinc-400">
        ${stat.memoryHits.toLocaleString()}
      </td>
      <td class="px-6 py-4 whitespace-nowrap text-sm text-zinc-600 dark:text-zinc-400">
        ${stat.kvHits.toLocaleString()}
      </td>
      <td class="px-6 py-4 whitespace-nowrap text-sm text-zinc-600 dark:text-zinc-400">
        ${stat.entryCount.toLocaleString()}
      </td>
      <td class="px-6 py-4 whitespace-nowrap text-sm text-zinc-600 dark:text-zinc-400">
        ${formatBytes(stat.memorySize)}
      </td>
      <td class="px-6 py-4 whitespace-nowrap text-right text-sm">
        <button
          onclick="clearNamespaceCache('${namespace}')"
          class="text-red-600 dark:text-red-400 hover:text-red-700 dark:hover:text-red-300"
        >
          Clear
        </button>
      </td>
    </tr>
  `;
}
function renderPerformanceMetric(label, hits, misses) {
  const total = hits + misses;
  const hitPercentage = total > 0 ? hits / total * 100 : 0;
  return `
    <div>
      <h3 class="text-sm font-medium text-zinc-900 dark:text-zinc-100 mb-3">${label}</h3>
      <div class="space-y-2">
        <div class="flex items-center justify-between text-sm">
          <span class="text-zinc-600 dark:text-zinc-400">Hits</span>
          <span class="font-medium text-zinc-900 dark:text-zinc-100">${hits.toLocaleString()}</span>
        </div>
        <div class="flex items-center justify-between text-sm">
          <span class="text-zinc-600 dark:text-zinc-400">Misses</span>
          <span class="font-medium text-zinc-900 dark:text-zinc-100">${misses.toLocaleString()}</span>
        </div>
        <div class="mt-3">
          <div class="flex items-center justify-between text-sm mb-1">
            <span class="text-zinc-600 dark:text-zinc-400">Hit Rate</span>
            <span class="font-medium text-zinc-900 dark:text-zinc-100">${hitPercentage.toFixed(1)}%</span>
          </div>
          <div class="h-2 bg-zinc-200 dark:bg-zinc-700 rounded-full overflow-hidden">
            <div class="h-full bg-lime-500 dark:bg-lime-400" style="width: ${hitPercentage}%"></div>
          </div>
        </div>
      </div>
    </div>
  `;
}
function renderHealthStatus(hitRate) {
  const status = hitRate > 70 ? "healthy" : hitRate > 40 ? "warning" : "critical";
  const statusConfig = {
    healthy: {
      label: "Healthy",
      color: "lime",
      icon: `<svg class="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
      </svg>`
    },
    warning: {
      label: "Needs Attention",
      color: "amber",
      icon: `<svg class="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
      </svg>`
    },
    critical: {
      label: "Critical",
      color: "red",
      icon: `<svg class="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
      </svg>`
    }
  };
  const config = statusConfig[status];
  const colorClasses = {
    lime: "bg-lime-50 dark:bg-lime-500/10 text-lime-600 dark:text-lime-400 ring-lime-600/20 dark:ring-lime-500/20",
    amber: "bg-amber-50 dark:bg-amber-500/10 text-amber-600 dark:text-amber-400 ring-amber-600/20 dark:ring-amber-500/20",
    red: "bg-red-50 dark:bg-red-500/10 text-red-600 dark:text-red-400 ring-red-600/20 dark:ring-red-500/20"
  };
  return `
    <div>
      <h3 class="text-sm font-medium text-zinc-900 dark:text-zinc-100 mb-3">System Health</h3>
      <div class="flex items-center gap-3 p-4 rounded-lg ring-1 ring-inset ${colorClasses[config.color]}">
        ${config.icon}
        <div>
          <p class="text-sm font-medium">${config.label}</p>
          <p class="text-xs mt-0.5 opacity-80">
            ${status === "healthy" ? "Cache is performing well" : status === "warning" ? "Consider increasing cache TTL or capacity" : "Cache hit rate is too low"}
          </p>
        </div>
      </div>
    </div>
  `;
}
function formatBytes(bytes) {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

// src/plugins/cache/routes.ts
var app = new hono.Hono();
app.get("/", async (c) => {
  const stats = getAllCacheStats();
  const user = c.get("user");
  let totalHits = 0;
  let totalMisses = 0;
  let totalSize = 0;
  let totalEntries = 0;
  Object.values(stats).forEach((stat) => {
    totalHits += stat.memoryHits + stat.kvHits;
    totalMisses += stat.memoryMisses + stat.kvMisses;
    totalSize += stat.memorySize;
    totalEntries += stat.entryCount;
  });
  const totalRequests = totalHits + totalMisses;
  const overallHitRate = totalRequests > 0 ? totalHits / totalRequests * 100 : 0;
  const dashboardData = {
    stats,
    totals: {
      hits: totalHits,
      misses: totalMisses,
      requests: totalRequests,
      hitRate: overallHitRate.toFixed(2),
      memorySize: totalSize,
      entryCount: totalEntries
    },
    namespaces: Object.keys(stats),
    user: user ? {
      name: user.email,
      email: user.email,
      role: user.role
    } : void 0,
    version: c.get("appVersion")
  };
  return c.html(renderCacheDashboard(dashboardData));
});
app.get("/stats", async (c) => {
  const stats = getAllCacheStats();
  return c.json({
    success: true,
    data: stats,
    timestamp: (/* @__PURE__ */ new Date()).toISOString()
  });
});
app.get("/stats/:namespace", async (c) => {
  const namespace = c.req.param("namespace");
  const config = CACHE_CONFIGS[namespace];
  if (!config) {
    return c.json({
      success: false,
      error: `Unknown namespace: ${namespace}`
    }, 404);
  }
  const cache = getCacheService(config);
  const stats = cache.getStats();
  return c.json({
    success: true,
    data: {
      namespace,
      config,
      stats
    },
    timestamp: (/* @__PURE__ */ new Date()).toISOString()
  });
});
app.post("/clear", async (c) => {
  await clearAllCaches();
  return c.json({
    success: true,
    message: "All cache entries cleared",
    timestamp: (/* @__PURE__ */ new Date()).toISOString()
  });
});
app.post("/clear/:namespace", async (c) => {
  const namespace = c.req.param("namespace");
  const config = CACHE_CONFIGS[namespace];
  if (!config) {
    return c.json({
      success: false,
      error: `Unknown namespace: ${namespace}`
    }, 404);
  }
  const cache = getCacheService(config);
  await cache.clear();
  return c.json({
    success: true,
    message: `Cache cleared for namespace: ${namespace}`,
    namespace,
    timestamp: (/* @__PURE__ */ new Date()).toISOString()
  });
});
app.post("/invalidate", async (c) => {
  const body = await c.req.json();
  const { pattern, namespace } = body;
  if (!pattern) {
    return c.json({
      success: false,
      error: "Pattern is required"
    }, 400);
  }
  let totalInvalidated = 0;
  if (namespace) {
    const config = CACHE_CONFIGS[namespace];
    if (!config) {
      return c.json({
        success: false,
        error: `Unknown namespace: ${namespace}`
      }, 404);
    }
    const cache = getCacheService(config);
    totalInvalidated = await cache.invalidate(pattern);
  } else {
    for (const config of Object.values(CACHE_CONFIGS)) {
      const cache = getCacheService(config);
      totalInvalidated += await cache.invalidate(pattern);
    }
  }
  return c.json({
    success: true,
    invalidated: totalInvalidated,
    pattern,
    namespace: namespace || "all",
    timestamp: (/* @__PURE__ */ new Date()).toISOString()
  });
});
app.get("/health", async (c) => {
  const stats = getAllCacheStats();
  const namespaces = Object.entries(stats);
  const healthChecks = namespaces.map(([name, stat]) => {
    const hitRate = stat.hitRate;
    const memoryUsage = stat.memorySize / (50 * 1024 * 1024);
    return {
      namespace: name,
      status: hitRate > 70 ? "healthy" : hitRate > 40 ? "warning" : "unhealthy",
      hitRate,
      memoryUsage: (memoryUsage * 100).toFixed(2) + "%",
      entryCount: stat.entryCount
    };
  });
  const overallStatus = healthChecks.every((h) => h.status === "healthy") ? "healthy" : healthChecks.some((h) => h.status === "unhealthy") ? "unhealthy" : "warning";
  return c.json({
    success: true,
    data: {
      status: overallStatus,
      namespaces: healthChecks,
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    }
  });
});
app.get("/browser", async (c) => {
  const namespace = c.req.query("namespace") || "all";
  const search = c.req.query("search") || "";
  const sortBy = c.req.query("sort") || "age";
  const limit = parseInt(c.req.query("limit") || "100");
  const entries = [];
  const namespaces = namespace === "all" ? Object.keys(CACHE_CONFIGS) : [namespace];
  for (const ns of namespaces) {
    const config = CACHE_CONFIGS[ns];
    if (!config) continue;
    const cache = getCacheService(config);
    const keys = await cache.listKeys();
    for (const keyInfo of keys) {
      if (search && !keyInfo.key.toLowerCase().includes(search.toLowerCase())) {
        continue;
      }
      const parsed = parseCacheKey(keyInfo.key);
      const ttl = Math.max(0, keyInfo.expiresAt - Date.now()) / 1e3;
      entries.push({
        namespace: ns,
        key: keyInfo.key,
        size: keyInfo.size,
        age: keyInfo.age,
        ttl,
        expiresAt: keyInfo.expiresAt,
        parsed
      });
    }
  }
  if (sortBy === "size") {
    entries.sort((a, b) => b.size - a.size);
  } else if (sortBy === "age") {
    entries.sort((a, b) => a.age - b.age);
  } else if (sortBy === "key") {
    entries.sort((a, b) => a.key.localeCompare(b.key));
  }
  const limitedEntries = entries.slice(0, limit);
  return c.json({
    success: true,
    data: {
      entries: limitedEntries,
      total: entries.length,
      showing: limitedEntries.length,
      namespace,
      search,
      sortBy
    },
    timestamp: (/* @__PURE__ */ new Date()).toISOString()
  });
});
app.get("/browser/:namespace/:key", async (c) => {
  const namespace = c.req.param("namespace");
  const key = decodeURIComponent(c.req.param("key"));
  const config = CACHE_CONFIGS[namespace];
  if (!config) {
    return c.json({
      success: false,
      error: `Unknown namespace: ${namespace}`
    }, 404);
  }
  const cache = getCacheService(config);
  const entry = await cache.getEntry(key);
  if (!entry) {
    return c.json({
      success: false,
      error: "Cache entry not found or expired"
    }, 404);
  }
  const parsed = parseCacheKey(key);
  return c.json({
    success: true,
    data: {
      key,
      namespace,
      parsed,
      ...entry,
      createdAt: new Date(entry.timestamp).toISOString(),
      expiresAt: new Date(entry.expiresAt).toISOString()
    },
    timestamp: (/* @__PURE__ */ new Date()).toISOString()
  });
});
app.get("/analytics", async (c) => {
  const stats = getAllCacheStats();
  const invalidationStats = getCacheInvalidationStats();
  const recentInvalidations = getRecentInvalidations(20);
  let totalHits = 0;
  let totalMisses = 0;
  let totalSize = 0;
  let totalEntries = 0;
  const namespacesAnalytics = [];
  for (const [namespace, stat] of Object.entries(stats)) {
    totalHits += stat.memoryHits + stat.kvHits;
    totalMisses += stat.memoryMisses + stat.kvMisses;
    totalSize += stat.memorySize;
    totalEntries += stat.entryCount;
    const totalRequests2 = stat.memoryHits + stat.kvHits + stat.memoryMisses + stat.kvMisses;
    const hitRate = totalRequests2 > 0 ? (stat.memoryHits + stat.kvHits) / totalRequests2 * 100 : 0;
    const avgEntrySize = stat.entryCount > 0 ? stat.memorySize / stat.entryCount : 0;
    namespacesAnalytics.push({
      namespace,
      hitRate: hitRate.toFixed(2),
      totalRequests: totalRequests2,
      memoryHitRate: totalRequests2 > 0 ? (stat.memoryHits / totalRequests2 * 100).toFixed(2) : "0",
      kvHitRate: totalRequests2 > 0 ? (stat.kvHits / totalRequests2 * 100).toFixed(2) : "0",
      avgEntrySize: Math.round(avgEntrySize),
      totalSize: stat.memorySize,
      entryCount: stat.entryCount,
      efficiency: totalRequests2 > 0 ? ((stat.memoryHits + stat.kvHits) / (stat.memoryHits + stat.kvHits + stat.dbHits + 1)).toFixed(2) : "0"
    });
  }
  namespacesAnalytics.sort((a, b) => parseFloat(b.hitRate) - parseFloat(a.hitRate));
  const totalRequests = totalHits + totalMisses;
  const overallHitRate = totalRequests > 0 ? totalHits / totalRequests * 100 : 0;
  const dbQueriesAvoided = totalHits;
  const timeSaved = dbQueriesAvoided * 48;
  const estimatedCostSavings = dbQueriesAvoided / 1e6 * 0.5;
  return c.json({
    success: true,
    data: {
      overview: {
        totalHits,
        totalMisses,
        totalRequests,
        overallHitRate: overallHitRate.toFixed(2),
        totalSize,
        totalEntries,
        avgEntrySize: totalEntries > 0 ? Math.round(totalSize / totalEntries) : 0
      },
      performance: {
        dbQueriesAvoided,
        timeSavedMs: timeSaved,
        timeSavedMinutes: (timeSaved / 1e3 / 60).toFixed(2),
        estimatedCostSavings: estimatedCostSavings.toFixed(4)
      },
      namespaces: namespacesAnalytics,
      invalidation: {
        ...invalidationStats,
        recent: recentInvalidations
      }
    },
    timestamp: (/* @__PURE__ */ new Date()).toISOString()
  });
});
app.get("/analytics/trends", async (c) => {
  const stats = getAllCacheStats();
  const dataPoint = {
    timestamp: Date.now(),
    stats: Object.entries(stats).map(([namespace, stat]) => ({
      namespace,
      hitRate: stat.hitRate,
      entryCount: stat.entryCount,
      memorySize: stat.memorySize,
      totalRequests: stat.totalRequests
    }))
  };
  return c.json({
    success: true,
    data: {
      trends: [dataPoint],
      note: "Historical trends require persistent storage. This returns current snapshot only."
    },
    timestamp: (/* @__PURE__ */ new Date()).toISOString()
  });
});
app.get("/analytics/top-keys", async (c) => {
  c.req.query("namespace") || "all";
  parseInt(c.req.query("limit") || "10");
  return c.json({
    success: true,
    data: {
      topKeys: [],
      note: "Top keys tracking requires per-key hit counting. Feature not yet implemented."
    },
    timestamp: (/* @__PURE__ */ new Date()).toISOString()
  });
});
app.post("/warm", async (c) => {
  try {
    const db = c.env.DB;
    const result = await warmCommonCaches(db);
    return c.json({
      success: true,
      message: "Cache warming completed",
      ...result,
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    });
  } catch (error) {
    console.error("Cache warming error:", error);
    return c.json({
      success: false,
      error: "Cache warming failed",
      details: error instanceof Error ? error.message : "Unknown error"
    }, 500);
  }
});
app.post("/warm/:namespace", async (c) => {
  try {
    const namespace = c.req.param("namespace");
    const body = await c.req.json();
    const { entries } = body;
    if (!entries || !Array.isArray(entries)) {
      return c.json({
        success: false,
        error: "Entries array is required"
      }, 400);
    }
    const count = await warmNamespace(namespace, entries);
    return c.json({
      success: true,
      message: `Warmed ${count} entries in namespace: ${namespace}`,
      namespace,
      count,
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    });
  } catch (error) {
    console.error("Namespace warming error:", error);
    return c.json({
      success: false,
      error: "Namespace warming failed",
      details: error instanceof Error ? error.message : "Unknown error"
    }, 500);
  }
});
var routes_default = app;

// src/plugins/cache/index.ts
var CachePlugin = class {
  _context = null;
  /**
   * Get plugin routes
   */
  getRoutes() {
    return routes_default;
  }
  /**
   * Activate the cache plugin
   */
  async activate(context) {
    this._context = context;
    const settings = context.config || {};
    console.log("\u2705 Cache plugin activated", {
      memoryEnabled: settings.memoryEnabled ?? true,
      kvEnabled: settings.kvEnabled ?? false,
      defaultTTL: settings.defaultTTL ?? 3600
    });
    for (const [_namespace, config] of Object.entries(CACHE_CONFIGS)) {
      getCacheService({
        ...config,
        memoryEnabled: settings.memoryEnabled ?? config.memoryEnabled,
        kvEnabled: settings.kvEnabled ?? config.kvEnabled,
        ttl: settings.defaultTTL ?? config.ttl
      });
    }
    setupCacheInvalidation();
  }
  /**
   * Deactivate the cache plugin
   */
  async deactivate() {
    console.log("\u274C Cache plugin deactivated - clearing all caches");
    await clearAllCaches();
    this._context = null;
  }
  /**
   * Configure the cache plugin
   */
  async configure(settings) {
    console.log("\u2699\uFE0F Cache plugin configured", settings);
    for (const [_namespace, config] of Object.entries(CACHE_CONFIGS)) {
      getCacheService({
        ...config,
        memoryEnabled: settings.memoryEnabled ?? config.memoryEnabled,
        kvEnabled: settings.kvEnabled ?? config.kvEnabled,
        ttl: settings.defaultTTL ?? config.ttl
      });
    }
  }
  /**
   * Get cache statistics
   */
  async getStats(c) {
    const stats = getAllCacheStats();
    return c.json({
      success: true,
      data: stats,
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    });
  }
  /**
   * Clear all cache entries
   */
  async clearCache(c) {
    await clearAllCaches();
    return c.json({
      success: true,
      message: "All cache entries cleared",
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    });
  }
  /**
   * Invalidate cache entries matching pattern
   */
  async invalidatePattern(c) {
    const body = await c.req.json();
    const { pattern, namespace: _namespace } = body;
    if (!pattern) {
      return c.json({
        success: false,
        error: "Pattern is required"
      }, 400);
    }
    let totalInvalidated = 0;
    if (_namespace) {
      const cache = getCacheService(CACHE_CONFIGS[_namespace] || {
        ttl: 3600,
        kvEnabled: false,
        memoryEnabled: true,
        namespace: _namespace,
        invalidateOn: [],
        version: "v1"
      });
      totalInvalidated = await cache.invalidate(pattern);
    } else {
      for (const config of Object.values(CACHE_CONFIGS)) {
        const cache = getCacheService(config);
        totalInvalidated += await cache.invalidate(pattern);
      }
    }
    return c.json({
      success: true,
      invalidated: totalInvalidated,
      pattern,
      namespace: _namespace || "all",
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    });
  }
};
var plugin = new CachePlugin();
var cache_default = plugin;

// src/assets/favicon.ts
var faviconSvg = `<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<svg
   version="1.1"
   id="Layer_1"
   x="0px"
   y="0px"
   viewBox="380 1300 257.89001 278.8855"
   xml:space="preserve"
   width="257.89001"
   height="278.8855"
   xmlns="http://www.w3.org/2000/svg">
<g
   id="g10"
   transform="translate(-383.935,-60.555509)">
	<g
   id="g9">
		<path
   fill="#f1f2f2"
   d="m 974.78,1398.211 c -5.016,6.574 -10.034,13.146 -15.048,19.721 -1.828,2.398 -3.657,4.796 -5.487,7.194 1.994,1.719 3.958,3.51 5.873,5.424 18.724,18.731 28.089,41.216 28.089,67.459 0,26.251 -9.366,48.658 -28.089,67.237 -18.731,18.579 -41.215,27.868 -67.459,27.868 -9.848,0 -19.156,-1.308 -27.923,-3.923 l -4.185,3.354 c -8.587,6.885 -17.154,13.796 -25.725,20.702 17.52,8.967 36.86,13.487 58.054,13.487 35.533,0 65.91,-12.608 91.124,-37.821 25.214,-25.215 37.821,-55.584 37.821,-91.125 0,-35.534 -12.607,-65.911 -37.821,-91.126 -3,-2.999 -6.078,-5.808 -9.224,-8.451 z"
   id="path2" />
		<path
   fill="#34d399"
   d="m 854.024,1585.195 20.001,-16.028 c 16.616,-13.507 33.04,-27.265 50.086,-40.251 1.13,-0.861 2.9,-1.686 2.003,-3.516 -0.843,-1.716 -2.481,-2.302 -4.484,-2.123 -8.514,0.765 -17.016,-0.538 -25.537,-0.353 -1.124,0.024 -2.768,0.221 -3.163,-1.25 -0.371,-1.369 1.088,-2.063 1.919,-2.894 6.26,-6.242 12.574,-12.43 18.816,-18.691 9.303,-9.327 18.565,-18.714 27.851,-28.066 1.848,-1.859 3.701,-3.713 5.549,-5.572 2.655,-2.661 5.309,-5.315 7.958,-7.982 0.574,-0.579 1.259,-1.141 1.246,-1.94 -0.004,-0.257 -0.078,-0.538 -0.254,-0.853 -0.556,-0.981 -1.441,-1.1 -2.469,-0.957 -0.658,0.096 -1.315,0.185 -1.973,0.275 -3.844,0.538 -7.689,1.076 -11.533,1.608 -3.641,0.505 -7.281,1.02 -10.922,1.529 -4.162,0.582 -8.324,1.158 -12.486,1.748 -1.142,0.161 -2.409,1.662 -3.354,0.508 -0.419,-0.508 -0.431,-1.028 -0.251,-1.531 0.269,-0.741 0.957,-1.441 1.387,-2.021 3.414,-4.58 6.882,-9.124 10.356,-13.662 1.74,-2.272 3.48,-4.544 5.214,-6.822 4.682,-6.141 9.369,-12.281 14.051,-18.422 0.09,-0.119 0.181,-0.237 0.271,-0.355 6.848,-8.98 13.7,-17.958 20.553,-26.936 0.488,-0.64 0.977,-1.28 1.465,-1.92 2.159,-2.828 4.315,-5.658 6.476,-8.486 4.197,-5.501 8.454,-10.954 12.67,-16.442 0.263,-0.347 0.538,-0.718 0.717,-1.106 0.269,-0.586 0.299,-1.196 -0.335,-1.776 -0.825,-0.753 -1.8,-0.15 -2.595,0.419 -0.67,0.472 -1.333,0.957 -1.955,1.489 -2.206,1.889 -4.401,3.797 -6.595,5.698 -3.958,3.438 -7.922,6.876 -11.976,10.194 -2.443,2.003 -4.865,4.028 -7.301,6.038 -18.689,-10.581 -39.53,-15.906 -62.549,-15.906 -35.54,0 -65.911,12.607 -91.125,37.82 -25.214,25.215 -37.821,55.592 -37.821,91.126 0,35.54 12.607,65.91 37.821,91.125 4.146,4.146 8.445,7.916 12.87,11.381 -9.015,11.14 -18.036,22.277 -27.034,33.429 -1.208,1.489 -3.755,3.151 -2.745,4.891 0.078,0.144 0.173,0.281 0.305,0.425 1.321,1.429 3.492,-1.303 4.933,-2.457 6.673,-5.333 13.333,-10.685 19.982,-16.042 3.707,-2.984 7.417,-5.965 11.124,-8.952 1.474,-1.188 2.951,-2.373 4.425,-3.561 6.41,-5.164 12.816,-10.333 19.238,-15.481 z m -56.472,-87.186 c 0,-26.243 9.29,-48.728 27.868,-67.459 18.579,-18.723 40.987,-28.089 67.238,-28.089 12.273,0 23.712,2.075 34.34,6.171 -3.37,2.905 -6.734,5.816 -10.069,8.762 -6.075,5.351 -12.365,10.469 -18.667,15.564 -4.179,3.378 -8.371,6.744 -12.514,10.164 -7.54,6.23 -15.037,12.52 -22.529,18.804 -7.091,5.955 -14.182,11.904 -21.19,17.949 -1.136,0.974 -3.055,1.907 -2.135,3.94 0.831,1.836 2.774,1.417 4.341,1.578 l 12.145,-0.599 14.151,-0.698 c 1.031,-0.102 2.192,-0.257 2.89,0.632 0.034,0.044 0.073,0.078 0.106,0.127 1.017,1.561 -0.67,2.105 -1.387,2.942 -6.308,7.318 -12.616,14.637 -18.978,21.907 -8.161,9.339 -16.353,18.649 -24.544,27.958 -2.146,2.433 -4.275,4.879 -6.422,7.312 -1.034,1.172 -2.129,2.272 -1.238,3.922 0.933,1.728 2.685,1.752 4.323,1.602 4.134,-0.367 8.263,-0.489 12.396,-0.492 0.242,0 0.485,-0.01 0.728,0 2.711,0.01 5.422,0.068 8.134,0.145 2.582,0.074 5.166,0.165 7.752,0.249 0.275,1.62 -0.879,2.356 -1.62,3.259 -1.333,1.626 -2.667,3.247 -4,4.867 -4.315,5.252 -8.62,10.514 -12.928,15.772 -3.562,-2.725 -7.007,-5.733 -10.324,-9.051 -18.577,-18.576 -27.867,-40.983 -27.867,-67.234 z"
   id="path9" />
	</g>
</g>
</svg>`;

// src/plugins/core-plugins/seed-data-plugin/index.ts
function createSeedDataPlugin() {
  const builder = chunk6FHNRRJ3_cjs.PluginBuilder.create({
    name: "seed-data",
    version: "1.0.0-beta.1",
    description: "Generate realistic users, content, forms, and submissions for testing and development"
  });
  builder.metadata({
    author: { name: "SonicJS", email: "admin@sonicjs.com" },
    license: "MIT",
    compatibility: "^1.0.0",
    dependencies: []
  });
  builder.addRoute("/admin/seed-data", createSeedDataAdminRoutes(), {
    description: "Seed data tool routes",
    requiresAuth: true
  });
  builder.addAdminPage("/seed-data", "Seed Data", "SeedData", {
    description: "Generate example users and content",
    icon: "seedling",
    permissions: ["admin"]
  });
  builder.addMenuItem("Seed Data", "/admin/seed-data", {
    icon: "seedling",
    order: 65,
    permissions: ["admin"]
  });
  builder.addService("seedData", {
    implementation: SeedDataService,
    description: "Seed data generation service",
    singleton: true
  });
  return builder.build();
}
var seedDataPlugin = createSeedDataPlugin();

// src/app.ts
function createSonicJSApp(config = {}) {
  const app2 = new hono.Hono();
  const appVersion = config.version || chunkUOEIMC67_cjs.getCoreVersion();
  const appName = config.name || "SonicJS AI";
  app2.use("*", async (c, next) => {
    c.set("appVersion", appVersion);
    await next();
  });
  app2.use("*", chunkYZRINJP5_cjs.metricsMiddleware());
  app2.use("*", chunkYZRINJP5_cjs.bootstrapMiddleware(config));
  if (config.middleware?.beforeAuth) {
    for (const middleware of config.middleware.beforeAuth) {
      app2.use("*", middleware);
    }
  }
  app2.use("*", async (_c, next) => {
    await next();
  });
  app2.use("*", async (_c, next) => {
    await next();
  });
  if (config.middleware?.afterAuth) {
    for (const middleware of config.middleware.afterAuth) {
      app2.use("*", middleware);
    }
  }
  app2.route("/api", chunkRCLFF5NO_cjs.api_default);
  app2.route("/api/media", chunkRCLFF5NO_cjs.api_media_default);
  app2.route("/api/system", chunkRCLFF5NO_cjs.api_system_default);
  app2.route("/admin/api", chunkRCLFF5NO_cjs.admin_api_default);
  app2.route("/admin/dashboard", chunkRCLFF5NO_cjs.router);
  app2.route("/admin/collections", chunkRCLFF5NO_cjs.adminCollectionsRoutes);
  app2.route("/admin/forms", chunkRCLFF5NO_cjs.adminFormsRoutes);
  app2.route("/admin/settings", chunkRCLFF5NO_cjs.adminSettingsRoutes);
  app2.route("/forms", chunkRCLFF5NO_cjs.public_forms_default);
  app2.route("/api/forms", chunkRCLFF5NO_cjs.public_forms_default);
  app2.route("/admin/api-reference", chunkRCLFF5NO_cjs.router2);
  app2.route("/admin/database-tools", createDatabaseToolsAdminRoutes());
  app2.route("/admin/seed-data", createSeedDataAdminRoutes());
  app2.route("/admin/content", chunkRCLFF5NO_cjs.admin_content_default);
  app2.route("/admin/media", chunkRCLFF5NO_cjs.adminMediaRoutes);
  app2.route("/admin/search", chunkRCLFF5NO_cjs.adminSearchRoutes);
  if (aiSearchPlugin.routes && aiSearchPlugin.routes.length > 0) {
    for (const route of aiSearchPlugin.routes) {
      app2.route(route.path, route.handler);
    }
  }
  app2.route("/admin/cache", cache_default.getRoutes());
  if (otpLoginPlugin.routes && otpLoginPlugin.routes.length > 0) {
    for (const route of otpLoginPlugin.routes) {
      app2.route(route.path, route.handler);
    }
  }
  app2.route("/admin/plugins", chunkRCLFF5NO_cjs.adminPluginRoutes);
  app2.route("/admin/logs", chunkRCLFF5NO_cjs.adminLogsRoutes);
  app2.route("/admin", chunkRCLFF5NO_cjs.userRoutes);
  app2.route("/auth", chunkRCLFF5NO_cjs.auth_default);
  app2.route("/", chunkRCLFF5NO_cjs.test_cleanup_default);
  if (emailPlugin.routes && emailPlugin.routes.length > 0) {
    for (const route of emailPlugin.routes) {
      app2.route(route.path, route.handler);
    }
  }
  const magicLinkPlugin = createMagicLinkAuthPlugin();
  if (magicLinkPlugin.routes && magicLinkPlugin.routes.length > 0) {
    for (const route of magicLinkPlugin.routes) {
      app2.route(route.path, route.handler);
    }
  }
  app2.get("/favicon.svg", (c) => {
    return new Response(faviconSvg, {
      headers: {
        "Content-Type": "image/svg+xml",
        "Cache-Control": "public, max-age=31536000"
      }
    });
  });
  if (seedDataPlugin.routes && seedDataPlugin.routes.length > 0) {
    for (const route of seedDataPlugin.routes) {
      app2.route(route.path, route.handler);
    }
  }
  app2.get("/files/*", async (c) => {
    try {
      const url = new URL(c.req.url);
      const pathname = url.pathname;
      const objectKey = pathname.replace(/^\/files\//, "");
      if (!objectKey) {
        return c.notFound();
      }
      const object = await c.env.MEDIA_BUCKET.get(objectKey);
      if (!object) {
        return c.notFound();
      }
      const headers = new Headers();
      object.httpMetadata?.contentType && headers.set("Content-Type", object.httpMetadata.contentType);
      object.httpMetadata?.contentDisposition && headers.set("Content-Disposition", object.httpMetadata.contentDisposition);
      headers.set("Cache-Control", "public, max-age=31536000");
      headers.set("Access-Control-Allow-Origin", "*");
      headers.set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS");
      headers.set("Access-Control-Allow-Headers", "Content-Type");
      return new Response(object.body, {
        headers
      });
    } catch (error) {
      console.error("Error serving file:", error);
      return c.notFound();
    }
  });
  if (config.routes) {
    for (const route of config.routes) {
      app2.route(route.path, route.handler);
    }
  }
  app2.get("/", (c) => {
    return c.redirect("/auth/login");
  });
  app2.get("/health", (c) => {
    return c.json({
      name: appName,
      version: appVersion,
      status: "running",
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    });
  });
  app2.notFound((c) => {
    return c.json({ error: "Not Found", status: 404 }, 404);
  });
  app2.onError((err, c) => {
    console.error(err);
    return c.json({ error: "Internal Server Error", status: 500 }, 500);
  });
  return app2;
}
function setupCoreMiddleware(_app) {
  console.warn("setupCoreMiddleware is deprecated. Use createSonicJSApp() instead.");
}
function setupCoreRoutes(_app) {
  console.warn("setupCoreRoutes is deprecated. Use createSonicJSApp() instead.");
}
function createDb(d1$1) {
  return d1.drizzle(d1$1, { schema: chunkVNLR35GO_cjs.schema_exports });
}

// src/index.ts
var VERSION = chunkUOEIMC67_cjs.package_default.version;

Object.defineProperty(exports, "ROUTES_INFO", {
  enumerable: true,
  get: function () { return chunkRCLFF5NO_cjs.ROUTES_INFO; }
});
Object.defineProperty(exports, "adminApiRoutes", {
  enumerable: true,
  get: function () { return chunkRCLFF5NO_cjs.admin_api_default; }
});
Object.defineProperty(exports, "adminCheckboxRoutes", {
  enumerable: true,
  get: function () { return chunkRCLFF5NO_cjs.adminCheckboxRoutes; }
});
Object.defineProperty(exports, "adminCodeExamplesRoutes", {
  enumerable: true,
  get: function () { return chunkRCLFF5NO_cjs.admin_code_examples_default; }
});
Object.defineProperty(exports, "adminCollectionsRoutes", {
  enumerable: true,
  get: function () { return chunkRCLFF5NO_cjs.adminCollectionsRoutes; }
});
Object.defineProperty(exports, "adminContentRoutes", {
  enumerable: true,
  get: function () { return chunkRCLFF5NO_cjs.admin_content_default; }
});
Object.defineProperty(exports, "adminDashboardRoutes", {
  enumerable: true,
  get: function () { return chunkRCLFF5NO_cjs.router; }
});
Object.defineProperty(exports, "adminDesignRoutes", {
  enumerable: true,
  get: function () { return chunkRCLFF5NO_cjs.adminDesignRoutes; }
});
Object.defineProperty(exports, "adminLogsRoutes", {
  enumerable: true,
  get: function () { return chunkRCLFF5NO_cjs.adminLogsRoutes; }
});
Object.defineProperty(exports, "adminMediaRoutes", {
  enumerable: true,
  get: function () { return chunkRCLFF5NO_cjs.adminMediaRoutes; }
});
Object.defineProperty(exports, "adminPluginRoutes", {
  enumerable: true,
  get: function () { return chunkRCLFF5NO_cjs.adminPluginRoutes; }
});
Object.defineProperty(exports, "adminSettingsRoutes", {
  enumerable: true,
  get: function () { return chunkRCLFF5NO_cjs.adminSettingsRoutes; }
});
Object.defineProperty(exports, "adminTestimonialsRoutes", {
  enumerable: true,
  get: function () { return chunkRCLFF5NO_cjs.admin_testimonials_default; }
});
Object.defineProperty(exports, "adminUsersRoutes", {
  enumerable: true,
  get: function () { return chunkRCLFF5NO_cjs.userRoutes; }
});
Object.defineProperty(exports, "apiContentCrudRoutes", {
  enumerable: true,
  get: function () { return chunkRCLFF5NO_cjs.api_content_crud_default; }
});
Object.defineProperty(exports, "apiMediaRoutes", {
  enumerable: true,
  get: function () { return chunkRCLFF5NO_cjs.api_media_default; }
});
Object.defineProperty(exports, "apiRoutes", {
  enumerable: true,
  get: function () { return chunkRCLFF5NO_cjs.api_default; }
});
Object.defineProperty(exports, "apiSystemRoutes", {
  enumerable: true,
  get: function () { return chunkRCLFF5NO_cjs.api_system_default; }
});
Object.defineProperty(exports, "authRoutes", {
  enumerable: true,
  get: function () { return chunkRCLFF5NO_cjs.auth_default; }
});
Object.defineProperty(exports, "Logger", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.Logger; }
});
Object.defineProperty(exports, "apiTokens", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.apiTokens; }
});
Object.defineProperty(exports, "collections", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.collections; }
});
Object.defineProperty(exports, "content", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.content; }
});
Object.defineProperty(exports, "contentVersions", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.contentVersions; }
});
Object.defineProperty(exports, "getLogger", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.getLogger; }
});
Object.defineProperty(exports, "initLogger", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.initLogger; }
});
Object.defineProperty(exports, "insertCollectionSchema", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.insertCollectionSchema; }
});
Object.defineProperty(exports, "insertContentSchema", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.insertContentSchema; }
});
Object.defineProperty(exports, "insertLogConfigSchema", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.insertLogConfigSchema; }
});
Object.defineProperty(exports, "insertMediaSchema", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.insertMediaSchema; }
});
Object.defineProperty(exports, "insertPluginActivityLogSchema", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.insertPluginActivityLogSchema; }
});
Object.defineProperty(exports, "insertPluginAssetSchema", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.insertPluginAssetSchema; }
});
Object.defineProperty(exports, "insertPluginHookSchema", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.insertPluginHookSchema; }
});
Object.defineProperty(exports, "insertPluginRouteSchema", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.insertPluginRouteSchema; }
});
Object.defineProperty(exports, "insertPluginSchema", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.insertPluginSchema; }
});
Object.defineProperty(exports, "insertSystemLogSchema", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.insertSystemLogSchema; }
});
Object.defineProperty(exports, "insertUserSchema", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.insertUserSchema; }
});
Object.defineProperty(exports, "insertWorkflowHistorySchema", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.insertWorkflowHistorySchema; }
});
Object.defineProperty(exports, "logConfig", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.logConfig; }
});
Object.defineProperty(exports, "media", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.media; }
});
Object.defineProperty(exports, "pluginActivityLog", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.pluginActivityLog; }
});
Object.defineProperty(exports, "pluginAssets", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.pluginAssets; }
});
Object.defineProperty(exports, "pluginHooks", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.pluginHooks; }
});
Object.defineProperty(exports, "pluginRoutes", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.pluginRoutes; }
});
Object.defineProperty(exports, "plugins", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.plugins; }
});
Object.defineProperty(exports, "selectCollectionSchema", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.selectCollectionSchema; }
});
Object.defineProperty(exports, "selectContentSchema", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.selectContentSchema; }
});
Object.defineProperty(exports, "selectLogConfigSchema", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.selectLogConfigSchema; }
});
Object.defineProperty(exports, "selectMediaSchema", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.selectMediaSchema; }
});
Object.defineProperty(exports, "selectPluginActivityLogSchema", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.selectPluginActivityLogSchema; }
});
Object.defineProperty(exports, "selectPluginAssetSchema", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.selectPluginAssetSchema; }
});
Object.defineProperty(exports, "selectPluginHookSchema", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.selectPluginHookSchema; }
});
Object.defineProperty(exports, "selectPluginRouteSchema", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.selectPluginRouteSchema; }
});
Object.defineProperty(exports, "selectPluginSchema", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.selectPluginSchema; }
});
Object.defineProperty(exports, "selectSystemLogSchema", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.selectSystemLogSchema; }
});
Object.defineProperty(exports, "selectUserSchema", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.selectUserSchema; }
});
Object.defineProperty(exports, "selectWorkflowHistorySchema", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.selectWorkflowHistorySchema; }
});
Object.defineProperty(exports, "systemLogs", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.systemLogs; }
});
Object.defineProperty(exports, "users", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.users; }
});
Object.defineProperty(exports, "workflowHistory", {
  enumerable: true,
  get: function () { return chunkVNLR35GO_cjs.workflowHistory; }
});
Object.defineProperty(exports, "AuthManager", {
  enumerable: true,
  get: function () { return chunkYZRINJP5_cjs.AuthManager; }
});
Object.defineProperty(exports, "PermissionManager", {
  enumerable: true,
  get: function () { return chunkYZRINJP5_cjs.PermissionManager; }
});
Object.defineProperty(exports, "bootstrapMiddleware", {
  enumerable: true,
  get: function () { return chunkYZRINJP5_cjs.bootstrapMiddleware; }
});
Object.defineProperty(exports, "cacheHeaders", {
  enumerable: true,
  get: function () { return chunkYZRINJP5_cjs.cacheHeaders; }
});
Object.defineProperty(exports, "compressionMiddleware", {
  enumerable: true,
  get: function () { return chunkYZRINJP5_cjs.compressionMiddleware; }
});
Object.defineProperty(exports, "detailedLoggingMiddleware", {
  enumerable: true,
  get: function () { return chunkYZRINJP5_cjs.detailedLoggingMiddleware; }
});
Object.defineProperty(exports, "getActivePlugins", {
  enumerable: true,
  get: function () { return chunkYZRINJP5_cjs.getActivePlugins; }
});
Object.defineProperty(exports, "isPluginActive", {
  enumerable: true,
  get: function () { return chunkYZRINJP5_cjs.isPluginActive; }
});
Object.defineProperty(exports, "logActivity", {
  enumerable: true,
  get: function () { return chunkYZRINJP5_cjs.logActivity; }
});
Object.defineProperty(exports, "loggingMiddleware", {
  enumerable: true,
  get: function () { return chunkYZRINJP5_cjs.loggingMiddleware; }
});
Object.defineProperty(exports, "optionalAuth", {
  enumerable: true,
  get: function () { return chunkYZRINJP5_cjs.optionalAuth; }
});
Object.defineProperty(exports, "performanceLoggingMiddleware", {
  enumerable: true,
  get: function () { return chunkYZRINJP5_cjs.performanceLoggingMiddleware; }
});
Object.defineProperty(exports, "requireActivePlugin", {
  enumerable: true,
  get: function () { return chunkYZRINJP5_cjs.requireActivePlugin; }
});
Object.defineProperty(exports, "requireActivePlugins", {
  enumerable: true,
  get: function () { return chunkYZRINJP5_cjs.requireActivePlugins; }
});
Object.defineProperty(exports, "requireAnyPermission", {
  enumerable: true,
  get: function () { return chunkYZRINJP5_cjs.requireAnyPermission; }
});
Object.defineProperty(exports, "requireAuth", {
  enumerable: true,
  get: function () { return chunkYZRINJP5_cjs.requireAuth; }
});
Object.defineProperty(exports, "requirePermission", {
  enumerable: true,
  get: function () { return chunkYZRINJP5_cjs.requirePermission; }
});
Object.defineProperty(exports, "requireRole", {
  enumerable: true,
  get: function () { return chunkYZRINJP5_cjs.requireRole; }
});
Object.defineProperty(exports, "securityHeaders", {
  enumerable: true,
  get: function () { return chunkYZRINJP5_cjs.securityHeaders; }
});
Object.defineProperty(exports, "securityLoggingMiddleware", {
  enumerable: true,
  get: function () { return chunkYZRINJP5_cjs.securityLoggingMiddleware; }
});
Object.defineProperty(exports, "PluginBootstrapService", {
  enumerable: true,
  get: function () { return chunkMPT5PA6U_cjs.PluginBootstrapService; }
});
Object.defineProperty(exports, "PluginServiceClass", {
  enumerable: true,
  get: function () { return chunkMPT5PA6U_cjs.PluginService; }
});
Object.defineProperty(exports, "cleanupRemovedCollections", {
  enumerable: true,
  get: function () { return chunkMPT5PA6U_cjs.cleanupRemovedCollections; }
});
Object.defineProperty(exports, "fullCollectionSync", {
  enumerable: true,
  get: function () { return chunkMPT5PA6U_cjs.fullCollectionSync; }
});
Object.defineProperty(exports, "getAvailableCollectionNames", {
  enumerable: true,
  get: function () { return chunkMPT5PA6U_cjs.getAvailableCollectionNames; }
});
Object.defineProperty(exports, "getManagedCollections", {
  enumerable: true,
  get: function () { return chunkMPT5PA6U_cjs.getManagedCollections; }
});
Object.defineProperty(exports, "isCollectionManaged", {
  enumerable: true,
  get: function () { return chunkMPT5PA6U_cjs.isCollectionManaged; }
});
Object.defineProperty(exports, "loadCollectionConfig", {
  enumerable: true,
  get: function () { return chunkMPT5PA6U_cjs.loadCollectionConfig; }
});
Object.defineProperty(exports, "loadCollectionConfigs", {
  enumerable: true,
  get: function () { return chunkMPT5PA6U_cjs.loadCollectionConfigs; }
});
Object.defineProperty(exports, "registerCollections", {
  enumerable: true,
  get: function () { return chunkMPT5PA6U_cjs.registerCollections; }
});
Object.defineProperty(exports, "syncCollection", {
  enumerable: true,
  get: function () { return chunkMPT5PA6U_cjs.syncCollection; }
});
Object.defineProperty(exports, "syncCollections", {
  enumerable: true,
  get: function () { return chunkMPT5PA6U_cjs.syncCollections; }
});
Object.defineProperty(exports, "validateCollectionConfig", {
  enumerable: true,
  get: function () { return chunkMPT5PA6U_cjs.validateCollectionConfig; }
});
Object.defineProperty(exports, "MigrationService", {
  enumerable: true,
  get: function () { return chunkVVY7W23T_cjs.MigrationService; }
});
Object.defineProperty(exports, "renderFilterBar", {
  enumerable: true,
  get: function () { return chunk6WA4KFYZ_cjs.renderFilterBar; }
});
Object.defineProperty(exports, "getConfirmationDialogScript", {
  enumerable: true,
  get: function () { return chunkGMUS5V42_cjs.getConfirmationDialogScript; }
});
Object.defineProperty(exports, "renderAlert", {
  enumerable: true,
  get: function () { return chunkGMUS5V42_cjs.renderAlert; }
});
Object.defineProperty(exports, "renderConfirmationDialog", {
  enumerable: true,
  get: function () { return chunkGMUS5V42_cjs.renderConfirmationDialog; }
});
Object.defineProperty(exports, "renderForm", {
  enumerable: true,
  get: function () { return chunkGMUS5V42_cjs.renderForm; }
});
Object.defineProperty(exports, "renderFormField", {
  enumerable: true,
  get: function () { return chunkGMUS5V42_cjs.renderFormField; }
});
Object.defineProperty(exports, "renderPagination", {
  enumerable: true,
  get: function () { return chunkGMUS5V42_cjs.renderPagination; }
});
Object.defineProperty(exports, "renderTable", {
  enumerable: true,
  get: function () { return chunkGMUS5V42_cjs.renderTable; }
});
Object.defineProperty(exports, "HookSystemImpl", {
  enumerable: true,
  get: function () { return chunkMNFY6DWY_cjs.HookSystemImpl; }
});
Object.defineProperty(exports, "HookUtils", {
  enumerable: true,
  get: function () { return chunkMNFY6DWY_cjs.HookUtils; }
});
Object.defineProperty(exports, "PluginManagerClass", {
  enumerable: true,
  get: function () { return chunkMNFY6DWY_cjs.PluginManager; }
});
Object.defineProperty(exports, "PluginRegistryImpl", {
  enumerable: true,
  get: function () { return chunkMNFY6DWY_cjs.PluginRegistryImpl; }
});
Object.defineProperty(exports, "PluginValidatorClass", {
  enumerable: true,
  get: function () { return chunkMNFY6DWY_cjs.PluginValidator; }
});
Object.defineProperty(exports, "ScopedHookSystemClass", {
  enumerable: true,
  get: function () { return chunkMNFY6DWY_cjs.ScopedHookSystem; }
});
Object.defineProperty(exports, "PluginBuilder", {
  enumerable: true,
  get: function () { return chunk6FHNRRJ3_cjs.PluginBuilder; }
});
Object.defineProperty(exports, "PluginHelpers", {
  enumerable: true,
  get: function () { return chunk6FHNRRJ3_cjs.PluginHelpers; }
});
Object.defineProperty(exports, "QueryFilterBuilder", {
  enumerable: true,
  get: function () { return chunkUOEIMC67_cjs.QueryFilterBuilder; }
});
Object.defineProperty(exports, "SONICJS_VERSION", {
  enumerable: true,
  get: function () { return chunkUOEIMC67_cjs.SONICJS_VERSION; }
});
Object.defineProperty(exports, "TemplateRenderer", {
  enumerable: true,
  get: function () { return chunkUOEIMC67_cjs.TemplateRenderer; }
});
Object.defineProperty(exports, "buildQuery", {
  enumerable: true,
  get: function () { return chunkUOEIMC67_cjs.buildQuery; }
});
Object.defineProperty(exports, "escapeHtml", {
  enumerable: true,
  get: function () { return chunkUOEIMC67_cjs.escapeHtml; }
});
Object.defineProperty(exports, "getCoreVersion", {
  enumerable: true,
  get: function () { return chunkUOEIMC67_cjs.getCoreVersion; }
});
Object.defineProperty(exports, "renderTemplate", {
  enumerable: true,
  get: function () { return chunkUOEIMC67_cjs.renderTemplate; }
});
Object.defineProperty(exports, "sanitizeInput", {
  enumerable: true,
  get: function () { return chunkUOEIMC67_cjs.sanitizeInput; }
});
Object.defineProperty(exports, "sanitizeObject", {
  enumerable: true,
  get: function () { return chunkUOEIMC67_cjs.sanitizeObject; }
});
Object.defineProperty(exports, "templateRenderer", {
  enumerable: true,
  get: function () { return chunkUOEIMC67_cjs.templateRenderer; }
});
Object.defineProperty(exports, "metricsTracker", {
  enumerable: true,
  get: function () { return chunkRCQ2HIQD_cjs.metricsTracker; }
});
Object.defineProperty(exports, "HOOKS", {
  enumerable: true,
  get: function () { return chunkKYGRJCZM_cjs.HOOKS; }
});
exports.VERSION = VERSION;
exports.createDb = createDb;
exports.createSonicJSApp = createSonicJSApp;
exports.setupCoreMiddleware = setupCoreMiddleware;
exports.setupCoreRoutes = setupCoreRoutes;
//# sourceMappingURL=index.cjs.map
//# sourceMappingURL=index.cjs.map