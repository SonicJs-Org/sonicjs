import { Hono } from 'hono'
import { html } from 'hono/html'
import type { D1Database, KVNamespace } from '@cloudflare/workers-types'
import { requireAuth } from '../middleware'
import { RbacService } from '../services/rbac'
import { getLogger, type LogLevel, type LogCategory, type LogFilter } from '../services'
import { renderLogsListPage, type LogsListPageData } from '../templates/pages/admin-logs-list.template'
import { renderLogDetailsPage, type LogDetailsPageData } from '../templates/pages/admin-log-details.template'
import { renderLogConfigPage, type LogConfigPageData } from '../templates/pages/admin-log-config.template'
import type { Bindings, Variables } from '../app'

const adminLogsRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// Apply authentication middleware
adminLogsRoutes.use('*', requireAuth())

// Main logs listing page
adminLogsRoutes.get('/', async (c) => {
  try {
    const user = c.get('user')
    const logger = getLogger(c.env.DB)
    
    // Use Hono's built-in query method instead of parsing URL
    const query = c.req.query()
    
    // Parse query parameters
    const page = parseInt(query.page || '1')
    const limit = parseInt(query.limit || '50')
    const level = query.level
    const category = query.category
    const search = query.search
    const startDate = query.start_date
    const endDate = query.end_date
    const source = query.source
    
    // Build filter
    const filter: LogFilter = {
      limit,
      offset: (page - 1) * limit,
      sortBy: 'created_at',
      sortOrder: 'desc'
    }
    
    if (level) {
      filter.level = level.split(',') as LogLevel[]
    }
    
    if (category) {
      filter.category = category.split(',') as LogCategory[]
    }
    
    if (search) {
      filter.search = search
    }
    
    if (startDate) {
      filter.startDate = new Date(startDate)
    }
    
    if (endDate) {
      filter.endDate = new Date(endDate)
    }
    
    if (source) {
      filter.source = source
    }
    
    // Get logs and total count
    const { logs, total } = await logger.getLogs(filter)
    
    // Format logs for display
    const formattedLogs = logs.map(log => ({
      ...log,
      data: log.data ? JSON.parse(log.data) : null,
      tags: log.tags ? JSON.parse(log.tags) : [],
      formattedDate: new Date(log.createdAt).toLocaleString(),
      formattedDuration: log.duration ? `${log.duration}ms` : null,
      levelClass: getLevelClass(log.level),
      categoryClass: getCategoryClass(log.category)
    }))
    
    const totalPages = Math.ceil(total / limit)
    
    const pageData: LogsListPageData = {
      logs: formattedLogs,
      pagination: {
        currentPage: page,
        totalPages,
        totalItems: total,
        itemsPerPage: limit,
        startItem: (page - 1) * limit + 1,
        endItem: Math.min(page * limit, total),
        baseUrl: '/admin/logs'
      },
      filters: {
        level: level || '',
        category: category || '',
        search: search || '',
        startDate: startDate || '',
        endDate: endDate || '',
        source: source || ''
      },
      user: user ? {
        name: user.email,
        email: user.email,
        role: user.role
      } : undefined
    }
    
    return c.html(renderLogsListPage(pageData))
  } catch (error) {
    console.error('Error fetching logs:', error)
    return c.html(html`<p>Error loading logs: ${error}</p>`)
  }
})

// Log details page
adminLogsRoutes.get('/:id', async (c) => {
  try {
    const id = c.req.param('id')
    const user = c.get('user')
    const logger = getLogger(c.env.DB)
    
    // Get single log by ID
    const { logs } = await logger.getLogs({ 
      limit: 1, 
      offset: 0,
      search: id // Using search to find by ID - this is a simplification
    })
    
    const log = logs.find(l => l.id === id)
    
    if (!log) {
      return c.html(html`<p>Log entry not found</p>`)
    }
    
    const formattedLog = {
      ...log,
      data: log.data ? JSON.parse(log.data) : null,
      tags: log.tags ? JSON.parse(log.tags) : [],
      formattedDate: new Date(log.createdAt).toLocaleString(),
      formattedDuration: log.duration ? `${log.duration}ms` : null,
      levelClass: getLevelClass(log.level),
      categoryClass: getCategoryClass(log.category)
    }
    
    const pageData: LogDetailsPageData = {
      log: formattedLog,
      user: user ? {
        name: user.email,
        email: user.email,
        role: user.role
      } : undefined
    }
    
    return c.html(renderLogDetailsPage(pageData))
  } catch (error) {
    console.error('Error fetching log details:', error)
    return c.html(html`<p>Error loading log details: ${error}</p>`)
  }
})

// Log configuration page
adminLogsRoutes.get('/config', async (c) => {
  try {
    const user = c.get('user')
    const logger = getLogger(c.env.DB)
    
    // Get all log configurations
    const configs = await logger.getAllConfigs()
    
    const pageData: LogConfigPageData = {
      configs,
      user: user ? {
        name: user.email,
        email: user.email,
        role: user.role
      } : undefined
    }
    
    return c.html(renderLogConfigPage(pageData))
  } catch (error) {
    console.error('Error fetching log config:', error)
    return c.html(html`<p>Error loading log configuration: ${error}</p>`)
  }
})

// Update log configuration
adminLogsRoutes.post('/config/:category', async (c) => {
  try {
    const category = c.req.param('category') as LogCategory
    const formData = await c.req.formData()
    
    const enabled = formData.get('enabled') === 'on'
    const level = formData.get('level') as string
    const retention = parseInt(formData.get('retention') as string)
    const maxSize = parseInt(formData.get('max_size') as string)
    
    const logger = getLogger(c.env.DB)
    await logger.updateConfig(category, {
      enabled,
      level,
      retention,
      maxSize
    })
    
    return c.html(html`
      <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded">
        Configuration updated successfully!
      </div>
    `)
  } catch (error) {
    console.error('Error updating log config:', error)
    return c.html(html`
      <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
        Failed to update configuration. Please try again.
      </div>
    `)
  }
})

// Export logs
adminLogsRoutes.get('/export', async (c) => {
  try {
    const query = c.req.query()
    const format = query.format || 'csv'
    const level = query.level
    const category = query.category
    const startDate = query.start_date
    const endDate = query.end_date
    
    const logger = getLogger(c.env.DB)
    
    // Build filter for export
    const filter: LogFilter = {
      limit: 10000, // Export up to 10k logs
      offset: 0,
      sortBy: 'created_at',
      sortOrder: 'desc'
    }
    
    if (level) {
      filter.level = level.split(',') as LogLevel[]
    }
    
    if (category) {
      filter.category = category.split(',') as LogCategory[]
    }
    
    if (startDate) {
      filter.startDate = new Date(startDate)
    }
    
    if (endDate) {
      filter.endDate = new Date(endDate)
    }
    
    const { logs } = await logger.getLogs(filter)
    
    if (format === 'json') {
      return c.json(logs, 200, {
        'Content-Disposition': 'attachment; filename="logs-export.json"'
      })
    } else {
      // Default to CSV
      const headers = [
        'ID', 'Level', 'Category', 'Message', 'Source', 'User ID', 
        'IP Address', 'Method', 'URL', 'Status Code', 'Duration', 
        'Created At'
      ]
      const csvRows = [headers.join(',')]
      
      logs.forEach(log => {
        const row = [
          log.id,
          log.level,
          log.category,
          `"${log.message.replace(/"/g, '""')}"`, // Escape quotes
          log.source || '',
          log.userId || '',
          log.ipAddress || '',
          log.method || '',
          log.url || '',
          log.statusCode || '',
          log.duration || '',
          new Date(log.createdAt).toISOString()
        ]
        csvRows.push(row.join(','))
      })
      
      const csv = csvRows.join('\n')
      
      return new Response(csv, {
        headers: {
          'Content-Type': 'text/csv',
          'Content-Disposition': 'attachment; filename="logs-export.csv"'
        }
      })
    }
  } catch (error) {
    console.error('Error exporting logs:', error)
    return c.json({ error: 'Failed to export logs' }, 500)
  }
})

// Clean up old logs
adminLogsRoutes.post('/cleanup', async (c) => {
  try {
    const user = c.get('user')
    
    // Only allow admin users to run cleanup
    if (!user || !(await new RbacService(c.env.DB).can(user.userId, 'settings', 'manage'))) {
      return c.json({ 
        success: false, 
        error: 'Unauthorized. Admin access required.' 
      }, 403)
    }
    
    const logger = getLogger(c.env.DB)
    await logger.cleanupByRetention()
    
    return c.html(html`
      <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded">
        Log cleanup completed successfully!
      </div>
    `)
  } catch (error) {
    console.error('Error cleaning up logs:', error)
    return c.html(html`
      <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
        Failed to clean up logs. Please try again.
      </div>
    `)
  }
})

// Search logs (HTMX endpoint)
adminLogsRoutes.post('/search', async (c) => {
  try {
    const formData = await c.req.formData()
    const search = formData.get('search') as string
    const level = formData.get('level') as string
    const category = formData.get('category') as string
    
    const logger = getLogger(c.env.DB)
    
    const filter: LogFilter = {
      limit: 20,
      offset: 0,
      sortBy: 'created_at',
      sortOrder: 'desc'
    }
    
    if (search) filter.search = search
    if (level) filter.level = [level] as LogLevel[]
    if (category) filter.category = [category] as LogCategory[]
    
    const { logs } = await logger.getLogs(filter)
    
    // Return just the logs table rows for HTMX
    const rows = logs.map(log => {
      const formattedLog = {
        ...log,
        formattedDate: new Date(log.createdAt).toLocaleString(),
        levelClass: getLevelClass(log.level),
        categoryClass: getCategoryClass(log.category)
      }

      return `
        <tr class="hover:bg-gray-50">
          <td class="px-6 py-4 whitespace-nowrap">
            <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${formattedLog.levelClass}">
              ${formattedLog.level}
            </span>
          </td>
          <td class="px-6 py-4 whitespace-nowrap">
            <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${formattedLog.categoryClass}">
              ${formattedLog.category}
            </span>
          </td>
          <td class="px-6 py-4">
            <div class="text-sm text-gray-900 max-w-md truncate">${formattedLog.message}</div>
          </td>
          <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${formattedLog.source || '-'}</td>
          <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${formattedLog.formattedDate}</td>
          <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
            <a href="/admin/logs/${formattedLog.id}" class="text-indigo-600 hover:text-indigo-900">View</a>
          </td>
        </tr>
      `
    }).join('')

    return c.html(rows)
  } catch (error) {
    console.error('Error searching logs:', error)
    return c.html(html`<tr><td colspan="6" class="px-6 py-4 text-center text-red-500">Error searching logs</td></tr>`)
  }
})

// Helper functions
function getLevelClass(level: string): string {
  switch (level) {
    case 'debug': return 'bg-gray-100 text-gray-800'
    case 'info': return 'bg-blue-100 text-blue-800'
    case 'warn': return 'bg-yellow-100 text-yellow-800'
    case 'error': return 'bg-red-100 text-red-800'
    case 'fatal': return 'bg-purple-100 text-purple-800'
    default: return 'bg-gray-100 text-gray-800'
  }
}

function getCategoryClass(category: string): string {
  switch (category) {
    case 'auth': return 'bg-green-100 text-green-800'
    case 'api': return 'bg-blue-100 text-blue-800'
    case 'workflow': return 'bg-purple-100 text-purple-800'
    case 'plugin': return 'bg-indigo-100 text-indigo-800'
    case 'media': return 'bg-pink-100 text-pink-800'
    case 'system': return 'bg-gray-100 text-gray-800'
    case 'security': return 'bg-red-100 text-red-800'
    case 'error': return 'bg-red-100 text-red-800'
    default: return 'bg-gray-100 text-gray-800'
  }
}

export { adminLogsRoutes }