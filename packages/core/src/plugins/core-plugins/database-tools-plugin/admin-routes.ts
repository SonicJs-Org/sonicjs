import { Hono } from 'hono'
import { DatabaseToolsService } from './services/database-service'
import { renderDatabaseTablePage, DatabaseTablePageData } from '../../../templates/pages/admin-database-table.template'
import { requireAuth } from '../../../middleware'
import { RbacService } from '../../../services/rbac'

type Bindings = {
  DB: D1Database
}

type Variables = {
  user?: {
    userId: string
    email: string
    role: string
  }
}

export function createDatabaseToolsAdminRoutes() {
  const router = new Hono<{ Bindings: Bindings; Variables: Variables }>()

  // Apply authentication middleware
  router.use('*', requireAuth())

  // Get database statistics
  router.get('/api/stats', async (c) => {
    try {
      const user = c.get('user')
      
      if (!user || !(await new RbacService(c.env.DB).can(user.userId, 'settings', 'manage'))) {
        return c.json({ 
          success: false, 
          error: 'Unauthorized. Admin access required.' 
        }, 403)
      }

      const db = c.env.DB
      const service = new DatabaseToolsService(db)
      const stats = await service.getDatabaseStats()

      return c.json({
        success: true,
        data: stats
      })
    } catch (error) {
      console.error('Error fetching database stats:', error)
      return c.json({ 
        success: false, 
        error: 'Failed to fetch database statistics' 
      }, 500)
    }
  })

  // Truncate all data except admin user
  router.post('/api/truncate', async (c) => {
    try {
      const user = c.get('user')
      
      if (!user || !(await new RbacService(c.env.DB).can(user.userId, 'settings', 'manage'))) {
        return c.json({ 
          success: false, 
          error: 'Unauthorized. Admin access required.' 
        }, 403)
      }

      const body = await c.req.json()
      const { confirmText } = body

      // Require confirmation text for safety
      if (confirmText !== 'TRUNCATE ALL DATA') {
        return c.json({
          success: false,
          error: 'Invalid confirmation text. Operation cancelled.'
        }, 400)
      }

      const db = c.env.DB
      const service = new DatabaseToolsService(db)
      const result = await service.truncateAllData(user.email)

      return c.json({
        success: result.success,
        message: result.message,
        data: {
          tablesCleared: result.tablesCleared,
          adminUserPreserved: result.adminUserPreserved,
          errors: result.errors
        }
      })
    } catch (error) {
      console.error('Error truncating database:', error)
      return c.json({ 
        success: false, 
        error: 'Failed to truncate database' 
      }, 500)
    }
  })

  // Create backup
  router.post('/api/backup', async (c) => {
    try {
      const user = c.get('user')
      
      if (!user || !(await new RbacService(c.env.DB).can(user.userId, 'settings', 'manage'))) {
        return c.json({ 
          success: false, 
          error: 'Unauthorized. Admin access required.' 
        }, 403)
      }

      const db = c.env.DB
      const service = new DatabaseToolsService(db)
      const result = await service.createBackup()

      return c.json({
        success: result.success,
        message: result.message,
        data: {
          backupId: result.backupId
        }
      })
    } catch (error) {
      console.error('Error creating backup:', error)
      return c.json({ 
        success: false, 
        error: 'Failed to create backup' 
      }, 500)
    }
  })

  // Validate database
  router.get('/api/validate', async (c) => {
    try {
      const user = c.get('user')

      if (!user || !(await new RbacService(c.env.DB).can(user.userId, 'settings', 'manage'))) {
        return c.json({
          success: false,
          error: 'Unauthorized. Admin access required.'
        }, 403)
      }

      const db = c.env.DB
      const service = new DatabaseToolsService(db)
      const validation = await service.validateDatabase()

      return c.json({
        success: true,
        data: validation
      })
    } catch (error) {
      console.error('Error validating database:', error)
      return c.json({
        success: false,
        error: 'Failed to validate database'
      }, 500)
    }
  })

  // Get table data (API endpoint)
  router.get('/api/tables/:tableName', async (c) => {
    try {
      const user = c.get('user')

      if (!user || !(await new RbacService(c.env.DB).can(user.userId, 'settings', 'manage'))) {
        return c.json({
          success: false,
          error: 'Unauthorized. Admin access required.'
        }, 403)
      }

      const tableName = c.req.param('tableName')
      const limit = parseInt(c.req.query('limit') || '100')
      const offset = parseInt(c.req.query('offset') || '0')
      const sortColumn = c.req.query('sort')
      const sortDirection = (c.req.query('dir') || 'asc') as 'asc' | 'desc'

      const db = c.env.DB
      const service = new DatabaseToolsService(db)
      const tableData = await service.getTableData(tableName, limit, offset, sortColumn, sortDirection)

      return c.json({
        success: true,
        data: tableData
      })
    } catch (error) {
      console.error('Error fetching table data:', error)
      return c.json({
        success: false,
        error: `Failed to fetch table data: ${error}`
      }, 500)
    }
  })

  // View table data page
  router.get('/tables/:tableName', async (c) => {
    try {
      const user = c.get('user')

      if (!user || !(await new RbacService(c.env.DB).can(user.userId, 'settings', 'manage'))) {
        return c.redirect('/admin/login')
      }

      const tableName = c.req.param('tableName')
      const page = parseInt(c.req.query('page') || '1')
      const pageSize = parseInt(c.req.query('pageSize') || '20')
      const sortColumn = c.req.query('sort')
      const sortDirection = (c.req.query('dir') || 'asc') as 'asc' | 'desc'

      const offset = (page - 1) * pageSize

      const db = c.env.DB
      const service = new DatabaseToolsService(db)
      const tableData = await service.getTableData(tableName, pageSize, offset, sortColumn, sortDirection)

      const pageData: DatabaseTablePageData = {
        user: {
          name: user.email.split('@')[0] || 'Unknown',
          email: user.email,
          role: user.role
        },
        tableName: tableData.tableName,
        columns: tableData.columns,
        rows: tableData.rows,
        totalRows: tableData.totalRows,
        currentPage: page,
        pageSize: pageSize,
        sortColumn: sortColumn,
        sortDirection: sortDirection
      }

      return c.html(renderDatabaseTablePage(pageData))
    } catch (error) {
      console.error('Error rendering table page:', error)
      return c.text(`Error: ${error}`, 500)
    }
  })

  return router
}