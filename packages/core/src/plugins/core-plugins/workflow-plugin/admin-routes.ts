import { Hono } from 'hono'
import { WorkflowEngine } from './services/workflow-service'
import { SchedulerService } from './services/scheduler'
import { RbacService } from '../../../services/rbac'
import { renderWorkflowDashboard } from './templates/workflow-dashboard'
import { renderWorkflowContentDetail } from './templates/workflow-content'
import { renderScheduledContent } from './templates/scheduled-content'

type Bindings = {
  DB: D1Database
  KV: KVNamespace
  MEDIA_BUCKET: R2Bucket
  EMAIL_QUEUE?: Queue
  SENDGRID_API_KEY?: string
  DEFAULT_FROM_EMAIL?: string
  IMAGES_ACCOUNT_ID?: string
  IMAGES_API_TOKEN?: string
}

type Variables = {
  user: {
    userId: string
    email: string
    role: string
    exp: number
    iat: number
  }
}

export function createWorkflowAdminRoutes() {
  const adminRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()

  // Workflow Dashboard
  adminRoutes.get('/dashboard', async (c) => {
    const user = c.get('user')
    if (!user) {
      return c.redirect('/auth/login')
    }

    // Check permissions (simplified for now - assume admin has all permissions)
    if (!(await new RbacService(c.env.DB).can(user.userId, 'content', 'manage'))) {
      return c.text('Forbidden', 403)
    }

    try {
      const workflowEngine = new WorkflowEngine(c.env.DB)
      
      // Get workflow states and counts with error handling
      console.log('Fetching workflow states...')
      const states = await workflowEngine.getWorkflowStates()
      console.log(`Found ${states.length} workflow states:`, states.map(s => s.name))
      
      const stateData = []
      
      for (const state of states) {
        console.log(`Processing state: ${state.name} (${state.id})`)
        try {
          const content = await workflowEngine.getContentByState(state.id, 10)
          console.log(`Found ${content.length} content items for state ${state.name}`)
          
          stateData.push({
            ...state,
            count: content.length,
            content: content.slice(0, 5) // Show first 5 items
          })
        } catch (stateError) {
          console.error(`Error getting content for state ${state.name}:`, stateError)
          // Add state with zero count if there's an error
          stateData.push({
            ...state,
            count: 0,
            content: []
          })
        }
      }

      // Get assigned content with error handling
      console.log('Fetching assigned content...')
      let assignedContent = []
      try {
        assignedContent = await workflowEngine.getAssignedContent(user.userId)
        console.log(`Found ${assignedContent.length} assigned content items`)
      } catch (assignedError) {
        console.error('Error getting assigned content:', assignedError)
      }

      const data = {
        user,
        states: stateData,
        assignedContent
      }

      console.log('Dashboard data prepared:', {
        stateCount: data.states.length,
        assignedCount: data.assignedContent.length
      })

      return c.html(renderWorkflowDashboard(data))
    } catch (error) {
      console.error('Critical error in workflow dashboard:', error)
      
      // Return error page or basic HTML with error info
      return c.html(`
        <div style="padding: 20px; font-family: Arial, sans-serif;">
          <h1>Workflow Dashboard Error</h1>
          <p><strong>Error:</strong> ${(error as Error).message}</p>
          <p><strong>Stack:</strong> <pre>${(error as Error).stack}</pre></p>
          <hr>
          <p><a href="/admin/workflow/debug">Check Debug Endpoint</a></p>
          <p><a href="/admin">Return to Admin</a></p>
        </div>
      `)
    }
  })

  // Content workflow detail
  adminRoutes.get('/content/:contentId', async (c) => {
    const user = await c.get('user')
    if (!user) {
      return c.redirect('/auth/login')
    }

    const contentId = c.req.param('contentId')
    const workflowEngine = new WorkflowEngine(c.env.DB)
    
    // Get content details
    const content = await c.env.DB.prepare(`
      SELECT c.*, col.name as collection_name, u.username as author_name
      FROM content c
      JOIN collections col ON c.collection_id = col.id
      JOIN users u ON c.author_id = u.id
      WHERE c.id = ?
    `).bind(contentId).first()

    if (!content) {
      return c.text('Content not found', 404)
    }

    // Get workflow status
    const workflowStatus = await workflowEngine.getContentWorkflowStatus(contentId)
    const currentState = await c.env.DB.prepare(`
      SELECT * FROM workflow_states WHERE id = ?
    `).bind(workflowStatus?.current_state_id || 'draft').first()

    // Get available transitions
    const availableTransitions = workflowStatus 
      ? await workflowEngine.getAvailableTransitions(
          workflowStatus.workflow_id, 
          workflowStatus.current_state_id, 
          user.userId
        )
      : []

    // Get workflow history
    const history = await workflowEngine.getWorkflowHistory(contentId)

    // Get scheduled actions
    const scheduler = new SchedulerService(c.env.DB)
    const scheduledActions = await scheduler.getScheduledContentForContent(contentId)

    const data = {
      user,
      content,
      currentState,
      workflowStatus,
      availableTransitions,
      history,
      scheduledActions
    }

    return c.html(renderWorkflowContentDetail(data))
  })

  // Get scheduled content
  adminRoutes.get('/scheduled', async (c) => {
    const user = await c.get('user')
    if (!user) {
      return c.redirect('/auth/login')
    }

    const scheduler = new SchedulerService(c.env.DB)
    const scheduledContent = await scheduler.getScheduledContentForUser(user.userId)
    const stats = await scheduler.getScheduledContentStats()

    const data = {
      user,
      scheduledContent,
      stats
    }

    return c.html(renderScheduledContent(data))
  })

  return adminRoutes
}