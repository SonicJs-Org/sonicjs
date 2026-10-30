/**
 * Workflow Plugin — Payload-shaped port.
 *
 * Content workflow management. The original PluginBuilder shape declared a
 * pile of addAdminPage / addComponent / addService entries the runtime never
 * wired; this port keeps only the lifecycle (migrations) + content hooks
 * that actually run.
 */

import { definePlugin } from '../../sdk/define-plugin'
import { workflowMigration } from './migrations'
import { WorkflowService, WorkflowEngine } from './services/workflow-service'

export const workflowPlugin = definePlugin({
  id: 'workflow-plugin',
  version: '1.0.0',
  name: 'Workflow',
  description: 'Content workflow management with approval chains, scheduling, and automation.',
  sonicjsVersionRange: '^3.0.0',
  author: { name: 'SonicJS', email: 'info@sonicjs.com' },
  dependencies: ['content-plugin'],
  capabilities: ['hooks.content:subscribe'],

  menu: [
    { label: 'Workflow', path: '/admin/workflow/dashboard', icon: 'document', order: 30, permissions: ['admin', 'editor'] },
    { label: 'Scheduled', path: '/admin/workflow/scheduled', icon: 'document', order: 31, permissions: ['admin', 'editor'] },
  ],

  async onBoot(ctx) {
    // Legacy non-typed content hooks (content:create / :save / :delete) —
    // subscribe via the raw bus.
    const hooks = (ctx.raw as any)?.hooks
    if (!hooks?.register) return
    hooks.register('content:create', async (data: any, context: any) => {
      if (context?.db) {
        const workflowEngine = new WorkflowEngine(context.db)
        await workflowEngine.initializeContentWorkflow(data.id, data.collectionId || data.collection_id)
      }
      return data
    })
    hooks.register('content:save', async (data: any) => data)
    hooks.register('content:delete', async (data: any) => data)
  },

  install: async (context: any) => {
    const { db } = context
    await db.prepare(workflowMigration).run()
    console.log('Workflow plugin installed successfully')
  },
  uninstall: async (context: any) => {
    const { db } = context
    await db.prepare('DROP TABLE IF EXISTS workflow_history').run()
    await db.prepare('DROP TABLE IF EXISTS scheduled_content').run()
    await db.prepare('DROP TABLE IF EXISTS content_workflow_status').run()
    await db.prepare('DROP TABLE IF EXISTS workflow_transitions').run()
    await db.prepare('DROP TABLE IF EXISTS workflows').run()
    await db.prepare('DROP TABLE IF EXISTS workflow_states').run()
    console.log('Workflow plugin uninstalled successfully')
  },
  activate: async (context: any) => {
    const _workflowService = new WorkflowService(context.db)
    console.log('Workflow plugin activated')
  },
  deactivate: async () => console.log('Workflow plugin deactivated'),
})

export function createWorkflowPlugin() {
  return workflowPlugin
}

// Service re-exports
export { WorkflowService, WorkflowEngine } from './services/workflow-service'
export { SchedulerService as WorkflowSchedulerService } from './services/scheduler'
export { AutomationEngine as WorkflowAutomationEngine } from './services/automation'
export { NotificationService as WorkflowNotificationService } from './services/notifications'
export { WebhookService as WorkflowWebhookService } from './services/webhooks'
export {
  ContentWorkflow as WorkflowContentWorkflow,
  WorkflowManager as WorkflowContentManager,
  ContentStatus,
  WorkflowAction,
  defaultWorkflowPermissions,
  workflowTransitions,
} from './services/content-workflow'
