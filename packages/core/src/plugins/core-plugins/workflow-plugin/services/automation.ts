// @ts-nocheck
import { D1Database } from '@cloudflare/workers-types'
import { WorkflowEngine } from './workflow-service'
import { NotificationService } from './notifications'
import { SchedulerService } from './scheduler'

export interface AutomationRule {
  id: string
  name: string
  description?: string
  trigger_type: 'content_created' | 'content_updated' | 'workflow_transition' | 'schedule'
  trigger_conditions?: any
  action_type: 'workflow_transition' | 'send_notification' | 'webhook_call' | 'auto_save'
  action_config?: any
  is_active: boolean
}

export interface AutoSaveDraft {
  id: string
  content_id?: string
  user_id: string
  title?: string
  content?: string
  fields?: any
  last_saved_at: string
}

export class AutomationEngine {
  constructor(private db: D1Database) {}

  async createAutomationRule(
    name: string,
    description: string,
    triggerType: 'content_created' | 'content_updated' | 'workflow_transition' | 'schedule',
    triggerConditions: any,
    actionType: 'workflow_transition' | 'send_notification' | 'webhook_call' | 'auto_save',
    actionConfig: any
  ): Promise<string> {
    const ruleId = globalThis.crypto.randomUUID()
    
    await this.db.prepare(`
      INSERT INTO automation_rules 
      (id, name, description, trigger_type, trigger_conditions, action_type, action_config, is_active)
      VALUES (?, ?, ?, ?, ?, ?, ?, 1)
    `).bind(
      ruleId,
      name,
      description,
      triggerType,
      JSON.stringify(triggerConditions),
      actionType,
      JSON.stringify(actionConfig)
    ).run()

    return ruleId
  }

  async getAutomationRules(isActive?: boolean): Promise<AutomationRule[]> {
    const whereClause = isActive !== undefined ? 'WHERE is_active = ?' : ''
    const params = isActive !== undefined ? [isActive ? 1 : 0] : []

    const { results } = await this.db.prepare(`
      SELECT * FROM automation_rules 
      ${whereClause}
      ORDER BY created_at DESC
    `).bind(...params).all()

    return results.map(row => ({
      ...row,
      trigger_conditions: row.trigger_conditions ? JSON.parse(row.trigger_conditions) : null,
      action_config: row.action_config ? JSON.parse(row.action_config) : null
    })) as AutomationRule[]
  }

  async updateAutomationRule(
    ruleId: string,
    updates: Partial<AutomationRule>
  ): Promise<boolean> {
    try {
      const fields = []
      const values = []

      if (updates.name !== undefined) {
        fields.push('name = ?')
        values.push(updates.name)
      }
      if (updates.description !== undefined) {
        fields.push('description = ?')
        values.push(updates.description)
      }
      if (updates.trigger_conditions !== undefined) {
        fields.push('trigger_conditions = ?')
        values.push(JSON.stringify(updates.trigger_conditions))
      }
      if (updates.action_config !== undefined) {
        fields.push('action_config = ?')
        values.push(JSON.stringify(updates.action_config))
      }
      if (updates.is_active !== undefined) {
        fields.push('is_active = ?')
        values.push(updates.is_active ? 1 : 0)
      }

      if (fields.length === 0) return false

      fields.push('updated_at = CURRENT_TIMESTAMP')
      values.push(ruleId)

      await this.db.prepare(`
        UPDATE automation_rules 
        SET ${fields.join(', ')}
        WHERE id = ?
      `).bind(...values).run()

      return true
    } catch (error) {
      console.error('Failed to update automation rule:', error)
      return false
    }
  }

  async deleteAutomationRule(ruleId: string): Promise<boolean> {
    try {
      const result = await this.db.prepare(`
        DELETE FROM automation_rules WHERE id = ?
      `).bind(ruleId).run()

      return result.changes > 0
    } catch (error) {
      console.error('Failed to delete automation rule:', error)
      return false
    }
  }

  // Trigger automation when content is created
  async triggerContentCreated(contentId: string, userId: string): Promise<void> {
    const rules = await this.getActiveRulesByTrigger('content_created')
    
    for (const rule of rules) {
      try {
        // Check if conditions match
        if (rule.trigger_conditions && !await this.evaluateConditions(rule.trigger_conditions, { contentId, userId, event: 'created' })) {
          continue
        }

        await this.executeAction(rule, { contentId, userId, event: 'created' })
      } catch (error) {
        console.error(`Failed to execute automation rule ${rule.id}:`, error)
      }
    }
  }

  // Trigger automation when content is updated
  async triggerContentUpdated(contentId: string, userId: string, changes: any): Promise<void> {
    const rules = await this.getActiveRulesByTrigger('content_updated')
    
    for (const rule of rules) {
      try {
        if (rule.trigger_conditions && !await this.evaluateConditions(rule.trigger_conditions, { contentId, userId, changes, event: 'updated' })) {
          continue
        }

        await this.executeAction(rule, { contentId, userId, changes, event: 'updated' })
      } catch (error) {
        console.error(`Failed to execute automation rule ${rule.id}:`, error)
      }
    }
  }

  // Trigger automation when workflow state changes
  async triggerWorkflowTransition(contentId: string, fromState: string, toState: string, userId: string): Promise<void> {
    const rules = await this.getActiveRulesByTrigger('workflow_transition')
    
    for (const rule of rules) {
      try {
        if (rule.trigger_conditions && !await this.evaluateConditions(rule.trigger_conditions, { contentId, fromState, toState, userId, event: 'transition' })) {
          continue
        }

        await this.executeAction(rule, { contentId, fromState, toState, userId, event: 'transition' })
      } catch (error) {
        console.error(`Failed to execute automation rule ${rule.id}:`, error)
      }
    }
  }

  private async getActiveRulesByTrigger(triggerType: string): Promise<AutomationRule[]> {
    const { results } = await this.db.prepare(`
      SELECT * FROM automation_rules 
      WHERE trigger_type = ? AND is_active = 1
      ORDER BY created_at ASC
    `).bind(triggerType).all()

    return results.map(row => ({
      ...row,
      trigger_conditions: row.trigger_conditions ? JSON.parse(row.trigger_conditions) : null,
      action_config: row.action_config ? JSON.parse(row.action_config) : null
    })) as AutomationRule[]
  }

  private async evaluateConditions(conditions: any, context: any): Promise<boolean> {
    try {
      // Simple condition evaluation - in production this would be more sophisticated
      if (conditions.collection_id && context.contentId) {
        const content = await this.db.prepare(`
          SELECT collection_id FROM content WHERE id = ?
        `).bind(context.contentId).first()
        
        if (content && content.collection_id !== conditions.collection_id) {
          return false
        }
      }

      if (conditions.from_state && context.fromState !== conditions.from_state) {
        return false
      }

      if (conditions.to_state && context.toState !== conditions.to_state) {
        return false
      }

      if (conditions.user_role && context.userId) {
        const user = await this.db.prepare(`
          SELECT role FROM auth_user WHERE id = ?
        `).bind(context.userId).first()
        
        if (user && user.role !== conditions.user_role) {
          return false
        }
      }

      return true
    } catch (error) {
      console.error('Error evaluating conditions:', error)
      return false
    }
  }

  private async executeAction(rule: AutomationRule, context: any): Promise<void> {
    const workflowEngine = new WorkflowEngine(this.db)
    const notificationService = new NotificationService(this.db)
    const schedulerService = new SchedulerService(this.db)

    switch (rule.action_type) {
      case 'workflow_transition':
        if (rule.action_config?.to_state && context.contentId) {
          await workflowEngine.transitionContent(
            context.contentId,
            rule.action_config.to_state,
            context.userId || 'system',
            'Automated transition'
          )
        }
        break

      case 'send_notification':
        if (rule.action_config?.user_id || rule.action_config?.role) {
          let targetUsers = []
          
          if (rule.action_config.user_id) {
            targetUsers.push(rule.action_config.user_id)
          }
          
          if (rule.action_config.role) {
            const { results } = await this.db.prepare(`
              SELECT id FROM auth_user WHERE role = ? AND is_active = 1
            `).bind(rule.action_config.role).all()
            targetUsers.push(...results.map(u => u.id))
          }

          for (const userId of targetUsers) {
            await notificationService.createNotification(
              userId,
              'system',
              rule.action_config.title || 'Automated Action',
              rule.action_config.message || 'An automated action was triggered',
              context
            )
          }
        }
        break

      case 'webhook_call':
        if (rule.action_config?.webhook_url) {
          // In production, this would use a queue or background job
          try {
            await fetch(rule.action_config.webhook_url, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                ...(rule.action_config.headers || {})
              },
              body: JSON.stringify({
                rule_id: rule.id,
                rule_name: rule.name,
                trigger_type: rule.trigger_type,
                context
              })
            })
          } catch (error) {
            console.error('Webhook call failed:', error)
          }
        }
        break

      case 'auto_save':
        // Auto-save is handled separately by the auto-save system
        break
    }
  }

  // Auto-save functionality
  async saveAutoSaveDraft(
    userId: string,
    contentId: string | null,
    title?: string,
    content?: string,
    fields?: any
  ): Promise<string> {
    const draftId = globalThis.crypto.randomUUID()
    
    await this.db.prepare(`
      INSERT OR REPLACE INTO auto_save_drafts 
      (id, content_id, user_id, title, content, fields, last_saved_at)
      VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    `).bind(
      draftId,
      contentId,
      userId,
      title,
      content,
      fields ? JSON.stringify(fields) : null
    ).run()

    return draftId
  }

  async getAutoSaveDrafts(userId: string): Promise<AutoSaveDraft[]> {
    const { results } = await this.db.prepare(`
      SELECT * FROM auto_save_drafts 
      WHERE user_id = ?
      ORDER BY last_saved_at DESC
      LIMIT 50
    `).bind(userId).all()

    return results.map(row => ({
      ...row,
      fields: row.fields ? JSON.parse(row.fields) : null
    })) as AutoSaveDraft[]
  }

  async getAutoSaveDraft(draftId: string, userId: string): Promise<AutoSaveDraft | null> {
    const draft = await this.db.prepare(`
      SELECT * FROM auto_save_drafts 
      WHERE id = ? AND user_id = ?
    `).bind(draftId, userId).first()

    if (!draft) return null

    return {
      ...draft,
      fields: draft.fields ? JSON.parse(draft.fields) : null
    } as AutoSaveDraft
  }

  async deleteAutoSaveDraft(draftId: string, userId: string): Promise<boolean> {
    try {
      const result = await this.db.prepare(`
        DELETE FROM auto_save_drafts 
        WHERE id = ? AND user_id = ?
      `).bind(draftId, userId).run()

      return result.changes > 0
    } catch (error) {
      console.error('Failed to delete auto-save draft:', error)
      return false
    }
  }

  async cleanupOldAutoSaves(daysToKeep: number = 7): Promise<number> {
    const result = await this.db.prepare(`
      DELETE FROM auto_save_drafts 
      WHERE last_saved_at < datetime('now', '-${daysToKeep} days')
    `).run()

    return result.changes
  }

  // Content versioning
  async createContentVersion(
    contentId: string,
    title: string,
    content: string,
    fields: any,
    userId: string,
    changeSummary?: string
  ): Promise<number> {
    // Get next version number
    const latestVersion = await this.db.prepare(`
      SELECT MAX(version_number) as max_version 
      FROM content_versions 
      WHERE content_id = ?
    `).bind(contentId).first()

    const nextVersion = (latestVersion?.max_version || 0) + 1

    await this.db.prepare(`
      INSERT INTO content_versions 
      (content_id, version_number, title, content, fields, user_id, change_summary)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(
      contentId,
      nextVersion,
      title,
      content,
      JSON.stringify(fields),
      userId,
      changeSummary
    ).run()

    // Update content table version number
    await this.db.prepare(`
      UPDATE content SET version_number = ? WHERE id = ?
    `).bind(nextVersion, contentId).run()

    return nextVersion
  }

  async getContentVersions(contentId: string): Promise<any[]> {
    const { results } = await this.db.prepare(`
      SELECT 
        cv.*,
        u.email as user_name
      FROM content_versions cv
      LEFT JOIN auth_user u ON cv.user_id = u.id
      WHERE cv.content_id = ?
      ORDER BY cv.version_number DESC
    `).bind(contentId).all()

    return results.map(row => ({
      ...row,
      fields: row.fields ? JSON.parse(row.fields) : null
    }))
  }

  async rollbackToVersion(
    contentId: string,
    versionNumber: number,
    userId: string
  ): Promise<boolean> {
    try {
      // Get the version data
      const version = await this.db.prepare(`
        SELECT * FROM content_versions 
        WHERE content_id = ? AND version_number = ?
      `).bind(contentId, versionNumber).first()

      if (!version) return false

      // Update the content
      await this.db.prepare(`
        UPDATE content 
        SET title = ?, data = ?, updated_at = ?
        WHERE id = ?
      `).bind(
        version.title,
        version.content,
        Date.now(),
        contentId
      ).run()

      // Create a new version for the rollback
      await this.createContentVersion(
        contentId,
        version.title,
        version.content,
        JSON.parse(version.fields || '{}'),
        userId,
        `Rolled back to version ${versionNumber}`
      )

      return true
    } catch (error) {
      console.error('Failed to rollback content:', error)
      return false
    }
  }
}