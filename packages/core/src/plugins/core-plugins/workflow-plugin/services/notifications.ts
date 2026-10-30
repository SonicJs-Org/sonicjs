// @ts-nocheck
import { D1Database } from '@cloudflare/workers-types'

export interface Notification {
  id: string
  user_id: string
  type: 'workflow' | 'schedule' | 'system'
  title: string
  message: string
  data?: any
  is_read: boolean
  created_at: string
}

export interface NotificationPreference {
  id: string
  user_id: string
  notification_type: string
  email_enabled: boolean
  in_app_enabled: boolean
  digest_frequency: 'immediate' | 'hourly' | 'daily' | 'weekly'
}

export class NotificationService {
  constructor(private db: D1Database) {}

  async createNotification(
    userId: string,
    type: 'workflow' | 'schedule' | 'system',
    title: string,
    message: string,
    data?: any
  ): Promise<string> {
    const notificationId = globalThis.crypto.randomUUID()
    
    await this.db.prepare(`
      INSERT INTO notifications 
      (id, user_id, type, title, message, data)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(
      notificationId,
      userId,
      type,
      title,
      message,
      data ? JSON.stringify(data) : null
    ).run()

    // Check if user wants immediate notifications
    const preferences = await this.getUserPreferences(userId, type)
    if (preferences?.digest_frequency === 'immediate') {
      // In a real implementation, this would send email/push notification
      console.log(`Immediate notification for user ${userId}: ${title}`)
    }

    return notificationId
  }

  async getUserNotifications(
    userId: string, 
    limit: number = 50, 
    unreadOnly: boolean = false
  ): Promise<Notification[]> {
    const whereClause = unreadOnly 
      ? 'WHERE user_id = ? AND is_read = 0'
      : 'WHERE user_id = ?'
    
    const { results } = await this.db.prepare(`
      SELECT * FROM notifications 
      ${whereClause}
      ORDER BY created_at DESC
      LIMIT ?
    `).bind(userId, limit).all()
    
    return results.map(row => ({
      ...row,
      data: row.data ? JSON.parse(row.data) : null
    })) as Notification[]
  }

  async markAsRead(notificationId: string, userId: string): Promise<boolean> {
    try {
      const result = await this.db.prepare(`
        UPDATE notifications 
        SET is_read = 1 
        WHERE id = ? AND user_id = ?
      `).bind(notificationId, userId).run()

      return result.changes > 0
    } catch (error) {
      console.error('Failed to mark notification as read:', error)
      return false
    }
  }

  async markAllAsRead(userId: string): Promise<boolean> {
    try {
      await this.db.prepare(`
        UPDATE notifications 
        SET is_read = 1 
        WHERE user_id = ? AND is_read = 0
      `).bind(userId).run()

      return true
    } catch (error) {
      console.error('Failed to mark all notifications as read:', error)
      return false
    }
  }

  async deleteNotification(notificationId: string, userId: string): Promise<boolean> {
    try {
      const result = await this.db.prepare(`
        DELETE FROM notifications 
        WHERE id = ? AND user_id = ?
      `).bind(notificationId, userId).run()

      return result.changes > 0
    } catch (error) {
      console.error('Failed to delete notification:', error)
      return false
    }
  }

  async getUnreadCount(userId: string): Promise<number> {
    const result = await this.db.prepare(`
      SELECT COUNT(*) as count FROM notifications 
      WHERE user_id = ? AND is_read = 0
    `).bind(userId).first()

    return result?.count || 0
  }

  async getUserPreferences(userId: string, notificationType?: string): Promise<NotificationPreference | null> {
    const whereClause = notificationType 
      ? 'WHERE user_id = ? AND notification_type = ?'
      : 'WHERE user_id = ?'
    
    const params = notificationType ? [userId, notificationType] : [userId]
    
    const preference = await this.db.prepare(`
      SELECT * FROM notification_preferences 
      ${whereClause}
      LIMIT 1
    `).bind(...params).first()

    return preference as NotificationPreference | null
  }

  async updateUserPreferences(
    userId: string,
    notificationType: string,
    emailEnabled: boolean,
    inAppEnabled: boolean,
    digestFrequency: 'immediate' | 'hourly' | 'daily' | 'weekly'
  ): Promise<boolean> {
    try {
      await this.db.prepare(`
        INSERT OR REPLACE INTO notification_preferences 
        (user_id, notification_type, email_enabled, in_app_enabled, digest_frequency, updated_at)
        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
      `).bind(
        userId,
        notificationType,
        emailEnabled ? 1 : 0,
        inAppEnabled ? 1 : 0,
        digestFrequency
      ).run()

      return true
    } catch (error) {
      console.error('Failed to update notification preferences:', error)
      return false
    }
  }

  async getAllUserPreferences(userId: string): Promise<NotificationPreference[]> {
    const { results } = await this.db.prepare(`
      SELECT * FROM notification_preferences 
      WHERE user_id = ?
      ORDER BY notification_type
    `).bind(userId).all()

    return results as NotificationPreference[]
  }

  // Bulk notification methods for system events
  async notifyWorkflowTransition(
    contentId: string,
    fromState: string,
    toState: string,
    userId: string
  ): Promise<void> {
    // Get content details
    const content = await this.db.prepare(`
      SELECT c.title, c.slug, col.name as collection_name
      FROM content c
      JOIN collections col ON c.collection_id = col.id
      WHERE c.id = ?
    `).bind(contentId).first()

    if (!content) return

    // Get users who should be notified (assignees, reviewers, etc.)
    const { results: usersToNotify } = await this.db.prepare(`
      SELECT DISTINCT u.id
      FROM auth_user u
      JOIN content_workflow_status cws ON u.id = cws.assigned_to
      WHERE cws.content_id = ?
      AND u.id != ?
    `).bind(contentId, userId).all()

    const title = `Content "${content.title}" moved to ${toState}`
    const message = `The content "${content.title}" in ${content.collection_name} has been moved from ${fromState} to ${toState}.`

    for (const userToNotify of usersToNotify) {
      await this.createNotification(
        userToNotify.id,
        'workflow',
        title,
        message,
        { contentId, fromState, toState, contentTitle: content.title }
      )
    }
  }

  async notifyContentScheduled(
    contentId: string,
    action: string,
    scheduledAt: string,
    userId: string
  ): Promise<void> {
    const content = await this.db.prepare(`
      SELECT c.title, c.slug, col.name as collection_name
      FROM content c
      JOIN collections col ON c.collection_id = col.id
      WHERE c.id = ?
    `).bind(contentId).first()

    if (!content) return

    const title = `Content "${content.title}" scheduled for ${action}`
    const message = `The content "${content.title}" has been scheduled for ${action} on ${new Date(scheduledAt).toLocaleString()}.`

    await this.createNotification(
      userId,
      'schedule',
      title,
      message,
      { contentId, action, scheduledAt, contentTitle: content.title }
    )
  }

  async notifyContentAssigned(
    contentId: string,
    assignedToUserId: string,
    assignedByUserId: string,
    dueDate?: string
  ): Promise<void> {
    const content = await this.db.prepare(`
      SELECT c.title, c.slug, col.name as collection_name
      FROM content c
      JOIN collections col ON c.collection_id = col.id
      WHERE c.id = ?
    `).bind(contentId).first()

    if (!content) return

    const assignedBy = await this.db.prepare(`
      SELECT email FROM auth_user WHERE id = ?
    `).bind(assignedByUserId).first() as { email?: string } | null

    const dueDateText = dueDate ? ` (due: ${new Date(dueDate).toLocaleDateString()})` : ''
    const title = `You've been assigned content: "${content.title}"`
    const message = `${assignedBy?.email || 'Someone'} has assigned you the content "${content.title}" for review${dueDateText}.`

    await this.createNotification(
      assignedToUserId,
      'workflow',
      title,
      message,
      { contentId, assignedBy: assignedByUserId, dueDate, contentTitle: content.title }
    )
  }

  // Method to send digest notifications (would be called by a cron job)
  async sendDigestNotifications(frequency: 'hourly' | 'daily' | 'weekly'): Promise<number> {
    const timeFilter = {
      hourly: "datetime('now', '-1 hour')",
      daily: "datetime('now', '-1 day')",
      weekly: "datetime('now', '-7 days')"
    }[frequency]

    // Get users who want digest notifications for this frequency
    const { results: users } = await this.db.prepare(`
      SELECT DISTINCT np.user_id, u.email
      FROM notification_preferences np
      JOIN auth_user u ON np.user_id = u.id
      WHERE np.digest_frequency = ? AND np.email_enabled = 1
    `).bind(frequency).all()

    let sentCount = 0

    for (const user of users) {
      // Get unread notifications for this user since the last digest
      const { results: notifications } = await this.db.prepare(`
        SELECT * FROM notifications 
        WHERE user_id = ? AND is_read = 0 
        AND created_at >= ${timeFilter}
        ORDER BY created_at DESC
      `).bind(user.user_id).all()

      if (notifications.length > 0) {
        // In a real implementation, this would send an email
        console.log(`Sending ${frequency} digest to ${user.email} with ${notifications.length} notifications`)
        sentCount++
      }
    }

    return sentCount
  }

  // Clean up old notifications
  async cleanupOldNotifications(daysToKeep: number = 30): Promise<number> {
    const result = await this.db.prepare(`
      DELETE FROM notifications 
      WHERE created_at < datetime('now', '-${daysToKeep} days')
    `).run()

    return result.changes
  }
}