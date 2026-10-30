// @ts-nocheck
import { describe, test, expect, beforeEach, vi } from 'vitest'
// TODO: Skip until notifications service exists in core package
// import { NotificationService } from '../../src/services/notifications'

// Mock D1Database
const mockDB = {
  prepare: vi.fn(),
  exec: vi.fn(),
  dump: vi.fn(),
  batch: vi.fn()
}

const mockStatement = {
  bind: vi.fn(),
  first: vi.fn(),
  all: vi.fn(),
  run: vi.fn()
}

// Setup mock chain
beforeEach(() => {
  vi.clearAllMocks()
  mockDB.prepare.mockReturnValue(mockStatement)
  mockStatement.bind.mockReturnValue(mockStatement)
  mockStatement.first.mockResolvedValue(null)
  mockStatement.all.mockResolvedValue({ results: [] })
  mockStatement.run.mockResolvedValue({ changes: 1, success: true })
})

describe.skip('NotificationService', () => {
  let notificationService: any // NotificationService

  beforeEach(() => {
    notificationService = new NotificationService(mockDB as any)
  })

  describe('createNotification', () => {
    test('should successfully create a workflow notification', async () => {
      const notificationId = await notificationService.createNotification(
        'user-123',
        'workflow',
        'Content Assigned',
        'You have been assigned content for review',
        { contentId: 'content-456', dueDate: '2024-12-31' }
      )

      expect(notificationId).toBeDefined()
      expect(typeof notificationId).toBe('string')
      expect(mockDB.prepare).toHaveBeenCalledWith(expect.stringContaining('INSERT INTO notifications'))
      expect(mockStatement.bind).toHaveBeenCalledWith(
        notificationId,
        'user-123',
        'workflow',
        'Content Assigned',
        'You have been assigned content for review',
        JSON.stringify({ contentId: 'content-456', dueDate: '2024-12-31' })
      )
    })

    test('should create notification without data', async () => {
      await notificationService.createNotification(
        'user-123',
        'system',
        'System Update',
        'System maintenance completed'
      )

      expect(mockStatement.bind).toHaveBeenCalledWith(
        expect.any(String),
        'user-123',
        'system',
        'System Update',
        'System maintenance completed',
        null
      )
    })

    test('should handle immediate notification preferences', async () => {
      // Mock user preferences
      mockStatement.first.mockResolvedValueOnce({
        digest_frequency: 'immediate',
        email_enabled: 1,
        in_app_enabled: 1
      })

      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})

      await notificationService.createNotification(
        'user-123',
        'workflow',
        'Urgent Alert',
        'Immediate attention required'
      )

      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Immediate notification for user user-123')
      )

      consoleSpy.mockRestore()
    })
  })

  describe('getUserNotifications', () => {
    test('should return user notifications with parsed data', async () => {
      const mockNotifications = [
        {
          id: 'notif-1',
          user_id: 'user-123',
          type: 'workflow',
          title: 'Content Assigned',
          message: 'Review required',
          data: '{"contentId":"content-456"}',
          is_read: 0,
          created_at: '2024-01-01T00:00:00Z'
        }
      ]

      mockStatement.all.mockResolvedValueOnce({ results: mockNotifications })

      const result = await notificationService.getUserNotifications('user-123')

      expect(mockDB.prepare).toHaveBeenCalledWith(expect.stringContaining('WHERE user_id = ?'))
      expect(mockStatement.bind).toHaveBeenCalledWith('user-123', 50)
      expect(result[0].data).toEqual({ contentId: 'content-456' })
    })

    test('should filter unread notifications only', async () => {
      await notificationService.getUserNotifications('user-123', 25, true)

      expect(mockDB.prepare).toHaveBeenCalledWith(expect.stringContaining('AND is_read = 0'))
      expect(mockStatement.bind).toHaveBeenCalledWith('user-123', 25)
    })

    test('should handle notifications without data', async () => {
      const mockNotifications = [
        {
          id: 'notif-1',
          user_id: 'user-123',
          type: 'system',
          title: 'System Update',
          message: 'Update completed',
          data: null,
          is_read: 1,
          created_at: '2024-01-01T00:00:00Z'
        }
      ]

      mockStatement.all.mockResolvedValueOnce({ results: mockNotifications })

      const result = await notificationService.getUserNotifications('user-123')

      expect(result[0].data).toBeNull()
    })
  })

  describe('markAsRead', () => {
    test('should successfully mark notification as read', async () => {
      mockStatement.run.mockResolvedValueOnce({ changes: 1 })

      const result = await notificationService.markAsRead('notif-123', 'user-456')

      expect(result).toBe(true)
      expect(mockDB.prepare).toHaveBeenCalledWith(expect.stringContaining('UPDATE notifications'))
      expect(mockDB.prepare).toHaveBeenCalledWith(expect.stringContaining('SET is_read = 1'))
      expect(mockStatement.bind).toHaveBeenCalledWith('notif-123', 'user-456')
    })

    test('should return false when notification not found', async () => {
      mockStatement.run.mockResolvedValueOnce({ changes: 0 })

      const result = await notificationService.markAsRead('nonexistent', 'user-456')

      expect(result).toBe(false)
    })

    test('should handle database errors', async () => {
      mockStatement.run.mockRejectedValueOnce(new Error('Database error'))

      const result = await notificationService.markAsRead('notif-123', 'user-456')

      expect(result).toBe(false)
    })
  })

  describe('markAllAsRead', () => {
    test('should mark all user notifications as read', async () => {
      const result = await notificationService.markAllAsRead('user-123')

      expect(result).toBe(true)
      expect(mockDB.prepare).toHaveBeenCalledWith(expect.stringContaining('UPDATE notifications'))
      expect(mockDB.prepare).toHaveBeenCalledWith(expect.stringContaining('WHERE user_id = ? AND is_read = 0'))
      expect(mockStatement.bind).toHaveBeenCalledWith('user-123')
    })

    test('should handle errors gracefully', async () => {
      mockStatement.run.mockRejectedValueOnce(new Error('Database error'))

      const result = await notificationService.markAllAsRead('user-123')

      expect(result).toBe(false)
    })
  })

  describe('deleteNotification', () => {
    test('should successfully delete notification', async () => {
      mockStatement.run.mockResolvedValueOnce({ changes: 1 })

      const result = await notificationService.deleteNotification('notif-123', 'user-456')

      expect(result).toBe(true)
      expect(mockDB.prepare).toHaveBeenCalledWith(expect.stringContaining('DELETE FROM notifications'))
      expect(mockStatement.bind).toHaveBeenCalledWith('notif-123', 'user-456')
    })

    test('should return false when notification not found', async () => {
      mockStatement.run.mockResolvedValueOnce({ changes: 0 })

      const result = await notificationService.deleteNotification('nonexistent', 'user-456')

      expect(result).toBe(false)
    })
  })

  describe('getUnreadCount', () => {
    test('should return unread notification count', async () => {
      mockStatement.first.mockResolvedValueOnce({ count: 5 })

      const result = await notificationService.getUnreadCount('user-123')

      expect(result).toBe(5)
      expect(mockDB.prepare).toHaveBeenCalledWith(expect.stringContaining('SELECT COUNT(*) as count'))
      expect(mockDB.prepare).toHaveBeenCalledWith(expect.stringContaining('WHERE user_id = ? AND is_read = 0'))
      expect(mockStatement.bind).toHaveBeenCalledWith('user-123')
    })

    test('should return 0 when no result', async () => {
      mockStatement.first.mockResolvedValueOnce(null)

      const result = await notificationService.getUnreadCount('user-123')

      expect(result).toBe(0)
    })
  })

  describe('getUserPreferences', () => {
    test('should return user preferences for specific type', async () => {
      const mockPreferences = {
        id: 'pref-1',
        user_id: 'user-123',
        notification_type: 'workflow_assigned',
        email_enabled: 1,
        in_app_enabled: 1,
        digest_frequency: 'immediate'
      }

      mockStatement.first.mockResolvedValueOnce(mockPreferences)

      const result = await notificationService.getUserPreferences('user-123', 'workflow_assigned')

      expect(result).toEqual(mockPreferences)
      expect(mockStatement.bind).toHaveBeenCalledWith('user-123', 'workflow_assigned')
    })

    test('should return preferences for all types when type not specified', async () => {
      await notificationService.getUserPreferences('user-123')

      expect(mockStatement.bind).toHaveBeenCalledWith('user-123')
    })
  })

  describe('updateUserPreferences', () => {
    test('should successfully update notification preferences', async () => {
      const result = await notificationService.updateUserPreferences(
        'user-123',
        'workflow_assigned',
        true,
        false,
        'daily'
      )

      expect(result).toBe(true)
      expect(mockDB.prepare).toHaveBeenCalledWith(expect.stringContaining('INSERT OR REPLACE INTO notification_preferences'))
      expect(mockStatement.bind).toHaveBeenCalledWith(
        'user-123',
        'workflow_assigned',
        1,
        0,
        'daily'
      )
    })

    test('should handle update errors', async () => {
      mockStatement.run.mockRejectedValueOnce(new Error('Database error'))

      const result = await notificationService.updateUserPreferences(
        'user-123',
        'workflow_assigned',
        true,
        true,
        'immediate'
      )

      expect(result).toBe(false)
    })
  })

  describe('getAllUserPreferences', () => {
    test('should return all preferences for user', async () => {
      const mockPreferences = [
        {
          notification_type: 'workflow_assigned',
          email_enabled: 1,
          in_app_enabled: 1,
          digest_frequency: 'immediate'
        },
        {
          notification_type: 'content_scheduled',
          email_enabled: 0,
          in_app_enabled: 1,
          digest_frequency: 'daily'
        }
      ]

      mockStatement.all.mockResolvedValueOnce({ results: mockPreferences })

      const result = await notificationService.getAllUserPreferences('user-123')

      expect(result).toEqual(mockPreferences)
      expect(mockDB.prepare).toHaveBeenCalledWith(expect.stringContaining('WHERE user_id = ?'))
      expect(mockStatement.bind).toHaveBeenCalledWith('user-123')
    })
  })

  describe('Bulk Notification Methods', () => {
    test('should notify workflow transition', async () => {
      // Mock content details
      mockStatement.first.mockResolvedValueOnce({
        title: 'Test Article',
        slug: 'test-article',
        collection_name: 'Articles'
      })

      // Mock users to notify
      mockStatement.all.mockResolvedValueOnce({
        results: [
          { id: 'user-456' },
          { id: 'user-789' }
        ]
      })

      await notificationService.notifyWorkflowTransition(
        'content-123',
        'draft',
        'review',
        'user-123'
      )

      // Should create notifications for each user
      expect(mockStatement.run).toHaveBeenCalledTimes(2)
    })

    test('should notify content scheduled', async () => {
      mockStatement.first.mockResolvedValueOnce({
        title: 'Test Article',
        slug: 'test-article',
        collection_name: 'Articles'
      })

      await notificationService.notifyContentScheduled(
        'content-123',
        'publish',
        '2024-12-31T23:59:00Z',
        'user-123'
      )

      expect(mockStatement.run).toHaveBeenCalledTimes(1)
    })

    test('should notify content assigned', async () => {
      // Mock content details
      mockStatement.first
        .mockResolvedValueOnce({
          title: 'Test Article',
          slug: 'test-article',
          collection_name: 'Articles'
        })
        .mockResolvedValueOnce({

        })

      await notificationService.notifyContentAssigned(
        'content-123',
        'user-456',
        'user-123',
        '2024-12-31'
      )

      expect(mockStatement.run).toHaveBeenCalledTimes(1)
    })
  })

  describe('sendDigestNotifications', () => {
    test('should send daily digest notifications', async () => {
      // Mock users with daily digest preference
      mockStatement.all
        .mockResolvedValueOnce({
          results: [
            { user_id: 'user-1', email: 'user1@example.com' },
            { user_id: 'user-2', email: 'user2@example.com' }
          ]
        })
        .mockResolvedValueOnce({
          results: [
            { id: 'notif-1', title: 'Test Notification 1' }
          ]
        })
        .mockResolvedValueOnce({
          results: [] // No notifications for user-2
        })

      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {})

      const result = await notificationService.sendDigestNotifications('daily')

      expect(result).toBe(1) // Only user-1 had notifications
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('Sending daily digest to user1@example.com with 1 notifications')
      )

      consoleSpy.mockRestore()
    })

    test('should handle different digest frequencies', async () => {
      mockStatement.all.mockResolvedValueOnce({ results: [] })

      const result = await notificationService.sendDigestNotifications('weekly')

      expect(result).toBe(0)
      expect(mockStatement.bind).toHaveBeenCalledWith('weekly')
    })
  })

  describe('cleanupOldNotifications', () => {
    test('should delete old notifications', async () => {
      mockStatement.run.mockResolvedValueOnce({ changes: 15 })

      const result = await notificationService.cleanupOldNotifications(30)

      expect(result).toBe(15)
      expect(mockDB.prepare).toHaveBeenCalledWith(expect.stringContaining("created_at < datetime('now', '-30 days')"))
    })

    test('should use default retention period', async () => {
      mockStatement.run.mockResolvedValueOnce({ changes: 10 })

      const result = await notificationService.cleanupOldNotifications()

      expect(result).toBe(10)
      expect(mockDB.prepare).toHaveBeenCalledWith(expect.stringContaining("'-30 days'"))
    })
  })
})