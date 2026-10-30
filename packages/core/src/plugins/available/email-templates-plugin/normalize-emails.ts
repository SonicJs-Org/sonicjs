/**
 * Email Normalization Script
 * 
 * This script normalizes all existing email addresses in the database to lowercase.
 * Run this after deploying the email normalization changes to ensure existing
 * users can still log in with case-insensitive emails.
 */

export async function normalizeExistingEmails(db: D1Database): Promise<void> {
  try {
    console.log('Starting email normalization...')
    
    // Get all users with potentially non-lowercase emails
    const users = await db.prepare('SELECT id, email FROM auth_user WHERE email != LOWER(email)').all()
    
    if (!users.results || users.results.length === 0) {
      console.log('No emails to normalize - all emails are already lowercase')
      return
    }
    
    console.log(`Found ${users.results.length} emails that need normalization`)
    
    // Update each user's email to lowercase
    for (const user of users.results) {
      const normalizedEmail = (user.email as string).toLowerCase()
      
      try {
        await db.prepare('UPDATE auth_user SET email = ?, updated_at = ? WHERE id = ?')
          .bind(normalizedEmail, Date.now(), user.id)
          .run()
        
        console.log(`Normalized email: ${user.email} -> ${normalizedEmail}`)
      } catch (error) {
        console.error(`Failed to normalize email for user ${user.id}:`, error)
      }
    }
    
    console.log('Email normalization completed successfully')
  } catch (error) {
    console.error('Email normalization failed:', error)
    throw error
  }
}

// Export a standalone function that can be called from an API endpoint
export async function createEmailNormalizationEndpoint() {
  return async (db: D1Database) => {
    await normalizeExistingEmails(db)
    return {
      message: 'Email normalization completed',
      timestamp: new Date().toISOString()
    }
  }
}