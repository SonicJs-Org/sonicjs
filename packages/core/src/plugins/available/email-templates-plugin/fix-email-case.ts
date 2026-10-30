#!/usr/bin/env tsx

/**
 * Emergency Email Case Fix Script
 * 
 * This script directly updates the local D1 database to normalize email cases.
 * Run this when you can't login due to email case sensitivity issues.
 */

import { createClient } from '@libsql/client'
import path from 'path'
import fs from 'fs'

async function fixEmailCases() {
  try {
    console.log('🔧 Starting email case normalization...')
    
    // Find the local D1 database file
    const dbPath = path.join(process.cwd(), '.wrangler', 'state', 'v3', 'd1', 'miniflare-D1DatabaseObject')
    
    // Check if database file exists
    if (!fs.existsSync(dbPath)) {
      console.error('❌ Local D1 database not found. Make sure you have run the project locally first.')
      console.log('Expected location:', dbPath)
      return
    }
    
    // Connect to the local SQLite database
    const db = createClient({
      url: `file:${dbPath}/sonicjs-dev.sqlite`
    })
    
    console.log('📂 Connected to local database')
    
    // Get all users with potentially mixed-case emails
    const users = await db.execute('SELECT id, email FROM auth_user')
    
    if (!users.rows || users.rows.length === 0) {
      console.log('ℹ️  No users found in database')
      return
    }
    
    console.log(`👥 Found ${users.rows.length} users`)
    
    let normalizedCount = 0
    
    // Update each user's email to lowercase
    for (const user of users.rows) {
      const currentEmail = user.email as string
      const normalizedEmail = currentEmail.toLowerCase()
      
      if (currentEmail !== normalizedEmail) {
        try {
          await db.execute(
            'UPDATE auth_user SET email = ?, updated_at = ? WHERE id = ?',
            [normalizedEmail, Date.now(), user.id || '']
          )
          
          console.log(`✅ Normalized: ${currentEmail} → ${normalizedEmail}`)
          normalizedCount++
        } catch (error) {
          console.error(`❌ Failed to normalize email for user ${user.id}:`, error)
        }
      } else {
        console.log(`✓ Already normalized: ${currentEmail}`)
      }
    }
    
    console.log(`\n🎉 Email normalization completed!`)
    console.log(`📊 Normalized ${normalizedCount} email(s)`)
    
    if (normalizedCount > 0) {
      console.log('\n💡 You should now be able to login with lowercase email addresses')
    }
    
  } catch (error) {
    console.error('💥 Email normalization failed:', error)
    throw error
  }
}

// Run the fix
fixEmailCases().catch(console.error)