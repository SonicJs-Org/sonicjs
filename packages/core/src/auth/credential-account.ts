/**
 * Better Auth's password sign-in reads the hash from `auth_account.password` (provider
 * 'credential'), not from `auth_user.password_hash`. Every SonicJS path that sets a password
 * must write both, or the new password fails at sign-in while the old one keeps working.
 *
 * Returns statements for the caller's `db.batch([...])`, alongside its `auth_user` write:
 * update the user's credential row if one exists (Better Auth's own sign-up gives it a random
 * id), otherwise insert one with the `cred-${userId}` id the other SonicJS paths use.
 */
import type { D1Database, D1PreparedStatement } from '@cloudflare/workers-types'

export function credentialPasswordStatements(
  db: D1Database,
  userId: string,
  passwordHash: string,
): D1PreparedStatement[] {
  const nowSec = Math.floor(Date.now() / 1000)
  return [
    db.prepare(
      `UPDATE auth_account SET password = ?, updated_at = ? WHERE user_id = ? AND provider_id = 'credential'`,
    ).bind(passwordHash, nowSec, userId),
    db.prepare(
      `INSERT INTO auth_account (id, user_id, account_id, provider_id, password, created_at, updated_at)
       SELECT ?, ?, ?, 'credential', ?, ?, ?
       WHERE NOT EXISTS (SELECT 1 FROM auth_account WHERE user_id = ? AND provider_id = 'credential')`,
    ).bind(`cred-${userId}`, userId, userId, passwordHash, nowSec, nowSec, userId),
  ]
}
