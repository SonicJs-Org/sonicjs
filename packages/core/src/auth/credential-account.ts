/**
 * Better Auth signs in against `auth_account.password` (provider 'credential'),
 * not `auth_user.password_hash`. Every path that sets a password must write both.
 *
 * Returns statements for the caller's `db.batch([...])`.
 */
export function syncCredentialPassword(
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
