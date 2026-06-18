/**
 * Email plugin error classes (PR-E Phase B, 2026-05-13).
 *
 * Validation errors thrown by `EmailServiceImpl.send` when input shape is
 * bad — programmer or configuration errors:
 *   - Missing `html` AND `text` on the options
 *   - Malformed email address on `to` / `from` / `cc` / `bcc`
 *   - Missing `purpose` (required per Decision 6 + migration 106
 *     `purpose TEXT NOT NULL`)
 *   - Missing `from` when caller omitted it AND D1 settings have no
 *     `fromEmail` (configuration error)
 *
 * Pattern matches `packages/core/src/plugins/sdk/register-plugins.ts:83`
 * (`SonicCapabilityError`) and `:103` (`SonicAdapterError`) — `extends Error`
 * directly with a `name` field set to the class name. **There is NO
 * `SonicError` base class** in this codebase, despite earlier scope-memo
 * text suggesting one; the correction was confirmed in the design doc
 * §3 Decision 6 deep-review correction on 2026-05-13.
 *
 * Hono's `app.onError()` maps `EmailValidationError` to a 400 response
 * (caller error, not a 5xx). Non-Hono callers (e.g., the OTP login
 * critical-path send, plugin hook handlers) let it bubble — those code
 * paths are themselves bug paths if validation fails (the inputs come
 * from the application, not the user).
 *
 * Transport-side failures (CF Email Service rejected the send) are NOT
 * thrown — they return as `SendEmailResult { status: 'failed_at_send',
 * errorCode, errorMessage, logId }`. The caller decides retry vs. log vs.
 * surface. Validation errors throw because they're never recoverable at
 * the call site.
 */
export class EmailValidationError extends Error {
  readonly code = 'EMAIL_VALIDATION_FAILED'
  constructor(
    public readonly field: string,
    public readonly reason: string,
  ) {
    super(`EmailValidationError: ${field} - ${reason}`)
    this.name = 'EmailValidationError'
  }
}
