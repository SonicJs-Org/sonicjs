/**
 * RFC 6238 TOTP over WebCrypto — test-only.
 *
 * Exists so tests can compute a code Better Auth will actually accept, which is the difference
 * between asserting that wrong inputs are rejected and asserting that the real enrolment flow
 * works. There is no OTP dependency in this repo and this is ~40 lines, so it stays inline.
 *
 * Deliberately shared between two very different tiers:
 *   - `__tests__/services/two-factor-roundtrip.test.ts` drives real BA over real SQLite and proves
 *     the codes this produces are accepted by `createOTP(...).verify()`.
 *   - `tests/e2e/106-two-factor-auth.spec.ts` imports the SAME function for the browser round trip.
 *
 * One implementation, and the cheap tier verifies it. Two copies would let the E2E copy drift and
 * fail in CI for a reason that looks like a product bug.
 *
 * ── The trap this encodes ──
 * `secret` in an `otpauth://` URI is **base32 of the raw secret**, while BA HMACs the raw secret
 * bytes. So the URI value MUST be base32-decoded before use. Passing it through verbatim yields a
 * perfectly well-formed six-digit code that is simply wrong, and BA rejects it with the same 401 a
 * genuine mismatch produces — which reads as "TOTP is broken" rather than "the test is wrong".
 * {@link totpFromOtpauthUri} exists so no caller has to remember this.
 */

/** Default TOTP parameters — match Better Auth's twoFactor defaults (SHA-1, 6 digits, 30s). */
const DIGITS = 6
const PERIOD_SECONDS = 30

/**
 * Compute the current TOTP code for a **base32-encoded** secret, as it appears in an `otpauth://`
 * URI's `secret` parameter.
 *
 * @param base32Secret the `secret` query parameter, base32, padding optional
 * @param atMs         evaluate at this instant instead of now (for step-boundary tests)
 */
export async function totp(base32Secret: string, atMs: number = Date.now()): Promise<string> {
  return hotp(base32Decode(base32Secret), Math.floor(atMs / 1000 / PERIOD_SECONDS))
}

/** Pull `secret` out of an `otpauth://` URI and compute its current code. */
export async function totpFromOtpauthUri(uri: string, atMs: number = Date.now()): Promise<string> {
  const secret = new URL(uri).searchParams.get('secret')
  if (!secret) throw new Error(`otpauth URI has no secret parameter: ${uri}`)
  return totp(secret, atMs)
}

/** HMAC-SHA1 based one-time password (RFC 4226) over an 8-byte big-endian counter. */
async function hotp(key: Uint8Array, counter: number): Promise<string> {
  const msg = new Uint8Array(8)
  for (let i = 7, c = counter; i >= 0; i--, c = Math.floor(c / 256)) msg[i] = c % 256
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key as unknown as ArrayBuffer,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign'],
  )
  const mac = new Uint8Array(
    await crypto.subtle.sign('HMAC', cryptoKey, msg as unknown as ArrayBuffer),
  )
  // Dynamic truncation: low nibble of the last byte selects the 4-byte window.
  const offset = mac[mac.length - 1]! & 0x0f
  const bin =
    ((mac[offset]! & 0x7f) << 24) |
    (mac[offset + 1]! << 16) |
    (mac[offset + 2]! << 8) |
    mac[offset + 3]!
  return String(bin % 10 ** DIGITS).padStart(DIGITS, '0')
}

/** RFC 4648 base32 decode, padding optional, non-alphabet characters ignored. */
export function base32Decode(input: string): Uint8Array {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const clean = input.replace(/=+$/, '').toUpperCase()
  let bits = 0
  let value = 0
  const out: number[] = []
  for (const ch of clean) {
    const idx = alphabet.indexOf(ch)
    if (idx === -1) continue
    value = (value << 5) | idx
    bits += 5
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff)
      bits -= 8
    }
  }
  return new Uint8Array(out)
}
