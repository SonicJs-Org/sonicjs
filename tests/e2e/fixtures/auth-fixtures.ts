// Shared unchanged OTP and magic-link address generation.
export function uniqueEmail(prefix: string): string {
  return `${prefix}.${Date.now()}.${Math.random().toString(36).substring(7)}@test.sonicjs.com`;
}
