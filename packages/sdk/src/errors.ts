export class SonicError extends Error {
  readonly status: number
  readonly code: string
  readonly details?: unknown

  constructor(args: { status: number; code: string; message: string; details?: unknown }) {
    super(args.message)
    this.name = 'SonicError'
    this.status = args.status
    this.code = args.code
    this.details = args.details
  }
}
