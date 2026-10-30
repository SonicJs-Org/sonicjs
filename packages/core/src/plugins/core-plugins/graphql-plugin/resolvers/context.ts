import type { D1Database } from '@cloudflare/workers-types'
import type { PrincipalRef } from '../../../../schemas/document'

export interface GraphqlResolverContext {
  db: D1Database
  tenantId: string
  principalSet: PrincipalRef[]
  userId: string | null
}
