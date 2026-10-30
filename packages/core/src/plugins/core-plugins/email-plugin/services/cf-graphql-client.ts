/**
 * CfGraphqlClient — typed wrapper for the Cloudflare GraphQL Analytics API,
 * specifically the `emailSendingAdaptive` dataset used by the reconciliation
 * cron (hub spec §6.3 + §8 + §10.2).
 *
 * The dataset is ZONE-scoped, NOT account-scoped. The hub spec originally
 * specified `accounts.emailSendingAdaptive`, but that field does not exist
 * in CF's GraphQL schema — empirical introspection (2026-05-22) confirms
 * the only outbound-email dataset is `zones.emailSendingAdaptive`.
 * See issue #701 final resolution comment.
 *
 * Constructor takes the zone ID + API token (consumed by callers from
 * `env.CF_ZONE_ID` + `env.EMAIL_API_TOKEN` via the ambient
 * `CloudflareBindings` declaration). Both are optional bindings on
 * `CloudflareBindings` — the constructor throws `EmailValidationError` if
 * either is missing, and the cron-tick handler catches and logs + skips
 * gracefully (defensive credential check per §0 trigger 12).
 *
 * The single `queryEmailSends({ startSeconds, endSeconds })` method returns
 * typed rows. The query targets the per-event variant
 * (`emailSendingAdaptive`) — higher cardinality than the aggregate
 * variant but provides the per-message `messageId` + `status` + `errorCause`
 * triplet the reconciliation cron needs.
 */
import { EmailValidationError } from '../errors'
import type { GraphQLActivityLogRow } from '../types'

interface GraphQLResponseEnvelope {
  data?: {
    viewer?: {
      zones?: Array<{
        emailSendingAdaptive?: GraphQLActivityLogRow[]
      }>
    }
  }
  errors?: Array<{ message: string }>
}

export interface QueryEmailSendsInput {
  startSeconds: number
  endSeconds: number
  limit?: number
}

const GRAPHQL_ENDPOINT = 'https://api.cloudflare.com/client/v4/graphql'

const RECONCILIATION_QUERY = `
query EmailReconciliation($zoneTag: String!, $start: Time!, $end: Time!, $limit: Int!) {
  viewer {
    zones(filter: { zoneTag: $zoneTag }) {
      emailSendingAdaptive(
        filter: { datetime_geq: $start, datetime_leq: $end }
        limit: $limit
        orderBy: [datetime_DESC]
      ) {
        messageId
        status
        errorCause
        datetime
      }
    }
  }
}
`

export class CfGraphqlClient {
  constructor(
    private readonly zoneId: string,
    private readonly apiToken: string,
    // Workers' globalThis.fetch must be invoked with globalThis as `this`.
    // Storing the bare reference as a property and calling `this.fetchImpl(...)`
    // throws "Illegal invocation" (V8 enforces the receiver). Default to an
    // arrow that calls the global fetch bare — preserves the closure's binding
    // (globalThis at module-load time). Test injection still works because an
    // injected mock function isn't bound to anything. Refs #701.
    private readonly fetchImpl: typeof fetch = (input, init) => fetch(input, init),
  ) {
    if (!zoneId) {
      throw new EmailValidationError('zoneId', 'CF_ZONE_ID is required for GraphQL queries')
    }
    if (!apiToken) {
      throw new EmailValidationError('apiToken', 'EMAIL_API_TOKEN is required for GraphQL queries')
    }
  }

  async queryEmailSends(input: QueryEmailSendsInput): Promise<readonly GraphQLActivityLogRow[]> {
    const startIso = new Date(input.startSeconds * 1000).toISOString()
    const endIso = new Date(input.endSeconds * 1000).toISOString()
    const limit = input.limit ?? 1000

    const res = await this.fetchImpl(GRAPHQL_ENDPOINT, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.apiToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        query: RECONCILIATION_QUERY,
        variables: {
          zoneTag: this.zoneId,
          start: startIso,
          end: endIso,
          limit,
        },
      }),
    })

    if (!res.ok) {
      throw new Error(`CF GraphQL request failed: HTTP ${res.status} ${res.statusText}`)
    }

    const body = (await res.json()) as GraphQLResponseEnvelope

    if (body.errors && body.errors.length > 0) {
      const messages = body.errors.map(e => e.message).join('; ')
      throw new Error(`CF GraphQL response errors: ${messages}`)
    }

    const rows = body.data?.viewer?.zones?.[0]?.emailSendingAdaptive

    // Observability for issue #701: when the query parses successfully but returns
    // no rows, log the response envelope shape (NOT the row data) so we can tell
    // whether the dataset is empty for the requested window vs the schema path is
    // wrong. Remove once reconciliation is verified working end-to-end.
    if (!rows || rows.length === 0) {
      const zonesCount = body.data?.viewer?.zones?.length ?? 0
      const hasZonesArray = Array.isArray(body.data?.viewer?.zones)
      const hasAdaptiveField = body.data?.viewer?.zones?.[0]
        ? 'emailSendingAdaptive' in body.data.viewer.zones[0]
        : false
      console.log('[email-plugin] CfGraphqlClient.queryEmailSends: 0 rows', {
        startSeconds: input.startSeconds,
        endSeconds: input.endSeconds,
        windowSeconds: input.endSeconds - input.startSeconds,
        hasDataField: Boolean(body.data),
        hasViewerField: Boolean(body.data?.viewer),
        hasZonesArray,
        zonesCount,
        hasAdaptiveField,
        rowsIsNull: rows === undefined || rows === null,
      })
    }

    return rows ?? []
  }
}
