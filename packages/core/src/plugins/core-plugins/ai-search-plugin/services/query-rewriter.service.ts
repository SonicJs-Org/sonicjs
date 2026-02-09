/**
 * Query Rewriter Service
 *
 * Uses Workers AI LLM to expand vague or short queries with
 * relevant search terms before dispatching to the search pipeline.
 *
 * Off by default (query_rewriting_enabled setting). Only activates when:
 * - AI binding is available
 * - Setting is enabled
 * - Query is at least 15 characters
 * - Mode is 'hybrid'
 */

const REWRITE_SYSTEM_PROMPT = `You are a search query optimizer. Given a user's search query, rewrite it to improve search results by:
- Adding relevant synonyms or related terms
- Expanding abbreviations
- Keeping the core intent intact

Rules:
- Return ONLY the rewritten query, nothing else
- Keep it concise (under 100 characters)
- Do not add explanations or formatting
- Do not wrap in quotes
- If the query is already precise, return it unchanged`

export class QueryRewriterService {
  constructor(private ai: any) {}

  /**
   * Rewrite a query using LLM expansion
   * Returns original query on any failure
   */
  async rewrite(originalQuery: string): Promise<string> {
    try {
      const response = await this.ai.run(
        '@cf/meta/llama-3.1-8b-instruct-fp8-fast',
        {
          messages: [
            { role: 'system', content: REWRITE_SYSTEM_PROMPT },
            { role: 'user', content: originalQuery }
          ],
          max_tokens: 100
        }
      )

      const rewritten = response.response?.trim()

      // Validation: reject if empty
      if (!rewritten) return originalQuery

      // Reject if too long (>3x original or >200 chars)
      if (rewritten.length > originalQuery.length * 3) return originalQuery
      if (rewritten.length > 200) return originalQuery

      // Reject multi-line responses (likely explanations, not queries)
      if (rewritten.includes('\n')) return originalQuery

      return rewritten
    } catch (error) {
      console.error('[QueryRewriter] LLM call failed, using original query:', error)
      return originalQuery
    }
  }

  /**
   * Check if a query should be rewritten
   * Short/precise queries don't benefit from rewriting
   */
  static shouldRewrite(query: string): boolean {
    return query.length >= 15
  }
}
