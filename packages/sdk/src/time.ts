/** Convert documents API timestamp (seconds) to Date. */
export const secondsToDate = (n: number): Date => new Date(n * 1000)

/** Convert content API timestamp (milliseconds) to Date. */
export const msToDate = (n: number): Date => new Date(n)
