// src/utils/metrics.ts
var MetricsTracker = class {
  requests = [];
  windowSize = 1e4;
  // 10 seconds window
  /**
   * Record a new request
   */
  recordRequest() {
    const now = Date.now();
    this.requests.push({ timestamp: now });
    this.cleanup(now);
  }
  /**
   * Clean up old requests outside the window
   */
  cleanup(now) {
    const cutoff = now - this.windowSize;
    this.requests = this.requests.filter((req) => req.timestamp > cutoff);
  }
  /**
   * Get current requests per second
   */
  getRequestsPerSecond() {
    const now = Date.now();
    this.cleanup(now);
    if (this.requests.length === 0) {
      return 0;
    }
    const oneSecondAgo = now - 1e3;
    const recentRequests = this.requests.filter((req) => req.timestamp > oneSecondAgo);
    return recentRequests.length;
  }
  /**
   * Get total requests in the current window
   */
  getTotalRequests() {
    const now = Date.now();
    this.cleanup(now);
    return this.requests.length;
  }
  /**
   * Get average requests per second over the window
   */
  getAverageRPS() {
    const now = Date.now();
    this.cleanup(now);
    if (this.requests.length === 0) {
      return 0;
    }
    const windowSeconds = this.windowSize / 1e3;
    return this.requests.length / windowSeconds;
  }
};
var metricsTracker = new MetricsTracker();

export { metricsTracker };
//# sourceMappingURL=chunk-FICTAGD4.js.map
//# sourceMappingURL=chunk-FICTAGD4.js.map