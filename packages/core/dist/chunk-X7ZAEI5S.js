// src/utils/telemetry-config.ts
function safeGetEnv(key) {
  try {
    if (typeof process !== "undefined" && process.env) {
      return process.env[key];
    }
  } catch {
  }
  return void 0;
}
function getDefaultTelemetryConfig() {
  return {
    enabled: true,
    host: safeGetEnv("SONICJS_TELEMETRY_ENDPOINT") || "https://stats.sonicjs.com",
    debug: safeGetEnv("NODE_ENV") === "development"
  };
}
function isTelemetryEnabled() {
  const telemetryEnv = safeGetEnv("SONICJS_TELEMETRY");
  if (telemetryEnv === "false" || telemetryEnv === "0" || telemetryEnv === "disabled") {
    return false;
  }
  const doNotTrack = safeGetEnv("DO_NOT_TRACK");
  if (doNotTrack === "1" || doNotTrack === "true") {
    return false;
  }
  return true;
}
function getTelemetryConfig() {
  return {
    ...getDefaultTelemetryConfig(),
    enabled: isTelemetryEnabled()
  };
}
function shouldSkipEvent(eventName, sampleRate = 1) {
  if (sampleRate >= 1) return false;
  if (sampleRate <= 0) return true;
  let hash = 0;
  for (let i = 0; i < eventName.length; i++) {
    hash = (hash << 5) - hash + eventName.charCodeAt(i);
    hash = hash & hash;
  }
  return Math.abs(hash % 100) / 100 > sampleRate;
}

// src/utils/telemetry-id.ts
function generateInstallationId() {
  return crypto.randomUUID();
}
function generateProjectId(projectName) {
  let hash = 0;
  for (let i = 0; i < projectName.length; i++) {
    const char = projectName.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash = hash & hash;
  }
  return `proj_${Math.abs(hash).toString(36)}`;
}
function sanitizeErrorMessage(error) {
  const message = typeof error === "string" ? error : error.message;
  const [errorTypeRaw] = message.split(":");
  const errorType = (errorTypeRaw || message).trim();
  const sanitized = errorType.replace(/\/Users\/[^/]+/g, "/Users/***").replace(/\/home\/[^/]+/g, "/home/***").replace(/C:\\Users\\[^\\]+/g, "C:\\Users\\***").replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, "***@***.***");
  return sanitized;
}
function sanitizeRoute(route) {
  return route.replace(/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/gi, ":id").replace(/\/\d+/g, "/:id").replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, ":email");
}

export { generateInstallationId, generateProjectId, getDefaultTelemetryConfig, getTelemetryConfig, isTelemetryEnabled, sanitizeErrorMessage, sanitizeRoute, shouldSkipEvent };
//# sourceMappingURL=chunk-X7ZAEI5S.js.map
//# sourceMappingURL=chunk-X7ZAEI5S.js.map