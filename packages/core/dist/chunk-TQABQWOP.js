// src/utils/sanitize.ts
function escapeHtml(text) {
  if (typeof text !== "string") {
    return "";
  }
  const map = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;"
  };
  return text.replace(/[&<>"']/g, (char) => map[char] || char);
}
function sanitizeInput(input) {
  if (!input) {
    return "";
  }
  return escapeHtml(String(input).trim());
}
function sanitizeRichText(html) {
  if (typeof html !== "string") {
    return "";
  }
  return html.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, "").replace(/\s+on\w+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, "").replace(/(href|src|action)\s*=\s*"javascript:[^"]*"/gi, '$1=""').replace(/(href|src|action)\s*=\s*'javascript:[^']*'/gi, "$1=''");
}
function sanitizeObject(obj, fields) {
  const sanitized = { ...obj };
  for (const field of fields) {
    if (typeof obj[field] === "string") {
      sanitized[field] = sanitizeInput(obj[field]);
    }
  }
  return sanitized;
}

export { escapeHtml, sanitizeInput, sanitizeObject, sanitizeRichText };
//# sourceMappingURL=chunk-TQABQWOP.js.map
//# sourceMappingURL=chunk-TQABQWOP.js.map