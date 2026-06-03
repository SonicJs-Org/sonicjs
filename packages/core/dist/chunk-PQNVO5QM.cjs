'use strict';

var zod = require('zod');

// src/services/auth-validation.ts
async function isRegistrationEnabled(db) {
  try {
    const plugin = await db.prepare("SELECT settings FROM plugins WHERE id = ?").bind("core-auth").first();
    if (plugin?.settings) {
      const settings = JSON.parse(plugin.settings);
      const enabled = settings?.registration?.enabled;
      return enabled !== false && enabled !== 0;
    }
    return true;
  } catch {
    return true;
  }
}
async function isFirstUserRegistration(db) {
  try {
    const result = await db.prepare("SELECT COUNT(*) as count FROM users").first();
    return result?.count === 0;
  } catch {
    return false;
  }
}
var baseRegistrationSchema = zod.z.object({
  email: zod.z.string().email("Valid email is required"),
  password: zod.z.string().min(8, "Password must be at least 8 characters"),
  username: zod.z.string().min(3, "Username must be at least 3 characters").optional(),
  firstName: zod.z.string().min(1, "First name is required").optional(),
  lastName: zod.z.string().min(1, "Last name is required").optional()
});
var authValidationService = {
  /**
   * Build registration schema dynamically based on auth settings
   * For now, returns a static schema with standard fields
   */
  async buildRegistrationSchema(_db) {
    return baseRegistrationSchema;
  },
  /**
   * Generate default values for optional fields
   */
  generateDefaultValue(field, data) {
    switch (field) {
      case "username":
        return data.email ? data.email.split("@")[0] : `user${Date.now()}`;
      case "firstName":
        return "User";
      case "lastName":
        return data.email ? data.email.split("@")[0] : "Account";
      default:
        return "";
    }
  }
};

exports.authValidationService = authValidationService;
exports.isFirstUserRegistration = isFirstUserRegistration;
exports.isRegistrationEnabled = isRegistrationEnabled;
//# sourceMappingURL=chunk-PQNVO5QM.cjs.map
//# sourceMappingURL=chunk-PQNVO5QM.cjs.map