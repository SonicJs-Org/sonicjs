'use strict';

var hono = require('hono');
var zod = require('zod');

// src/plugins/sdk/plugin-builder.ts
var PluginBuilder = class _PluginBuilder {
  plugin;
  constructor(options) {
    this.plugin = {
      name: options.name,
      version: options.version,
      description: options.description,
      author: options.author,
      dependencies: options.dependencies,
      routes: [],
      middleware: [],
      models: [],
      services: [],
      adminPages: [],
      adminComponents: [],
      menuItems: [],
      hooks: []
    };
  }
  /**
   * Create a new plugin builder
   */
  static create(options) {
    return new _PluginBuilder(options);
  }
  /**
   * Add metadata to the plugin
   */
  metadata(metadata) {
    Object.assign(this.plugin, metadata);
    return this;
  }
  /**
   * Add routes to plugin
   */
  addRoutes(routes) {
    this.plugin.routes = [...this.plugin.routes || [], ...routes];
    return this;
  }
  /**
   * Add a single route to plugin
   */
  addRoute(path, handler, options) {
    const route = {
      path,
      handler,
      ...options
    };
    this.plugin.routes = [...this.plugin.routes || [], route];
    return this;
  }
  /**
   * Add middleware to plugin
   */
  addMiddleware(middleware) {
    this.plugin.middleware = [...this.plugin.middleware || [], ...middleware];
    return this;
  }
  /**
   * Add a single middleware to plugin
   */
  addSingleMiddleware(name, handler, options) {
    const middleware = {
      name,
      handler,
      ...options
    };
    this.plugin.middleware = [...this.plugin.middleware || [], middleware];
    return this;
  }
  /**
   * Add models to plugin
   */
  addModels(models) {
    this.plugin.models = [...this.plugin.models || [], ...models];
    return this;
  }
  /**
   * Add a single model to plugin
   */
  addModel(name, options) {
    const model = {
      name,
      ...options
    };
    this.plugin.models = [...this.plugin.models || [], model];
    return this;
  }
  /**
   * Add services to plugin
   */
  addServices(services) {
    this.plugin.services = [...this.plugin.services || [], ...services];
    return this;
  }
  /**
   * Add a single service to plugin
   */
  addService(name, implementation, options) {
    const service = {
      name,
      implementation,
      ...options
    };
    this.plugin.services = [...this.plugin.services || [], service];
    return this;
  }
  /**
   * Add admin pages to plugin
   */
  addAdminPages(pages) {
    this.plugin.adminPages = [...this.plugin.adminPages || [], ...pages];
    return this;
  }
  /**
   * Add a single admin page to plugin
   */
  addAdminPage(path, title, component, options) {
    const page = {
      path,
      title,
      component,
      ...options
    };
    this.plugin.adminPages = [...this.plugin.adminPages || [], page];
    return this;
  }
  /**
   * Add admin components to plugin
   */
  addComponents(components) {
    this.plugin.adminComponents = [...this.plugin.adminComponents || [], ...components];
    return this;
  }
  /**
   * Add a single admin component to plugin
   */
  addComponent(name, template, options) {
    const component = {
      name,
      template,
      ...options
    };
    this.plugin.adminComponents = [...this.plugin.adminComponents || [], component];
    return this;
  }
  /**
   * Add menu items to plugin
   */
  addMenuItems(items) {
    this.plugin.menuItems = [...this.plugin.menuItems || [], ...items];
    return this;
  }
  /**
   * Add a single menu item to plugin
   */
  addMenuItem(label, path, options) {
    const menuItem = {
      label,
      path,
      ...options
    };
    this.plugin.menuItems = [...this.plugin.menuItems || [], menuItem];
    return this;
  }
  /**
   * Add hooks to plugin
   */
  addHooks(hooks) {
    this.plugin.hooks = [...this.plugin.hooks || [], ...hooks];
    return this;
  }
  /**
   * Add a single hook to plugin
   */
  addHook(name, handler, options) {
    const hook = {
      name,
      handler,
      ...options
    };
    this.plugin.hooks = [...this.plugin.hooks || [], hook];
    return this;
  }
  /**
   * Add lifecycle hooks
   */
  lifecycle(hooks) {
    Object.assign(this.plugin, hooks);
    return this;
  }
  /**
   * Build the plugin
   */
  build() {
    if (!this.plugin.name || !this.plugin.version) {
      throw new Error("Plugin name and version are required");
    }
    return this.plugin;
  }
};
var PluginHelpers = class {
  /**
   * Create a REST API route for a model.
   *
   * @experimental This method returns placeholder routes. Full implementation coming soon.
   */
  static createModelAPI(modelName, options) {
    const app = new hono.Hono();
    options?.basePath || `/${modelName.toLowerCase()}`;
    app.get("/", async (c) => {
      return c.json({ message: `List ${modelName} items` });
    });
    app.get("/:id", async (c) => {
      const id = c.req.param("id");
      return c.json({ message: `Get ${modelName} with ID: ${id}` });
    });
    app.post("/", async (c) => {
      return c.json({ message: `Create new ${modelName}` });
    });
    app.put("/:id", async (c) => {
      const id = c.req.param("id");
      return c.json({ message: `Update ${modelName} with ID: ${id}` });
    });
    app.delete("/:id", async (c) => {
      const id = c.req.param("id");
      return c.json({ message: `Delete ${modelName} with ID: ${id}` });
    });
    return app;
  }
  /**
   * Create an admin CRUD interface for a model.
   *
   * @experimental This method generates basic admin page structures. Full implementation coming soon.
   */
  static createAdminInterface(modelName, options) {
    const basePath = `/admin/${modelName.toLowerCase()}`;
    const displayName = modelName.charAt(0).toUpperCase() + modelName.slice(1);
    const pages = [
      {
        path: basePath,
        title: `${displayName} List`,
        component: `${modelName}List`,
        permissions: options?.permissions,
        icon: options?.icon
      },
      {
        path: `${basePath}/new`,
        title: `New ${displayName}`,
        component: `${modelName}Form`,
        permissions: options?.permissions
      },
      {
        path: `${basePath}/:id`,
        title: `Edit ${displayName}`,
        component: `${modelName}Form`,
        permissions: options?.permissions
      }
    ];
    const menuItems = [
      {
        label: displayName,
        path: basePath,
        icon: options?.icon,
        permissions: options?.permissions
      }
    ];
    return { pages, menuItems };
  }
  /**
   * Create a database migration for a model
   */
  static createMigration(tableName, fields) {
    const columns = fields.map((field) => {
      let definition = `${field.name} ${field.type}`;
      if (field.primaryKey) definition += " PRIMARY KEY";
      if (field.unique) definition += " UNIQUE";
      if (!field.nullable && !field.primaryKey) definition += " NOT NULL";
      if (field.defaultValue) definition += ` DEFAULT ${field.defaultValue}`;
      return definition;
    }).join(",\n  ");
    return `
CREATE TABLE IF NOT EXISTS ${tableName} (
  ${columns},
  created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
  updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE TRIGGER IF NOT EXISTS ${tableName}_updated_at
  AFTER UPDATE ON ${tableName}
BEGIN
  UPDATE ${tableName} SET updated_at = strftime('%s', 'now') WHERE id = NEW.id;
END;
    `.trim();
  }
  /**
   * Create a Zod schema for a model
   */
  static createSchema(fields) {
    const shape = {};
    const applyValidation = (field, schema) => {
      if (field.validation) {
        if (field.type === "string" && field.validation.min) {
          schema = schema.min(field.validation.min);
        }
        if (field.type === "string" && field.validation.max) {
          schema = schema.max(field.validation.max);
        }
        if (field.type === "string" && field.validation.email) {
          schema = schema.email();
        }
        if (field.type === "string" && field.validation.url) {
          schema = schema.url();
        }
      }
      return schema;
    };
    const buildSchema = (field) => {
      let schema;
      switch (field.type) {
        case "string":
          schema = zod.z.string();
          break;
        case "number":
          schema = zod.z.number();
          break;
        case "boolean":
          schema = zod.z.boolean();
          break;
        case "date":
          schema = zod.z.date();
          break;
        case "array":
          if (field.items?.blocks && typeof field.items.blocks === "object") {
            const discriminator = typeof field.items.discriminator === "string" && field.items.discriminator ? field.items.discriminator : "blockType";
            const blockSchemas = Object.entries(field.items.blocks).map(([blockName, blockDef]) => {
              const properties = blockDef?.properties && typeof blockDef.properties === "object" ? blockDef.properties : {};
              const blockShape = {
                [discriminator]: zod.z.literal(blockName)
              };
              Object.entries(properties).forEach(([propertyName, propertyConfigRaw]) => {
                const propertyConfig = propertyConfigRaw && typeof propertyConfigRaw === "object" ? propertyConfigRaw : {};
                const propertySchema = buildSchema({
                  ...propertyConfig,
                  optional: propertyConfig.required === false
                });
                blockShape[propertyName] = propertySchema;
              });
              return zod.z.object(blockShape);
            });
            if (blockSchemas.length === 1 && blockSchemas[0]) {
              schema = zod.z.array(blockSchemas[0]);
            } else if (blockSchemas.length > 1) {
              schema = zod.z.array(zod.z.union(blockSchemas));
            } else {
              schema = zod.z.array(zod.z.any());
            }
            break;
          }
          if (field.items) {
            schema = zod.z.array(buildSchema(field.items));
            break;
          }
          schema = zod.z.array(zod.z.any());
          break;
        case "object":
          if (field.properties && typeof field.properties === "object") {
            const objectShape = {};
            Object.entries(field.properties).forEach(([propertyName, propertyConfigRaw]) => {
              const propertyConfig = propertyConfigRaw && typeof propertyConfigRaw === "object" ? propertyConfigRaw : {};
              objectShape[propertyName] = buildSchema({
                ...propertyConfig,
                optional: propertyConfig.required === false
              });
            });
            schema = zod.z.object(objectShape);
            break;
          }
          schema = zod.z.object({});
          break;
        default:
          schema = zod.z.any();
      }
      schema = applyValidation(field, schema);
      if (field.optional || field.required === false) {
        schema = schema.optional();
      }
      return schema;
    };
    for (const field of fields) {
      shape[field.name] = buildSchema(field);
    }
    return zod.z.object(shape);
  }
};

// src/plugins/core-plugins/turnstile-plugin/manifest.json
var manifest_default = {
  id: "turnstile",
  name: "Cloudflare Turnstile",
  description: "CAPTCHA-free bot protection using Cloudflare Turnstile. Provides reusable verification for any form.",
  version: "1.0.0",
  author: "SonicJS",
  category: "security",
  icon: "shield-check",
  homepage: "https://developers.cloudflare.com/turnstile/",
  repository: "https://github.com/sonicjs/sonicjs",
  license: "MIT",
  permissions: ["settings:write", "admin:access"],
  dependencies: [],
  configSchema: {
    siteKey: {
      type: "string",
      label: "Site Key",
      description: "Your Cloudflare Turnstile site key (public)",
      required: true
    },
    secretKey: {
      type: "string",
      label: "Secret Key",
      description: "Your Cloudflare Turnstile secret key (private)",
      required: true,
      sensitive: true
    },
    theme: {
      type: "select",
      label: "Widget Theme",
      description: "Visual theme for the Turnstile widget",
      default: "auto",
      options: [
        { value: "light", label: "Light" },
        { value: "dark", label: "Dark" },
        { value: "auto", label: "Auto" }
      ]
    },
    size: {
      type: "select",
      label: "Widget Size",
      description: "Size of the Turnstile widget",
      default: "normal",
      options: [
        { value: "normal", label: "Normal" },
        { value: "compact", label: "Compact" }
      ]
    },
    mode: {
      type: "select",
      label: "Widget Mode",
      description: "Managed: Adaptive challenge. Non-Interactive: Always visible, minimal friction. Invisible: No visible widget",
      default: "managed",
      options: [
        { value: "managed", label: "Managed (Recommended)" },
        { value: "non-interactive", label: "Non-Interactive" },
        { value: "invisible", label: "Invisible" }
      ]
    },
    appearance: {
      type: "select",
      label: "Appearance",
      description: "When the Turnstile challenge is executed. Always: Verifies immediately. Execute: Challenge on form submit. Interaction Only: Only after user interaction",
      default: "always",
      options: [
        { value: "always", label: "Always" },
        { value: "execute", label: "Execute" },
        { value: "interaction-only", label: "Interaction Only" }
      ]
    },
    preClearance: {
      type: "boolean",
      label: "Enable Pre-clearance",
      description: "Issue a clearance cookie that bypasses Cloudflare Firewall Rules (as if the user passed a challenge on your proxied site)",
      default: false
    },
    preClearanceLevel: {
      type: "select",
      label: "Pre-clearance Level",
      description: "Controls which Cloudflare Firewall Rules the clearance cookie bypasses. Only applies if Pre-clearance is enabled",
      default: "managed",
      options: [
        { value: "interactive", label: "Interactive - Bypasses Interactive, Managed & JS Challenge Rules" },
        { value: "managed", label: "Managed - Bypasses Managed & JS Challenge Rules" },
        { value: "non-interactive", label: "Non-interactive - Bypasses JS Challenge Rules only" }
      ]
    },
    enabled: {
      type: "boolean",
      label: "Enable Turnstile",
      description: "Enable or disable Turnstile verification globally",
      default: true
    }
  },
  adminMenu: {
    label: "Turnstile",
    icon: "shield-check",
    href: "/admin/plugins/turnstile/settings",
    parentId: "plugins",
    order: 100
  }
};

// src/plugins/core-plugins/turnstile-plugin/services/turnstile.ts
var TurnstileService = class {
  db;
  VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
  constructor(db) {
    this.db = db;
  }
  /**
   * Get Turnstile settings from database
   */
  async getSettings() {
    try {
      const plugin = await this.db.prepare(`SELECT settings FROM plugins WHERE id = ? LIMIT 1`).bind(manifest_default.id).first();
      if (!plugin || !plugin.settings) {
        return null;
      }
      return JSON.parse(plugin.settings);
    } catch (error) {
      console.error("Error getting Turnstile settings:", error);
      return null;
    }
  }
  /**
   * Verify a Turnstile token with Cloudflare
   */
  async verifyToken(token, remoteIp) {
    try {
      const settings = await this.getSettings();
      if (!settings) {
        return { success: false, error: "Turnstile not configured" };
      }
      if (!settings.enabled) {
        return { success: true };
      }
      if (!settings.secretKey) {
        return { success: false, error: "Turnstile secret key not configured" };
      }
      const formData = new FormData();
      formData.append("secret", settings.secretKey);
      formData.append("response", token);
      if (remoteIp) {
        formData.append("remoteip", remoteIp);
      }
      const response = await fetch(this.VERIFY_URL, {
        method: "POST",
        body: formData
      });
      if (!response.ok) {
        return { success: false, error: "Turnstile verification request failed" };
      }
      const result = await response.json();
      if (!result.success) {
        const errorCode = result["error-codes"]?.[0] || "unknown-error";
        return { success: false, error: `Turnstile verification failed: ${errorCode}` };
      }
      return { success: true };
    } catch (error) {
      console.error("Error verifying Turnstile token:", error);
      return { success: false, error: "Turnstile verification error" };
    }
  }
  /**
   * Save Turnstile settings to database
   */
  async saveSettings(settings) {
    try {
      await this.db.prepare(`UPDATE plugins SET settings = ?, updated_at = ? WHERE id = ?`).bind(JSON.stringify(settings), Date.now(), manifest_default.id).run();
      console.log("Turnstile settings saved successfully");
    } catch (error) {
      console.error("Error saving Turnstile settings:", error);
      throw new Error("Failed to save Turnstile settings");
    }
  }
  /**
   * Check if Turnstile is enabled
   */
  async isEnabled() {
    const settings = await this.getSettings();
    return settings?.enabled === true && !!settings.siteKey && !!settings.secretKey;
  }
};

exports.PluginBuilder = PluginBuilder;
exports.PluginHelpers = PluginHelpers;
exports.TurnstileService = TurnstileService;
exports.manifest_default = manifest_default;
//# sourceMappingURL=chunk-6FHNRRJ3.cjs.map
//# sourceMappingURL=chunk-6FHNRRJ3.cjs.map