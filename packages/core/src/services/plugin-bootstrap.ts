import type { D1Database } from "@cloudflare/workers-types";
import { PluginService } from "./plugin-service";

export interface CorePlugin {
  id: string;
  name: string;
  display_name: string;
  description: string;
  version: string;
  author: string;
  category: string;
  icon: string;
  permissions: string[];
  dependencies: string[];
  settings?: any;
}

export class PluginBootstrapService {
  private pluginService: PluginService;

  constructor(private db: D1Database) {
    this.pluginService = new PluginService(db);
  }

  /**
   * Core plugins that should always be available in the system
   */
  private readonly CORE_PLUGINS: CorePlugin[] = [
    {
      id: "core-auth",
      name: "core-auth",
      display_name: "Authentication System",
      description: "Core authentication and user management system",
      version: "1.0.0",
      author: "SonicJS Team",
      category: "security",
      icon: "🔐",
      permissions: ["manage:users", "manage:roles", "manage:permissions"],
      dependencies: [],
      settings: {
        requiredFields: {
          email: { required: true, minLength: 5, label: "Email", type: "email" },
          password: { required: true, minLength: 8, label: "Password", type: "password" },
          username: { required: true, minLength: 3, label: "Username", type: "text" },
          firstName: { required: true, minLength: 1, label: "First Name", type: "text" },
          lastName: { required: true, minLength: 1, label: "Last Name", type: "text" },
        },
        validation: {
          emailFormat: true,
          allowDuplicateUsernames: false,
          passwordRequirements: {
            requireUppercase: false,
            requireLowercase: false,
            requireNumbers: false,
            requireSpecialChars: false,
          },
        },
        registration: {
          enabled: true,
          requireEmailVerification: false,
          defaultRole: "viewer",
        },
      },
    },
    {
      id: "core-media",
      name: "core-media",
      display_name: "Media Manager",
      description: "Core media upload and management system",
      version: "1.0.0",
      author: "SonicJS Team",
      category: "media",
      icon: "📸",
      permissions: ["manage:media", "upload:files"],
      dependencies: [],
      settings: {},
    },
    {
      id: "database-tools",
      name: "database-tools",
      display_name: "Database Tools",
      description:
        "Database management tools including truncate, backup, and validation",
      version: "1.0.0",
      author: "SonicJS Team",
      category: "system",
      icon: "🗄️",
      permissions: ["manage:database", "admin"],
      dependencies: [],
      settings: {
        enableTruncate: true,
        enableBackup: true,
        enableValidation: true,
        requireConfirmation: true,
      },
    },
    {
      id: "seed-data",
      name: "seed-data",
      display_name: "Seed Data",
      description:
        "Generate realistic example users and content for testing and development",
      version: "1.0.0",
      author: "SonicJS Team",
      category: "development",
      icon: "🌱",
      permissions: ["admin"],
      dependencies: [],
      settings: {
        userCount: 20,
        contentCount: 200,
        defaultPassword: "password123",
      },
    },
    {
      id: "core-cache",
      name: "core-cache",
      display_name: "Cache System",
      description:
        "Three-tiered caching system with memory, KV, and database layers",
      version: "1.0.0",
      author: "SonicJS Team",
      category: "performance",
      icon: "⚡",
      permissions: ["manage:cache", "view:stats"],
      dependencies: [],
      settings: {
        enableMemoryCache: true,
        enableKVCache: true,
        enableDatabaseCache: true,
        defaultTTL: 3600,
      },
    },
    {
      id: "workflow-plugin",
      name: "workflow-plugin",
      display_name: "Workflow Management",
      description:
        "Content workflow management with approval chains, scheduling, and automation",
      version: "1.0.0-beta.1",
      author: "SonicJS Team",
      category: "content",
      icon: "🔄",
      permissions: ["manage:workflows", "view:workflows", "transition:content"],
      dependencies: ["content-plugin"],
      settings: {
        enableApprovalChains: true,
        enableScheduling: true,
        enableAutomation: true,
        enableNotifications: true,
      },
    },
    {
      id: "easy-mdx",
      name: "easy-mdx",
      display_name: "EasyMDE Editor",
      description: "Lightweight markdown editor with live preview for richtext fields",
      version: "1.0.0",
      author: "SonicJS Team",
      category: "editor",
      icon: "✍️",
      permissions: [],
      dependencies: [],
      settings: {
        defaultHeight: 400,
        toolbar: "full",
        placeholder: "Start writing your content...",
      },
    },
    {
      id: "ai-search",
      name: "ai-search-plugin",
      display_name: "AI Search",
      description: "Advanced search with Cloudflare AI Search. Full-text search, semantic search, and advanced filtering across all content collections.",
      version: "1.0.0",
      author: "SonicJS Team",
      category: "search",
      icon: "🔍",
      permissions: ["settings:write", "admin:access", "content:read"],
      dependencies: [],
      settings: {
        enabled: false,
        ai_mode_enabled: true,
        selected_collections: [],
        dismissed_collections: [],
        autocomplete_enabled: true,
        cache_duration: 1,
        results_limit: 20,
        index_media: false,
      },
    },
    {
      id: "oauth-providers",
      name: "oauth-providers",
      display_name: "OAuth Providers",
      description: "OAuth2/OIDC social login with GitHub, Google, and more",
      version: "1.0.0-beta.1",
      author: "SonicJS Team",
      category: "authentication",
      icon: "🔑",
      permissions: ["oauth:manage"],
      dependencies: [],
      settings: {
        providers: {
          github: { clientId: "", clientSecret: "", enabled: false },
          google: { clientId: "", clientSecret: "", enabled: false },
        },
      },
    },
    {
      id: "global-variables",
      name: "global-variables",
      display_name: "Global Variables",
      description:
        "Dynamic content variables with inline token support. Use {variable_key} syntax in rich text fields for server-side resolution.",
      version: "1.0.0-beta.1",
      author: "SonicJS Team",
      category: "content",
      icon: "🔤",
      permissions: ["global-variables:manage", "global-variables:view"],
      dependencies: [],
      settings: {
        enableResolution: true,
        cacheEnabled: true,
        cacheTTL: 300,
      },
    },
  ];

  /**
   * Bootstrap all core plugins - install them if they don't exist
   */
  async bootstrapCorePlugins(): Promise<void> {
    console.log("[PluginBootstrap] Starting core plugin bootstrap process...");

    try {
      // Check each core plugin
      for (const corePlugin of this.CORE_PLUGINS) {
        await this.ensurePluginInstalled(corePlugin);
      }

      console.log(
        "[PluginBootstrap] Core plugin bootstrap completed successfully"
      );
    } catch (error) {
      console.error("[PluginBootstrap] Error during plugin bootstrap:", error);
      throw error;
    }
  }

  /**
   * Ensure a specific plugin is installed
   */
  private async ensurePluginInstalled(plugin: CorePlugin): Promise<void> {
    try {
      // Check if plugin already exists
      const existingPlugin = await this.pluginService.getPlugin(plugin.id);

      if (existingPlugin) {
        console.log(
          `[PluginBootstrap] Plugin already installed: ${plugin.display_name} (status: ${existingPlugin.status})`
        );

        // Update plugin if version changed
        if (existingPlugin.version !== plugin.version) {
          console.log(
            `[PluginBootstrap] Updating plugin version: ${plugin.display_name} from ${existingPlugin.version} to ${plugin.version}`
          );
          await this.updatePlugin(plugin);
        }

        // ALWAYS ensure core-auth is active (critical for system functionality)
        if (plugin.id === 'core-auth' && existingPlugin.status !== 'active') {
          console.log(
            `[PluginBootstrap] Core-auth plugin is inactive, activating it now...`
          );
          await this.pluginService.activatePlugin(plugin.id);
        }

        // Only auto-activate on first install, respect user's activation state on subsequent boots
        // This preserves the activation state across server restarts
        // Core plugins (with core- prefix) are activated on first install in the else block below
      } else {
        // Install the plugin
        console.log(
          `[PluginBootstrap] Installing plugin: ${plugin.display_name}`
        );
        await this.pluginService.installPlugin({
          ...plugin,
          is_core: plugin.name.startsWith("core-"),
        });

        // Activate core plugins immediately after installation
        if (plugin.name.startsWith("core-")) {
          console.log(
            `[PluginBootstrap] Activating newly installed core plugin: ${plugin.display_name}`
          );
          await this.pluginService.activatePlugin(plugin.id);
        }
      }
    } catch (error) {
      console.error(
        `[PluginBootstrap] Error ensuring plugin ${plugin.display_name}:`,
        error
      );
      // Don't throw - continue with other plugins
    }
  }

  /**
   * Update an existing plugin
   */
  private async updatePlugin(plugin: CorePlugin): Promise<void> {
    const now = Math.floor(Date.now() / 1000);

    const stmt = this.db.prepare(`
      UPDATE plugins 
      SET 
        version = ?,
        description = ?,
        permissions = ?,
        settings = ?,
        last_updated = ?
      WHERE id = ?
    `);

    await stmt
      .bind(
        plugin.version,
        plugin.description,
        JSON.stringify(plugin.permissions),
        JSON.stringify(plugin.settings || {}),
        now,
        plugin.id
      )
      .run();
  }

  /**
   * Check if bootstrap is needed (first run detection)
   */
  async isBootstrapNeeded(): Promise<boolean> {
    try {
      // Check if any core plugins are missing
      for (const corePlugin of this.CORE_PLUGINS.filter((p) =>
        p.name.startsWith("core-")
      )) {
        const exists = await this.pluginService.getPlugin(corePlugin.id);
        if (!exists) {
          return true;
        }
      }
      return false;
    } catch (error) {
      // If there's an error (like table doesn't exist), we need bootstrap
      console.error(
        "[PluginBootstrap] Error checking bootstrap status:",
        error
      );
      return true;
    }
  }

}
