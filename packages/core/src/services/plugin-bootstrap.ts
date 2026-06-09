import type { D1Database } from "@cloudflare/workers-types";
import { PluginService } from "./plugin-service";
import { PLUGIN_REGISTRY } from "../plugins/manifest-registry";
import type { PluginRegistryEntry } from "../plugins/manifest-registry";

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

/**
 * Build the CORE_PLUGINS list from the auto-generated registry.
 * To add a new bootstrapped plugin, create a manifest.json and
 * run: node packages/scripts/generate-plugin-registry.mjs
 *
 * Only plugins that are in the BOOTSTRAP_PLUGIN_IDS list will be
 * auto-installed on first boot. Edit this list to control which
 * plugins are bootstrapped.
 */
// Only core-auth is auto-installed. All others must be installed manually.
const BOOTSTRAP_PLUGIN_IDS = [
  "core-auth",
];

function registryToCorePlugin(entry: PluginRegistryEntry): CorePlugin {
  return {
    id: entry.id,
    name: entry.codeName,
    display_name: entry.displayName,
    description: entry.description,
    version: entry.version,
    author: entry.author,
    category: entry.category,
    icon: entry.iconEmoji,
    permissions: entry.permissions,
    dependencies: entry.dependencies,
    settings: entry.defaultSettings,
  };
}

export class PluginBootstrapService {
  private pluginService: PluginService;

  constructor(private db: D1Database) {
    this.pluginService = new PluginService(db);
  }

  /**
   * Core plugins derived from the auto-generated plugin registry.
   * Only plugins listed in BOOTSTRAP_PLUGIN_IDS AND marked is_core=true are auto-installed.
   * Non-core plugins are available in the registry but not bootstrapped.
   */
  private readonly CORE_PLUGINS: CorePlugin[] = BOOTSTRAP_PLUGIN_IDS
    .filter((id) => PLUGIN_REGISTRY[id] !== undefined && PLUGIN_REGISTRY[id]!.is_core === true)
    .map((id) => registryToCorePlugin(PLUGIN_REGISTRY[id]!));

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
      } else {
        // Install the plugin
        console.log(
          `[PluginBootstrap] Installing plugin: ${plugin.display_name}`
        );
        await this.pluginService.installPlugin({
          ...plugin,
          is_core: plugin.name.startsWith("core-"),
        });

        // Activate plugins immediately after installation
        console.log(
          `[PluginBootstrap] Activating newly installed plugin: ${plugin.display_name}`
        );
        await this.pluginService.activatePlugin(plugin.id);
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
   * Update an existing plugin's version/description/permissions/settings
   */
  private async updatePlugin(plugin: CorePlugin): Promise<void> {
    await this.pluginService.updatePluginVersion(plugin.id, {
      version: plugin.version,
      description: plugin.description,
      permissions: plugin.permissions,
      settings: plugin.settings || {},
    });
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
