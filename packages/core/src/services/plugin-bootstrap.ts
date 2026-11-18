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
// core-auth always bootstrapped. Plugins with defaultActive:true in manifest.json are also
// auto-installed and activated on greenfield installs.
const BOOTSTRAP_PLUGIN_IDS = [
  "core-auth",
  // Collect any registry entries marked defaultActive (e.g. lexical-editor)
  ...Object.values(PLUGIN_REGISTRY)
    .filter(e => e.defaultActive === true && e.id !== "core-auth")
    .map(e => e.id),
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
   * Bootstrap all core plugins - install them if they don't exist.
   * A plugin that fails is logged and skipped so the others still install; the ids of
   * the ones that failed are returned so the caller can tell a partial bootstrap apart.
   */
  async bootstrapCorePlugins(): Promise<string[]> {
    console.log("[PluginBootstrap] Starting core plugin bootstrap process...");

    try {
      const failed: string[] = [];
      // Check each core plugin
      for (const corePlugin of this.CORE_PLUGINS) {
        if (!(await this.ensurePluginInstalled(corePlugin))) failed.push(corePlugin.id);
      }

      if (failed.length) {
        console.warn(`[PluginBootstrap] Core plugin bootstrap completed with failures: ${failed.join(", ")}`);
      } else {
        console.log(
          "[PluginBootstrap] Core plugin bootstrap completed successfully"
        );
      }
      return failed;
    } catch (error) {
      console.error("[PluginBootstrap] Error during plugin bootstrap:", error);
      throw error;
    }
  }

  /**
   * Ensure a specific plugin is installed. Returns false if it failed (already logged).
   */
  private async ensurePluginInstalled(plugin: CorePlugin): Promise<boolean> {
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

        // Ensure bootstrapped plugins are active (defaultActive or core-auth).
        // If a plugin enters the bootstrap list it should be on unless the user
        // explicitly deactivated it — but we can't distinguish that from
        // "never activated", so we activate all bootstrapped plugins that are
        // currently inactive. This is safe: user can deactivate via admin UI.
        if (existingPlugin.status !== 'active') {
          console.log(
            `[PluginBootstrap] Activating bootstrapped plugin: ${plugin.display_name}`
          );
          await this.pluginService.activatePlugin(plugin.id);
        }

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
      return true;
    } catch (error) {
      console.error(
        `[PluginBootstrap] Error ensuring plugin ${plugin.display_name}:`,
        error
      );
      return false;
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
      // Every bootstrapped plugin counts here, not just the `core-*` ones. The filter that used
      // to sit on this line made the gate blind to `lexical-editor` and `two-factor-auth`: if
      // the first boot's install loop was cut short (the request that owns bootstrap can be
      // cancelled mid-loop), `core-auth` and `core-media` were already in place, the gate
      // answered "not needed" on every later boot, and those two stayed permanently
      // uninstalled. A deployment in that state renders every richtext field as a plain
      // textarea, because the field falls back whenever the lexical plugin is not active.
      const bootstrapped = this.CORE_PLUGINS
      if (!bootstrapped.length) return false

      const quote = (id: string) => `'${id.replace(/'/g, "''")}'`
      const allSlugs = bootstrapped.map((p) => quote(p.id)).join(',')
      // `core-*` must additionally be *active* — the app does not work without auth or media,
      // and the admin UI does not offer to turn them off. The other bootstrapped plugins are
      // only checked for existence, so deactivating one from the admin UI sticks instead of
      // being undone by the next cold start.
      const coreSlugs = bootstrapped
        .filter((p) => p.name.startsWith("core-"))
        .map((p) => quote(p.id))
      const coreIn = coreSlugs.length ? coreSlugs.join(',') : "''"

      const res = await this.db
        .prepare(
          `SELECT
             COUNT(DISTINCT slug) AS installed,
             COUNT(DISTINCT CASE WHEN slug IN (${coreIn}) THEN slug END) AS core_installed,
             COUNT(DISTINCT CASE WHEN slug IN (${coreIn})
                                  AND json_extract(data, '$.status') = 'active'
                                 THEN slug END) AS core_active
           FROM documents
           WHERE slug IN (${allSlugs}) AND type_id = 'plugin'
           AND tenant_id = 'default' AND is_current_draft = 1 AND deleted_at IS NULL`,
        )
        .first<{ installed: number; core_installed: number; core_active: number }>()
      const installed = res?.installed ?? 0
      const coreInstalled = res?.core_installed ?? 0
      const coreActive = res?.core_active ?? 0
      return installed < bootstrapped.length || coreActive < coreInstalled
    } catch (error) {
      console.error("[PluginBootstrap] Error checking bootstrap status:", error)
      return true
    }
  }

}
