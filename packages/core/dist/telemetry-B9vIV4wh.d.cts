/**
 * Telemetry Types
 *
 * Privacy-first telemetry types for SonicJS
 * No PII (Personally Identifiable Information) is collected
 */
type TelemetryEvent = 'installation_started' | 'installation_completed' | 'installation_failed' | 'setup_wizard_started' | 'setup_wizard_completed' | 'first_dev_server_start' | 'dev_server_started' | 'dev_server_stopped' | 'admin_login' | 'plugin_activated' | 'plugin_deactivated' | 'collection_created' | 'content_created' | 'page_viewed' | 'feature_used' | 'error_occurred' | 'migration_run' | 'deployment_triggered';
interface TelemetryProperties {
    os?: 'darwin' | 'linux' | 'win32' | string;
    nodeVersion?: string;
    packageManager?: 'npm' | 'yarn' | 'pnpm' | 'bun';
    installationDuration?: number;
    success?: boolean;
    errorType?: string;
    sessionDuration?: number;
    pluginsCount?: number;
    collectionsCount?: number;
    contentItemsCount?: number;
    route?: string;
    feature?: string;
    migrationType?: 'initial' | 'update' | 'rollback';
    migrationSuccess?: boolean;
    [key: string]: string | number | boolean | undefined;
}
interface TelemetryConfig {
    enabled: boolean;
    host?: string;
    debug?: boolean;
}
interface TelemetryIdentity {
    installationId: string;
    projectId?: string;
}

export type { TelemetryConfig as T, TelemetryEvent as a, TelemetryIdentity as b, TelemetryProperties as c };
