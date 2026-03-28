// src/types/plugin.ts
var HOOKS = {
  // Application lifecycle
  APP_INIT: "app:init",
  APP_READY: "app:ready",
  APP_SHUTDOWN: "app:shutdown",
  // Request lifecycle
  REQUEST_START: "request:start",
  REQUEST_END: "request:end",
  REQUEST_ERROR: "request:error",
  // Authentication
  AUTH_LOGIN: "auth:login",
  AUTH_LOGOUT: "auth:logout",
  AUTH_REGISTER: "auth:register",
  USER_LOGIN: "user:login",
  USER_LOGOUT: "user:logout",
  // Content lifecycle
  CONTENT_CREATE: "content:create",
  CONTENT_UPDATE: "content:update",
  CONTENT_DELETE: "content:delete",
  CONTENT_PUBLISH: "content:publish",
  CONTENT_SAVE: "content:save",
  // Media lifecycle
  MEDIA_UPLOAD: "media:upload",
  MEDIA_DELETE: "media:delete",
  MEDIA_TRANSFORM: "media:transform",
  // Plugin lifecycle
  PLUGIN_INSTALL: "plugin:install",
  PLUGIN_UNINSTALL: "plugin:uninstall",
  PLUGIN_ACTIVATE: "plugin:activate",
  PLUGIN_DEACTIVATE: "plugin:deactivate",
  // Admin interface
  ADMIN_MENU_RENDER: "admin:menu:render",
  ADMIN_PAGE_RENDER: "admin:page:render",
  // Database
  DB_MIGRATE: "db:migrate",
  DB_SEED: "db:seed"
};

export { HOOKS };
//# sourceMappingURL=chunk-LOUJRBXV.js.map
//# sourceMappingURL=chunk-LOUJRBXV.js.map