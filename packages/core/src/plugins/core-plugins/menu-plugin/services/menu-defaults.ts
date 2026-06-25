export interface SystemMenuItem {
  id: string
  label: string
  url: string
  icon: string
  target: '_self'
  isExternal: false
  visible: true
  parent: null
  source: 'system'
  pluginId: null
  permissions: []
  lockedFields: ['url', 'parent']
  sortOrder: number
}

export const SYSTEM_MENU_ITEMS: readonly SystemMenuItem[] = [
  {
    id: 'menu:system:content',
    label: 'Content',
    url: '/admin/content',
    icon: 'document',
    target: '_self',
    isExternal: false,
    visible: true,
    parent: null,
    source: 'system',
    pluginId: null,
    permissions: [],
    lockedFields: ['url', 'parent'],
    sortOrder: 10,
  },
  {
    id: 'menu:system:collections',
    label: 'Collections',
    url: '/admin/collections',
    icon: 'collection',
    target: '_self',
    isExternal: false,
    visible: true,
    parent: null,
    source: 'system',
    pluginId: null,
    permissions: [],
    lockedFields: ['url', 'parent'],
    sortOrder: 20,
  },
  {
    id: 'menu:system:users',
    label: 'Users',
    url: '/admin/users',
    icon: 'users',
    target: '_self',
    isExternal: false,
    visible: true,
    parent: null,
    source: 'system',
    pluginId: null,
    permissions: [],
    lockedFields: ['url', 'parent'],
    sortOrder: 30,
  },
  {
    id: 'menu:system:settings',
    label: 'Settings',
    url: '/admin/settings',
    icon: 'cog',
    target: '_self',
    isExternal: false,
    visible: true,
    parent: null,
    source: 'system',
    pluginId: null,
    permissions: [],
    lockedFields: ['url', 'parent'],
    sortOrder: 40,
  },
  {
    id: 'menu:system:plugins',
    label: 'Plugins',
    url: '/admin/plugins',
    icon: 'puzzle-piece',
    target: '_self',
    isExternal: false,
    visible: true,
    parent: null,
    source: 'system',
    pluginId: null,
    permissions: [],
    lockedFields: ['url', 'parent'],
    sortOrder: 50,
  },
  {
    id: 'menu:system:menu',
    label: 'Menu',
    url: '/admin/menu',
    icon: 'bars-3',
    target: '_self',
    isExternal: false,
    visible: true,
    parent: null,
    source: 'system',
    pluginId: null,
    permissions: [],
    lockedFields: ['url', 'parent'],
    sortOrder: 60,
  },
] as const
