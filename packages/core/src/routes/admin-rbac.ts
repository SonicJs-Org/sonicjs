/**
 * Admin RBAC management UI + routes. Global /admin/* middleware requires
 * portal access; this route also requires rbac:manage.
 *
 *   GET  /admin/rbac                 → matrix UI (per-role resource×verb grid),
 *                                       role/verb management, live check
 *   POST /admin/rbac/grants          → save the matrix for one role
 *   POST /admin/rbac/roles           → create a custom role
 *   POST /admin/rbac/roles/:id/delete
 *   POST /admin/rbac/verbs           → add a custom verb
 *   POST /admin/rbac/verbs/:id/delete
 *   GET  /admin/rbac/check           → can(role|me, resource, verb)
 */
import { Hono } from 'hono'
import { RbacService, type PermissionScope } from '../services/rbac'
import { renderAdminLayoutCatalyst } from '../templates/layouts/admin-layout-catalyst.template'
import { getCoreVersion } from '../utils/version'
import { requireRbac } from '../middleware/auth'
import type { Bindings, Variables } from '../app'

export const adminRbacRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>()
adminRbacRoutes.use('*', requireRbac('rbac', 'manage'))

const esc = (s: string) =>
  String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')

const TABS = `
  <div class="border-b border-zinc-950/10 dark:border-white/10 mb-6">
    <nav class="-mb-px flex space-x-6" aria-label="Tabs">
      <a href="/admin/users" class="whitespace-nowrap border-b-2 border-transparent px-1 py-3 text-sm font-medium text-zinc-500 dark:text-zinc-400 hover:border-zinc-300 hover:text-zinc-700 dark:hover:text-zinc-200">Users</a>
      <a href="/admin/rbac" aria-current="page" class="whitespace-nowrap border-b-2 border-cyan-500 px-1 py-3 text-sm font-medium text-cyan-600 dark:text-cyan-400">Roles &amp; Permissions</a>
    </nav>
  </div>`

adminRbacRoutes.get('/', async (c) => {
  const rbac = new RbacService(c.env.DB)
  const [roles, verbs, resources, grants] = await Promise.all([
    rbac.getRoles(),
    rbac.getVerbs(),
    rbac.getResources(),
    rbac.getGrants(),
  ])
  // Multi-select roles for side-by-side comparison. First visit defaults to the
  // first 3 roles to keep the matrix narrow; an explicit selector submit (incl.
  // the Clear button) with no roles selected stays empty.
  const requested = c.req.queries('roles') || []
  const hasCompareSelection = c.req.query('compare') === '1'
  const selectedIds = hasCompareSelection ? requested : roles.slice(0, 3).map((r) => r.id)
  const selectedRoles = roles.filter((r) => selectedIds.includes(r.id))
  const isAdmin = (r: { name: string }) => r.name === 'admin'
  const grantsByRole = new Map<string, Map<string, Exclude<PermissionScope, 'none'>>>()
  for (const r of roles) grantsByRole.set(r.id, new Map())
  for (const g of grants) grantsByRole.get(g.role_id)?.set(`${g.resource}|${g.verb}`, g.scope || 'any')
  const cellScope = (role: { id: string; name: string }, res: string, verb: string): PermissionScope =>
    isAdmin(role) ? 'any' : grantsByRole.get(role.id)?.get(`${res}|${verb}`) || 'none'
  const supportsOwnScope = (res: string, verb: string) =>
    (res === 'content' || res.startsWith('collection:')) && ['read', 'update', 'delete'].includes(verb)

  // System roles keep predictable colors. Custom roles get generated colors by
  // their current role order so they do not collide with each other.
  const SYSTEM_ROLE_COLORS: Record<string, string> = {
    admin: 'hsl(45 94% 54%)',
    editor: 'hsl(199 89% 60%)',
    author: 'hsl(258 90% 76%)',
    viewer: 'hsl(160 64% 52%)',
  }
  const customRoleColor = (index: number) => `hsl(${Math.round((315 + index * 137.508) % 360)} 82% 58%)`
  const assignedRoleColors = new Map<string, string>()
  let customRoleIndex = 0
  roles.forEach((role) => {
    const color = SYSTEM_ROLE_COLORS[role.name] || customRoleColor(customRoleIndex++)
    assignedRoleColors.set(role.id, color)
  })
  const roleColor = (seed: string) => assignedRoleColors.get(seed) || customRoleColor(0)
  const roleTone = (seed: string) => {
    const color = roleColor(seed)
    return [
      `--role-color:${color}`,
      `--role-bg:${color.replace(')', ' / 0.10)')}`,
      `--role-bg-strong:${color.replace(')', ' / 0.18)')}`,
      `--role-border:${color.replace(')', ' / 0.45)')}`,
      `--role-ring:${color.replace(')', ' / 0.28)')}`,
    ].join(';')
  }
  const roleStyle = (seed: string, extra = '') => `style="${roleTone(seed)};${extra}"`

  // 3-way (None/Own/Any) segmented switch. Hidden radios drive it so form
  // submission, the "All resources" cascade, and the POST parser all keep
  // working exactly as before; the checked segment gets a white "thumb".
  const seg = (
    key: string,
    val: string,
    label: string,
    scope: string,
    disabled: boolean,
    roleId: string,
    resKey: string,
    verbName: string
  ) =>
    `<label class="cursor-pointer ${disabled ? 'pointer-events-none' : ''}">
      <input type="radio" class="peer sr-only" name="${esc(key)}" value="${val}" data-role="${esc(
      roleId
    )}" data-res="${esc(resKey)}" data-verb="${esc(verbName)}" ${scope === val ? 'checked' : ''} ${
      disabled ? 'disabled' : ''
    }>
      <span class="block rounded-lg px-2 py-0.5 text-center leading-tight text-zinc-500 dark:text-zinc-400 peer-checked:bg-white dark:peer-checked:bg-zinc-700 peer-checked:text-zinc-900 dark:peer-checked:text-white peer-checked:shadow-sm transition-colors">${label}</span>
    </label>`
  const scopeSwitch = (
    key: string,
    scope: string,
    ownSupported: boolean,
    disabled: boolean,
    roleId: string,
    resKey: string,
    verbName: string
  ) =>
    `<div class="inline-flex flex-col items-stretch gap-0.5 rounded-2xl bg-zinc-100 dark:bg-white/10 p-0.5 text-[10px] font-medium ${
      disabled ? 'opacity-60' : ''
    }" role="radiogroup">${seg(key, 'none', 'None', scope, disabled, roleId, resKey, verbName)}${
      ownSupported ? seg(key, 'own', 'Own', scope, disabled, roleId, resKey, verbName) : ''
    }${seg(key, 'any', 'Any', scope, disabled, roleId, resKey, verbName)}</div>`

  // Two-level header: verb groups, each split into a sub-column per selected role.
  const headRow1 = verbs
    .map(
      (v) =>
        `<th colspan="${selectedRoles.length}" class="px-2 py-2 text-xs font-semibold text-zinc-700 dark:text-zinc-300 border-l border-zinc-950/10 dark:border-white/10" title="${esc(
          v.description || ''
        )}">${esc(v.name)}${v.is_system ? '' : ' <span class="text-cyan-500">✦</span>'}</th>`
    )
    .join('')
  const headRow2 = verbs
    .map((v) =>
      selectedRoles
        .map(
          (r, i) =>
            `<th class="px-1 py-2 align-bottom text-[11px] font-medium text-zinc-500 dark:text-zinc-400 ${
              i === 0 ? 'border-l border-zinc-950/10 dark:border-white/10' : ''
            }" ${roleStyle(
              r.id,
              'background:var(--role-bg);border-color:var(--role-border);box-shadow:inset 0 -2px 0 var(--role-color);'
            )} title="${esc(v.name)} · ${esc(r.display_name)}"><div class="flex flex-col items-center gap-1"><span class="h-2 w-2 rounded-full" style="background:var(--role-color)"></span><span class="[writing-mode:vertical-rl] rotate-180 whitespace-nowrap">${esc(
              r.display_name
            )}${isAdmin(r) ? ' 🔒' : ''}</span></div></th>`
        )
        .join('')
    )
    .join('')

  const rows = resources
    .map((res) => {
      const cells = verbs
        .map((v) =>
          selectedRoles
            .map((r, i) => {
              const key = `g|${r.id}|${res.key}|${v.name}`
              const scope = cellScope(r, res.key, v.name)
              const dis = isAdmin(r)
              const ownSupported = supportsOwnScope(res.key, v.name)
              return `<td class="px-2 py-1.5 text-center ${
                i === 0 ? 'border-l border-zinc-950/5 dark:border-white/5' : ''
              }" ${roleStyle(
                r.id,
                'background:var(--role-bg);border-color:var(--role-border);'
              )}>${scopeSwitch(key, scope, ownSupported, dis, r.id, res.key, v.name)}</td>`
            })
            .join('')
        )
        .join('')
      const isWild = res.key === '*' || res.key === 'collection:*'
      const resColor = isWild
        ? 'text-amber-600 dark:text-amber-400 font-medium'
        : res.group === 'collection'
          ? 'text-lime-600 dark:text-lime-400'
          : 'text-zinc-800 dark:text-zinc-200'
      return `<tr class="border-t border-zinc-950/5 dark:border-white/5">
        <td class="px-3 py-1.5 text-left whitespace-nowrap sticky left-0 bg-white dark:bg-zinc-900 ${resColor}">${esc(
          res.label
        )}<div class="text-[11px] text-zinc-400 dark:text-zinc-500">${esc(res.key)}</div></td>${cells}</tr>`
    })
    .join('')

  // Role selector: a checkbox inside each tab button; toggling reloads with the
  // chosen roles as columns.
  const roleTabs = roles
    .map((r) => {
      const sel = selectedIds.includes(r.id)
      return `<label class="inline-flex items-center gap-2 rounded-md border px-3 py-1.5 text-sm font-medium cursor-pointer select-none ${
        sel
          ? 'text-zinc-950 dark:text-white'
          : 'text-zinc-700 dark:text-zinc-300 hover:bg-zinc-100 dark:hover:bg-white/10'
      }" ${roleStyle(
        r.id,
        sel
          ? 'background:var(--role-bg-strong);border-color:var(--role-border);box-shadow:0 0 0 1px var(--role-ring);'
          : 'background:var(--role-bg);border-color:var(--role-border);'
      )}>
        <span class="h-2.5 w-2.5 rounded-full" style="background:var(--role-color)"></span>
        <input type="checkbox" name="roles" value="${esc(r.id)}" ${
          sel ? 'checked' : ''
        } onchange="this.form.submit()" class="h-3.5 w-3.5 rounded border-white/40" style="accent-color:var(--role-color)">
        ${esc(r.display_name)}${r.is_system ? '' : ' ✦'}
      </label>`
    })
    .join('')
  // Editable (non-admin) selected roles get saved; admin is locked.
  const saveRoleIds = selectedRoles.filter((r) => !isAdmin(r)).map((r) => r.id).join(',')
  const firstSelected = selectedRoles[0]

  const inpSm = 'rounded-md bg-white dark:bg-white/5 px-2 py-1 text-sm text-zinc-900 dark:text-white outline outline-1 -outline-offset-1 outline-zinc-300 dark:outline-white/15'
  const roleList = roles
    .map(
      (r) =>
        `<li class="py-2 border-b border-zinc-950/5 dark:border-white/5">
          <form method="post" action="/admin/rbac/roles/${esc(r.id)}" class="flex items-center gap-2 flex-wrap">
            <input class="${inpSm} flex-1 min-w-[120px]" name="display_name" value="${esc(
              r.display_name
            )}" required>
            ${
              r.is_system
                ? `<code class="text-xs text-zinc-500 dark:text-zinc-400">${esc(
                    r.name
                  )}</code><span class="rounded-full bg-zinc-100 dark:bg-white/10 px-2 py-0.5 text-[11px] text-zinc-500 dark:text-zinc-400">system</span>`
                : `<input class="${inpSm} w-28" name="name" value="${esc(r.name)}" required>`
            }
            <button class="rounded-md bg-zinc-200 dark:bg-white/10 px-2.5 py-1 text-xs font-medium text-zinc-900 dark:text-white hover:bg-zinc-300 dark:hover:bg-white/20">Save</button>
            ${
              r.is_system
                ? ''
                : `<button formaction="/admin/rbac/roles/${esc(
                    r.id
                  )}/delete" formnovalidate onclick="return confirm('Delete role ${esc(
                    r.name
                  )}?')" class="text-xs text-red-600 dark:text-red-400 hover:underline">delete</button>`
            }
          </form>
        </li>`
    )
    .join('')

  const verbList = verbs
    .map(
      (v) =>
        `<li class="flex items-center justify-between py-1.5 border-b border-zinc-950/5 dark:border-white/5">
          <code class="text-sm text-zinc-900 dark:text-white">${esc(v.name)}</code>
          ${
            v.is_system
              ? '<span class="rounded-full bg-zinc-100 dark:bg-white/10 px-2 py-0.5 text-[11px] text-zinc-500 dark:text-zinc-400">system</span>'
              : `<form method="post" action="/admin/rbac/verbs/${esc(
                  v.id
                )}/delete"><button class="text-xs text-red-600 dark:text-red-400 hover:underline">delete</button></form>`
          }
        </li>`
    )
    .join('')

  const btn = 'inline-flex items-center justify-center rounded-lg bg-zinc-950 dark:bg-white px-3.5 py-2 text-sm font-semibold text-white dark:text-zinc-950 hover:bg-zinc-800 dark:hover:bg-zinc-100'
  const inp = 'rounded-md bg-white dark:bg-white/5 px-3 py-1.5 text-sm text-zinc-950 dark:text-white outline outline-1 -outline-offset-1 outline-zinc-300 dark:outline-white/15'
  const card = 'rounded-xl bg-white dark:bg-zinc-900 ring-1 ring-zinc-950/5 dark:ring-white/10 p-5'

  const content = `
  ${TABS}
  <p class="text-sm text-zinc-500 dark:text-zinc-400 mb-4">Select roles to compare them side by side. Permission cells can be <strong>None</strong>, <strong>Own</strong>, or <strong>Any</strong>; <strong>Own</strong> is available for content and collection read/update/delete permissions and means the user can only act on content where they are the author. Wildcards: <code>*</code> = all resources, <code>collection:*</code> = all collections; <code>manage</code> implies all verbs. The <strong>All resources</strong> row selects a whole verb column for that role. <span class="text-amber-600 dark:text-amber-400">🔒 Administrator</span> is full-access and read-only.</p>

  <form method="get" action="/admin/rbac" class="flex flex-wrap items-center gap-2 mb-4">
    <input type="hidden" name="compare" value="1">
    <span class="text-xs text-zinc-500 dark:text-zinc-400 mr-1">Compare roles:</span>${roleTabs}
    <a href="/admin/rbac?compare=1" class="ml-auto inline-flex items-center gap-1 rounded-md border border-zinc-300 dark:border-white/15 px-3 py-1.5 text-sm font-medium text-zinc-700 dark:text-zinc-300 hover:bg-zinc-100 dark:hover:bg-white/10">Clear</a>
  </form>

  <form method="post" action="/admin/rbac/grants" class="${card} mb-8 overflow-x-auto">
    <input type="hidden" name="save_roles" value="${esc(saveRoleIds)}">
    <input type="hidden" name="compare" value="1">
    ${selectedRoles.map((r) => `<input type="hidden" name="view_roles" value="${esc(r.id)}">`).join('')}
    <div class="flex items-center justify-between mb-3">
      <h3 class="text-base font-semibold text-zinc-950 dark:text-white">Permission matrix <span class="text-sm font-normal text-zinc-500">(${selectedRoles.length} role${selectedRoles.length === 1 ? '' : 's'})</span></h3>
      <button type="submit" class="${btn}">Save changes</button>
    </div>
    ${
      selectedRoles.length === 0
        ? '<p class="text-sm text-zinc-500">Select one or more roles above to compare.</p>'
        : `<table class="w-full text-sm border-collapse">
      <thead>
        <tr class="border-b border-zinc-950/10 dark:border-white/10">
          <th rowspan="2" class="px-3 py-2 text-left text-xs font-semibold text-zinc-700 dark:text-zinc-300 sticky left-0 bg-white dark:bg-zinc-900">Resource</th>
          ${headRow1}
        </tr>
        <tr class="border-b border-zinc-950/10 dark:border-white/10">${headRow2}</tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>`
    }
  </form>

  <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
    <div class="${card}">
      <h3 class="text-base font-semibold text-zinc-950 dark:text-white mb-3">Roles</h3>
      <ul class="mb-4">${roleList}</ul>
      <form method="post" action="/admin/rbac/roles" class="flex flex-wrap gap-2">
        <input class="${inp}" type="text" name="name" placeholder="name (e.g. moderator)" required>
        <input class="${inp}" type="text" name="display_name" placeholder="Display name" required>
        <button class="${btn}">Add role</button>
      </form>
    </div>
    <div class="${card}">
      <h3 class="text-base font-semibold text-zinc-950 dark:text-white mb-3">Verbs</h3>
      <ul class="mb-4">${verbList}</ul>
      <form method="post" action="/admin/rbac/verbs" class="flex flex-wrap gap-2">
        <input class="${inp}" type="text" name="name" placeholder="custom verb (e.g. publish)" required>
        <button class="${btn}">Add verb</button>
      </form>
    </div>
  </div>

  <div class="${card}">
    <h3 class="text-base font-semibold text-zinc-950 dark:text-white mb-3">Live permission check</h3>
    <div class="flex flex-wrap items-center gap-2">
      <span class="text-sm text-zinc-500">resource</span><input class="${inp}" type="text" id="ck_res" value="collection:blog_posts">
      <span class="text-sm text-zinc-500">verb</span><input class="${inp}" type="text" id="ck_verb" value="update">
      <button type="button" class="${btn}" onclick="ckme()">Can I?</button>
      ${
        firstSelected
          ? `<button type="button" class="${btn}" onclick="ckrole()">Can "${esc(firstSelected.name)}"?</button>`
          : ''
      }
    </div>
    <pre id="out" class="mt-3 rounded-lg bg-zinc-950 text-lime-400 p-3 text-xs whitespace-pre-wrap">(results here)</pre>
  </div>

  <script>
    // "All resources" cascade — per role column: choosing Own/Any on the '*'
    // row selects (and locks) that role's whole verb column. Cells are radio
    // segmented switches (each its own group by name); drive .checked here.
    function cascade(role, verb){
      var master=document.querySelector('input[type=radio][data-res="*"][data-role="'+role+'"][data-verb="'+verb+'"]:checked');
      var val=master?master.value:'none';
      document.querySelectorAll('input[type=radio][data-role="'+role+'"][data-verb="'+verb+'"]:not([data-res="*"])').forEach(function(radio){
        if(val!=='none'){ radio.checked=(radio.value===val); radio.disabled=true; }
        else { radio.disabled=false; }
      });
    }
    document.querySelectorAll('input[type=radio][data-res="*"]').forEach(function(radio){
      radio.addEventListener('change', function(){ cascade(radio.dataset.role, radio.dataset.verb); });
    });
    document.querySelectorAll('input[type=radio][data-res="*"]:checked').forEach(function(radio){
      if(radio.value !== 'none' && !radio.disabled) cascade(radio.dataset.role, radio.dataset.verb);
    });
    var out=document.getElementById('out');
    function j(u){fetch(u,{credentials:'include'}).then(function(r){return r.text().then(function(t){out.textContent=r.status+' '+u+'\\n'+t;});});}
    function ckme(){j('/admin/rbac/check?resource='+encodeURIComponent(ck_res.value)+'&verb='+encodeURIComponent(ck_verb.value));}
    function ckrole(){j('/admin/rbac/check?role=${esc(firstSelected?.id || '')}&resource='+encodeURIComponent(ck_res.value)+'&verb='+encodeURIComponent(ck_verb.value));}
  </script>`

  const u = c.get('user') as { email?: string; role?: string } | undefined
  return c.html(
    renderAdminLayoutCatalyst({
      title: 'Roles & Permissions',
      pageTitle: 'Roles & Permissions',
      currentPath: '/admin/users',
      version: getCoreVersion(),
      user: u ? { name: u.email || 'Admin', email: u.email || '', role: u.role || 'admin' } : undefined,
      content,
    })
  )
})

adminRbacRoutes.post('/grants', async (c) => {
  const form = await c.req.formData()
  // Roles to persist (editable, non-admin) and roles to keep in view on redirect.
  const saveRoleIds = String(form.get('save_roles') || '').split(',').filter(Boolean)
  const viewRoleIds = form.getAll('view_roles').map((v) => String(v))

  // Collect scoped cells per role: key = g|<roleId>|<resource>|<verb>, value = none|own|any
  const pairsByRole = new Map<string, Array<{ resource: string; verb: string; scope: Exclude<PermissionScope, 'none'> }>>()
  for (const id of saveRoleIds) pairsByRole.set(id, [])
  for (const key of form.keys()) {
    if (!key.startsWith('g|')) continue
    const parts = key.split('|') // g | roleId | resource | verb
    if (parts.length < 4) continue
    const roleId = parts[1]!
    const verb = parts[parts.length - 1]!
    const resource = parts.slice(2, -1).join('|')
    const scope = String(form.get(key) || 'none')
    if (pairsByRole.has(roleId) && resource && verb && (scope === 'own' || scope === 'any')) {
      pairsByRole.get(roleId)!.push({ resource, verb, scope })
    }
  }

  const rbac = new RbacService(c.env.DB)
  for (const id of saveRoleIds) {
    await rbac.setRoleGrants(id, pairsByRole.get(id) || [])
  }

  const redirectRoleIds = viewRoleIds.length ? viewRoleIds : saveRoleIds
  const qs = [
    form.get('compare') === '1' ? 'compare=1' : '',
    ...redirectRoleIds.map((id) => `roles=${encodeURIComponent(id)}`),
  ].filter(Boolean).join('&')
  return c.redirect(`/admin/rbac${qs ? `?${qs}` : ''}`)
})

adminRbacRoutes.post('/roles', async (c) => {
  const form = await c.req.formData()
  const name = String(form.get('name') || '').trim()
  const displayName = String(form.get('display_name') || '').trim()
  if (name && displayName) {
    try {
      await new RbacService(c.env.DB).createRole(name, displayName)
    } catch { /* duplicate */ }
  }
  return c.redirect('/admin/rbac')
})

adminRbacRoutes.post('/roles/:id', async (c) => {
  const form = await c.req.formData()
  const displayName = String(form.get('display_name') || '').trim()
  const name = form.get('name') ? String(form.get('name')).trim() : undefined
  const description = String(form.get('description') || '').trim()
  if (displayName) {
    try {
      await new RbacService(c.env.DB).updateRole(c.req.param('id'), displayName, description, name)
    } catch { /* duplicate name */ }
  }
  return c.redirect(`/admin/rbac?role=${encodeURIComponent(c.req.param('id'))}`)
})

adminRbacRoutes.post('/roles/:id/delete', async (c) => {
  await new RbacService(c.env.DB).deleteRole(c.req.param('id'))
  return c.redirect('/admin/rbac')
})

adminRbacRoutes.post('/verbs', async (c) => {
  const form = await c.req.formData()
  const name = String(form.get('name') || '').trim()
  if (name) {
    try {
      await new RbacService(c.env.DB).createVerb(name)
    } catch { /* duplicate */ }
  }
  return c.redirect('/admin/rbac')
})

adminRbacRoutes.post('/verbs/:id/delete', async (c) => {
  await new RbacService(c.env.DB).deleteVerb(c.req.param('id'))
  return c.redirect('/admin/rbac')
})

adminRbacRoutes.get('/check', async (c) => {
  const rbac = new RbacService(c.env.DB)
  const resource = c.req.query('resource') || ''
  const verb = c.req.query('verb') || ''
  const roleId = c.req.query('role')
  if (roleId) {
    // Check a specific role by testing a synthetic membership.
    const grants = await rbac.getGrants()
    const roleGrants = grants.filter((g) => g.role_id === roleId)
    const matchingScopes = roleGrants
      .filter((g) =>
        (g.resource === '*' ||
          g.resource === resource ||
          (g.resource === 'collection:*' && resource.startsWith('collection:'))) &&
        (g.verb === '*' || g.verb === verb || g.verb === 'manage')
      )
      .map((g) => g.scope || 'any')
    const scope = matchingScopes.includes('any') ? 'any' : matchingScopes.includes('own') ? 'own' : 'none'
    return c.json({ role: roleId, resource, verb, allowed: scope !== 'none', scope })
  }
  const user = c.get('user') as { userId: string } | undefined
  if (!user) return c.json({ error: 'not signed in' }, 401)
  const scope = await rbac.getPermissionScope(user.userId, resource, verb)
  const perms = await rbac.permissionsForUser(user.userId)
  return c.json({ user: user.userId, resource, verb, allowed: scope !== 'none', scope, permissions: perms })
})
