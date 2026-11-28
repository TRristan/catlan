// ── Incidencias ──
const incId = id => 'INC-' + id; // para el seguimiento y para enlazarla con [[INC-n]]
const INC_STATUS = ['abierta', 'en curso', 'en espera', 'resuelta', 'cerrada'], INC_PRIO = ['baja', 'media', 'alta', 'crítica'];
const incOpen = n => !['resuelta', 'cerrada'].includes(n.status);
const incMine = n => n.assignee === ME?.id || (ME?.groups || []).includes(n.grp);
const statusPill = st => `<span class="pill ${{abierta: 'bad', 'en curso': 'warn', resuelta: 'ok'}[st] || ''}"><i></i>${esc(st)}</span>`;
const prioPill = p => `<span class="pill ${{'crítica': 'bad', alta: 'warn'}[p] || ''}"><i></i>${esc(p)}</span>`;
// El equipo de una incidencia, de un vistazo: si está encendido, su sistema y lo que dice Kitty de él
function pcCard(pc, h, fromKitty) {
  const i = h?.info || {}, on = h && h.state && h.state !== 'error', ram = h?.latest?.find(m => m.key === 'mem'), cpu = h?.latest?.find(m => m.key === 'cpu');
  const disk = h?.latest?.filter(m => m.key.startsWith('disk:')).sort((a, b) => b.value - a.value)[0];
  // el icono de su tipo, como en esquemas y racks («portátil» → laptop)
  const ic = Object.keys(ICONS).find(k => k === pc.kind || ICONS[k][0].toLowerCase() === (pc.kind || '').toLowerCase()) || 'pc';
  const row = (k, v) => v ? `<div class="pc-r"><span>${k}</span><b>${v}</b></div>` : '';
  return `<section class="card pcard" style="--i:0" aria-label="Equipo de la incidencia">
    <div class="pc-top"><span class="pc-ic${h ? (on ? ' on' : ' off') : ''}"><svg width="26" height="26" aria-hidden="true"><use href="#i-${ic}"/></svg></span>
      <div class="pc-n"><a href="#/inv/${+pc.id}"><b>${esc(pc.name)}</b></a>
        <small>${h ? `<i class="mdot ${on ? 'up' : 'down'}"></i>${on ? `Conectado · ${esc(ago(h.last))}` : 'Sin conexión'}` : esc(pc.kind || 'Equipo')}${fromKitty ? ' · avisó desde Kitty' : ''}</small></div></div>
    ${h ? `<div class="pc-kpi"><div><span>CPU</span><b>${cpu ? Math.round(cpu.value) + ' %' : '—'}</b></div><div><span>Memoria</span><b>${ram ? Math.round(ram.value) + ' %' : '—'}</b></div><div><span>${esc(disk?.label || 'Disco')}</span><b>${disk ? Math.round(disk.value) + ' %' : '—'}</b></div></div>` : ''}
    <div class="pc-rows">${row('Sistema', esc(osShort(i.descr)))}${row('IP', pc.ip && `<span class="mono">${esc(pc.ip)}</span>`)}${row('Encendido', i.uptime && 'hace ' + esc(upTxt(i.uptime)))}
      ${row('Seguridad', i.seclight && secPill(i))}${row('Parches', i.patch?.last && `<span class="pill ${daysTo(i.patch.last) < -30 ? 'bad' : ''}"><i></i>hace ${-daysTo(i.patch.last)} d</span>${i.patch.reboot ? ' <span class="pill warn"><i></i>reinicio</span>' : ''}`)}
      ${row('Ubicación', esc(pc.location))}</div>
    <div class="pc-acts">${h?.agent && on && !ME.readonly ? `<button class="btn sm pri" id="pc-rmt">${ui('screen', 15)}Control remoto</button>` : ''}
      <a class="btn sm" href="#/inv/${+pc.id}">${ui('box', 15)}Ficha</a>${h ? `<a class="btn sm ghost" href="#/salud/${+h.id}">${ui('pulse', 15)}Estado</a>` : ''}</div></section>`;
}
const optList = (list, cur, none) => (none ? `<option value="">${none}</option>` : '') + list.map(x => `<option value="${x.id ?? x}" ${(x.id ?? x) === cur ? 'selected' : ''}>${esc(x.name ?? x)}</option>`).join('');
async function incidentDialog(pre = {}) {
  const [users, groups, items] = await Promise.all([api('users'), api('groups'), api('items')]);
  const p = dialog(`<h3>${pre.parent ? `Nueva incidencia hija de ${incId(+pre.parent)}` : 'Nueva incidencia'}</h3>${pre.parent ? '<p>Cuando se resuelva la padre, esta se resolverá con ella.</p>' : ''}<div class="fields">
    <div class="field"><label for="i-t">Título</label><input id="i-t" name="title" required maxlength="200" value="${esc(pre.title || '')}" autofocus></div>
    <div class="field"><label for="i-b">Descripción <span class="dim">· opcional</span></label><textarea id="i-b" name="body" rows="4" placeholder="Qué pasa, desde cuándo, a quién afecta…"></textarea></div>
    <div class="fields two">
      <div class="field"><label for="i-p">Prioridad</label><select id="i-p" name="priority">${optList(INC_PRIO, pre.priority || 'media')}</select></div>
      <div class="field"><label for="i-i">Equipo</label><select id="i-i" name="item">${optList(items, pre.item, 'Ninguno')}</select></div>
      <div class="field"><label for="i-a">Asignar a</label><select id="i-a" name="assignee">${optList(users, pre.assignee, 'Nadie todavía')}</select></div>
      <div class="field"><label for="i-g">Grupo <span class="dim">· para trabajos de varias personas</span></label><select id="i-g" name="grp">${optList(groups, pre.grp, 'Ninguno')}</select></div></div></div>`, {ok: 'Crear incidencia'});
  richEditor(document.querySelector('dialog[open] #i-b'), Object.fromEntries(items.map(i => [i.id, i.name]))); // con el diálogo abierto: cerrado ya no está
  const f = await p;
  if (!f) return;
  const num = k => f.get(k) ? +f.get(k) : null;
  const n = await api('incidents', 'POST', {title: f.get('title').trim(), body: f.get('body'), priority: f.get('priority'), assignee: num('assignee'), grp: num('grp'), item: num('item'), parent: pre.parent || null});
  toast(`Incidencia ${incId(n.id)} creada`); location.hash = '#/inc/' + n.id;
}
async function groupDialog(g = {}, users) {
  const f = await dialog(`<h3>${g.id ? 'Editar grupo' : 'Nuevo grupo'}</h3><p>Para repartir incidencias entre varias personas (técnicos N1, N2…) y para dar permisos.</p><div class="fields">
    <div class="field"><label for="g-n">Nombre</label><input id="g-n" name="name" required maxlength="60" value="${esc(g.name || '')}" placeholder="Técnicos N1" autofocus></div>
    <div class="field"><label for="g-r">Permiso</label><select id="g-r" name="role"><option value="edit">Pueden editar</option><option value="view" ${g.role === 'view' ? 'selected' : ''}>Solo vista: ven todo, no cambian nada</option></select></div>
    <fieldset class="field" style="border:0;padding:0;margin:0"><legend style="font-size:12.5px;font-weight:560;color:var(--tx2);margin-bottom:6px">Miembros</legend>
      <div style="display:flex;flex-direction:column;gap:6px;max-height:220px;overflow:auto">${users.map(u => `<label style="display:flex;gap:8px;align-items:center;font-size:13.5px"><input type="checkbox" name="m" value="${u.id}" ${(g.members || []).includes(u.id) ? 'checked' : ''}>${esc(u.name)}${u.admin ? ' <span class="dim">· admin</span>' : ''}</label>`).join('')}</div></fieldset></div>`, {ok: 'Guardar'});
  if (!f) return false;
  const b = {name: f.get('name').trim(), role: f.get('role'), members: f.getAll('m').map(Number)};
  await (g.id ? api('groups/' + g.id, 'PUT', b) : api('groups', 'POST', b)); toast('Grupo guardado'); return true;
}
let incFilter = 'open';
const incOpenTree = new Set(); // padres desplegadas: se recuerdan al volver a la lista
