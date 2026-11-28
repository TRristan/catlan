// ── Piezas de página ────────────────────────────────────
const head = (title, sub = '', actions = '') => `<header class="ph"><div><h1>${title}</h1>${sub ? `<p class="sub">${sub}</p>` : ''}</div><div class="ph-a">${actions}</div></header>`;
const empty = (icon, title, text = '', action = '') => `<div class="empty"><span class="empty-ic">${ui(icon, 28)}</span><h3>${title}</h3>${text ? `<p>${text}</p>` : ''}${action}</div>`;
// Pestañas de una sección: enlaces a sus rutas (el tercer campo, solo administradores); route() coloca la píldora
const tabs = list => `<nav class="seg tabs" aria-label="Pestañas">${list.filter(t => !t[2] || ME?.admin).map(([t, h]) => { const on = location.hash === h || location.hash.startsWith(h + '/');
  return `<a href="${h}"${on ? ' class="on" aria-current="page"' : ''}>${t}</a>`; }).join('')}</nav>`;
const TABS = {
  monitor: [['Comprobaciones', '#/monitor'], ['Disponibilidad', '#/sla'], ['Mantenimientos', '#/mant']],
  inv: [['Equipos', '#/inv'], ['Descubrir red', '#/discover']],
  pcs: [['PCs', '#/pcs'], ['Avisos', '#/avisos'], ['Scripts', '#/scripts', 1], ['Programas', '#/apps', 1]],
  admin: [['General', '#/opts'], ['Usuarios y grupos', '#/users'], ['Sistema', '#/sistema']],
};
const moreBtn = `<button class="btn icon ghost" id="more" aria-label="Más acciones" aria-haspopup="menu" aria-expanded="false">${ui('more')}</button>`;
function crumbs(list) {
  $('#crumbs').innerHTML = list.map(([t, h], i) => (i ? '<span class="sep">/</span>' : '') + (h ? `<a href="${h}">${esc(t)}</a>` : `<span class="cur">${esc(t)}</span>`)).join('');
  document.title = list.length ? `${list[list.length - 1][0]} · catlan` : 'catlan';
}
const qv = () => ''; // shortcut: el filtro por sección lo sustituye el Spotlight (Alt+C); si se echa de menos, volver a leer un campo aquí

// ── Crear ───────────────────────────────────────────────
const create = {
  async page() { location.hash = '#/wiki/' + (await api('pages', 'POST', {title: 'Nueva página'})).id + '/edit'; },
  async item() { location.hash = '#/inv/' + (await api('items', 'POST', {name: 'Nuevo equipo'})).id; },
  async map() {
    const f = await dialog(`<h3>Nuevo esquema</h3><p>Un lienzo para montar tu red con iconos y conectarlos.</p>
      <div class="fields"><div class="field"><label for="d-n">Nombre</label><input id="d-n" name="name" placeholder="Red planta 1" autofocus></div>
      <div class="field"><label>Plano de fondo <span class="dim">· opcional</span></label><label class="file"><input type="file" name="file" accept="image/*"><span>${ui('plus', 16)}<em>Elegir imagen…</em></span></label></div></div>`, {ok: 'Crear esquema'});
    if (!f) return;
    const file = f.get('file'), has = file && file.size;
    const m = await api('maps?name=' + encodeURIComponent(f.get('name') || (has ? file.name : 'Esquema')), 'POST', has ? file : undefined, has ? file.type : undefined);
    location.hash = '#/maps/' + m.id;
  },
  async rack() {
    const f = await dialog(`<h3>Nuevo rack</h3><p>Un rack simulado que montas U a U.</p>
      <div class="fields"><div class="field"><label for="d-n">Nombre</label><input id="d-n" name="name" placeholder="Rack CPD 1" autofocus></div>
      <div class="field"><label for="d-h">Altura (U)</label><input id="d-h" name="height" type="number" min="1" max="60" value="42"></div></div>`, {ok: 'Crear rack'});
    if (!f) return;
    const r = await api('maps?type=rack&name=' + encodeURIComponent(f.get('name') || 'Rack'), 'POST');
    await api('maps/' + r.id, 'PUT', {data: {type: 'rack', height: Math.min(60, Math.max(1, Math.round(+f.get('height')) || 42)), devices: []}}); // entero: el servidor lo exige
    location.hash = '#/racks/' + r.id;
  },
};

