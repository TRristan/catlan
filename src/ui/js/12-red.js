// ── Red, estado de guardado y avisos ────────────────────
let pending = 0, syncT;
function sync(state) {
  const el = $('#sync'); clearTimeout(syncT);
  el.className = 'sync show ' + state;
  el.lastChild.textContent = {saving: 'Guardando…', saved: 'Guardado', error: 'Sin guardar'}[state];
  if (state === 'saved') syncT = setTimeout(() => el.classList.remove('show'), 1800);
}
// Auto-topología: catlan lee LLDP, CDP y la tabla MAC del switch y dibuja (o rehace) su esquema
async function autoTopo(sid) {
  toast('Leyendo LLDP, CDP y la tabla MAC del switch…');
  try {
    const r = await api(`sources/${sid}/topology`, 'POST'), n = r.neighbors.length;
    toast(`${n} ${n === 1 ? 'equipo conectado' : 'equipos conectados'} · ${r.neighbors.filter(x => x.item).length} del inventario`);
    location.hash === '#/maps/' + r.map ? route(false) : location.hash = '#/maps/' + r.map;
  } catch {} // el aviso con el motivo ya sale
}
async function autoTopoDialog() {
  const srcs = (await api('health')).filter(h => !['kitty', 'hikvision'].includes(h.kind));
  if (!srcs.length) return toast('Primero añade el switch en Hardware (por SNMP): catlan usará sus credenciales', 'bad');
  const f = await dialog(`<h3>Topología automática</h3><p>catlan lee del switch quién está conectado a cada puerto (vecinos LLDP y CDP, y su tabla MAC con la ARP para las IP) y lo dibuja en un esquema. Los equipos que estén en el inventario salen enlazados.</p>
    <div class="field"><label for="tp-s">Switch</label><select id="tp-s" name="src">${srcs.map(h => `<option value="${h.id}">${esc(srcName(h))} · ${esc(h.host)}</option>`).join('')}</select></div>
    <p class="small muted">En el switch tienen que estar activos LLDP o CDP y SNMP. Si el esquema ya existe, se rehace.</p>`, {ok: 'Dibujar'});
  if (f) autoTopo(f.get('src'));
}
// Guarda sin pisar a otro: si alguien lo cambió desde que lo abriste, pregunta. Tus cambios siguen en pantalla.
async function putFresh(path, body, seen) {
  try { return await api(path, 'PUT', {...body, _seen: seen}); }
  catch (e) {
    if (e.message !== '409') throw e;
    if (!await ask('Alguien lo ha cambiado mientras editabas', `${esc(e.info?.error || '')} Si guardas igualmente, tu versión sustituye a la suya (la suya queda en Actividad). Si no, recarga para ver sus cambios; los tuyos siguen en pantalla hasta que salgas.`, 'Guardar igualmente')) throw e;
    return api(path, 'PUT', body);
  }
}
async function api(path, method = 'GET', body, type = 'application/json') {
  const write = method !== 'GET';
  if (write) { pending++; sync('saving'); }
  let r;
  try { r = await fetch('/api/' + path, {method, body: body && type === 'application/json' ? JSON.stringify(body) : body, headers: body ? {'Content-Type': type} : {}}); }
  catch (e) { toast('Sin conexión con el servidor', 'bad'); if (write) sync('error'); throw e; }
  finally { if (write) pending--; }
  if (r.status === 401) { showLogin(); if (write) sync('error'); throw new Error(401); } // sesión caducada o cerrada en otro sitio
  if (!r.ok) {
    const e = await r.json().catch(() => ({}));
    if (!(r.status === 409 && body?._seen != null)) toast(e.error || r.statusText, 'bad'); // el conflicto lo pregunta putFresh
    if (write) sync('error'); throw Object.assign(new Error(r.status), {info: e});
  }
  if (write && !pending) sync('saved');
  return r.status === 204 ? null : r.json();
}
let undoLast = null; // el último borrado: Ctrl+Z lo deshace durante 10 s
async function undoDel(ids) {
  undoLast = null;
  const res = await Promise.allSettled(ids.map(id => api(`log/${id}/undo`, 'POST')));
  const ok = res.filter(r => r.status === 'fulfilled').length;
  if (ok) toast(ok > 1 ? `${ok} recuperados` : 'Recuperado');
  const one = res.length === 1 && res[0].value;
  if (one && ['item', 'page', 'map', 'rack', 'subnet'].includes(one.kind)) location.hash = `#/${KINDS[one.kind][1]}/${one.id}`; else route(false);
}
// Borra sin preguntar y ofrece deshacer: el borrado queda en Actividad con su foto y se recupera con el mismo id
async function delUndo(list, msg) {
  const ids = [];
  for (const [kind, path] of list) {
    try { await api(path, 'DELETE'); } catch { continue; }
    const l = await api(`log?kind=${kind}&ref=${path.split('/')[1]}`).catch(() => []);
    const e = l.find(x => x.action === 'borrar'); if (e) ids.push(e.id);
  }
  if (!ids.length) return 0;
  undoLast = {ids, at: Date.now()};
  const t = document.createElement('div');
  t.className = 'toast'; t.innerHTML = ui('check', 17) + `<span>${esc(msg)}</span><button class="undo">Deshacer <kbd style="opacity:.7">Ctrl+Z</kbd></button>`;
  t.querySelector('.undo').onclick = () => { t.remove(); undoDel(ids); };
  $('#toasts').append(t);
  setTimeout(() => { t.classList.add('out'); setTimeout(() => t.remove(), 300); }, 10000);
  return ids.length;
}
addEventListener('keydown', e => {
  if (!(e.ctrlKey || e.metaKey) || e.shiftKey || e.key.toLowerCase() !== 'z' || !undoLast || Date.now() - undoLast.at > 10000) return;
  if (e.target.closest?.('input,textarea,select,[contenteditable]')) return; // en un campo, Ctrl+Z es del campo
  e.preventDefault(); document.querySelectorAll('#toasts .undo').forEach(b => b.closest('.toast').remove()); undoDel(undoLast.ids);
});
// Mantenimiento programado: sin avisos de esos equipos (o de los del rack) entre dos horas
async function maintDialog(target, name) {
  const local = d => new Date(d - d.getTimezoneOffset() * 6e4).toISOString().slice(0, 16), now = new Date();
  const f = await dialog(`<h3>Programar mantenimiento</h3><p>${esc(name)}: mientras dure, catlan sigue comprobando pero no avisa ni suena. Vale para sus comprobaciones del monitor y de Salud.</p>
    <div class="fields two"><div class="field"><label for="m-f">Desde</label><input id="m-f" name="from" type="datetime-local" required value="${local(now)}"></div>
    <div class="field"><label for="m-t">Hasta</label><input id="m-t" name="to" type="datetime-local" required value="${local(new Date(+now + 2 * 36e5))}"></div></div>`, {ok: 'Programar'});
  if (!f) return;
  try {
    const r = await api('maintenance', 'POST', {...target, from: new Date(f.get('from')).toISOString(), to: new Date(f.get('to')).toISOString()});
    toast(r.muted ? `Mantenimiento programado: ${r.muted} ${r.muted === 1 ? 'comprobación' : 'comprobaciones'}` : 'Ninguna comprobación vigila esos equipos', r.muted ? undefined : 'bad');
    pollMonitor();
  } catch {}
}
function toast(msg, kind = '') {
  const t = document.createElement('div');
  t.className = 'toast ' + kind; t.innerHTML = ui(kind === 'bad' ? 'alert' : 'check', 17) + `<span>${esc(msg)}</span>`;
  $('#toasts').append(t);
  setTimeout(() => { t.classList.add('out'); setTimeout(() => t.remove(), 300); }, 2800);
}
// Diálogo modal; devuelve los datos del formulario o null si se cancela
function dialog(html, {ok = 'Aceptar', danger = false} = {}) {
  const d = document.createElement('dialog');
  d.innerHTML = `<form method="dialog">${html}<div class="dlg-a"><button class="btn ${danger ? 'danger-fill' : 'pri'}" value="ok">${ok}</button><button class="btn ghost" value="" formnovalidate>Cancelar</button></div></form>`;
  document.body.append(d);
  d.querySelectorAll('.file input').forEach(i => i.onchange = () => i.nextElementSibling.querySelector('em').textContent = i.files[0]?.name || 'Elegir imagen…');
  d.showModal();
  return new Promise(res => d.addEventListener('close', () => { res(d.returnValue === 'ok' ? new FormData(d.querySelector('form')) : null); setTimeout(() => d.remove(), 50); }));
}
const ask = (title, text, ok = 'Borrar') => dialog(`<h3>${title}</h3><p>${text}</p>`, {ok, danger: true});
// Menú desplegable anclado a un botón
let openMenu = null;
function closeMenu() {
  if (!openMenu) return;
  const {m, btn} = openMenu; openMenu = null;
  btn.setAttribute('aria-expanded', 'false');
  m.classList.add('out'); setTimeout(() => m.remove(), 140);
}
function menu(btn, items) {
  if (openMenu?.btn === btn) return closeMenu();
  closeMenu();
  const m = document.createElement('div');
  m.className = 'menu'; m.setAttribute('role', 'menu');
  m.innerHTML = items.map((it, i) => it === '-' ? '<hr>' : `<button role="menuitem" data-i="${i}" class="${it[2]?.danger ? 'danger' : ''}">${it[2]?.icon ? ui(it[2].icon, 17) : ''}${esc(it[0])}</button>`).join('');
  document.body.append(m);
  const r = btn.getBoundingClientRect(), w = m.offsetWidth, h = m.offsetHeight;
  const left = Math.max(8, Math.min(r.right - w, innerWidth - w - 8)), up = r.bottom + h + 12 > innerHeight && r.top > h + 12;
  Object.assign(m.style, {left: left + 'px', top: (up ? r.top - h - 6 : r.bottom + 6) + 'px'});
  m.style.setProperty('--ox', `${r.left + r.width / 2 - left}px ${up ? '100%' : '0'}`);
  btn.setAttribute('aria-expanded', 'true');
  openMenu = {m, btn};
  m.onclick = e => { const b = e.target.closest('[data-i]'); if (b) { closeMenu(); items[+b.dataset.i][1](); } };
  m.onkeydown = e => {
    const bs = [...m.querySelectorAll('button')], i = bs.indexOf(document.activeElement);
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); bs[(i + (e.key === 'ArrowDown' ? 1 : -1) + bs.length) % bs.length].focus(); }
    if (e.key === 'Escape' || e.key === 'Tab') { closeMenu(); btn.focus(); }
  };
  m.querySelector('button')?.focus({preventScroll: true});
}
addEventListener('pointerdown', e => { if (openMenu && !openMenu.m.contains(e.target) && !openMenu.btn.contains(e.target)) closeMenu(); });
addEventListener('resize', closeMenu);
// Plegables y segmentados
const collapsible = (label, body, {open = false, mini = false} = {}) =>
  `<div class="coll${open ? ' open' : ''}${mini ? ' mini' : ''}"><button class="coll-btn" aria-expanded="${open}">${label}${ui('chev', 15).replace('class="ic"', 'class="ic chev"')}</button><div class="coll-body"><div>${body}</div></div></div>`;
document.addEventListener('click', e => {
  const b = e.target.closest('.coll-btn'); if (!b) return;
  b.setAttribute('aria-expanded', b.parentElement.classList.toggle('open'));
});
function seg(el) {
  const on = el.querySelector('.on'); if (!on) return;
  el.style.setProperty('--x', on.offsetLeft - 3 + 'px'); el.style.setProperty('--w', on.offsetWidth + 'px');
}
async function copy(text) {
  try { await navigator.clipboard.writeText(text); }
  catch { // http en LAN: sin API de portapapeles
    const t = Object.assign(document.createElement('textarea'), {value: text}); document.body.append(t); t.select(); document.execCommand('copy'); t.remove();
  }
  toast(`Copiado ${text}`);
}

