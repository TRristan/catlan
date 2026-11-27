// ── Navegación ──────────────────────────────────────────
let redraw = null, onSave = null, cleanup = null; // redraw: la vista abierta se refiltra en sitio para no perder cambios sin guardar
function moveInd() {
  const a = $('#nav a.on'), ind = $('#nav .ind');
  ind.style.opacity = a ? 1 : 0;
  if (a) ind.style.transform = `translateY(${a.offsetTop}px)`;
}
async function route(animate = true) {
  cleanup?.(); redraw = onSave = cleanup = null; closeMenu(); hideCard();
  for (const k in cards) delete cards[k]; // al cambiar de vista, las fichas flotantes se vuelven a pedir: pueden haber cambiado
  document.querySelectorAll('dialog[open]').forEach(d => d.close());
  document.body.classList.remove('nav-open');
  const [, view = 'home', ...rest] = location.hash.split('/');
  const v = views[view] ? view : 'home';
  document.querySelectorAll('#nav a').forEach(a => { a.classList.toggle('on', a.dataset.v === ({p: 'wiki', discover: 'inv', cad: 'inv', sla: 'monitor', users: 'opts', sistema: 'opts', apps: 'opts', tablero: 'inc', remoto: 'salud'}[v] || v)); a.toggleAttribute('aria-current', a.classList.contains('on')); });
  moveInd();
  delete app.dataset.w;
  try { await views[v](rest.join('/') || null); }
  catch (e) { console.error(e); app.innerHTML = empty('alert', 'No se ha podido abrir', 'Puede que se haya borrado o que el servidor no responda.', `<a class="btn" href="#/${v === 'p' ? 'wiki' : v}">Volver</a>`); }
  app.classList.remove('in');
  if (animate) { void app.offsetWidth; app.classList.add('in'); scrollTo({top: 0}); }
}
addEventListener('hashchange', () => route());
$('#spot-btn').onclick = spotlight;
$('#new').onclick = e => menu(e.currentTarget, [['Página de wiki', create.page, {icon: 'book'}], ['Equipo', create.item, {icon: 'box'}], ['Equipos en serie…', itemSeries, {icon: 'layers'}], ['Esquema', create.map, {icon: 'nodes'}], ['Rack', create.rack, {icon: 'rack'}], ['Incidencia', () => incidentDialog(), {icon: 'ticket'}]]);
// Rueda del ratón sobre la barra lateral: sección anterior / siguiente
let wheelAcc = 0, wheelLock = 0;
$('#side').addEventListener('wheel', e => {
  if (matchMedia('(max-width:760px)').matches) return;
  e.preventDefault();
  if (Date.now() < wheelLock) return;
  wheelAcc += e.deltaY;
  if (Math.abs(wheelAcc) < 40) return;
  const links = [...document.querySelectorAll('#nav a')], i = links.findIndex(a => a.classList.contains('on'));
  const next = links[Math.max(0, Math.min(links.length - 1, i + Math.sign(wheelAcc)))];
  wheelAcc = 0; wheelLock = Date.now() + 420; // un paso por gesto, también con trackpad
  if (next && !next.classList.contains('on')) location.hash = next.getAttribute('href');
}, {passive: false});
// Ficha flotante al pasar por una referencia [[#id]]
const cards = {};
let hcard = null, hcT;
function hideCard() { clearTimeout(hcT); if (!hcard) return; const c = hcard; hcard = null; c.classList.add('out'); setTimeout(() => c.remove(), 140); }
function floatCard(anchor, html, key = '') {
  hideCard();
  const c = document.createElement('div');
  c.className = 'hcard'; c.setAttribute('role', 'tooltip'); c.dataset.for = key; c.innerHTML = html;
  (anchor.closest('dialog') || document.body).append(c); // un diálogo modal tapa todo lo que esté fuera de él
  const r = anchor.getBoundingClientRect(), w = c.offsetWidth, h = c.offsetHeight, up = r.bottom + h + 12 > innerHeight;
  const left = Math.max(8, Math.min(r.left, innerWidth - w - 8));
  Object.assign(c.style, {left: left + 'px', top: Math.max(8, up ? r.top - h - 8 : r.bottom + 8) + 'px'});
  c.style.setProperty('--ox', `${r.left - left + 12}px ${up ? '100%' : '0'}`);
  c.onmouseenter = () => clearTimeout(hcT); c.onmouseleave = () => { hcT = setTimeout(hideCard, 150); };
  hcard = c;
}
function rackCard(r, byId) {
  const d = r.data || {}, H = d.height || 42, devs = [...(d.devices || [])].sort((a, b) => b.u - a.u), used = devs.reduce((s, x) => s + x.h, 0);
  const u = Math.max(2, Math.min(6, Math.floor(230 / H))), name = x => x.label || byId[x.item]?.name || RACK_TYPES[x.t]?.[0] || x.t;
  return `<div class="hc-h"><span class="badge-ic">${ui('rack', 16)}</span><div><b>${esc(r.name)}</b><small>Rack · ${H}U · ${devs.length} ${devs.length === 1 ? 'equipo' : 'equipos'}</small></div></div>
    <div class="rk-prev"><div class="mini-rack" style="height:${H * u}px">${devs.map(x => `<i class="t-${esc(x.t)}" style="bottom:${(x.u - 1) * u}px;height:${Math.max(1, x.h * u - 1)}px"></i>`).join('')}</div>
      <ul>${devs.slice(0, 9).map(x => `<li><span class="mono dim">U${x.u}</span><span class="sw t-${esc(x.t)}"></span>${esc(name(x))}</li>`).join('') || '<li class="dim">Rack vacío</li>'}${devs.length > 9 ? `<li class="dim">y ${devs.length - 9} más…</li>` : ''}</ul></div>
    <div class="meter" style="width:100%"><i style="width:${Math.min(100, used / H * 100)}%"></i></div>
    <div class="hc-f">${used} de ${H} U ocupadas · doble clic para abrir el rack</div>`;
}
async function showCard(a) {
  const id = a.getAttribute('href').split('/').pop();
  if (!cards[id] || Date.now() - cards[id].at > 30000) // en la misma vista, como mucho 30 s sin refrescar
    cards[id] = {at: Date.now(), p: Promise.all([api('items/' + id), api(`items/${id}/refs`)]).catch(() => null)};
  const res = await cards[id].p;
  if (!res || !a.isConnected || !(a.matches(':hover') || a === document.activeElement)) return;
  const [i, refs] = res;
  const where = [...refs.maps.map(m => [m.type === 'rack' ? 'rack' : 'nodes', `${m.type === 'rack' ? 'Montado en' : 'En el esquema'} ${m.name}`]), ...refs.pages.map(p => ['book', `En la wiki: ${p.title}`])].slice(0, 4);
  floatCard(a, `<div class="hc-h"><span class="badge-ic">${ui('box', 16)}</span><div><b>${esc(i.name)}</b><small>${esc(i.kind) || 'Equipo'}</small></div>${i.status ? `<span class="pill ${tone(i.status)}"><i></i>${esc(i.status)}</span>` : ''}</div>
    <dl>${[['IP', i.ip, 'mono'], ['Ubicación', i.location], ['Nº serie', i.serial, 'mono']].filter(f => f[1]).map(([k, v, c]) => `<dt>${k}</dt><dd class="${c || ''}">${esc(v)}</dd>`).join('') || '<dt>Sin datos</dt><dd></dd>'}</dl>
    ${where.length ? `<div class="hc-w">${where.map(([ic, t]) => `<span>${ui(ic, 14)}${esc(t)}</span>`).join('')}</div>` : ''}
    <div class="hc-f">Clic para abrir la ficha · <span class="mono">[[#${i.id}]]</span></div>`);
}
const refOf = e => e.target.closest?.('a.ref');
document.addEventListener('mouseover', e => { const a = refOf(e); if (a) { clearTimeout(hcT); hcT = setTimeout(() => showCard(a), 160); } });
document.addEventListener('mouseout', e => { if (refOf(e)) { clearTimeout(hcT); hcT = setTimeout(hideCard, 150); } });
document.addEventListener('focusin', e => { const a = refOf(e); if (a) showCard(a); });
document.addEventListener('focusout', e => { if (refOf(e)) hideCard(); });
addEventListener('scroll', () => $('#top').classList.toggle('scrolled', scrollY > 4), {passive: true});
// Cajones: ajustes y menú móvil
// Tutorial: la primera vez de cada usuario en este navegador; se repite desde Ajustes → Ver el tutorial
const TOUR = [
  [null, '¡Bienvenido a catlan!', 'En un minuto te enseño dónde está cada cosa. Puedes saltarlo y volver a verlo cuando quieras desde Ajustes.'],
  ['[data-v="dash"]', 'Dashboard', 'Tu tablero: elige las tarjetas en «Personalizar», arrástralas y agrándalas. Es lo primero que ve todo el equipo.'],
  ['[data-v="wiki"]', 'Wiki', 'Procedimientos y documentación. Enlaza un equipo con [[#id]], una incidencia con [[INC-n]] y otra página con [[Nombre]]. Aquí tienes también la «Guía de catlan».'],
  ['[data-v="inv"]', 'Inventario', 'Todos tus equipos con IP, nº de serie, ubicación y garantía. Altas a mano, en serie o descubriendo la red; y «Añadir con Kitty» para los PCs.'],
  ['[data-v="maps"]', 'Esquemas', 'Diagramas de red con iconos. «Topología automática» lo dibuja solo leyendo LLDP, CDP y la tabla MAC de un switch.'],
  ['[data-v="racks"]', 'Racks', 'Tus armarios montados U a U, con bocas de switch, patch panel y PDU.'],
  ['[data-v="monitor"]', 'Monitor', 'Ping, puertos, webs, certificados y DNS cada pocos segundos. Si algo cae, avisa en pantalla, con su sonido y por tus canales.'],
  ['[data-v="salud"]', 'Salud', 'Temperaturas, discos, ventiladores y puertos de NAS y switches por SNMP, y los PCs con Kitty en «Kittens».'],
  ['[data-v="inc"]', 'Incidencias', 'Tickets con prioridad, estado y persona o grupo asignado. Los críticos avisan por tus canales. En la vista «Tablero» los cambias de estado arrastrándolos y llevas tus tareas y notas.'],
  ['[data-v="log"]', 'Actividad', 'Quién cambió qué y cuándo, con una foto de cada versión.'],
  ['#nav-opts', 'Opciones', 'Usuarios y grupos, avisos por correo, Telegram o webhook, copia de seguridad y la zona de peligro. Solo la ven los administradores.', 'admin'],
  ['#spot-btn', 'Buscar en todo', 'Alt+C o / desde cualquier sitio. Empieza por W: para la wiki, U: para equipos o T: para incidencias.'],
  ['#new', 'Nuevo', 'Crea cualquier cosa desde aquí: página, equipo, esquema, rack o incidencia. Lo que vigila el monitor se añade en Monitor → Vigilar.'],
  ['#open-settings', 'Ajustes', 'Tema, color y densidad (los sonidos de alerta están en Monitor). Y si se te olvida algo, aquí puedes volver a ver este tutorial.'],
  [null, 'Listo', 'Todo es local: catlan no envía tus datos a nadie que no configures tú. En la Wiki tienes la «Guía de catlan» con todos los detalles.', 'end'],
];
const tourKey = () => 'catlan-tour-' + (ME?.id || 0);
const tourSeen = () => { try { return !!localStorage.getItem(tourKey()); } catch { return true; } }; // sin almacenamiento: no insistir
function tour(i = 0) {
  const steps = TOUR.filter(t => t[3] !== 'admin' || ME?.admin);
  document.querySelector('#tour')?.remove();
  if (i >= steps.length) { try { localStorage.setItem(tourKey(), '1'); } catch {} return; }
  const [sel, title, text, extra] = steps[i], el = sel && document.querySelector(sel), r = el?.getBoundingClientRect();
  const shown = r && r.width > 0 && r.right > 0 && r.left < innerWidth && !el.closest('[hidden]'); // en el móvil el menú está plegado: tarjeta al centro
  const t = document.createElement('div');
  t.id = 'tour';
  t.innerHTML = `<div class="hole${shown ? '' : ' none'}"></div><div class="tcard" role="dialog" aria-modal="true" aria-labelledby="tour-t" aria-describedby="tour-x">
    <span class="tstep">${i + 1} de ${steps.length}</span><h3 id="tour-t">${esc(title)}</h3><p id="tour-x">${esc(text)}</p>
    <div class="tbtns">${i < steps.length - 1 ? '<button class="btn ghost sm" data-t="skip">Saltar</button>' : ''}<span class="grow"></span>
      ${i ? '<button class="btn sm" data-t="prev">Anterior</button>' : ''}${extra === 'end' ? '<button class="btn sm" data-t="guide">Abrir la guía</button>' : ''}
      <button class="btn pri sm" data-t="next">${i < steps.length - 1 ? 'Siguiente' : 'Terminar'}</button></div></div>`;
  document.body.append(t);
  const card = t.querySelector('.tcard'), hole = t.querySelector('.hole'), w = card.offsetWidth, h = card.offsetHeight, pad = 6;
  if (shown) {
    Object.assign(hole.style, {left: r.left - pad + 'px', top: r.top - pad + 'px', width: r.width + pad * 2 + 'px', height: r.height + pad * 2 + 'px'});
    const side = r.left < innerWidth / 3 && r.top > 60; // menú lateral: a su derecha; cabecera: debajo
    const left = side ? r.right + 16 : Math.min(Math.max(16, r.left + r.width / 2 - w / 2), innerWidth - w - 16);
    const top = side ? Math.min(Math.max(16, r.top + r.height / 2 - h / 2), innerHeight - h - 16) : r.bottom + 14;
    Object.assign(card.style, {left: Math.min(left, innerWidth - w - 16) + 'px', top: top + 'px'});
  } else Object.assign(card.style, {left: (innerWidth - w) / 2 + 'px', top: Math.max(16, (innerHeight - h) / 2) + 'px'});
  t.onclick = async e => {
    const b = e.target.closest('[data-t]'); if (!b) return;
    if (b.dataset.t === 'prev') return tour(i - 1);
    if (b.dataset.t === 'next') return tour(i + 1);
    tour(steps.length); // saltar o abrir la guía: no vuelve a salir solo
    if (b.dataset.t === 'guide') openGuide();
  };
  t.onkeydown = e => {
    if (e.key === 'Escape') tour(steps.length);
    else if (e.key === 'ArrowRight') tour(i + 1);
    else if (e.key === 'ArrowLeft' && i) tour(i - 1);
    else if (e.key === 'Tab') { // el foco no se escapa de la tarjeta
      const f = [...card.querySelectorAll('button')], k = f.indexOf(document.activeElement);
      e.preventDefault(); f[(k + (e.shiftKey ? -1 : 1) + f.length) % f.length].focus();
    }
  };
  card.querySelector('[data-t="next"]').focus();
}
async function openGuide() {
  const g = (await api('pages').catch(() => [])).find(x => x.title === 'Guía de catlan');
  if (g) location.hash = '#/wiki/' + g.id;
  else toast('No encuentro la «Guía de catlan» en la Wiki: se crea al instalar catlan, y quizá se borró', 'bad');
}
addEventListener('resize', () => { const t = document.querySelector('#tour'); if (t) tour(+t.querySelector('.tstep').textContent.split(' ')[0] - 1); });
function drawer(open) {
  document.body.classList.toggle('drawer-open', open);
  $('#settings').inert = !open;
  if (open) { requestAnimationFrame(() => document.querySelectorAll('#settings .seg').forEach(seg)); setTimeout(() => $('#close-settings').focus(), 50); }
}
$('#open-settings').onclick = () => drawer(true);
$('#tour-again').onclick = () => { drawer(false); setTimeout(() => tour(), 250); };
$('#guide-open').onclick = () => { drawer(false); openGuide(); };
$('#close-settings').onclick = () => drawer(false);
$('#open-nav').onclick = () => document.body.classList.add('nav-open');
$('#scrim').onclick = () => { drawer(false); document.body.classList.remove('nav-open'); };
$('#toggle-rail').onclick = () => { S.rail = !S.rail; applySettings(); };
$('#settings .swatches').innerHTML = ACCENTS.map(([n, c]) => `<button data-v="${c}" style="--c:${c}" title="${n}" aria-label="Acento ${n}"></button>`).join('');
$('#settings').onclick = e => {
  const sw = e.target.closest('.switch');
  if (sw) { S[sw.dataset.k] = !S[sw.dataset.k]; return applySettings(); }
  const b = e.target.closest('[data-v]'), g = b?.closest('[data-k]');
  if (g) { S[g.dataset.k] = b.dataset.v; applySettings(); }
};
$('#reset-settings').onclick = () => { S = {...DEF}; applySettings(); toast('Ajustes restablecidos'); };
addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') { e.preventDefault(); onSave?.(); return; }
  if (e.key === 'Escape') { closeMenu(); drawer(false); document.body.classList.remove('nav-open'); }
  if (e.altKey && e.code === 'KeyC' || e.key === '/' && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName) && !document.activeElement.isContentEditable) { e.preventDefault(); spotlight(); } // Alt+C (o /): Spotlight
});
matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => document.querySelectorAll('.seg').forEach(seg));
