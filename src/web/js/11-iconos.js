// ── Iconos ──────────────────────────────────────────────
// Interfaz (24x24, trazo fino)
const UI = {
  cog: '<path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/>',
  print: '<path d="M6 9V3h12v6"/><rect x="6" y="14" width="12" height="7" rx="1"/><path d="M6 18H4a1 1 0 0 1-1-1v-6a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v6a1 1 0 0 1-1 1h-2"/>',
  undo: '<path d="M9 14 4 9l5-5"/><path d="M4 9h10.5a5.5 5.5 0 0 1 0 11H11"/>',
  redo: '<path d="m15 14 5-5-5-5"/><path d="M20 9H9.5a5.5 5.5 0 0 0 0 11H13"/>',
  ul: '<path d="M9 6h11M9 12h11M9 18h11"/><circle cx="4.5" cy="6" r="1"/><circle cx="4.5" cy="12" r="1"/><circle cx="4.5" cy="18" r="1"/>',
  ol: '<path d="M10 6h10M10 12h10M10 18h10M4 4.5h1.5V9M4 9h3M4 14.5c0-.9.7-1.5 1.6-1.5.8 0 1.4.6 1.4 1.3 0 1.4-3 2-3 3.7h3"/>',
  code: '<path d="m8 8-4 4 4 4M16 8l4 4-4 4M13.5 5l-3 14"/>',
  ticket: '<path d="M4 7a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v2a2 2 0 0 0 0 4v2a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-2a2 2 0 0 0 0-4z"/><path d="M9 9.5h6M9 13.5h4"/>',
  users: '<circle cx="9" cy="8.5" r="3"/><path d="M3.5 19a5.5 5.5 0 0 1 11 0"/><path d="M15.5 5.6a3 3 0 0 1 0 5.8M17.5 14.2A5.5 5.5 0 0 1 20.5 19"/>',
  user: '<circle cx="12" cy="8" r="3.5"/><path d="M5 20a7 7 0 0 1 14 0"/>',
  screen: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8.5 20h7M12 16v4"/><path d="m10.5 7.5 4.5 2.5-4.5 2.5z"/>',
  kanban: '<rect x="3.5" y="3.5" width="5" height="13" rx="1.5"/><rect x="9.5" y="3.5" width="5" height="9" rx="1.5"/><rect x="15.5" y="3.5" width="5" height="17" rx="1.5"/>',
  grid: '<rect x="3.5" y="3.5" width="7" height="9" rx="2"/><rect x="13.5" y="3.5" width="7" height="5" rx="2"/><rect x="13.5" y="11.5" width="7" height="9" rx="2"/><rect x="3.5" y="15.5" width="7" height="5" rx="2"/>',
  bars: '<path d="M4 20h16"/><rect x="5.5" y="11" width="3" height="6" rx="1"/><rect x="10.5" y="5" width="3" height="12" rx="1"/><rect x="15.5" y="8" width="3" height="9" rx="1"/>',
  pie: '<path d="M12 3a9 9 0 1 0 9 9h-9z"/><path d="M15 3.4A9 9 0 0 1 20.6 9H15z"/>',
  line: '<path d="M4 19.5h16"/><path d="m4 15 4.5-5 4 3L20 6"/>',
  cat: '<path fill="currentColor" stroke="none" fill-rule="evenodd" transform="scale(.09375)" d="M40 32L96 88H160L216 32V164A56 56 0 0 1 160 220H96A56 56 0 0 1 40 164Z M118 146A22 22 0 1 0 74 146A22 22 0 1 0 118 146Z M144 135.0H176A11.0 11.0 0 0 1 176 157.0H144A11.0 11.0 0 0 1 144 135.0Z"/>',
  book: '<path d="M5 4.5A1.5 1.5 0 0 1 6.5 3H19v15H6.5A1.5 1.5 0 0 0 5 19.5z"/><path d="M5 19.5A1.5 1.5 0 0 0 6.5 21H19M9 7.5h6"/>',
  box: '<path d="M3.5 7.5 12 3l8.5 4.5v9L12 21l-8.5-4.5z"/><path d="M3.5 7.5 12 12l8.5-4.5M12 12v9"/>',
  nodes: '<circle cx="6" cy="6" r="2.5"/><circle cx="18" cy="6" r="2.5"/><circle cx="12" cy="18" r="2.5"/><path d="M8.5 6h7M7.2 8.2l3.6 7.6M16.8 8.2l-3.6 7.6"/>',
  rack: '<rect x="5" y="3" width="14" height="18" rx="2"/><path d="M5 9h14M5 15h14M8 6h.01M8 12h.01M8 18h.01"/>',
  pulse: '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
  sliders: '<path d="M4 6h9M17 6h3M4 12h3M11 12h9M4 18h11M19 18h1"/><circle cx="15" cy="6" r="2"/><circle cx="9" cy="12" r="2"/><circle cx="17" cy="18" r="2"/>',
  sidebar: '<rect x="3.5" y="4.5" width="17" height="15" rx="2.5"/><path d="M9 4.5v15M15 10l-2 2 2 2"/>',
  search: '<circle cx="11" cy="11" r="6.5"/><path d="m20 20-4.2-4.2"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  more: '<circle cx="5.5" cy="12" r="1.2" fill="currentColor"/><circle cx="12" cy="12" r="1.2" fill="currentColor"/><circle cx="18.5" cy="12" r="1.2" fill="currentColor"/>',
  chev: '<path d="m6 9 6 6 6-6"/>',
  x: '<path d="M6 6l12 12M18 6 6 18"/>',
  menu: '<path d="M4 7h16M4 12h16M4 17h10"/>',
  check: '<path d="m5 12.5 4.5 4.5L19 7.5"/>',
  alert: '<circle cx="12" cy="12" r="8.5"/><path d="M12 8v4.5M12 16h.01"/>',
  copy: '<rect x="8" y="8" width="12" height="12" rx="2.5"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/>',
  trash: '<path d="M4 7h16M10 11v6M14 11v6M6 7l1 12a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2l1-12M9 7V4.5h6V7"/>',
  edit: '<path d="M4 20h4L19 9a2.1 2.1 0 0 0-3-3L5 17z"/><path d="m14 7 3 3"/>',
  link: '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
  clock: '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>',
  layers: '<path d="m12 3 9 5-9 5-9-5z"/><path d="m3 13 9 5 9-5"/>',
  thermo: '<path d="M14 14.5V5a2 2 0 0 0-4 0v9.5a4 4 0 1 0 4 0z"/><path d="M12 10v6"/>',
  signal: '<path d="M5 19v-3M10 19v-7M15 19v-11M20 19V5"/>',
  bell: '<path d="M6 16v-5a6 6 0 0 1 12 0v5l1.5 2h-15z"/><path d="M10 20.5a2 2 0 0 0 4 0"/>',
  mail: '<rect x="3.5" y="5.5" width="17" height="13" rx="2"/><path d="m4 7 8 6 8-6"/>',
  play: '<path d="M8 5.5v13l10-6.5z"/>',
  eye: '<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z"/><circle cx="12" cy="12" r="2.5"/>',
  key: '<circle cx="7.5" cy="15.5" r="4"/><path d="M10.5 12.5 20 3M16 7l3 3M14 9l2 2"/>',
  net: '<rect x="8" y="3" width="8" height="6" rx="1.5"/><path d="M12 9v4M5 21v-4h14v4M12 13v8"/>',
};
const ui = (n, s = 18) => `<svg class="ic" width="${s}" height="${s}" aria-hidden="true"><use href="#u-${n}"/></svg>`;
// Equipos del montador (48x48, trazo = currentColor)
const ICONS = {
  router: ['Router', '<rect x="5" y="16" width="38" height="16" rx="8"/><path d="M15 24h18M29 20l4 4-4 4M19 20l-4 4 4 4"/>'],
  switch: ['Switch', '<rect x="4" y="15" width="40" height="18" rx="3"/><path d="M10 28h4M18 28h4M26 28h4M34 28h4M12 21h24"/>'],
  firewall: ['Firewall', '<rect x="6" y="10" width="36" height="28" rx="2"/><path d="M6 19h36M6 28h36M18 10v9M30 10v9M12 19v9M24 19v9M36 19v9M18 28v10M30 28v10"/>'],
  server: ['Servidor', '<rect x="10" y="6" width="28" height="11" rx="2"/><rect x="10" y="19" width="28" height="11" rx="2"/><rect x="10" y="32" width="28" height="11" rx="2"/><path d="M15 11.5h2M15 24.5h2M15 37.5h2M26 11.5h7M26 24.5h7M26 37.5h7"/>'],
  nas: ['NAS', '<ellipse cx="24" cy="12" rx="14" ry="5"/><path d="M10 12v24a14 5 0 0 0 28 0V12M10 24a14 5 0 0 0 28 0"/>'],
  pc: ['PC', '<rect x="6" y="8" width="36" height="24" rx="2"/><path d="M24 32v8M16 40h16"/>'],
  laptop: ['Portátil', '<rect x="10" y="10" width="28" height="20" rx="2"/><path d="M4 37h40l-4-7H8z"/>'],
  ap: ['Wi-Fi AP', '<circle cx="24" cy="36" r="2"/><path d="M17 30a10 10 0 0 1 14 0M11 24a18 18 0 0 1 26 0M5 18a26 26 0 0 1 38 0"/>'],
  printer: ['Impresora', '<rect x="13" y="6" width="22" height="10"/><rect x="6" y="16" width="36" height="16" rx="2"/><rect x="13" y="27" width="22" height="15"/>'],
  phone: ['Teléfono', '<rect x="15" y="4" width="18" height="40" rx="3"/><path d="M22 38h4"/>'],
  camera: ['Cámara', '<rect x="5" y="15" width="27" height="18" rx="3"/><path d="M32 21l11-6v18l-11-6"/>'],
  ups: ['SAI', '<rect x="8" y="12" width="30" height="24" rx="3"/><path d="M38 20h3v8h-3M25 16l-5 8h7l-5 8"/>'],
  cloud: ['Internet', '<path d="M14 36h22a8 8 0 0 0 0-16 12 12 0 0 0-23-2 9 9 0 0 0 1 18z"/>'],
  user: ['Usuario', '<circle cx="24" cy="16" r="7"/><path d="M10 41a14 14 0 0 1 28 0"/>'],
  rack: ['Rack', '<rect x="12" y="4" width="24" height="40" rx="2"/><path d="M12 14h24M12 24h24M12 34h24M17 9h2M17 19h2M17 29h2M17 39h2"/>'],
};
document.body.insertAdjacentHTML('beforeend', `<svg width="0" height="0" style="position:absolute" aria-hidden="true"><defs><symbol id="wm-catlan" viewBox="10 -36 541 137.5"><path fill="currentColor" fill-rule="evenodd" d="M100.95 16.90A51.5 51.5 0 1 0 100.95 83.10L85.63 70.25A31.5 31.5 0 1 1 85.63 29.75Z"/><path fill="currentColor" fill-rule="evenodd" d="M216.0 50A51.5 51.5 0 1 0 113.0 50A51.5 51.5 0 1 0 216.0 50Z M196.0 50A31.5 31.5 0 1 1 133.0 50A31.5 31.5 0 1 1 196.0 50Z"/><path fill="currentColor" fill-rule="evenodd" d="M196 0H216V100H196Z"/><path fill="currentColor" fill-rule="evenodd" d="M250 -36H270V100H250Z"/><path fill="currentColor" fill-rule="evenodd" d="M228 0H292V18H228Z"/><path fill="currentColor" fill-rule="evenodd" d="M306 -36H326V100H306Z"/><path fill="currentColor" fill-rule="evenodd" d="M443.0 50A51.5 51.5 0 1 0 340.0 50A51.5 51.5 0 1 0 443.0 50Z M423.0 50A31.5 31.5 0 1 1 360.0 50A31.5 31.5 0 1 1 423.0 50Z"/><path fill="currentColor" fill-rule="evenodd" d="M423 0H443V100H423Z"/><path fill="currentColor" fill-rule="evenodd" d="M461 0H481V100H461Z"/><path fill="currentColor" fill-rule="evenodd" d="M461 45A45 45 0 0 1 551 45V100H531V45A25 25 0 0 0 481 45Z"/></symbol>${
  Object.entries(UI).map(([k, p]) => `<symbol id="u-${k}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">${p}</symbol>`).join('')}${
  Object.entries(ICONS).map(([k, [, p]]) => `<symbol id="i-${k}" viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">${p}</symbol>`).join('')}</defs></svg>`);
// Tipos montables en rack: [nombre, U por defecto]. Los que coinciden con ICONS usan su icono.
const RACK_TYPES = {server: ['Servidor', 2], switch: ['Switch', 1], patch: ['Patch panel', 1], router: ['Router', 1], firewall: ['Firewall', 1],
  nas: ['Almacenamiento', 2], ups: ['SAI', 2], pdu: ['PDU', 1], kvm: ['KVM', 1], tray: ['Bandeja', 1], blank: ['Panel ciego', 1], other: ['Otro', 1]};
const PORT_OPTS = [4, 8, 12, 16, 24, 48], SFP_OPTS = [0, 2, 4, 8];
const hasPorts = t => t === 'switch' || t === 'patch' || t === 'pdu';
const nPorts = x => x.ports || (x.t === 'pdu' ? 8 : 24);
const pw = (x, plural) => x.t === 'pdu' ? (plural ? 'enchufes' : 'enchufe') : (plural ? 'bocas' : 'boca'); // la PDU tiene enchufes, no bocas
const sfpCount = x => x.t === 'switch' ? (x.sfp ?? 2) : 0;
// Claves de boca: números para cobre, "s1", "s2"… para SFP
const pkey = v => /^s/.test(v) ? v : +v;
const portName = (p, x) => /^s/.test(p) ? `SFP ${String(p).slice(1)}` : `${x?.t === 'pdu' ? 'Enchufe' : 'Boca'} ${p}`;
const portSeq = x => [...Array.from({length: nPorts(x)}, (_, i) => i + 1), ...Array.from({length: sfpCount(x)}, (_, i) => 's' + (i + 1))];
// Series: {n} = número, {nn}/{nnn} = con ceros (01, 001)
const series = (t, i) => t.replace(/\{(n+)\}/g, (_, w) => String(i).padStart(w.length, '0'));
// [[#id]] dentro de notas: texto plano con el nombre, o enlace con ficha flotante
const refName = (s, byId = {}) => String(s ?? '').replace(/\[\[#(\d+)\]\]/g, (_, n) => byId[n]?.name ?? `#${n}`);
const refHTML = (s, byId = {}) => esc(s).replace(/\[\[#(\d+)\]\]/g, (_, n) => byId[n] ? `<a class="ref" href="#/inv/${n}">${esc(byId[n].name)}</a>` : `<s title="equipo borrado">#${n}</s>`);
// Bocas: impares arriba y pares abajo, como en los equipos reales
const portGrid = n => { const rows = n >= 16 ? 2 : 1, cols = Math.ceil(n / rows);
  return {rows, cols, order: Array.from({length: n}, (_, i) => rows === 2 ? (i < cols ? i * 2 + 1 : (i - cols) * 2 + 2) : i + 1)}; };
// Frontal de un equipo de rack según su tipo
function face(x, name, ip, byId) {
  const head = `${ICONS[x.t] ? `<svg width="15" height="15" aria-hidden="true"><use href="#i-${x.t}"/></svg>` : ''}<span class="dn">${esc(name)}</span><span class="dm">${x.h}U${ip ? ' · ' + esc(ip) : ''}</span>`;
  const led = '<span class="led"></span>', pm = x.pmap || {};
  const tip = p => esc(portName(p, x) + (pm[p] ? ' → ' + refName(pm[p], byId) : ' · libre'));
  if (hasPorts(x.t)) {
    const {rows, cols, order} = portGrid(nPorts(x)), sfp = portSeq(x).filter(p => /^s/.test(p));
    return head + `<span class="pts" style="--cols:${cols};--rows:${rows}">${order.map(p => `<i class="pt${pm[p] ? ' on' : ''}" data-p="${p}" title="${tip(p)}"></i>`).join('')}</span>`
      + (sfp.length ? `<span class="sfp" style="--k:${Math.ceil(sfp.length / (sfp.length > 2 ? 2 : 1))}">${sfp.map(p => `<i class="sf${pm[p] ? ' on' : ''}" data-p="${p}" title="${tip(p)}"></i>`).join('')}</span>` : '')
      + (x.t === 'switch' || x.t === 'pdu' ? led : '');
  }
  return head + ({
    server: '<span class="bays"></span>' + led, nas: '<span class="bays big"></span>' + led,
    ups: '<span class="lcd">100%</span><span class="bars"><i></i><i></i><i></i><i></i><i></i></span>',     router: '<span class="mports" style="--n:4"></span>' + led, firewall: '<span class="mports" style="--n:8"></span>' + led, kvm: '<span class="mports" style="--n:8"></span>' + led,
    tray: '<span class="shelf"></span>', blank: '<span class="vent"></span>'}[x.t] ?? led);
}
// Diálogo centrado con todas las bocas: clic en una y escribe a qué va
function portsDialog(x, title, start, byId, onChange) {
  const n = nPorts(x), seq = portSeq(x), sfp = seq.slice(n), {rows, cols, order} = portGrid(n);
  const half = Math.ceil(sfp.length / (sfp.length > 2 ? 2 : 1));
  x.pmap ||= {};
  let cur = seq.find(p => String(p) === String(start)) ?? 1;
  const d = document.createElement('dialog');
  d.className = 'ports-dlg';
  d.innerHTML = `<div class="pd"><header class="pd-h"><div><h3>${esc(title)}</h3><p class="muted small">${RACK_TYPES[x.t][0]} · ${n} ${pw(x, 1)}${sfp.length ? ` + ${sfp.length} SFP` : ''} · <span id="pd-c"></span></p></div>
      <button class="btn icon ghost" id="pd-x" aria-label="Cerrar">${ui('x')}</button></header>
    <div class="pd-face t-${x.t}"><div class="pd-cu" style="--cols:${cols}">${order.map((p, i) => `<button class="pp${rows === 2 && i >= cols ? ' bottom' : ''}" data-p="${p}" aria-label="${portName(p, x)}"><span>${p}</span><i></i></button>`).join('')}</div>
      ${sfp.length ? `<div class="pd-sfp" style="--cols:${half}">${sfp.map((p, i) => `<button class="pp sfp${sfp.length > 2 && i >= half ? ' bottom' : ''}" data-p="${p}" aria-label="${portName(p, x)}"><span>${p.toUpperCase()}</span><i></i></button>`).join('')}</div>` : ''}</div>
    <div class="pd-ed"><label for="pd-in"><span id="pd-n"></span> →</label><input id="pd-in" list="pd-items" placeholder="${x.t === 'pdu' ? '¿Qué se enchufa? ESXi-01 fuente A, o el [[#id]] de un equipo' : '¿A qué va? Puesto 12, o el [[#id]] de un equipo'}" autocomplete="off">
      <button class="btn" id="pd-next" title="Siguiente (Intro)">Siguiente ${ui('chev', 14).replace('class="ic"', 'class="ic" style="transform:rotate(-90deg)"')}</button></div>
    <div class="pd-ref" id="pd-ref"></div>
    <div class="pd-ser">${collapsible(`${ui('layers', 15)}Rellenar en serie`, `<div class="ser">
        <div class="field"><label for="sr-a">Desde ${pw(x)}</label><input id="sr-a" type="number" min="1" max="${n}" value="1" class="mono"></div>
        <div class="field"><label for="sr-b">Hasta</label><input id="sr-b" type="number" min="1" max="${n}" value="${n}" class="mono"></div>
        <div class="field grow"><label for="sr-t">Texto</label><input id="sr-t" placeholder="${x.t === 'pdu' ? 'Servidor {n}' : 'Oficina mesa {n}'}"></div>
        <div class="field"><label for="sr-s">Empieza en</label><input id="sr-s" type="number" value="1" class="mono"></div>
        <button class="btn pri" id="sr-go">Aplicar</button><button class="btn ghost" id="sr-clr">Vaciar rango</button></div>
      <p class="muted small" id="sr-pv"></p>`)}</div>
    <div class="pd-list" id="pd-list"></div>
    <datalist id="pd-items">${Object.values(byId).map(i => `<option value="[[#${i.id}]]">${esc(i.name)}${i.ip ? ' · ' + esc(i.ip) : ''}</option>`).join('')}</datalist></div>`;
  document.body.append(d);
  const $d = s => d.querySelector(s), inp = $d('#pd-in');
  const paint = () => {
    d.querySelectorAll('.pp').forEach(b => { const p = pkey(b.dataset.p); b.classList.toggle('on', !!x.pmap[p]); b.classList.toggle('cur', p === cur); b.title = portName(p, x) + (x.pmap[p] ? ' → ' + refName(x.pmap[p], byId) : ' · libre'); });
    const used = seq.filter(p => x.pmap[p]);
    $d('#pd-c').textContent = `${used.length} anotad${x.t === 'pdu' ? 'os' : 'as'} · ${seq.length - used.length} libres`;
    $d('#pd-list').innerHTML = used.length ? `<table>${used.map(p => `<tr data-p="${p}"><td>${portName(p, x)}</td><td>${refHTML(x.pmap[p], byId)}</td></tr>`).join('')}</table>`
      : `<p class="muted small" style="margin:14px 0 0">Ningún${x.t === 'pdu' ? ' enchufe anotado' : 'a boca anotada'} todavía.</p>`;
  };
  // Si la nota lleva [[#id]], muestra a qué equipo corresponde
  const refInfo = () => {
    const ids = [...inp.value.matchAll(/\[\[#(\d+)\]\]/g)].map(m => byId[m[1]]).filter(Boolean);
    $d('#pd-ref').innerHTML = ids.map(i => `<span>${ui('box', 14)}<a class="ref" href="#/inv/${i.id}">${esc(i.name)}</a>${[esc(i.kind), i.ip && `<span class="mono">${esc(i.ip)}</span>`, esc(i.location)].filter(Boolean).join(' · ')}</span>`).join('');
  };
  const go = p => { cur = p; $d('#pd-n').textContent = portName(p, x); inp.value = x.pmap[p] || ''; paint(); refInfo(); inp.focus(); inp.select(); };
  const step = k => go(seq[(seq.indexOf(cur) + k + seq.length) % seq.length]);
  d.onclick = e => { const b = e.target.closest('[data-p]'); if (b && !e.target.closest('a')) go(pkey(b.dataset.p)); };
  inp.oninput = () => { inp.value.trim() ? x.pmap[cur] = inp.value : delete x.pmap[cur]; paint(); refInfo(); onChange(); };
  inp.onkeydown = e => { if (e.key === 'Enter') { e.preventDefault(); step(e.shiftKey ? -1 : 1); } };
  $d('#pd-next').onclick = () => step(1);
  // Rellenar en serie sobre un rango de bocas de cobre
  const range = () => { const a = Math.max(1, Math.min(n, +$d('#sr-a').value || 1)), b = Math.max(1, Math.min(n, +$d('#sr-b').value || n)); return [Math.min(a, b), Math.max(a, b)]; };
  const preview = () => {
    const [a, b] = range(), t = $d('#sr-t').value, s = +$d('#sr-s').value || 0;
    $d('#sr-pv').innerHTML = t ? `${portName(a, x)} → <b>${esc(series(t, s))}</b>${b > a ? ` · … · ${portName(b, x)} → <b>${esc(series(t, s + b - a))}</b>` : ''}` : '<code>{n}</code> es el número; <code>{nn}</code> o <code>{nnn}</code> rellena con ceros (01, 001). Sin <code>{n}</code> pone el mismo texto en todas.';
  };
  ['#sr-a', '#sr-b', '#sr-t', '#sr-s'].forEach(s => $d(s).oninput = preview);
  $d('#sr-go').onclick = () => {
    const [a, b] = range(), t = $d('#sr-t').value, s = +$d('#sr-s').value || 0;
    if (!t.trim()) { shake($d('#sr-t')); return $d('#sr-t').focus(); }
    for (let p = a; p <= b; p++) x.pmap[p] = series(t, s + p - a);
    onChange(); go(cur); toast(`${b - a + 1} ${pw(x, 1)} rellenad${x.t === 'pdu' ? 'os' : 'as'}`);
    $d('#sr-a').value = Math.min(n, b + 1); $d('#sr-s').value = 1; $d('#sr-t').value = ''; preview(); // listo para la siguiente tanda
  };
  $d('#sr-clr').onclick = () => { const [a, b] = range(); for (let p = a; p <= b; p++) delete x.pmap[p]; onChange(); go(cur); toast(`${x.t === 'pdu' ? 'Enchufes' : 'Bocas'} ${a}–${b} vaciad${x.t === 'pdu' ? 'os' : 'as'}`); };
  $d('#pd-x').onclick = () => d.close();
  d.addEventListener('close', () => { onChange(true); setTimeout(() => d.remove(), 50); });
  preview(); d.showModal(); go(cur);
}
// Alta de equipos en serie: PC-{nnn} × 100, IP consecutiva opcional
async function itemSeries() {
  const p = dialog(`<h3>Añadir equipos en serie</h3><p>Crea muchos equipos de golpe: portátiles, tablets, PCs de un aula…</p>
    <div class="fields two"><div class="field full"><label for="s-n">Nombre</label><input id="s-n" name="name" value="PC-{nnn}" class="mono" required></div>
      <div class="field"><label for="s-c">Cantidad</label><input id="s-c" name="count" type="number" min="1" max="500" value="20" class="mono"></div>
      <div class="field"><label for="s-s">Empieza en</label><input id="s-s" name="start" type="number" value="1" class="mono"></div>
      <div class="field"><label for="s-k">Tipo</label><input id="s-k" name="kind" list="s-dk" placeholder="pc"></div>
      <div class="field"><label for="s-st">Estado</label><input id="s-st" name="status" list="s-ds" placeholder="activo"></div>
      <div class="field"><label for="s-l">Ubicación</label><input id="s-l" name="location" placeholder="Aula 3"></div>
      <div class="field"><label for="s-ip">IP inicial <span class="dim">· opcional</span></label><input id="s-ip" name="ip" placeholder="10.0.30.101" class="mono"></div>
      <p class="field full muted small" id="s-pv" style="margin:0"></p></div>
    <datalist id="s-dk">${Object.values(ICONS).map(([n]) => `<option value="${n.toLowerCase()}">`).join('')}</datalist><datalist id="s-ds">${STATUSES.map(s => `<option value="${s}">`).join('')}</datalist>`, {ok: 'Crear equipos'});
  const d = document.querySelector('dialog[open]:last-of-type'), v = k => d.querySelector(`[name=${k}]`).value;
  const build = () => {
    const c = Math.round(+v('count')), s = Math.round(+v('start') || 0), ip = v('ip').trim(), m = ip.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})$/);
    if (!(c >= 1 && c <= 500)) return 'La cantidad va de 1 a 500.';
    if (ip && !m) return 'La IP inicial no es válida (ej. 10.0.30.101).';
    if (m && +m[2] + c - 1 > 254) return `Con ${c} equipos la IP pasaría de .254.`;
    return Array.from({length: c}, (_, i) => ({name: series(v('name'), s + i), kind: v('kind'), status: v('status'), location: v('location'), ip: m ? m[1] + (+m[2] + i) : ''}));
  };
  const pv = () => { const r = build(); d.querySelector('#s-pv').innerHTML = typeof r === 'string' ? `<span style="color:var(--bad)">${r}</span>`
    : `${r.length} equipos: <b class="mono">${esc(r[0].name)}</b>${r[0].ip ? ` <span class="mono dim">${r[0].ip}</span>` : ''}${r.length > 1 ? ` … <b class="mono">${esc(r.at(-1).name)}</b>${r.at(-1).ip ? ` <span class="mono dim">${r.at(-1).ip}</span>` : ''}` : ''}`; };
  d.oninput = pv; pv();
  if (!await p) return;
  const r = build();
  if (typeof r === 'string') return toast(r, 'bad');
  await api('items', 'POST', r);
  toast(`${r.length} equipos creados`);
  location.hash === '#/inv' ? route(false) : location.hash = '#/inv';
}
const ITEM_FIELDS = [['name','Nombre'],['kind','Tipo'],['ip','IP'],['serial','Nº serie'],['location','Ubicación'],['status','Estado'],['warranty','Fin de garantía']];
const VERSION = '1.0';
// Días hasta una fecha AAAA-MM-DD (negativo: ya pasó). Por fecha local, sin horas.
const daysTo = d => Math.round((new Date(d + 'T00:00') - new Date(new Date().toDateString())) / 864e5);
const warrantyTxt = d => { const n = daysTo(d); return n < 0 ? `caducó hace ${-n} ${n === -1 ? 'día' : 'días'}` : n === 0 ? 'caduca hoy' : `caduca en ${n} ${n === 1 ? 'día' : 'días'}`; };
const STATUSES = ['activo', 'en stock', 'mantenimiento', 'averiado', 'baja'];
const tone = s => /activ|online|produc|en uso|operativ|^ok$/i.test(s) ? 'ok' : /baja|aver|roto|ca[ií]d|offline|retir/i.test(s) ? 'bad' : /manten|repar|pend|stock|almac/i.test(s) ? 'warn' : '';

