// ── Texto ───────────────────────────────────────────────
// Markdown mínimo: títulos, listas, código, negrita, cursiva, enlaces, imágenes subidas a catlan, [[#id]] (equipo), [[INC-n]] (incidencia) y [[Página]]
function md(src, names = {}) {
  const inline = s => String(s).split(/(`[^`]+`)/).map((part, k) => k % 2 ? `<code>${esc(part.slice(1, -1))}</code>` : esc(part) // el código, tal cual
    .replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>')
    .replace(/\*([^*]+)\*/g, '<i>$1</i>')
    .replace(/\[\[#(\d+)\]\]/g, (_, n) => n in names ? `<a class="ref" href="#/inv/${n}">${esc(names[n])}</a>` : `<s title="equipo borrado">#${n}</s>`)
    .replace(/\[\[INC-(\d+)\]\]/gi, (_, n) => `<a class="iref" href="#/inc/${+n}">${incId(+n)}</a>`)
    .replace(/\[\[([^\]]+)\]\]/g, (_, t) => `<a href="#/p/${encodeURIComponent(t)}">${t}</a>`)
    // solo imágenes subidas a catlan: una de fuera avisaría a otra web de quién lee la página
    .replace(/!\[([^\]]*)\]\((\/api\/files\/\d+)\)/g, (_, t, u) => `<img src="${u}" alt="${t}" loading="lazy">`)
    .replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (m, t, u) => /^(https?:|\/|#)/.test(u) ? `<a href="${u}" target="_blank" rel="noopener">${t}</a>` : m)).join('');
  let out = '', list = false, code = null;
  for (const line of (src || '').split('\n')) {
    if (line.startsWith('```')) { if (code === null) code = ''; else { out += `<pre><code>${esc(code)}</code></pre>`; code = null; } continue; }
    if (code !== null) { code += line + '\n'; continue; }
    const ul = line.match(/^\s*[-*] (.*)/), ol = line.match(/^\s*\d+\. (.*)/), li = ul || ol, kind = ul ? 'ul' : ol ? 'ol' : '';
    if (list && list !== kind) { out += `</${list}>`; list = false; }
    if (li && !list) { out += `<${kind}>`; list = kind; }
    const h = line.match(/^(#{1,4}) (.*)/);
    if (li) out += `<li>${inline(li[1])}</li>`;
    else if (h) out += `<h${h[1].length + 1}>${inline(h[2])}</h${h[1].length + 1}>`;
    else if (line.trim()) out += `<p>${inline(line)}</p>`;
  }
  return out + (list ? `</${list}>` : '') + (code !== null ? `<pre><code>${esc(code)}</code></pre>` : '');
}
const excerpt = s => (s || '').replace(/!\[[^\]]*\]\([^)]*\)/g, '').replace(/^#+\s/gm, '').replace(/[*`>\[\]_]/g, '').replace(/\s+/g, ' ').trim().slice(0, 160);
const date = ts => new Date(ts.replace(' ', 'T') + 'Z'); // SQLite guarda UTC
const when = ts => ts ? date(ts).toLocaleString() : '';
const rtf = new Intl.RelativeTimeFormat('es', {numeric: 'auto'});
function ago(ts) {
  if (!ts) return '';
  const s = (date(ts) - Date.now()) / 1000;
  for (const [u, n] of [['year', 31536000], ['month', 2592000], ['week', 604800], ['day', 86400], ['hour', 3600], ['minute', 60]])
    if (Math.abs(s) >= n) return rtf.format(Math.round(s / n), u);
  return 'ahora mismo';
}
const names = async () => Object.fromEntries((await api('items')).map(i => [i.id, i.name]));

// ── Historial ───────────────────────────────────────────
const KINDS = {page: ['Wiki', 'wiki', 'book'], item: ['Equipo', 'inv', 'box'], map: ['Esquema', 'maps', 'nodes'], rack: ['Rack', 'racks', 'rack'], check: ['Monitor', 'monitor', 'signal'], source: ['Hardware', 'salud', 'thermo'], user: ['Usuario', 'users', 'user'], group: ['Grupo', 'users', 'users'], incident: ['Incidencia', 'inc', 'ticket'], agent: ['Kitty', 'inv', 'box'], expiry: ['Caducidad', 'cad', 'clock'], subnet: ['Red', 'redes', 'net'], db: ['Opciones', 'opts', 'cog'], alerts: ['Avisos', 'opts', 'bell'], sso: ['Inicio de sesión', 'opts', 'key'], notice: ['Aviso a los PCs', 'avisos', 'bell'], script: ['Script', 'scripts', 'code'], software: ['Inventario de programas', 'apps', 'box']};
const VERB = {crear: 'creó', editar: 'editó', borrar: 'borró', aceptar: 'aceptó', rechazar: 'rechazó', olvidar: 'olvidó', vaciar: 'borró', descargar: 'descargó', ejecutar: 'ejecutó un script en', encender: 'encendió'};
const NOUN = {page: 'la página', item: 'el equipo', map: 'el esquema', rack: 'el rack', check: 'la vigilancia de', source: 'la lectura de', agent: 'el Kitty de'};
// Fotos de perfil: nombre (en minúsculas) → {id, photo_v}; las carga boot() y se renuevan al cambiar la tuya
let PEOPLE = {};
const loadPeople = async () => { PEOPLE = Object.fromEntries((await api('users').catch(() => [])).map(u => [u.name.toLowerCase(), u])); };
// Quién hizo algo: Kitty con su gato, una persona con su foto o, sin ella, su inicial en un color propio
function avatar(who) {
  who ||= 'Alguien';
  if (who.startsWith('Kitty · ')) return `<span class="av kit" aria-hidden="true">${ui('cat', 22)}</span>`;
  const p = PEOPLE[who.toLowerCase()];
  if (p?.photo_v) return `<img class="av" src="/api/users/${+p.id}/photo?v=${+p.photo_v}" alt="" aria-hidden="true">`;
  return `<span class="av" style="--h:${hue(who)}" aria-hidden="true">${esc(who[0].toUpperCase())}</span>`;
}
const hue = s => Math.abs([...(s || '?')].reduce((h, c) => (h * 31 + c.charCodeAt(0)) | 0, 7)) % 360;
function entry(l) {
  const k = KINDS[l.kind] || [l.kind, ''], snap = JSON.parse(l.data || '{}'), who = l.who || 'Alguien';
  const target = l.action === 'borrar' ? `<b>${esc(l.name)}</b>` : `<a href="#/${k[1]}${['agent', 'db', 'alerts', 'sso'].includes(l.kind) ? '' : '/' + +l.ref}">${esc(l.name) || 'sin nombre'}</a>`;
  return `<li class="ev">${avatar(who)}
    <div><p><b>${esc(who)}</b> ${VERB[l.action] || esc(l.action)} ${NOUN[l.kind] || ''} ${target}</p>
    <time datetime="${esc(l.ts)}" title="${esc(when(l.ts))}">${esc(ago(l.ts))}</time>
    ${collapsible('Ver esta versión', `<pre class="snap">${esc(l.kind === 'page' ? snap.body : JSON.stringify(snap, null, 2))}</pre>`, {mini: true})}</div></li>`;
}
function timeline(rows, group = false) {
  if (!rows.length) return '<p class="muted small">Sin cambios registrados todavía.</p>';
  if (!group) return `<ol class="tl compact">${rows.map(entry).join('')}</ol>`;
  const days = new Map(), today = new Date().toDateString(), yest = new Date(Date.now() - 864e5).toDateString();
  for (const l of rows) { const d = date(l.ts).toDateString(); days.has(d) || days.set(d, []); days.get(d).push(l); }
  return [...days].map(([d, ls]) => `<h3 class="day">${d === today ? 'Hoy' : d === yest ? 'Ayer' : esc(new Date(d).toLocaleDateString('es', {weekday: 'long', day: 'numeric', month: 'long'}))}</h3><ol class="tl">${ls.map(entry).join('')}</ol>`).join('');
}

