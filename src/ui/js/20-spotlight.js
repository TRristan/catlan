// ── Spotlight (Alt+C): buscar en todo. W: wiki · U: equipos (Intro copia su UID) · T: incidencias ──
const SPOT_F = {w: ['Wiki', 'page'], u: ['Equipos', 'item'], t: ['Incidencias', 'incident']};
let spotEl = null;
async function spotlight() {
  if (spotEl) return spotEl.querySelector('input').focus();
  const back = document.activeElement, el = document.createElement('div');
  el.className = 'spot'; spotEl = el;
  el.innerHTML = `<div class="spot-p" role="dialog" aria-modal="true" aria-label="Buscar en catlan">
      <div class="spot-in">${ui('search', 18)}<span class="spot-f" hidden></span>
        <input role="combobox" aria-expanded="true" aria-controls="spot-l" aria-autocomplete="list" placeholder="Buscar en todo catlan…" spellcheck="false" autocomplete="off"><kbd>Esc</kbd></div>
      <div class="spot-l" id="spot-l" role="listbox" aria-label="Resultados"><p class="spot-e">Cargando…</p></div>
      <div class="spot-h"><span><kbd>W:</kbd> wiki</span><span><kbd>U:</kbd> equipos, Intro copia el UID</span><span><kbd>T:</kbd> incidencias</span><span class="dim">↑↓ · Intro</span></div></div>`;
  document.body.append(el);
  const inp = el.querySelector('input'), list = el.querySelector('.spot-l'), chip = el.querySelector('.spot-f');
  anim(el, [{opacity: 0}, {opacity: 1}], {duration: 220, easing: 'ease-out'});
  anim(el.firstChild, [{opacity: 0, transform: 'translateY(-14px) scale(.96)'}, {opacity: 1, transform: 'none'}], {duration: 460, easing: 'cubic-bezier(.34,1.45,.64,1)'});
  inp.focus();
  const close = () => {
    if (!spotEl) return; spotEl = null;
    const a = anim(el, [{opacity: 1}, {opacity: 0}], {duration: 160, easing: 'ease-in', fill: 'forwards'});
    anim(el.firstChild, [{transform: 'none'}, {transform: 'translateY(-8px) scale(.97)'}], {duration: 160, easing: 'ease-in', fill: 'forwards'});
    a ? a.finished.then(() => el.remove()) : el.remove();
    back?.focus?.();
  };
  el.onclick = e => { if (e.target === el) close(); };
  // Todo lo buscable, ya con su icono, enlace y textos donde buscar
  const [pages, items, incs, maps] = await Promise.all([api('pages'), api('items'), api('incidents').catch(() => []), api('maps')]);
  const all = [
    ...pages.map(x => ({k: 'page', ic: 'book', t: x.title || 'Sin título', sub: excerpt(x.body), more: x.body, go: '#/wiki/' + x.id})),
    ...items.map(x => ({k: 'item', ic: 'box', t: x.name || 'Sin nombre', sub: [x.kind, x.ip, x.location].filter(Boolean).join(' · '), uid: `[[#${x.id}]]`,
      more: [x.ip, x.serial, x.location, x.kind, x.status, x.notes, '#' + x.id].join(' '), go: '#/inv/' + x.id})),
    ...incs.map(x => ({k: 'incident', ic: 'ticket', t: `${incId(x.id)} ${x.title}`, sub: [x.status, x.priority, x.assignee_name, x.item_name].filter(Boolean).join(' · '), more: x.body, go: '#/inc/' + x.id, done: !incOpen(x)})),
    ...maps.map(x => ({k: x.type === 'rack' ? 'rack' : 'map', ic: x.type === 'rack' ? 'rack' : 'nodes', t: x.name, sub: x.type === 'rack' ? 'Rack' : 'Esquema', more: '', go: `#/${x.type === 'rack' ? 'racks' : 'maps'}/${x.id}`})),
    ...(monData?.checks || []).map(x => ({k: 'check', ic: 'signal', t: monName(x), sub: `Monitor · ${x.host}`, more: x.host, go: '#/monitor'}))];
  const GROUP = {page: 'Wiki', item: 'Equipos', incident: 'Incidencias', map: 'Esquemas', rack: 'Racks', check: 'Monitor'};
  let res = [], act = 0, mode = '';
  const mark = (t, q) => { const i = q ? t.toLowerCase().indexOf(q) : -1; return i < 0 ? esc(t) : esc(t.slice(0, i)) + `<mark>${esc(t.slice(i, i + q.length))}</mark>` + esc(t.slice(i + q.length)); };
  const paint = () => {
    const m = /^\s*([wut])\s*:\s*/i.exec(inp.value), q = inp.value.slice(m ? m[0].length : 0).toLowerCase().trim();
    mode = m ? m[1].toLowerCase() : '';
    chip.hidden = !mode; chip.textContent = mode ? SPOT_F[mode][0] : '';
    const pool = mode ? all.filter(x => x.k === SPOT_F[mode][1]) : all;
    res = q ? pool.map(x => { const t = x.t.toLowerCase(), r = t.startsWith(q) ? 0 : t.includes(q) ? 1 : (x.sub + ' ' + (x.more || '')).toLowerCase().includes(q) ? 2 : -1; return [r, x]; })
        .filter(([r]) => r >= 0).sort((a, b) => a[0] - b[0] || a[1].done - b[1].done).map(([, x]) => x).slice(0, 40)
      : pool.filter(x => mode || x.k !== 'check').slice(0, mode ? 40 : 12);
    res.sort((a, b) => Object.keys(GROUP).indexOf(a.k) - Object.keys(GROUP).indexOf(b.k)); // agrupado por tipo
    act = Math.min(act, Math.max(0, res.length - 1));
    let g = '';
    list.innerHTML = res.length ? res.map((x, i) => (x.k !== g ? `<div class="spot-g" role="presentation">${GROUP[g = x.k]}</div>` : '')
      + `<div class="spot-o${i === act ? ' on' : ''}${x.done ? ' done' : ''}" role="option" id="so-${i}" data-i="${i}" aria-selected="${i === act}"><span class="spot-ic">${ui(x.ic, 16)}</span>
         <span class="spot-t"><b>${mark(x.t, q)}</b>${x.sub ? `<small>${esc(x.sub)}</small>` : ''}</span>
         ${x.uid ? `<button class="spot-uid" data-copy="${i}" title="Copiar el UID para enlazarlo">${ui('copy', 13)}<span class="mono">${esc(x.uid)}</span></button>` : ''}</div>`).join('')
      : `<p class="spot-e">${q ? `Nada coincide con «${esc(q)}»` : 'Nada por aquí todavía'}</p>`;
    inp.setAttribute('aria-activedescendant', res.length ? 'so-' + act : '');
  };
  const move = d => { if (!res.length) return; act = (act + d + res.length) % res.length; paint(); list.querySelector('.on')?.scrollIntoView({block: 'nearest'}); };
  const pickRes = (i, copyUid = mode === 'u') => {
    const x = res[i]; if (!x) return;
    if (copyUid && x.uid) { copy(x.uid); return close(); }
    close(); location.hash = x.go;
  };
  inp.oninput = () => { act = 0; paint(); };
  inp.onkeydown = e => {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); move(e.key === 'ArrowDown' ? 1 : -1); }
    else if (e.key === 'Enter') { e.preventDefault(); pickRes(act, mode === 'u' ? !e.shiftKey : false); } // en U:, Mayús+Intro abre la ficha
    else if (e.key === 'Escape') { e.preventDefault(); close(); }
    else if (e.key === 'Tab') e.preventDefault(); // el foco no sale del buscador
  };
  list.onclick = e => {
    const c = e.target.closest('[data-copy]'); if (c) { e.stopPropagation(); copy(res[+c.dataset.copy].uid); return close(); }
    const o = e.target.closest('[data-i]'); if (o) pickRes(+o.dataset.i, false);
  };
  list.onmousemove = e => { const o = e.target.closest('[data-i]'); if (o && +o.dataset.i !== act) { act = +o.dataset.i; list.querySelectorAll('.spot-o').forEach(x => x.classList.toggle('on', x === o)); } };
  paint();
}
// Contraseña provisional al azar (12 caracteres, sin los que se confunden: 0/O, 1/l/I)
const genPass = () => { const a = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789-'; return [...crypto.getRandomValues(new Uint32Array(12))].map(n => a[n % a.length]).join(''); };
// Contraseñas recién creadas: solo se ven ahora, así que se pueden copiar o descargar de una vez
function credsDialog(title, list) {
  const tsv = list.map(x => `${x.name}\t${x.pass}`).join('\n');
  const p = dialog(`<h3>${esc(title)}</h3><p>Apúntalas ahora: no se vuelven a mostrar. Cada persona tendrá que cambiar la suya al entrar.</p>
    <div class="creds"><table class="data-t"><thead><tr><th>Usuario</th><th>Contraseña provisional</th></tr></thead><tbody>${list.map(x => `<tr><td>${esc(x.name)}</td><td class="mono">${esc(x.pass)}</td></tr>`).join('')}</tbody></table></div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:12px"><button type="button" class="btn" id="cr-copy">${ui('copy', 15)}Copiar todo</button><button type="button" class="btn" id="cr-csv">${ui('box', 15)}Descargar CSV</button></div>`, {ok: 'Listo'});
  const d = document.querySelector('dialog[open]:last-of-type');
  d.querySelector('.dlg-a .ghost').remove();
  d.querySelector('#cr-copy').onclick = () => copy(tsv);
  d.querySelector('#cr-csv').onclick = () => {
    const a = Object.assign(document.createElement('a'), {href: URL.createObjectURL(new Blob(['\ufeffusuario;contraseña\n' + list.map(x => `${x.name};${x.pass}`).join('\n')], {type: 'text/csv'})), download: 'usuarios-catlan.csv'});
    a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  };
  return p;
}
// Alta de uno o muchos usuarios: una línea por persona («nombre» o «nombre;contraseña»), con vista previa en vivo
async function usersDialog(us, gs) {
  const taken = new Set(us.map(u => u.name.toLowerCase()));
  const p = dialog(`<h3>Añadir usuarios</h3><p>Una persona por línea; puedes pegar una columna de Excel. Si no pones contraseña, catlan genera una provisional.</p>
    <div class="fields"><div class="field"><label for="bu-t">Usuarios <span class="dim">· nombre, o nombre;contraseña</span></label>
      <textarea id="bu-t" name="lines" rows="6" class="mono" required placeholder="laura&#10;marcos&#10;ana.garcia;Bienvenida-2026" spellcheck="false"></textarea></div>
      <div class="bu-pv" id="bu-pv" aria-live="polite"></div>
      ${gs.length ? `<fieldset class="field" style="border:0;padding:0;margin:0"><legend class="small" style="font-weight:560;color:var(--tx2);margin-bottom:6px">Añadirlos a los grupos</legend>
        <div class="gpick">${gs.map(g => `<label><input type="checkbox" name="g" value="${g.id}">${esc(g.name)}${g.role === 'view' ? ' <span class="dim">· solo vista</span>' : ''}</label>`).join('')}</div></fieldset>` : ''}
      <label style="display:flex;align-items:center;gap:8px;font-size:13.5px"><input type="checkbox" name="admin"> Administradores <span class="dim">· pueden gestionar usuarios</span></label></div>`, {ok: 'Crear'});
  const d = document.querySelector('dialog[open]:last-of-type'), ta = d.querySelector('#bu-t'), ok = d.querySelector('.dlg-a .pri');
  let good = [];
  const parse = () => {
    const seen = new Set(), rows = ta.value.split(/\r?\n/).map(l => l.trim()).filter(Boolean).map(l => {
      const [name, pass] = l.split(/[;\t,]/).map(x => x.trim()), k = name.toLowerCase();
      const err = !/^[A-Za-z0-9._@-]{1,40}$/.test(name) ? 'nombre no válido' : taken.has(k) ? 'ya existe' : seen.has(k) ? 'repetido' : pass && pass.length < 8 ? 'contraseña corta' : '';
      seen.add(k); return {name, pass: pass || null, err};
    });
    good = rows.filter(r => !r.err);
    d.querySelector('#bu-pv').innerHTML = rows.length ? `<div class="small" style="margin-bottom:6px">${good.length} ${good.length === 1 ? 'nuevo' : 'nuevos'}${rows.length > good.length ? ` · <span class="t-bad">${rows.length - good.length} con errores</span>` : ''}</div>`
      + rows.map(r => `<span class="uchip${r.err ? ' bad' : ''}" title="${esc(r.err)}">${r.err ? ui('alert', 12) : ui('check', 12)}${esc(r.name)}${r.pass ? ' <span class="dim">· con contraseña</span>' : ''}${r.err ? ` <span>· ${esc(r.err)}</span>` : ''}</span>`).join('') : '';
    ta.setCustomValidity(rows.length > good.length ? 'Corrige o quita las líneas en rojo' : '');
    ok.textContent = good.length > 1 ? `Crear ${good.length} usuarios` : 'Crear';
  };
  ta.oninput = parse; parse();
  const f = await p; if (!f) return;
  const groups = f.getAll('g').map(Number), admin = f.has('admin');
  const made = await api('users', 'POST', good.map(r => ({name: r.name, ...(r.pass ? {pass: r.pass} : {}), groups, admin})));
  const gen = made.filter(u => u.pass);
  if (gen.length) await credsDialog(`${made.length} ${made.length === 1 ? 'usuario creado' : 'usuarios creados'}`, gen.map(u => ({name: u.name, pass: u.pass})));
  else toast(`${made.length} ${made.length === 1 ? 'usuario creado' : 'usuarios creados'}`);
  route(false);
}
// Alta de varios grupos: uno por línea
async function groupsDialog(gs, us) {
  const taken = new Set(gs.map(g => g.name.toLowerCase()));
  const p = dialog(`<h3>Añadir grupos</h3><p>Uno por línea, por ejemplo «Técnicos N1», «Técnicos N2», «Dirección». Luego eliges quién está en cada uno, o seleccionas usuarios y «Añadir a grupo».</p>
    <div class="fields"><div class="field"><label for="bg-t">Grupos</label><textarea id="bg-t" name="lines" rows="4" required placeholder="Técnicos N1&#10;Técnicos N2"></textarea></div>
      <div class="bu-pv" id="bg-pv"></div>
      <div class="field"><label for="bg-r">Permiso</label><select id="bg-r" name="role"><option value="edit">Pueden editar</option><option value="view">Solo vista: ven todo, no cambian nada</option></select></div></div>`, {ok: 'Crear'});
  const d = document.querySelector('dialog[open]:last-of-type'), ta = d.querySelector('#bg-t'), ok = d.querySelector('.dlg-a .pri');
  let good = [];
  ta.oninput = () => {
    const seen = new Set(), rows = ta.value.split(/\r?\n/).map(l => l.trim()).filter(Boolean).map(name => {
      const k = name.toLowerCase(), err = name.length > 60 ? 'demasiado largo' : taken.has(k) ? 'ya existe' : seen.has(k) ? 'repetido' : ''; seen.add(k); return {name, err}; });
    good = rows.filter(r => !r.err);
    d.querySelector('#bg-pv').innerHTML = rows.map(r => `<span class="uchip${r.err ? ' bad' : ''}">${r.err ? ui('alert', 12) : ui('check', 12)}${esc(r.name)}${r.err ? ` <span>· ${esc(r.err)}</span>` : ''}</span>`).join('');
    ta.setCustomValidity(rows.length > good.length ? 'Corrige o quita las líneas en rojo' : '');
    ok.textContent = good.length > 1 ? `Crear ${good.length} grupos` : 'Crear';
  };
  const f = await p; if (!f) return;
  const made = await api('groups', 'POST', good.map(g => ({name: g.name, role: f.get('role')})));
  toast(`${made.length} ${made.length === 1 ? 'grupo creado' : 'grupos creados'}`); route(false);
}
