// ── PCs (Kitty): avisos para la ventana de Kitty y scripts de PowerShell ──
// Elegir PCs con Kitty (sus fichas del inventario): una lista con casillas y «Todos»
async function pcPicker(title, intro, extra = '', ok = 'Aceptar', allowAll = true) {
  const kits = (await api('health')).filter(h => h.kind === 'kitty' && h.item).sort((a, b) => srcName(a).localeCompare(srcName(b)));
  const p = dialog(`<h3>${title}</h3><p>${intro}</p><div class="fields">${extra}
      <fieldset class="field" style="border:0;padding:0;margin:0"><legend class="small" style="font-weight:560;color:var(--tx2);margin-bottom:6px">PCs</legend>
        ${allowAll ? `<label style="display:flex;gap:8px;align-items:center;font-size:13.5px;margin-bottom:6px"><input type="checkbox" name="all" checked> Todos los PCs con Kitty</label>` : ''}
        <div class="gpick" id="pp-l" style="max-height:220px;overflow:auto">${kits.map(h => `<label><input type="checkbox" name="it" value="${+h.item}">${esc(srcName(h))}</label>`).join('') || '<span class="dim small">Ningún PC con Kitty todavía.</span>'}</div></fieldset></div>`, {ok});
  const d = document.querySelector('dialog[open]:last-of-type'), all = d.querySelector('[name=all]');
  const sync = () => d.querySelectorAll('[name=it]').forEach(c => c.disabled = !!all?.checked);
  if (all) { all.onchange = sync; sync(); }
  const f = await p; if (!f) return null;
  return {f, items: f.has('all') ? null : f.getAll('it').map(Number)};
}
const RUN_ST = {pendiente: ['', 'pendiente'], enviado: ['warn', 'ejecutándose'], hecho: ['ok', 'hecho'], error: ['bad', 'con error'], 'sin respuesta': ['bad', 'sin respuesta']};
const runPill = r => { const [c, t] = RUN_ST[r.state] || ['', r.state]; return `<span class="pill ${c}"><i></i>${t}${r.code != null && r.state !== 'hecho' ? ` (${r.code})` : ''}</span>`; };
// Ejecuciones con su salida, plegada
const runsList = rs => rs.length ? `<div class="rows">${rs.map(r => `<details class="run"><summary><b>${esc(r.name)}</b>${r.item_name ? ` <span class="dim">· ${esc(r.item_name)}</span>` : ''} ${runPill(r)}
    <span class="dim small" style="margin-left:auto">${esc(r.who || '')} · ${esc(ago(r.created))}</span></summary>
    <pre class="mono small" style="white-space:pre-wrap;max-height:320px;overflow:auto;margin:8px 0 0">${esc(r.output) || '<span class="dim">Sin salida todavía.</span>'}</pre></details>`).join('')}</div>`
  : '<p class="muted small">Ningún script ejecutado todavía.</p>';
// Lanzar un script: elige los PCs (sin «Todos»: se marcan a propósito)
async function scriptRun(s, items) {
  if (!items) {
    const r = await pcPicker(`Ejecutar «${esc(s.name)}»`, 'Kitty lo ejecuta como SYSTEM en cada PC en el próximo minuto (si está encendido) y su salida queda en la ficha del equipo.', '', 'Ejecutar', false);
    if (!r) return; items = r.items;
  }
  if (!items.length) return toast('Elige al menos un PC', 'bad');
  try { const r = await api(`scripts/${s.id}/run`, 'POST', {items}); toast(`Enviado a ${r.runs.length} ${r.runs.length === 1 ? 'PC' : 'PCs'}${r.skipped.length ? ` · ${r.skipped.length} sin Kitty` : ''}`); } catch {}
}

Object.assign(views, {
  async avisos() {
    crumbs([['PCs (Kitty)', '#/pcs'], ['Avisos']]);
    const [list, items] = await Promise.all([api('notices'), api('items')]), byId = Object.fromEntries(items.map(i => [i.id, i.name]));
    const live = n => date(n.until) > Date.now();
    app.innerHTML = head('Avisos en los PCs', 'Un mensaje arriba en la ventana de Kitty: «El correo estará caído de 14 a 15 h». Kitty se abre sola para enseñarlo.', ME.readonly ? '' : `<button class="btn pri" id="add">${ui('plus', 16)}Nuevo aviso</button>`)
      + tabs(TABS.pcs) + (list.length ? `<div class="card tbl-wrap"><table class="tbl"><thead><tr><th>Aviso</th><th>Para</th><th>Hasta</th><th class="hide-m">Quién</th><th></th></tr></thead>
        <tbody>${list.map(n => { const to = JSON.parse(n.items || '[]'); return `<tr class="${live(n) ? '' : 'dim'}"><td>${esc(n.text)}</td><td class="small">${to.length ? esc(to.map(i => byId[i] || '#' + i).join(', ')) : 'Todos'}</td>
          <td class="small" title="${esc(when(n.until))}">${live(n) ? esc(date(n.until).toLocaleString('es')) : 'terminado'}</td><td class="dim small hide-m">${esc(n.who || '')}</td>
          <td>${live(n) && !ME.readonly ? `<button class="btn ghost sm" data-del="${n.id}">Quitar</button>` : ''}</td></tr>`; }).join('')}</tbody></table></div>`
        : empty('bell', 'Ningún aviso', 'Avisa a todos los PCs, o a unos cuantos, de cortes y cambios: lo verán en Kitty sin abrir el correo.'));
    $('#add') && ($('#add').onclick = async () => {
      const r = await pcPicker('Nuevo aviso', 'Sale arriba en la ventana de Kitty, que se abre sola para enseñarlo.',
        `<div class="field"><label for="nv-t">Aviso</label><textarea id="nv-t" name="text" rows="3" maxlength="500" required placeholder="El correo estará caído de 14 a 15 h por mantenimiento."></textarea></div>
         <div class="field"><label for="nv-h">Se ve durante</label><select id="nv-h" name="hours">${[[2, '2 horas'], [8, '8 horas'], [24, '1 día'], [72, '3 días'], [168, '1 semana']].map(([v, t]) => `<option value="${v}"${v === 8 ? ' selected' : ''}>${t}</option>`).join('')}</select></div>`, 'Avisar');
      if (!r) return;
      if (r.items && !r.items.length) return toast('Elige al menos un PC', 'bad');
      try { await api('notices', 'POST', {text: r.f.get('text').trim(), hours: +r.f.get('hours'), ...(r.items ? {items: r.items} : {})}); } catch { return; }
      toast('Aviso enviado: los PCs lo verán en el próximo minuto'); route(false);
    });
    app.querySelectorAll('[data-del]').forEach(b => b.onclick = async () => { await api('notices/' + b.dataset.del, 'DELETE'); toast('Aviso quitado'); route(false); });
  },
  async scripts() {
    crumbs([['PCs (Kitty)', '#/pcs'], ['Scripts']]);
    if (!ME.admin) { app.innerHTML = empty('cog', 'Solo para administradores', 'Los scripts se ejecutan como SYSTEM en los PCs.'); return; }
    const [list, runs] = await Promise.all([api('scripts'), api('runs')]);
    app.innerHTML = head('Scripts de PowerShell', 'Kitty los ejecuta como SYSTEM en los PCs que elijas, y la salida queda en la ficha de cada equipo y aquí. Cada ejecución queda en Actividad.', `<button class="btn pri" id="add">${ui('plus', 16)}Nuevo script</button>`)
      + tabs(TABS.pcs) + (list.length ? `<div class="card tbl-wrap"><table class="tbl"><thead><tr><th>Script</th><th class="hide-m">Notas</th><th></th></tr></thead>
        <tbody>${list.map(s => `<tr data-id="${s.id}" tabindex="0"><td><b>${esc(s.name)}</b><div class="mono dim small" style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:420px">${esc(s.body.split('\n')[0])}</div></td>
          <td class="muted hide-m">${esc(s.notes)}</td><td><button class="btn sm" data-run="${s.id}">${ui('play', 14)}Ejecutar</button></td></tr>`).join('')}</tbody></table></div>`
        : empty('code', 'Ningún script todavía', 'Guarda aquí lo que repites en los PCs (limpiar la cola de impresión, forzar gpupdate, ver quién ha iniciado sesión…) y lánzalo en uno o en todos.'))
      + `<section class="card pad mt"><h3 class="card-t">${ui('clock', 15)}Últimas ejecuciones <span class="count">${runs.length}</span></h3>${runsList(runs.slice(0, 50))}</section>`;
    const edit = async (s = {}) => {
      const f = await dialog(`<h3>${s.id ? 'Editar script' : 'Nuevo script'}</h3><div class="fields">
        <div class="field"><label for="sc-n">Nombre</label><input id="sc-n" name="name" required maxlength="100" value="${esc(s.name || '')}" placeholder="Vaciar la cola de impresión" autofocus></div>
        <div class="field"><label for="sc-b">PowerShell <span class="dim">· se ejecuta como SYSTEM; «exit N» es su código</span></label><textarea id="sc-b" name="body" class="mono" rows="10" required spellcheck="false" placeholder="Stop-Service Spooler&#10;Remove-Item C:\\Windows\\System32\\spool\\PRINTERS\\* -Force&#10;Start-Service Spooler">${esc(s.body || '')}</textarea></div>
        <div class="field"><label for="sc-o">Notas</label><textarea id="sc-o" name="notes" rows="2" maxlength="2000">${esc(s.notes || '')}</textarea></div></div>`, {ok: 'Guardar'});
      if (!f) return;
      const d = {name: f.get('name').trim(), body: f.get('body'), notes: f.get('notes')};
      try { await (s.id ? api('scripts/' + s.id, 'PUT', d) : api('scripts', 'POST', d)); } catch { return; }
      toast('Guardado'); route(false);
    };
    $('#add').onclick = () => edit();
    app.querySelectorAll('[data-run]').forEach(b => b.onclick = e => { e.stopPropagation(); scriptRun(list.find(x => x.id === +b.dataset.run)); });
    app.querySelectorAll('tr[data-id]').forEach(tr => {
      const s = list.find(x => x.id === +tr.dataset.id);
      tr.onclick = () => menu(tr, [['Ejecutar…', () => scriptRun(s), {icon: 'play'}], ['Editar', () => edit(s), {icon: 'edit'}], '-',
        ['Borrar', async () => { if (await ask('¿Borrar este script?', `«${esc(s.name)}» se borra; sus ejecuciones se quedan con su salida.`, 'Borrar')) { await api('scripts/' + s.id, 'DELETE'); toast('Script borrado'); route(false); } }, {icon: 'trash', danger: true}]]);
      tr.onkeydown = ev => ev.key === 'Enter' && tr.onclick(ev);
    });
    if (runs.some(r => r.state === 'pendiente' || r.state === 'enviado')) { const t = setTimeout(() => route(false), 10000); cleanup = () => clearTimeout(t); }
  },
});
