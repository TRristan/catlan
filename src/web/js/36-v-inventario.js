Object.assign(views, {
  async inv(id) {
    if (!id) {
      const [items, agents, exps] = await Promise.all([api('items'), ME?.admin ? api('agents') : [], api('expiries')]), q = qv(), ro = ME.readonly, sel = new Set();
      const waiting = agents.filter(a => a.state !== 'adoptado'), code = c => c.toUpperCase().replace(/^(.{4})/, '$1-');
      const expiring = [...items.filter(i => i.warranty).map(i => ({name: i.name, date: i.warranty, kind: 'garantía', href: '#/inv/' + i.id})),
        ...exps.map(e => ({name: e.name, date: e.date, kind: e.kind, href: '#/cad'}))].filter(e => daysTo(e.date) <= 60).sort((a, b) => a.date.localeCompare(b.date));
      const hits = items.filter(i => Object.values(i).join(' ').toLowerCase().includes(q));
      crumbs([['Inventario']]);
      app.innerHTML = head('Inventario', items.length ? `${q ? `${hits.length} de ` : ''}${items.length} ${items.length === 1 ? 'equipo' : 'equipos'}` : 'Todo lo que tiene IP, número de serie o enchufe',
          `<a class="btn ghost" href="#/discover">${ui('search', 16)}Descubrir red</a><a class="btn ghost" href="#/cad">${ui('clock', 16)}Caducidades</a><button class="btn ghost" id="bulk">${ui('layers', 16)}En serie</button>${ME.admin ? `<button class="btn ghost" id="addpc">${ui('signal', 16)}Añadir con Kitty</button>` : ''}${items.length ? `<button class="btn ghost" id="csv">${ui('box', 16)}Exportar CSV</button>` : ''}` + (items.length ? `<button class="btn" id="add">${ui('plus', 16)}Nuevo equipo</button>` : ''))
        + (waiting.length ? `<section class="card" style="margin-bottom:16px"><div class="pad"><h3 class="card-t">Kitty pide entrar <span class="count">${waiting.length}</span></h3>
            <p class="muted small">Equipos con Kitty instalado que han encontrado este catlan. Acepta solo los que reconozcas: el código debe coincidir con el que mostró el instalador en ese equipo.</p></div>
            ${waiting.map(a => `<div data-ag="${a.id}" style="display:flex;flex-wrap:wrap;align-items:center;gap:8px 16px;padding:12px 16px;border-top:1px solid var(--line)">
              <div style="flex:1 1 220px;min-width:0"><b>${esc(a.name)}</b>${a.state === 'rechazado' ? ' <span class="pill bad"><i></i>rechazado</span>' : ''}
                <br><small class="dim"><span class="mono">${esc(a.ip)}</span> · ${esc(a.os)} · ${esc(ago(a.seen))}</small></div>
              <span class="mono" title="Código de este Kitty">${esc(code(a.code))}</span>
              <div style="display:flex;gap:8px"><button class="btn pri" data-st="adoptado">${ui('check', 15)}Aceptar</button>${a.state === 'pendiente' ? '<button class="btn ghost" data-st="rechazado">Rechazar</button>' : '<button class="btn ghost" data-st="del">Olvidar</button>'}</div></div>`).join('')}</section>` : '')
        + (expiring.length ? `<section class="card pad" style="margin-bottom:16px"><h3 class="card-t">${ui('clock', 15)}Caducan pronto <span class="count">${expiring.length}</span></h3>
            <ul class="rel">${expiring.map(e => `<li><a href="${e.href}"><span class="badge-ic">${ui(daysTo(e.date) < 0 ? 'alert' : 'clock', 16)}</span><span><b>${esc(e.name)}</b><small class="${daysTo(e.date) < 0 ? 't-bad' : ''}">${esc(e.kind)} · ${warrantyTxt(e.date)} · ${esc(new Date(e.date + 'T00:00').toLocaleDateString('es'))}</small></span></a></li>`).join('')}</ul></section>` : '')
        + (items.length ? `<div class="ufil"><input id="ifil" style="width:min(480px,100%)" type="search" placeholder="Filtrar por nombre, IP, tipo, ubicación, estado o nº de serie…" aria-label="Filtrar equipos" autocomplete="off"></div>` : '')
        + (hits.length ? `<div class="card tbl-wrap"><table class="tbl utbl itbl"><thead><tr>${ro ? '' : '<th style="width:36px"><input type="checkbox" id="uall" aria-label="Seleccionar todos"></th>'}<th>Nombre</th><th class="hide-m">Tipo</th><th>IP</th><th class="hide-m">Ubicación</th><th>Estado</th><th class="hide-m">Nº serie</th></tr></thead>
          <tbody class="stagger">${hits.map((i, k) => `<tr data-id="${i.id}" tabindex="0" style="--i:${Math.min(k, 14)}">${ro ? '' : `<td><input type="checkbox" class="usel" value="${i.id}" aria-label="Seleccionar ${esc(i.name)}"></td>`}<td><b>${esc(i.name)}</b></td><td class="muted hide-m">${esc(i.kind)}</td>
            <td class="mono">${esc(i.ip)}</td><td class="muted hide-m">${esc(i.location)}</td><td>${i.status ? `<span class="pill ${tone(i.status)}"><i></i>${esc(i.status)}</span>` : ''}</td>
            <td class="mono dim hide-m">${esc(i.serial)}</td></tr>`).join('')}</tbody></table></div>
          <div class="actionbar ubar" id="ubar" hidden><b id="ucount"></b><span class="grow"></span>
            <button class="btn" data-bulk="edit">${ui('edit', 15)}Cambiar…</button><button class="btn" data-bulk="maint">${ui('bell', 15)}Mantenimiento…</button>
            <button class="btn danger" data-bulk="del">${ui('trash', 15)}Borrar</button><button class="btn icon ghost" data-bulk="none" aria-label="Quitar la selección">${ui('x', 16)}</button></div>`
        : items.length ? empty('search', 'Sin resultados', `Ningún equipo coincide con «${esc(q)}».`)
        : empty('box', 'Inventario vacío', 'Añade switches, servidores, impresoras… y luego úsalos en esquemas y racks.', `<button class="btn pri" id="add">${ui('plus', 16)}Añadir el primer equipo</button>`));
      const rows = [...app.querySelectorAll('.itbl tbody tr')];
      $('#ifil') && ($('#ifil').oninput = e => { // filtro al vuelo sobre lo que ya hay en pantalla
        const t = e.target.value.trim().toLowerCase(), byId = Object.fromEntries(items.map(i => [i.id, [i.name, i.kind, i.ip, i.serial, i.location, i.status].join(' ').toLowerCase()]));
        rows.forEach(r => { r.hidden = !!t && !byId[r.dataset.id].includes(t); if (r.hidden) sel.delete(+r.dataset.id); });
        if (!ro) paintSel(); // lo que queda oculto deja de estar seleccionado: «Borrar» solo toca lo que se ve
      });
      $('#csv') && ($('#csv').onclick = () => {
        const cols = [['id', 'id'], ...ITEM_FIELDS, ['notes', 'Notas']], cell = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
        const csv = '\ufeff' + [cols.map(c => cell(c[1])).join(';'), ...items.map(i => cols.map(([k]) => cell(i[k])).join(';'))].join('\r\n');
        const a = Object.assign(document.createElement('a'), {href: URL.createObjectURL(new Blob([csv], {type: 'text/csv'})), download: `inventario-${new Date().toISOString().slice(0, 10)}.csv`});
        a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
      });
      rows.forEach(tr => { tr.onclick = e => e.target.closest('td:has(.usel)') || (location.hash = '#/inv/' + tr.dataset.id); tr.onkeydown = e => e.key === 'Enter' && e.target === tr && tr.click(); });
      const paintSel = () => {
        rows.forEach(r => { const on = sel.has(+r.dataset.id); r.querySelector('.usel').checked = on; r.classList.toggle('on', on); });
        const shown = rows.filter(r => !r.hidden).length;
        $('#uall').checked = !!shown && sel.size === shown; $('#uall').indeterminate = !!sel.size && sel.size < shown;
        $('#ubar').hidden = !sel.size; $('#ucount').textContent = `${sel.size} ${sel.size === 1 ? 'seleccionado' : 'seleccionados'}`;
      };
      let last = null; // mayúsculas + clic marca el tramo desde el anterior
      if (!ro && rows.length) {
        $('#uall').onchange = e => { rows.filter(r => !r.hidden).forEach(r => e.target.checked ? sel.add(+r.dataset.id) : sel.delete(+r.dataset.id)); paintSel(); };
        app.querySelector('.itbl tbody').onclick = e => {
          const c = e.target.closest('td:has(.usel)'); if (!c) return;
          const r = c.parentElement, on = e.target.matches('.usel') ? e.target.checked : !sel.has(+r.dataset.id);
          const span = e.shiftKey && last ? rows.slice(Math.min(rows.indexOf(last), rows.indexOf(r)), Math.max(rows.indexOf(last), rows.indexOf(r)) + 1) : [r];
          span.filter(x => !x.hidden).forEach(x => on ? sel.add(+x.dataset.id) : sel.delete(+x.dataset.id)); last = r; paintSel();
        };
        $('#ubar').onclick = async e => {
          const b = e.target.closest('[data-bulk]'); if (!b) return;
          if (b.dataset.bulk === 'none') { sel.clear(); return paintSel(); }
          const list = items.filter(i => sel.has(i.id));
          if (b.dataset.bulk === 'maint') return maintDialog({items: list.map(i => i.id)}, `${list.length} equipos`);
          if (b.dataset.bulk === 'edit') { // el mismo valor en un campo de todos los elegidos
            const f = await dialog(`<h3>Cambiar ${list.length} ${list.length === 1 ? 'equipo' : 'equipos'}</h3><div class="fields two">
              <div class="field"><label for="b-k">Campo</label><select id="b-k" name="k">${['location', 'status', 'kind', 'warranty'].map(k => `<option value="${k}">${ITEM_FIELDS.find(f => f[0] === k)[1]}</option>`).join('')}</select></div>
              <div class="field"><label for="b-v">Nuevo valor</label><input id="b-v" name="v" list="dl-bulk" autocomplete="off"></div></div>
              <datalist id="dl-bulk">${[...new Set(items.flatMap(i => [i.location, i.status, i.kind]).filter(Boolean))].map(v => `<option value="${esc(v)}">`).join('')}</datalist>
              <p class="muted small">Vacío lo borra. La fecha de garantía va como AAAA-MM-DD. Cada cambio queda en el historial de su equipo.</p>`, {ok: 'Cambiar'});
            if (!f) return;
            const res = await Promise.allSettled(list.map(i => api('items/' + i.id, 'PUT', {[f.get('k')]: f.get('v').trim()})));
            const bad = res.filter(r => r.status === 'rejected').length;
            toast(bad ? `${list.length - bad} cambiados, ${bad} fallaron` : `${list.length} cambiados`, bad ? 'bad' : undefined); sel.clear(); return route(false);
          }
          const n = await delUndo(list.map(i => ['item', 'items/' + i.id]), `${list.length} ${list.length === 1 ? 'equipo borrado' : 'equipos borrados'}`);
          if (n < list.length) toast(`${list.length - n} no se pudieron borrar`, 'bad');
          route(false);
        };
      }
      $('#add') && ($('#add').onclick = create.item);
      $('#bulk').onclick = itemSeries;
      $('#addpc') && ($('#addpc').onclick = async () => {
        // Por https y, con el certificado autofirmado, anclado a su huella: nadie en la red puede colar otro instalador
        const k = await fetch('/kitty.json').then(r => r.json()).catch(() => ({})), base = `https://${location.host}`;
        const tls = `[Net.ServicePointManager]::SecurityProtocol='Tls12';` + (k.pin ? `[Net.ServicePointManager]::ServerCertificateValidationCallback={param($s,$c)[BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($c.GetRawCertData())).Replace('-','') -eq '${k.pin}'};` : '');
        const cmd = `${tls}irm ${base}/kitty.ps1|iex`, sh = k.spki ? `curl -fsSLk --pinnedpubkey 'sha256//${k.spki}' ${base}/kitty.sh | sudo sh` : `curl -fsSL ${base}/kitty.sh | sudo sh`;
        const line = (c, id) => `<div style="display:flex;gap:8px;align-items:center"><code class="mono" style="flex:1;padding:10px 12px;border:1px solid var(--line);border-radius:8px;word-break:break-all">${esc(c)}</code><button type="button" class="btn" id="${id}">${ui('copy', 15)}Copiar</button></div>`;
        dialog(`<h3>Añadir un equipo con Kitty</h3><p><b>Windows</b>: en el PC, <a href="/kitty.exe" download>descarga Kitty</a>, ábrelo y pulsa «Conectar este PC». Busca este catlan en la red, se instala (Windows pide permiso de administrador) y aparece aquí para que lo aceptes. Envía el estado del PC cada minuto y deja en la bandeja un gato para que el usuario avise a IT, sin tener que llamar.</p>
          <p class="muted small">Para muchos equipos a la vez, lo mismo en Windows PowerShell (powershell.exe) como administrador. Va por https${k.pin ? ` y solo acepta este certificado (huella SHA-256 <span class="mono">${esc(k.pin)}</span>: compárala con la del candado del navegador)` : ""}:</p>${line(cmd, 'pc-copy')}
          <p class="muted small">Para quitarlo, en PowerShell como administrador: <span class="mono">Unregister-ScheduledTask Kitty -Confirm:$false; Stop-Process -Name kitty -Force; Remove-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run Kitty; Remove-Item -Recurse "$env:ProgramFiles\\Kitty", "$env:ProgramData\\Kitty", HKLM:\\SOFTWARE\\Kitty</span></p>
          <p><b>Linux</b> (con curl): pega esta línea en una terminal. Deja un temporizador de systemd (o cron) que envía lo mismo cada 5 minutos.</p>${line(sh, 'sh-copy')}
          <p class="muted small">Para quitarlo: <span class="mono">sudo sh /usr/local/lib/kitty-agent.sh quitar</span>. Después aparecerá aquí, en «Kitty pide entrar», para que lo aceptes.</p>`, {ok: 'Listo'});
        document.querySelector('dialog[open]:last-of-type .dlg-a .ghost').remove();
        document.querySelector('#pc-copy').onclick = () => copy(cmd);
        document.querySelector('#sh-copy').onclick = () => copy(sh);
      });
      app.querySelectorAll('[data-ag] [data-st]').forEach(b => b.onclick = async () => {
        const id = b.closest('[data-ag]').dataset.ag, st = b.dataset.st;
        await (st === 'del' ? api('agents/' + id, 'DELETE') : api('agents/' + id, 'PUT', {state: st}));
        toast({adoptado: 'Kitty aceptado: ya está en el inventario', rechazado: 'Kitty rechazado', del: 'Kitty olvidado'}[st]); route(false);
      });
      return;
    }
    const [i, n, refs, log, sys] = await Promise.all([api('items/' + id), names(), api(`items/${id}/refs`), api(`log?kind=item&ref=${id}`), api(`items/${id}/syslog`)]);
    const ref = `[[#${i.id}]]`;
    const rel = [...refs.pages.map(p => ['book', `#/wiki/${p.id}`, p.title, 'Página de la wiki']), ...refs.incidents.map(x => ['ticket', `#/inc/${x.id}`, `${incId(x.id)} ${x.title}`, 'Incidencia · ' + x.status]),
      ...refs.items.map(x => ['box', `#/inv/${x.id}`, x.name, 'Notas de otro equipo']),
      ...refs.expiries.map(x => ['clock', '#/cad', x.name, `${esc(x.kind)} · ${warrantyTxt(x.date)}`]),
      ...refs.maps.map(m => m.type === 'rack' ? ['rack', `#/racks/${m.id}`, m.name, 'Montado en rack'] : ['nodes', `#/maps/${m.id}`, m.name, 'Aparece en esquema'])];
    crumbs([['Inventario', '#/inv'], [i.name || 'Sin nombre']]);
    const mon = monData || await api('monitor').catch(() => null); // recién abierta la página aún no ha pasado el sondeo
    const watch = (mon?.checks || []).filter(c => c.item === i.id || i.ip && c.host === i.ip); // lo que vigila el monitor de este equipo
    const down = watch.filter(c => c.state === 'down');
    app.innerHTML = head(esc(i.name) || 'Sin nombre', [esc(i.kind), i.ip && `<span class="mono">${esc(i.ip)}</span>`, i.status && `<span class="pill ${tone(i.status)}"><i></i>${esc(i.status)}</span>`,
      watch.length && `<a href="#/monitor" class="pill ${down.length ? 'bad' : 'ok'}" title="${esc(watch.map(monName).join(', '))}"><i></i>${down.length ? `monitor: ${down.length} caído` : 'monitor: funciona'}</a>`,
      i.warranty && `<span class="pill ${daysTo(i.warranty) <= 30 ? (daysTo(i.warranty) < 0 ? 'bad' : 'warn') : ''}" title="Fin de garantía: ${esc(i.warranty)}"><i></i>garantía: ${warrantyTxt(i.warranty)}</span>`].filter(Boolean).join(' &nbsp;·&nbsp; ') || 'Equipo del inventario',
        (i.ip ? `<button class="btn ghost" id="ip-copy" title="Copiar ${esc(i.ip)}">${ui('copy', 15)}Copiar IP</button>
           <button class="btn ghost" id="ip-ping" title="Hacer ping a ${esc(i.ip)} ahora">${ui('signal', 15)}Ping</button>
           <a class="btn ghost" href="http://${esc(i.ip)}" target="_blank" rel="noopener" title="Abrir http://${esc(i.ip)} en otra pestaña">${ui('link', 15)}Abrir web</a>` : '')
        + `<button class="chip" id="ref" title="Copiar la referencia para enlazarlo desde la wiki">${ui('link', 14)}<span class="mono">${ref}</span></button>
         ${refs.agent ? `<button class="btn" id="rmt" title="Ver y usar este PC con Kitty, con permiso de quien lo usa">${ui('screen', 16)}Control remoto</button>` : ''}
         <button class="btn pri" id="save" disabled>${ui('check', 16)}Guardar</button>${moreBtn}`)
      + `<div class="split stagger"><section class="card pad" style="--i:0"><div class="fields two">
          ${ITEM_FIELDS.map(([k, l]) => `<div class="field"><label for="f-${k}">${l}</label><input id="f-${k}" value="${esc(i[k])}"${k === 'ip' || k === 'serial' ? ' class="mono" spellcheck="false"' : ''}${k === 'status' ? ' list="dl-status"' : k === 'kind' ? ' list="dl-kind"' : k === 'warranty' ? ' type="date"' : ''}></div>`).join('')}
          <div class="field full"><label for="f-notes">Notas</label><textarea id="f-notes" rows="5" placeholder="Markdown. Enlaza otros equipos con [[#id]]">${esc(i.notes)}</textarea></div></div>
          ${i.notes ? `<div class="prose notes">${md(i.notes, n)}</div>` : ''}</section>
        <aside class="side-col"><section class="card pad" style="--i:1"><h3 class="card-t">Relaciones <span class="count">${rel.length}</span></h3>
          ${rel.length ? `<ul class="rel">${rel.map(([ic, h, t, s]) => `<li><a href="${h}"><span class="badge-ic">${ui(ic, 16)}</span><span><b>${esc(t)}</b><small>${s}</small></span></a></li>`).join('')}</ul>`
            : `<p class="muted small">Aún no aparece en ningún sitio. Pega <code class="mono">${ref}</code> en una página o enlázalo desde un esquema o un rack.</p>`}</section>
          <section class="card pad" style="--i:2"><h3 class="card-t">${ui('clock', 15)}Historial <span class="count">${log.length}</span></h3><div class="scroll">${timeline(log)}</div></section></aside></div>
        ${sys.length ? `<section class="card pad mt"><h3 class="card-t">${ui('pulse', 15)}Syslog <span class="count">${sys.length}</span><span class="dim small" style="font-weight:400;margin-left:auto" title="Syslog llega por UDP sin firmar: alguien en la red puede mandarlo haciéndose pasar por la IP de este equipo">últimos 30 días · sin verificar</span></h3>
          <div class="scroll" style="max-height:340px"><table class="tbl kv"><tbody>${sys.map(l => `<tr><td class="mono dim small" style="white-space:nowrap">${esc(date(l.ts).toLocaleString('es'))}</td>
            <td>${l.sev <= 3 ? `<span class="pill bad"><i></i>${l.sev <= 2 ? 'crítico' : 'error'}</span>` : l.sev === 4 ? '<span class="pill warn"><i></i>aviso</span>' : ''}</td>
            <td class="mono small" style="word-break:break-word">${esc(l.msg)}</td></tr>`).join('')}</tbody></table></div></section>` : ''}
        <datalist id="dl-status">${STATUSES.map(s => `<option value="${s}">`).join('')}</datalist><datalist id="dl-kind">${Object.values(ICONS).map(([n]) => `<option value="${n.toLowerCase()}">`).join('')}</datalist>`;
    const save = $('#save');
    app.querySelectorAll('.field input,.field textarea').forEach(el => el.oninput = () => { save.disabled = false; onSave = doSave; });
    const doSave = async () => {
      const d = Object.fromEntries([...ITEM_FIELDS.map(f => f[0]), 'notes'].map(k => [k, $('#f-' + k).value]));
      try { await putFresh('items/' + id, d, i.updated); } catch { return; }
      toast('Equipo guardado'); route(false);
    };
    save.onclick = doSave;
    $('#ref').onclick = () => copy(ref);
    $('#rmt') && ($('#rmt').onclick = () => remoteStart(refs.agent));
    $('#ip-copy') && ($('#ip-copy').onclick = () => copy(i.ip)); // copy() ya avisa
    $('#ip-ping') && ($('#ip-ping').onclick = async e => {
      const b = e.currentTarget; b.disabled = true;
      try { const r = await api('ping', 'POST', {host: i.ip}); toast(r.up ? `${i.ip} responde${r.rtt != null ? ` en ${r.rtt} ms` : ''}` : `${i.ip} no responde`, r.up ? undefined : 'bad'); }
      catch {} finally { b.disabled = false; }
    });
    $('#more').onclick = e => menu(e.currentTarget, [
      ['Crear incidencia', () => incidentDialog({item: i.id}), {icon: 'ticket'}],
      ['Programar mantenimiento…', () => maintDialog({items: [i.id]}, i.name), {icon: 'bell'}], '-',
      ['Borrar equipo', async () => { if (await delUndo([['item', 'items/' + id]], 'Equipo borrado')) location.hash = '#/inv'; }, {icon: 'trash', danger: true}]]);
  },
  async sistema() {
    const h = await api('system'), mb = n => (n / 1048576).toFixed(n < 10485760 ? 1 : 0) + ' MB', m = h.monitor, ok = (v, t, f) => `<span class="pill ${v ? 'ok' : 'bad'}"><i></i>${v ? t : f}</span>`;
    crumbs([['Opciones', '#/opts'], ['Salud de catlan']]);
    const row = (k, v) => `<tr><td class="muted" style="width:40%">${k}</td><td>${v}</td></tr>`;
    app.innerHTML = head('Salud de catlan', `catlan ${esc(h.version)} · base de datos v${h.schema} · en marcha desde ${esc(ago(h.started))}`)
      + `<div class="split stagger"><section class="card pad" style="--i:0"><h3 class="card-t">${ui('pulse', 15)}Ahora</h3><table class="tbl kv"><tbody>
          ${row('Monitor', ok(m.age <= 30, `late (hace ${m.age} s)`, `parado desde hace ${esc(upTxt(m.age))}`) + (m.error ? `<div class="small muted mt">Último error${m.error_ago != null ? ` (hace ${esc(upTxt(m.error_ago))})` : ''}: <span class="mono">${esc(m.error)}</span></div>` : ''))}
          ${row('Comprobaciones atrasadas', h.late ? `<span class="pill warn"><i></i>${h.late}</span> <span class="small muted">llevan más de 3 vueltas sin hacerse</span>` : ok(true, 'ninguna'))}
          ${row('Base de datos', ok(h.integrity === 'ok', 'íntegra', 'con daños: ' + esc(h.integrity)) + ` · ${mb(h.db_bytes)}${h.wal_bytes ? ` + ${mb(h.wal_bytes)} en WAL` : ''}`)}
          ${row('Syslog', h.syslog ? `UDP ${h.syslog}` : '<span class="dim">apagado</span>')}${row('HTTPS', h.https ? `autofirmado, huella <span class="mono small" style="word-break:break-all">${esc(h.https)}</span>` : 'con certificado propio')}
          ${Object.entries(h.counts).map(([k, v]) => row({items: 'Equipos', pages: 'Páginas', checks: 'Comprobaciones', sources: 'Fuentes de Salud', incidents: 'Incidencias', log: 'Entradas de Actividad', metrics: 'Lecturas (7 días)', syslog: 'Mensajes de syslog'}[k], v.toLocaleString('es'))).join('')}
        </tbody></table></section>
        <aside class="side-col"><section class="card pad" style="--i:1"><h3 class="card-t">${ui('layers', 15)}Copias diarias <span class="count">${h.backups.length}</span></h3>
          ${h.backups.length ? `<ul class="rel">${h.backups.map(b => `<li><span style="display:flex;justify-content:space-between;gap:8px;padding:6px 0"><span class="mono small">${esc(b.name)}</span><span class="dim small">${mb(b.bytes)} · ${esc(ago(b.at))}</span></span></li>`).join('')}</ul>`
            : '<p class="muted small">Aún ninguna: la primera se hace en los primeros minutos.</p>'}
          <p class="muted small">En <span class="mono">data/backups/</span> del servidor, una al día; se guardan las 7 últimas. Para restaurar, con catlan parado, copia una sobre <span class="mono">data/catlan.db</span>.</p></section></aside></div>`;
    // Actualizaciones de catlan desde GitHub: solo si un admin lo pide o activa «Actualizar solo»
    const u = await api('update');
    app.insertAdjacentHTML('beforeend', `<section class="card pad mt" aria-labelledby="up-t"><h3 class="card-t" id="up-t">${ui('redo', 15)}Actualizaciones</h3>
      <p class="small muted" style="margin:0 0 12px">Tienes catlan <b>${esc(u.current)}</b>. Las versiones nuevas salen de GitHub (Releases) y se comprueban con su sha256 antes de instalarse; si catlan reparte <span class="mono">kitty.exe</span>, también se actualiza, y después los PCs con Kitty. catlan solo se conecta a GitHub si pulsas «Buscar» o activas «Actualizar solo».</p>
      ${u.can ? `<div class="set"><span>Actualizar solo<small>Una vez al día busca e instala la versión nueva, y se reinicia</small></span><button class="switch" role="switch" id="up-auto" aria-checked="${!!u.auto}" aria-label="Actualizar solo"></button></div>`
        : `<p class="small"><span class="pill warn"><i></i>${u.docker ? 'En Docker, catlan se actualiza con su imagen: vuelve a construirla con la versión nueva' : 'Aquí catlan no se puede actualizar solo (solo Linux y Windows de 64 bits)'}</span></p>`}
      <div id="up-res" class="mt"></div>
      <div class="acts" style="display:flex;gap:8px;margin-top:12px"><button class="btn" id="up-chk">${ui('search', 16)}Buscar actualizaciones</button><button class="btn pri" id="up-go" hidden>${ui('redo', 16)}Actualizar ahora</button></div></section>`);
    const show = l => {
      if (!l) return;
      $('#up-res').innerHTML = l.newer ? `<p><span class="pill ok"><i></i>Hay una versión nueva: ${esc(l.latest)}</span> <a href="${esc(l.url)}" target="_blank" rel="noopener">Qué cambia</a> <span class="dim small">· mirado ${esc(l.at)}</span></p>`
        : `<p><span class="pill"><i></i>Tienes la última versión (${esc(l.latest)})</span> <span class="dim small">· mirado ${esc(l.at)}</span></p>`;
      $('#up-go').hidden = !(l.newer && u.can);
    };
    show(u.last);
    if ($('#up-auto')) $('#up-auto').onclick = async e => { const on = e.currentTarget.getAttribute('aria-checked') !== 'true'; try { await api('update', 'PUT', {auto: on}); } catch { return; } e.currentTarget.setAttribute('aria-checked', on); toast(on ? 'catlan se actualizará solo' : 'Ya no se actualiza solo'); };
    $('#up-chk').onclick = async () => { $('#up-chk').disabled = true; try { show(await api('update/check', 'POST')); } catch {} $('#up-chk').disabled = false; };
    $('#up-go').onclick = async () => {
      if (!await dialog('<h3>¿Actualizar catlan ahora?</h3><p>Se descarga la versión nueva, se comprueba y catlan se reinicia: la web dejará de responder unos segundos. Antes de aplicar cambios en la base de datos, catlan guarda una copia.</p>', {ok: 'Actualizar'})) return;
      $('#up-go').disabled = true; $('#up-go').innerHTML = '<span class="spin"></span><span>Actualizando…</span>';
      try { const r = await api('update/apply', 'POST'); toast(`Instalada la ${r.version}: reiniciando…`); } catch { $('#up-go').disabled = false; $('#up-go').innerHTML = `${ui('redo', 16)}Actualizar ahora`; return; }
      for (let i = 0; i < 60; i++) { await new Promise(ok => setTimeout(ok, 2000)); try { if ((await fetch('/api/update')).ok) return location.reload(); } catch {} }
    };
  },
  async apps() {
    crumbs([['Opciones', '#/opts'], ['Programas en los PCs']]);
    if (!ME.admin) { app.innerHTML = empty('cog', 'Solo para administradores', 'Aquí se elige qué se instala en todos los PCs.'); return; }
    const [list, hs] = await Promise.all([api('apps'), api('health')]), kits = hs.filter(h => h.kind === 'kitty');
    const st = id => { const r = kits.map(h => [h, h.info?.apps?.[id]]).filter(([, x]) => x); return {ok: r.filter(([, x]) => x.ok).length, bad: r.filter(([, x]) => !x.ok), wait: kits.length - r.length}; };
    app.innerHTML = head('Programas en los PCs', `Kitty los instala si faltan y los actualiza cada hora con winget, en los ${kits.length} PCs con Kitty. Quitar uno de la lista no lo desinstala.`, `<button class="btn" id="add">${ui('plus', 16)}Añadir programa</button>`)
      + (list.length ? `<div class="card tbl-wrap"><table class="tbl"><thead><tr><th>Programa</th><th>Id de winget</th><th>En los PCs</th><th class="hide-m">Notas</th></tr></thead>
        <tbody class="stagger">${list.map((a, k) => { const s = st(a.winget); return `<tr data-id="${a.id}" tabindex="0" style="--i:${Math.min(k, 14)}"><td><b>${esc(a.name)}</b></td><td class="mono">${esc(a.winget)}</td>
          <td>${s.ok ? `<span class="pill ok"><i></i>${s.ok} bien</span> ` : ''}${s.bad.length ? `<span class="pill bad" title="${esc(s.bad.map(([h, x]) => `${srcName(h)}: ${x.msg}`).join(' · '))}"><i></i>${s.bad.length} con error</span> ` : ''}${s.wait ? `<span class="dim small">${s.wait} pendientes</span>` : ''}</td>
          <td class="muted hide-m">${esc(a.notes)}</td></tr>`; }).join('')}</tbody></table></div>`
        : empty('box', 'Ningún programa todavía', 'Añade programas con su id de winget (por ejemplo Google.Chrome o 7zip.7zip) y Kitty los instalará en todos los PCs y los mantendrá al día. Búscalos en winget.run o con «winget search» en un PC.', `<button class="btn" id="add2">${ui('plus', 16)}Añadir programa</button>`));
    const edit = async (a = {}) => {
      const f = await dialog(`<h3>${a.id ? 'Editar programa' : 'Añadir programa'}</h3><div class="fields">
        <div class="field"><label for="a-w">Id de winget</label><input id="a-w" name="winget" class="mono" required maxlength="128" value="${esc(a.winget || '')}" placeholder="Google.Chrome" spellcheck="false" autofocus></div>
        <div class="field"><label for="a-n">Nombre</label><input id="a-n" name="name" required maxlength="100" value="${esc(a.name || '')}" placeholder="Google Chrome"></div>
        <div class="field"><label for="a-o">Notas</label><textarea id="a-o" name="notes" rows="2" maxlength="2000">${esc(a.notes || '')}</textarea></div></div>`, {ok: 'Guardar'});
      if (!f) return;
      const d = {winget: f.get('winget').trim(), name: f.get('name').trim(), notes: f.get('notes')};
      try { await (a.id ? api('apps/' + a.id, 'PUT', d) : api('apps', 'POST', d)); } catch { return; }
      toast(a.id ? 'Guardado' : 'Los PCs lo instalarán en los próximos minutos'); route(false);
    };
    [$('#add'), $('#add2')].forEach(b => b && (b.onclick = () => edit()));
    app.querySelectorAll('tr[data-id]').forEach(tr => {
      const a = list.find(x => x.id === +tr.dataset.id);
      tr.onclick = () => menu(tr, [['Editar', () => edit(a), {icon: 'edit'}], '-',
        ['Quitar de la lista', async () => { if (await delUndo([['app', 'apps/' + a.id]], 'Quitado: los PCs dejan de actualizarlo')) route(false); }, {icon: 'trash', danger: true}]]);
      tr.onkeydown = ev => ev.key === 'Enter' && tr.onclick(ev);
    });
  },
  async cad() {
    const [exps, items] = await Promise.all([api('expiries'), api('items')]), ro = ME.readonly, byId = Object.fromEntries(items.map(i => [i.id, i]));
    crumbs([['Inventario', '#/inv'], ['Caducidades']]);
    app.innerHTML = head('Caducidades', 'Licencias, dominios, certificados y contratos. Avisan 30 días antes y el mismo día, como las garantías.', ro ? '' : `<button class="btn" id="add">${ui('plus', 16)}Nueva</button>`)
      + (exps.length ? `<div class="card tbl-wrap"><table class="tbl"><thead><tr><th>Nombre</th><th>Tipo</th><th>Caduca</th><th class="hide-m">Equipo</th><th class="hide-m">Notas</th></tr></thead>
        <tbody class="stagger">${exps.map((e, k) => { const n = daysTo(e.date); return `<tr data-id="${e.id}" tabindex="0" style="--i:${Math.min(k, 14)}"><td><b>${esc(e.name)}</b></td><td class="muted">${esc(e.kind)}</td>
          <td><span class="pill ${n < 0 ? 'bad' : n <= 30 ? 'warn' : ''}"><i></i>${warrantyTxt(e.date)}</span> <span class="dim small">${esc(new Date(e.date + 'T00:00').toLocaleDateString('es'))}</span></td>
          <td class="hide-m">${e.item && byId[e.item] ? `<a href="#/inv/${+e.item}">${esc(byId[e.item].name)}</a>` : ''}</td><td class="muted hide-m">${esc(e.notes)}</td></tr>`; }).join('')}</tbody></table></div>`
        : empty('clock', 'Nada que caduque todavía', 'Añade licencias, dominios o contratos con su fecha y catlan avisará por tus canales. Las garantías de los equipos se ponen en su ficha.', ro ? '' : `<button class="btn" id="add2">${ui('plus', 16)}Nueva</button>`));
    const edit = async (e = {kind: 'licencia'}) => {
      const f = await dialog(`<h3>${e.id ? 'Editar caducidad' : 'Nueva caducidad'}</h3><div class="fields two">
        <div class="field full"><label for="x-n">Nombre</label><input id="x-n" name="name" required maxlength="200" value="${esc(e.name || '')}" placeholder="Microsoft 365, midominio.es…" autofocus></div>
        <div class="field"><label for="x-k">Tipo</label><select id="x-k" name="kind">${optList(['licencia', 'dominio', 'certificado', 'contrato', 'soporte', 'otro'], e.kind)}</select></div>
        <div class="field"><label for="x-d">Caduca el</label><input id="x-d" name="date" type="date" required value="${esc(e.date || '')}"></div>
        <div class="field full"><label for="x-i">Equipo <span class="dim">· opcional</span></label><select id="x-i" name="item">${optList(items, e.item, 'Ninguno')}</select></div>
        <div class="field full"><label for="x-o">Notas</label><textarea id="x-o" name="notes" rows="3" maxlength="5000">${esc(e.notes || '')}</textarea></div></div>`, {ok: 'Guardar'});
      if (!f) return;
      const d = {name: f.get('name').trim(), kind: f.get('kind'), date: f.get('date'), item: f.get('item') ? +f.get('item') : null, notes: f.get('notes')};
      try { await (e.id ? api('expiries/' + e.id, 'PUT', d) : api('expiries', 'POST', d)); } catch { return; }
      toast('Guardado'); route(false);
    };
    [$('#add'), $('#add2')].forEach(b => b && (b.onclick = () => edit()));
    if (!ro) app.querySelectorAll('tr[data-id]').forEach(tr => {
      const e = exps.find(x => x.id === +tr.dataset.id);
      tr.onclick = ev => !ev.target.closest('a') && menu(tr, [['Editar', () => edit(e), {icon: 'edit'}], '-',
        ['Borrar', async () => { if (await delUndo([['expiry', 'expiries/' + e.id]], 'Caducidad borrada')) route(false); }, {icon: 'trash', danger: true}]]);
      tr.onkeydown = ev => ev.key === 'Enter' && tr.onclick(ev);
    });
  },
});
