Object.assign(views, {
  async sla(month) {
    const now = new Date().toLocaleDateString('sv').slice(0, 7); // AAAA-MM en hora local
    month = /^\d{4}-\d{2}$/.test(month || '') ? month : now;
    const r = await api('sla?month=' + month), when = new Date(month + '-15').toLocaleDateString('es', {month: 'long', year: 'numeric'});
    const pct = v => v == null ? '—' : v === 1 ? '100 %' : `${(Math.floor(v * 1e4) / 100).toLocaleString('es', {minimumFractionDigits: 2})} %`; // hacia abajo: 99,996 no es 100
    const dur = m => m == null ? '—' : m < 60 ? `${m} min` : `${Math.floor(m / 60)} h${m % 60 ? ` ${m % 60} min` : ''}`;
    const col = v => v >= .999 ? 'var(--ok)' : v >= .99 ? 'var(--warn)' : 'var(--bad)';
    const rows = [...r.checks].sort((a, b) => (a.uptime ?? 2) - (b.uptime ?? 2)), known = rows.filter(x => x.uptime != null), worst = known[0];
    const KN = {ping: 'Ping', tcp: 'TCP', http: 'HTTP', ssl: 'SSL', dns: 'DNS'};
    crumbs([['Monitor', '#/monitor'], ['Disponibilidad']]);
    app.innerHTML = head(`Disponibilidad de ${when}`, r.checks.length ? `${known.length} de ${r.checks.length} con datos${month === now ? ' · mes en curso, hasta hace una hora' : ''}` : 'Aún no vigilas nada',
        `<input type="month" id="sm" value="${month}" max="${now}" aria-label="Mes" class="mono"><button class="btn" id="print">${ui('print', 16)}Imprimir</button>`)
      + `<div class="kpi-row">${kpi('Media', pct(r.avg), 'de todo lo vigilado', r.avg != null && r.avg < .99)}${kpi('Peor', pct(worst?.uptime), worst ? worst.name : '', worst && worst.uptime < .99)}
          ${kpi('Tiempo caído', dur(known.reduce((t, x) => t + x.down_min, 0)), 'sumando todos')}${kpi('Horas del mes', r.hours, month === now ? 'transcurridas' : '')}</div>`
      + (known.length ? `<div class="card tbl-wrap"><table class="tbl sla-t"><thead><tr><th>Equipo</th><th class="hide-m">Tipo</th><th>Disponible</th><th class="num">Caído</th><th class="num hide-m" title="Horas con datos sobre las del mes">Datos</th><th class="num hide-m">Latencia</th></tr></thead>
          <tbody>${rows.map(x => `<tr><td><b>${esc(x.name)}</b>${x.name !== x.host ? `<div class="dim small mono">${esc(x.host)}</div>` : ''}</td><td class="muted hide-m">${KN[x.kind] || esc(x.kind || 'Ping')}</td>
            <td>${x.uptime == null ? '<span class="dim">sin datos</span>' : `<span class="sla-bar"><i style="--w:${x.uptime * 100}%;--c:${col(x.uptime)}"></i><b>${pct(x.uptime)}</b></span>`}</td>
            <td class="num">${dur(x.down_min)}</td><td class="num dim hide-m">${x.uptime == null ? '' : Math.round(x.coverage * 100) + ' %'}</td><td class="num dim hide-m">${x.rtt == null ? '' : x.rtt + ' ms'}</td></tr>`).join('')}</tbody></table></div>
          <p class="dim small mt">El tiempo caído es aproximado: cada comprobación fallida cuenta como un intervalo entero. «Datos» baja del 100 % si catlan estuvo apagado o la comprobación se creó a mitad de mes.
            Los periodos silenciados cuentan como caídos.</p>`
        : empty('bars', 'Sin datos de este mes', r.first ? `Hay datos desde el ${esc(date(r.first).toLocaleDateString('es'))}.` : 'Los resúmenes por hora se crean cada 10 minutos a partir de lo que vigila el Monitor.'));
    $('#sm').onchange = e => e.target.value && (location.hash = '#/sla/' + e.target.value);
    $('#print').onclick = () => print();
  },
  async monitor() {
    crumbs([['Monitor']]);
    const [items, sounds] = await Promise.all([api('items'), api('sounds'), pollMonitor()]);
    const withIp = items.filter(i => i.ip), every = s => s < 60 ? `${s} s` : `${s / 60} min`;
    if (S.sound.startsWith('u:') && !sounds.some(x => 'u:' + x.id === S.sound)) { S.sound = 'bell'; applySettings(); } // su audio se borró
    app.innerHTML = head('Monitor', '<span id="mon-sub"></span>', `<a class="btn ghost" href="#/sla">${ui('bars', 16)}Disponibilidad</a><button class="btn" id="maint" aria-haspopup="menu">${ui('bell', 16)}Mantenimiento</button><button class="btn pri" id="add">${ui('plus', 16)}Vigilar</button>`)
      + `<div class="split stagger"><section class="card mon-list" id="mon-list" style="--i:0" aria-live="polite"></section>
        <aside class="side-col">
          <section class="card pad" style="--i:1"><h3 class="card-t">${ui('signal', 15)}Ping rápido</h3>
            <form class="row" id="pf" style="margin:0"><input id="ph" list="mon-ips" class="mono" placeholder="IP o nombre" aria-label="IP o nombre" required style="flex:1;min-width:0"><button class="btn">Ping ×4</button></form>
            <pre class="snap" id="pout" hidden></pre></section>
          <section class="card pad" style="--i:2"><h3 class="card-t">${ui('bell', 15)}Alertas sonoras</h3>
            <div class="set"><span>Sonar si algo cae<small>Con catlan abierto en el navegador</small></span><button class="switch" role="switch" id="snd-on" aria-checked="${!!S.soundOn}" aria-label="Sonar si algo cae"></button></div>
            <div class="set"><select id="snd" aria-label="Sonido de alerta">${Object.entries(SOUNDS).map(([k, [n]]) => `<option value="${k}">${n}</option>`).join('')}
              ${sounds.length ? `<optgroup label="Subidos">${sounds.map(x => `<option value="u:${x.id}">${esc(x.name)}</option>`).join('')}</optgroup>` : ''}</select>
              <button class="btn icon" id="snd-play" aria-label="Probar sonido" title="Probar">${ui('play', 16)}</button></div>
            <div class="set"><span class="small muted">Volumen</span><input type="range" id="snd-vol" min="0" max="1" step=".05" value="${S.vol}" aria-label="Volumen"></div>
            <label class="file" style="margin-top:12px"><input type="file" id="snd-up" accept="audio/*"><span>${ui('plus', 16)}<em>Subir audio propio (máx. 3 MB)</em></span></label>
            ${sounds.length ? `<ul class="snd-list">${sounds.map(x => `<li><span>${esc(x.name)}</span><button class="btn icon ghost sm" data-del="${x.id}" aria-label="Borrar ${esc(x.name)}">${ui('trash', 15)}</button></li>`).join('')}</ul>` : ''}</section>
          <section class="card pad" style="--i:3"><h3 class="card-t">${ui('mail', 15)}Avisos fuera de catlan</h3>
            ${monData?.channels?.length ? `<p class="small muted" style="margin:0 0 12px">Por ${esc(monData.channels.join(', '))}: cuando algo falla y cuando vuelve.</p><button class="btn" id="mail-test">Enviar aviso de prueba</button>`
              : `<p class="small muted" style="margin:0">Sin configurar. ${ME.admin ? 'Configura el correo, Telegram o un webhook (Slack, Teams, Discord…) en <a href="#/opts">Opciones → Avisos</a>.' : 'Pide a un administrador que los configure en Opciones → Avisos.'}</p>`}
            ${ME.admin && monData?.channels?.length ? '<p class="small" style="margin:10px 0 0"><a href="#/opts">Cambiar en Opciones → Avisos</a></p>' : ''}</section>
        </aside></div>
        <datalist id="mon-ips">${withIp.map(i => `<option value="${esc(i.ip)}">${esc(i.name)}</option>`).join('')}</datalist>`;
    const paint = () => {
      const all = monData?.checks || [], q = qv(), cs = all.filter(c => [monName(c), c.host].join(' ').toLowerCase().includes(q)), down = all.filter(c => c.state === 'down').length;
      const deps = all.filter(c => c.dep).length;
      $('#mon-sub').textContent = all.length ? `${all.length} vigilados · ${down ? `${down - deps} con fallos${deps ? ` y ${deps} afectados por ellos` : ''}` : 'todo funciona'}` : 'Ping, puertos, webs, certificados y DNS, con aviso si algo falla';
      $('#mon-list').innerHTML = cs.length ? cs.map(c => `<div class="mon-row ${c.state || ''}${c.dep ? ' dep' : ''}" data-id="${c.id}">
          <span class="mdot ${c.state || ''}" title="${c.state === 'up' ? 'Funciona' : c.state === 'down' ? 'Falla' : 'Comprobando…'}"></span>
          <div class="mon-n"><b>${esc(monName(c))}</b><small>${isMuted(c) || isPlanned(c) ? `<span class="muted-pill">${ui('bell', 12)}${esc(muteTxt(c))}</span> · ` : ''}<span class="dim">${CHECK_KINDS[c.kind || 'ping']}</span> · <span class="mono">${esc(checkTarget(c))}</span> · cada ${every(c.every)}${c.dep ? ` · <span class="dim">cae porque cae <b>${esc(c.dep.join(', '))}</b>: sin aviso</span>` : c.state === 'down' ? ` · <span class="t-bad">${esc(c.detail || 'no responde')}</span> desde ${esc(ago(c.since))}` : ''}</small></div>
          <div class="spark" title="Últimas comprobaciones">${(c.recent || []).map(u => `<i class="${u ? '' : 'x'}"></i>`).join('')}</div>
          <div class="mon-k"><b class="mono">${c.state === 'down' ? 'falla' : c.state === 'up' && c.kind === 'ssl' ? esc(c.detail.replace('certificado caduca en ', '')) : c.state && c.rtt != null ? `${+(+c.rtt).toFixed(1)} ms` : '…'}</b><small>${c.uptime == null ? '—' : +(c.uptime * 100).toFixed(1) + '%'} en 24 h</small></div>
          <button class="btn icon ghost sm" data-more aria-label="Acciones de ${esc(monName(c))}" aria-haspopup="menu">${ui('more')}</button></div>`).join('')
        : all.length ? empty('search', 'Sin resultados', `Nada coincide con «${esc(q)}».`)
        : empty('signal', 'Nada vigilado todavía', 'Elige un equipo del inventario o cualquier IP: catlan le hará ping cada pocos segundos y te avisará si deja de responder.');
    };
    const edit = async (c = {}) => {
      const p = dialog(`<h3>${c.id ? 'Editar vigilancia' : 'Vigilar'}</h3><p id="c-p"></p>
        <div class="fields"><div class="field"><label for="c-k">Qué comprobar</label><select id="c-k" name="kind">${Object.entries(CHECK_KINDS).map(([k, n]) => `<option value="${k}" ${k === (c.kind || 'ping') ? 'selected' : ''}>${n}</option>`).join('')}</select></div>
        <div class="field k-host"><label for="c-it">Del inventario <span class="dim">· opcional</span></label><select id="c-it" name="item"><option value="">Otro host</option>
          ${withIp.map(i => `<option value="${i.id}" ${i.id === c.item ? 'selected' : ''}>${esc(i.name)} · ${esc(i.ip)}</option>`).join('')}</select></div>
        <div class="field k-host"><label for="c-h" id="c-hl">IP o nombre</label><input id="c-h" name="host" class="mono" required value="${esc(c.kind === 'http' ? '' : c.host || '')}" placeholder="10.0.0.1" autofocus></div>
        <div class="field k-port"><label for="c-po">Puerto</label><input id="c-po" name="port" type="number" min="1" max="65535" required class="mono" value="${c.port || ''}" placeholder="443"></div>
        <div class="field k-url"><label for="c-u">Dirección web</label><input id="c-u" name="url" type="url" required class="mono" value="${esc(c.url || '')}" placeholder="https://intranet.local/"></div>
        <div class="field k-expect"><label for="c-x" id="c-xl"></label><input id="c-x" name="expect" maxlength="200" value="${esc(c.expect || '')}"></div>
        <div class="field k-days"><label for="c-d">Avisar si caduca en menos de (días)</label><input id="c-d" name="warn_days" type="number" min="1" max="365" class="mono" value="${c.warn_days || 30}"></div>
        <div class="field"><label for="c-l">Nombre <span class="dim">· opcional</span></label><input id="c-l" name="label" value="${esc(c.label || '')}"></div>
        <div class="field"><label for="c-s">Sonido si cae</label><div style="display:flex;gap:8px"><select id="c-s" name="sound" style="flex:1;min-width:0">
          <option value="">El general (${esc(String(S.sound).startsWith('u:') ? sounds.find(x => 'u:' + x.id === S.sound)?.name || 'subido' : SOUNDS[S.sound]?.[0] || 'Campana')})</option><option value="none">Ninguno</option>
          ${Object.entries(SOUNDS).map(([k, [n]]) => `<option value="${k}">${n}</option>`).join('')}
          ${sounds.length ? `<optgroup label="Subidos">${sounds.map(x => `<option value="u:${x.id}">${esc(x.name)}</option>`).join('')}</optgroup>` : ''}</select>
          <button type="button" class="btn icon" id="c-sp" aria-label="Probar el sonido" title="Probar">${ui('play', 16)}</button></div></div>
        <div class="field"><label for="c-e">Comprobar cada</label><select id="c-e" name="every">${[[10, '10 segundos'], [30, '30 segundos'], [60, '1 minuto'], [300, '5 minutos'], [3600, '1 hora']].map(([v, t]) => `<option value="${v}" ${v === (c.every || 30) ? 'selected' : ''}>${t}</option>`).join('')}</select></div></div>`,
        {ok: c.id ? 'Guardar' : 'Empezar a vigilar'});
      const dl = document.querySelector('dialog[open]:last-of-type'), $d = x => dl.querySelector(x);
      const show = (sel, on) => dl.querySelectorAll(sel).forEach(f => { f.hidden = !on; f.querySelectorAll('input,select').forEach(i => i.disabled = !on); }); // desactivado = no va en el formulario
      const kind = () => {
        const k = $d('#c-k').value;
        show('.k-host', k !== 'http'); show('.k-port', k === 'tcp' || k === 'ssl'); show('.k-url', k === 'http'); show('.k-expect', k === 'http' || k === 'dns'); show('.k-days', k === 'ssl');
        if (k === 'ssl' && !$d('#c-po').value) $d('#c-po').value = 443;
        $d('#c-hl').textContent = k === 'dns' ? 'Nombre a resolver' : 'IP o nombre';
        $d('#c-xl').innerHTML = k === 'dns' ? 'IP esperada <span class="dim">· opcional</span>' : 'Texto que debe aparecer <span class="dim">· opcional</span>';
        $d('#c-p').textContent = {ping: 'catlan le hará ping y te avisará si deja de responder dos veces seguidas.', tcp: 'Comprueba que el puerto acepta conexiones (p. ej. 443 web, 3389 escritorio remoto, 22 SSH).',
          http: 'Abre la página como un navegador: avisa si da error, si su certificado no es válido o si falta el texto que esperas.',
          ssl: 'Lee la fecha de caducidad del certificado (también los autofirmados) y avisa con tiempo.', dns: 'Comprueba que el nombre resuelve y, si quieres, que lo hace a la IP correcta.'}[k];
      };
      $d('#c-k').onchange = kind; kind();
      $d('#c-s').value = c.sound || '';
      $d('#c-sp').onclick = () => { const v = $d('#c-s').value; if (v !== 'none') playSound(v || S.sound); };
      $d('#c-it').onchange = e => { const i = withIp.find(x => x.id === +e.target.value); if (i) $d('#c-h').value = i.ip; };
      const f = await p; if (!f) return;
      const k = f.get('kind'), url = (f.get('url') || '').trim();
      const hostOf = u => { try { return new URL(u).hostname.replace(/^\[|\]$/g, ''); } catch { return ''; } };
      const body = {kind: k, host: k === 'http' ? hostOf(url) : f.get('host').trim(), url: k === 'http' ? url : '', port: f.get('port') ? +f.get('port') : null,
        expect: (f.get('expect') || '').trim(), warn_days: +f.get('warn_days') || 30,
        label: f.get('label').trim(), item: f.get('item') ? +f.get('item') : null, every: +f.get('every'), sound: f.get('sound') || ''};
      await (c.id ? api('checks/' + c.id, 'PUT', body) : api('checks', 'POST', body));
      toast(c.id ? 'Guardado' : `Vigilando ${body.label || body.host}`); pollMonitor();
    };
    $('#add').onclick = () => edit();
    $('#mon-list').onclick = e => {
      const b = e.target.closest('[data-more]'), c = b && monData.checks.find(x => x.id === +b.closest('.mon-row').dataset.id); if (!c) return;
      menu(b, [['Editar', () => edit(c), {icon: 'edit'}], ['Ping ahora', () => { $('#ph').value = c.host; $('#pf').requestSubmit(); }, {icon: 'signal'}],
        [isMuted(c) ? 'Quitar silencio' : 'Silenciar…', () => mute('checks', c, monName(c)), {icon: 'bell'}],
        ['Crear incidencia', () => incidentDialog({title: `${monName(c)}: ${c.state === 'down' ? c.detail || 'no responde' : ''}`.replace(/: $/, ''), item: c.item, priority: c.state === 'down' ? 'alta' : 'media'}), {icon: 'ticket'}], '-',
        ['Dejar de vigilar', async () => { if (await delUndo([['check', 'checks/' + c.id]], 'Ya no se vigila')) pollMonitor(); }, {icon: 'trash', danger: true}]]);
    };
    // Ping rápido: 4 pings, uno por petición, para verlos llegar en directo
    $('#pf').onsubmit = async e => {
      e.preventDefault();
      const host = $('#ph').value.trim(), out = $('#pout'), rs = [];
      out.hidden = false; out.textContent = `PING ${host}\n`;
      for (let i = 1; i <= 4; i++) {
        const r = await fetch('/api/ping', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({host})}).then(r => r.json());
        if (r.error) { out.textContent += r.error; return; }
        rs.push(r); out.textContent += r.up ? `Respuesta de ${host}: ${r.rtt ?? '<1'} ms\n` : `Sin respuesta (${i})\n`;
        if (i < 4) await new Promise(ok => setTimeout(ok, 500));
      }
      const t = rs.filter(r => r.up).map(r => r.rtt ?? 0);
      out.textContent += `\n4 enviados · ${t.length} recibidos · ${100 - t.length * 25}% perdidos`
        + (t.length ? `\nmín ${Math.min(...t)} · media ${+(t.reduce((a, b) => a + b, 0) / t.length).toFixed(1)} · máx ${Math.max(...t)} ms` : '');
    };
    $('#snd').value = S.sound;
    $('#snd').onchange = e => { S.sound = e.target.value; applySettings(); playSound(); };
    $('#snd-play').onclick = () => playSound($('#snd').value);
    $('#snd-vol').oninput = e => { S.vol = +e.target.value; applySettings(); };
    $('#snd-on').onclick = e => { S.soundOn = !S.soundOn; e.currentTarget.setAttribute('aria-checked', S.soundOn); applySettings(); };
    $('#snd-up').onchange = async e => {
      const f = e.target.files[0]; if (!f) return;
      const x = await api('sounds?name=' + encodeURIComponent(f.name.replace(/\.[^.]+$/, '')), 'POST', f, f.type);
      S.sound = 'u:' + x.id; applySettings(); toast(`«${x.name}» es ahora el sonido de alerta`); route(false);
    };
    app.querySelectorAll('[data-del]').forEach(b => b.onclick = async () => { await api('sounds/' + b.dataset.del, 'DELETE'); if (S.sound === 'u:' + b.dataset.del) S.sound = 'bell'; applySettings(); route(false); });
    $('#mail-test') && ($('#mail-test').onclick = testAlerts);
    // Mantenimiento: silencia (o reactiva) todo lo vigilado y todo lo que se lee en Salud
    const muteAll = async m => {
      await Promise.all([...monData.checks.map(c => api(`checks/${c.id}/mute`, 'POST', {minutes: m})), ...(monData.sources || []).map(x => api(`sources/${x.id}/mute`, 'POST', {minutes: m}))]);
      toast(m ? 'Mantenimiento: avisos silenciados' : 'Avisos activados de nuevo'); pollMonitor();
    };
    $('#maint').onclick = e => menu(e.currentTarget, [['Silenciar todo…', async () => { const m = await muteDialog('Modo mantenimiento'); if (m) muteAll(m); }, {icon: 'bell'}],
      ['Quitar todos los silencios', () => muteAll(0), {icon: 'check'}]]);
    paint(); redraw = monPaint = paint; cleanup = () => { monPaint = null; };
  },
  async salud(id) {
    const items = await api('items');
    if (!id) {
      const hs = await api('health'), q = qv(), bad = hs.filter(h => h.state === 'warn' || h.state === 'error').length;
      const top = (h, pre) => h.latest.filter(m => m.key.startsWith(pre)).sort((a, b) => b.value - a.value)[0];
      const kits = hs.filter(h => h.kind === 'kitty').length, tab = h => saludTab === 'all' || (saludTab === 'kitty') === (h.kind === 'kitty');
      const shown = hs.filter(h => tab(h) && [srcName(h), h.host, SRC_KIND[h.kind], h.info?.descr].join(' ').toLowerCase().includes(q));
      crumbs([['Salud']]);
      app.innerHTML = head('Salud', hs.length ? `${hs.length} ${hs.length === 1 ? 'equipo' : 'equipos'} · ${bad ? `${bad} con avisos` : 'todo en orden'}` : 'Temperaturas, discos, ventiladores y RAID de tus equipos',
          `<button class="btn pri" id="add">${ui('plus', 16)}Añadir equipo</button>`)
        + (hs.length ? `<div class="seg" id="stab" style="margin-bottom:16px">${[['all', 'Todo', hs.length], ['snmp', 'SNMP', hs.length - kits], ['kitty', 'Kittens', kits]].map(([k, t, n]) =>
            `<button data-v="${k}" class="${k === saludTab ? 'on' : ''}">${t} <span class="dim">${n}</span></button>`).join('')}</div>` : '')
        + (shown.length ? `<div class="grid hgrid stagger">${shown.map((h, i) => { const t = top(h, 'temp:'), d = top(h, 'disk:'), c = h.latest.find(m => m.key === 'cpu'), m = h.latest.find(x => x.key === 'mem'), kit = h.kind === 'kitty';
            return `<a class="src-card ${h.state || ''}" style="--i:${Math.min(i, 14)}" href="#/salud/${h.id}">
              <header><span class="mdot ${h.state === 'ok' ? 'up' : h.state ? 'down' : ''}"></span><b>${esc(srcName(h))}</b><small>${esc(kit ? osShort(h.info?.descr) : SRC_KIND[h.kind] || h.kind)}</small></header>
              <div class="kpis">${kit ? kpi('Memoria', m ? fmtV(m.value, '%') : '—', h.info?.mem_total ? 'de ' + gb(h.info.mem_total) : '') : kpi('Temp. máx.', t ? fmtV(t.value, '°C') : '—', t?.label, t?.value > h.temp_max)}${kpi('Disco más lleno', d ? fmtV(d.value, '%') : '—', d?.label, d?.value > h.disk_max)}${kpi('CPU', c ? fmtV(c.value, '%') : '—')}</div>
              ${h.state === 'error' ? `<p class="hc-err">${ui('alert', 14)}${esc(h.error)}</p>`
                : h.problems.length ? `<ul class="probs">${h.problems.slice(0, 3).map(p => `<li>${ui('alert', 14)}${esc(p)}</li>`).join('')}${h.problems.length > 3 ? `<li class="dim">y ${h.problems.length - 3} más</li>` : ''}</ul>`
                : h.state === 'ok' ? `<p class="hc-ok">${ui('check', 14)}Todo en orden</p>` : '<p class="dim small" style="margin:0">Leyendo por primera vez…</p>'}
              <footer>${h.last ? `${h.kind === 'kitty' ? 'Enviado' : 'Leído'} ${esc(ago(h.last))}` : 'Pendiente'} · cada ${everyTxt(h.every)}${isMuted(h) || isPlanned(h) ? ` · ${esc(muteTxt(h))}` : ''}</footer></a>`; }).join('')}</div>`
        : saludTab === 'kitty' && !kits ? empty('box', 'Ningún Kitten todavía', 'Instala Kitty en un PC o servidor y acéptalo en Inventario: aparecerá aquí con su sistema, CPU, memoria, discos y tiempo encendido.')
        : hs.length ? empty('search', 'Sin resultados', `Nada coincide con «${esc(q)}».`)
        : empty('thermo', 'Aún no lees ningún equipo', 'Activa SNMP en tu NAS o switch (o usa la API de tu grabador Hikvision) y catlan guardará sus temperaturas, discos y estado para dibujarlos y avisarte.'));
      $('#add').onclick = () => sourceDialog({}, items);
      if ($('#stab')) { seg($('#stab')); $('#stab').onclick = e => { const b = e.target.closest('[data-v]'); if (b) { saludTab = b.dataset.v; route(false); } }; }
      const t = setInterval(() => route(false), 15000); cleanup = () => clearInterval(t);
      return;
    }
    let h, hours = healthRange, selPort = null, showAll = false;
    crumbs([['Salud', '#/salud'], ['…']]);
    const paint = async () => {
      const [all, ms] = await Promise.all([api('health'), api(`metrics?source=${+id}&hours=${hours}`)]);
      if (!(h = all.find(x => x.id === +id))) throw new Error('404');
      crumbs([['Salud', '#/salud'], [srcName(h)]]);
      const lat = k => h.latest.filter(m => m.key.startsWith(k)), top = k => [...lat(k)].sort((a, b) => b.value - a.value)[0];
      const t = top('temp:'), d = top('disk:'), c = lat('cpu')[0], m = lat('mem')[0];
      const kit = h.kind === 'kitty', inf = h.info || {};
      $('#h-sub').innerHTML = `${esc(kit ? inf.descr || 'Kitty' : SRC_KIND[h.kind] || h.kind)} · <span class="mono">${esc(h.host)}</span>${inf.uptime ? ` · encendido hace ${esc(upTxt(inf.uptime))}` : ''}${h.last ? ` · ${kit ? 'enviado' : 'leído'} ${esc(ago(h.last))}` : ''}${isMuted(h) || isPlanned(h) ? ` · <span class="muted-pill">${ui('bell', 12)}${esc(muteTxt(h))}</span>` : ''}`;
      $('#h-state').innerHTML = h.state === 'error' ? `<div class="banner bad">${ui('alert', 16)}<span>${esc(h.error)}</span></div>`
        : h.problems.length ? `<div class="banner warn">${ui('alert', 16)}<ul>${h.problems.map(p => `<li>${esc(p)}</li>`).join('')}</ul></div>` : '';
      $('#kpis').innerHTML = (kit ? kpi('Encendido', inf.uptime ? upTxt(inf.uptime) : '—', inf.uptime && h.last ? 'desde ' + new Date(date(h.last) - inf.uptime * 1000).toLocaleString() : '') : kpi('Temperatura máxima', t ? fmtV(t.value, '°C') : '—', t?.label || 'sin sensores', t?.value > h.temp_max))
        + kpi('Disco más lleno', d ? fmtV(d.value, '%') : '—', d?.label || 'sin discos', d?.value > h.disk_max)
        + kpi('CPU', c ? fmtV(c.value, '%') : '—') + kpi('Memoria', m ? fmtV(m.value, '%') : '—')
        + kpi('Avisos', h.problems.length || (h.state === 'error' ? 1 : 0), h.state === 'ok' ? 'todo en orden' : '', h.state === 'warn' || h.state === 'error');
      // Series por tipo; más de 8 en un gráfico se resumen (los colores no dan para más) y siguen en «Ver datos»
      const pick = pre => Object.entries(ms).filter(([k]) => k.startsWith(pre)).map(([k, v]) => ({key: k, ...v})).sort((a, b) => (b.points.at(-1)?.[1] ?? 0) - (a.points.at(-1)?.[1] ?? 0));
      const cap = (list, what) => [list.slice(0, 8), list.length > 8 ? `${list.length - 8} ${what} más en «Ver datos».` : ''];
      const [temps, tMore] = cap(pick('temp:'), 'sensores'), [dh, dMore] = cap(pick('disk:'), 'discos'), fans = pick('fan:').slice(0, 8);
      $('#temp-card').hidden = kit;
      $('#kit-card').hidden = !kit;
      if (kit) $('#kit-info').innerHTML = `<table class="data-t"><tbody>${[['Sistema', inf.descr], ['Modelo', inf.model], ['Procesador', inf.cpu && `${inf.cpu}${inf.cores ? ` · ${inf.cores} hilos` : ''}`],
          ['Memoria', inf.mem_total && gb(inf.mem_total)], ['Discos', (inf.disks || []).map(x => `${x.name} ${gb(x.free)} libres de ${gb(x.total)}`).join(' · ')],
          ['IPs', (inf.ips || []).join(' · ')], ['Nº de serie', inf.serial]].filter(r => r[1]).map(([k, v]) => `<tr><td class="dim">${k}</td><td>${esc(v)}</td></tr>`).join('')}</tbody></table>`;
      const aps = Object.entries(kit && inf.apps || {});
      $('#app-card').hidden = !aps.length;
      if (aps.length) $('#app-list').innerHTML = `<table class="data-t"><tbody>${aps.map(([id, r]) => `<tr><td class="mono">${esc(id)}</td><td style="text-align:left"><span class="pill ${r.ok ? 'ok' : 'bad'}"><i></i>${esc(r.msg)}</span></td></tr>`).join('')}</tbody></table>`;
      const evs = kit ? inf.events || [] : [];
      $('#ev-card').hidden = !evs.length;
      if (evs.length) $('#ev-list').innerHTML = `<div class="tbl-wrap"><table class="data-t"><thead><tr><th>Cuándo</th><th>Nivel</th><th class="hide-m">Registro</th><th>Origen</th><th>Mensaje</th></tr></thead><tbody>${evs.map(e =>
        `<tr><td style="white-space:nowrap" title="${esc(when(e.time))}">${esc(ago(e.time))}</td><td class="${e.level === 1 ? 't-bad' : 'dim'}">${e.level === 1 ? 'Crítico' : 'Error'}</td>
          <td class="dim hide-m">${e.log === 'System' ? 'Sistema' : e.log === 'Application' ? 'Aplicación' : esc(e.log)}</td><td>${esc(e.source)} <span class="mono dim">${e.code}</span></td><td class="small" style="text-align:left">${esc(e.msg) || '<span class="dim">sin mensaje</span>'}</td></tr>`).join('')}</tbody></table></div>`;
      lineChart($('#c-temp'), temps, {unit: '°C', limit: h.temp_max, title: 'Temperatura', more: tMore, empty: 'Este equipo no informa de temperaturas.'});
      diskBars($('#c-disk'), lat('disk:').sort((a, b) => b.value - a.value), h.disk_max);
      lineChart($('#c-disk-h'), dh, {unit: '%', lo: 0, hi: 100, limit: h.disk_max, h: 170, title: 'Ocupación de discos en el tiempo', more: dMore, empty: ''});
      lineChart($('#c-cpu'), ['cpu', 'mem'].filter(k => ms[k]).map(k => ({key: k, ...ms[k]})), {unit: '%', lo: 0, hi: 100, title: 'CPU y memoria', empty: 'Este equipo no informa de CPU ni memoria.'});
      $('#fan-card').hidden = !fans.length;
      if (fans.length) lineChart($('#c-fan'), fans, {unit: 'rpm', lo: 0, title: 'Ventiladores'});
      // Interfaces: tabla de puertos y, del elegido, su tráfico en el tiempo
      const ports = h.info?.ports || [];
      $('#if-card').hidden = !ports.length;
      if (ports.length) {
        const load = x => (x.rx || 0) + (x.tx || 0);
        const main = [...ports].filter(x => x.up || x.alias).sort((a, b) => b.up - a.up || load(b) - load(a)), rest = ports.filter(x => !x.up && !x.alias);
        if (!ports.some(x => x.name === selPort)) selPort = main[0]?.name;
        const sum = k => fmtBw(ports.reduce((t, x) => t + (x[k] || 0), 0));
        $('#if-sum').textContent = `${ports.filter(x => x.up).length} de ${ports.length} conectados${ports.some(x => 'rx' in x) ? ` · ${sum('rx')} ↓ · ${sum('tx')} ↑` : ''}`;
        const sel = ports.find(x => x.name === selPort);
        if (sel) lineChart($('#if-chart'), [{label: 'Entrada ↓', points: ms['rx:' + sel.name]?.points || []}, {label: 'Salida ↑', points: ms['tx:' + sel.name]?.points || []}],
          {unit: 'Mbps', lo: 0, title: `Tráfico de ${sel.name}`, empty: 'El tráfico aparece a partir de la segunda lectura.'});
        $('#if-sel').textContent = sel ? `${sel.name}${sel.alias ? ' · ' + sel.alias : ''}` : '';
        const row = x => `<tr data-n="${esc(x.name)}" tabindex="0" class="${x.name === selPort ? 'on' : ''}" aria-selected="${x.name === selPort}">
          <td><span class="mdot ${x.up ? 'up' : x.alias && x.admin ? 'down' : ''}" title="${x.up ? 'Conectado' : x.admin ? 'Sin conexión' : 'Desactivado'}"></span></td>
          <td><b>${esc(x.name)}</b>${x.alias ? `<div class="dim small">${esc(x.alias)}</div>` : ''}</td><td class="mono hide-m">${x.speed ? (x.speed >= 1000 ? x.speed / 1000 + ' G' : x.speed + ' M') : '—'}</td>
          <td class="mono">${x.up && 'rx' in x ? fmtBw(x.rx) : '—'}</td><td class="mono">${x.up && 'tx' in x ? fmtBw(x.tx) : '—'}</td>
          <td class="hide-m" style="min-width:90px">${x.speed && 'rx' in x ? `<div class="track" style="height:8px" title="${Math.round(Math.max(x.rx, x.tx) / x.speed * 100)} % de uso"><i style="width:${Math.min(100, Math.max(x.rx, x.tx) / x.speed * 100)}%"></i></div>` : ''}</td>
          <td class="mono ${x.err > 0 ? 't-bad' : 'dim'}">${'err' in x ? +x.err.toFixed(1) : '—'}</td></tr>`;
        $('#if-table').innerHTML = `<div class="tbl-wrap"><table class="tbl if-t"><thead><tr><th></th><th>Puerto</th><th class="hide-m">Velocidad</th><th>↓ Entrada</th><th>↑ Salida</th><th class="hide-m">Uso</th><th>Errores/min</th></tr></thead>
          <tbody>${main.map(row).join('')}${showAll ? rest.map(row).join('') : ''}</tbody></table></div>
          ${rest.length ? `<button class="btn ghost sm mt" id="if-more">${showAll ? 'Ocultar' : 'Ver'} ${rest.length} ${rest.length === 1 ? 'puerto' : 'puertos'} sin conectar ni descripción</button>` : ''}`;
        $('#if-table').onclick = e => {
          if (e.target.closest('#if-more')) { showAll = !showAll; return paint(); }
          const tr = e.target.closest('tr[data-n]'); if (tr) { selPort = tr.dataset.n; paint(); }
        };
        $('#if-table').onkeydown = e => e.key === 'Enter' && e.target.matches('tr[data-n]') && e.target.click();
      }
      $('#h-data').innerHTML = h.latest.length ? `<table class="data-t"><thead><tr><th>Lectura</th><th>Tipo</th><th>Valor</th></tr></thead><tbody>${h.latest.map(x =>
        `<tr><td>${esc(x.label)}</td><td class="dim">${({temp: 'Temperatura', disk: 'Disco', fan: 'Ventilador', cpu: 'CPU', mem: 'Memoria', rx: 'Entrada', tx: 'Salida', err: 'Errores'})[x.key.split(':')[0]] || ''}</td><td>${esc(fmtV(x.value, x.unit))}</td></tr>`).join('')}</tbody></table>`
        : '<p class="muted small">Sin lecturas todavía.</p>';
    };
    app.innerHTML = head(`<span id="h-name"></span>`, '<span id="h-sub"></span>', `<div class="seg" id="rng">${[[6, '6 h'], [24, '24 h'], [168, '7 días'], [720, '30 días'], [2160, '90 días']].map(([v, t]) =>
        `<button data-v="${v}" class="${v === hours ? 'on' : ''}">${t}</button>`).join('')}</div><button class="btn pri" id="rmt" hidden>${ui('screen', 16)}Control remoto</button><button class="btn" id="edit">${ui('edit', 16)}Editar</button>${moreBtn}`)
      + `<div id="h-state"></div><div class="kpi-row" id="kpis"></div>
      <section class="card pad" id="kit-card" hidden style="margin-bottom:16px"><h3 class="card-t">Equipo</h3><div id="kit-info"></div>
        <p class="dim small" style="margin:8px 0 0">Lo envía Kitty. Solo lo justo para ver fallos: nada de usuarios, archivos ni más programas que los que IT pide instalar.</p></section>
      <section class="card pad" id="app-card" hidden style="margin-bottom:16px"><h3 class="card-t">Programas <span class="dim small" style="font-weight:400">· los que IT instala y mantiene al día en los PCs (<a href="#/apps">Opciones → Programas</a>)</span></h3><div id="app-list"></div></section>
      <section class="card pad" id="ev-card" hidden style="margin-bottom:16px"><h3 class="card-t">Visor de eventos <span class="dim small" style="font-weight:400">· críticos y errores de los últimos 7 días</span></h3><div id="ev-list"></div></section>
      <div class="charts stagger"><section class="card pad" style="--i:0" id="temp-card"><h3 class="card-t">Temperatura</h3><div id="c-temp"></div></section>
        <section class="card pad" style="--i:1"><h3 class="card-t">Ocupación de discos</h3><div id="c-disk"></div><div id="c-disk-h" class="mt"></div></section>
        <section class="card pad" style="--i:2"><h3 class="card-t">CPU y memoria</h3><div id="c-cpu"></div></section>
        <section class="card pad" id="fan-card" hidden><h3 class="card-t">Ventiladores</h3><div id="c-fan"></div></section></div>
      <section class="card pad mt" id="if-card" hidden><h3 class="card-t">Interfaces <span class="dim small" id="if-sum" style="font-weight:400"></span></h3>
        <p class="small muted" style="margin:0 0 8px">Tráfico de <b id="if-sel"></b> · elige otro puerto en la tabla</p><div id="if-chart"></div><div id="if-table" class="mt"></div></section>
      <div class="card pad mt">${collapsible('Ver datos de la última lectura', '<div id="h-data"></div>')}</div>`;
    await paint();
    $('#h-name').textContent = srcName(h);
    seg($('#rng'));
    $('#rng').onclick = e => { const b = e.target.closest('[data-v]'); if (!b) return; hours = healthRange = +b.dataset.v;
      $('#rng').querySelectorAll('button').forEach(x => x.classList.toggle('on', x === b)); seg($('#rng')); paint(); };
    $('#edit').hidden = h.kind === 'kitty'; // shortcut: los umbrales de un Kitty no se editan desde la web; añadir un diálogo propio si hace falta
    $('#edit').onclick = () => sourceDialog(h, items);
    $('#rmt').hidden = !(h.kind === 'kitty' && h.agent); // h llega con paint(): antes no se sabe si es un Kitty
    $('#rmt').onclick = () => remoteStart(h.agent);
    $('#more').onclick = e => menu(e.currentTarget, h.kind === 'kitty' ? [
      [isMuted(h) ? 'Quitar silencio' : 'Silenciar…', async () => { await mute('sources', h, srcName(h)); paint(); }, {icon: 'bell'}],
      ...(ME.admin && h.agent ? ['-', ['Expulsar Kitty', async () => { if (await ask('¿Expulsar este Kitty?', `«${esc(srcName(h))}» saldrá de Salud con su historial y dejará de enviar datos. Su ficha del inventario se queda. Podrás volver a aceptarlo en Inventario.`, 'Expulsar')) { await api('agents/' + h.agent, 'PUT', {state: 'rechazado'}); toast('Kitty expulsado'); location.hash = '#/salud'; } }, {icon: 'trash', danger: true}]] : [])] : [
      ['Dibujar topología', () => autoTopo(h.id), {icon: 'nodes'}],
      ['Leer ahora', async () => { await api('sources/' + h.id, 'PUT', {every: h.every}); toast('Leyendo…'); setTimeout(paint, 4000); }, {icon: 'signal'}],
      [isMuted(h) ? 'Quitar silencio' : 'Silenciar…', async () => { await mute('sources', h, srcName(h)); paint(); }, {icon: 'bell'}], '-',
      ['Dejar de leer', async () => { if (await ask('¿Dejar de leer este equipo?', `Se borrarán la configuración de «${esc(srcName(h))}» y sus avisos. El historial se limpia solo en 7 días.`, 'Dejar de leer')) { await api('sources/' + h.id, 'DELETE'); toast('Ya no se lee'); location.hash = '#/salud'; } }, {icon: 'trash', danger: true}]]);
    const t = setInterval(paint, 15000); cleanup = () => clearInterval(t);
  },
  async log() {
    const rows = await api('log');
    crumbs([['Actividad']]);
    const tabs = [['all', 'Todo'], ['page', 'Wiki'], ['item', 'Equipos'], ['map', 'Esquemas'], ['rack', 'Racks']];
    app.innerHTML = head('Actividad', 'Quién cambió qué y cuándo. Cada versión queda guardada.', `<div class="seg" id="lf">${tabs.map(([v, t]) => `<button data-v="${v}" class="${v === logFilter ? 'on' : ''}">${t}</button>`).join('')}</div>`)
      + `<div id="tl"></div>`;
    const paint = (animate) => {
      const q = qv(), f = rows.filter(l => (logFilter === 'all' || l.kind === logFilter) && [l.who, l.action, l.name, KINDS[l.kind]?.[0]].join(' ').toLowerCase().includes(q));
      $('#tl').innerHTML = f.length ? timeline(f, true) : empty('pulse', 'Sin actividad', q ? `Nada coincide con «${esc(q)}».` : 'Los cambios aparecerán aquí en cuanto alguien edite algo.');
      if (animate) $('#tl').querySelectorAll('.ev,.day').forEach((el, i) => i < 16 && anim(el, [{opacity: 0, transform: 'translateY(8px)'}, {opacity: 1, transform: 'none'}], {duration: 420, delay: i * 22, easing: 'cubic-bezier(.22,.8,.24,1)', fill: 'backwards'}));
    };
    seg($('#lf')); paint(false);
    $('#lf').onclick = e => { const b = e.target.closest('[data-v]'); if (!b) return; logFilter = b.dataset.v; $('#lf').querySelectorAll('button').forEach(x => x.classList.toggle('on', x === b)); seg($('#lf')); paint(true); };
    redraw = () => paint(false);
  },
});
