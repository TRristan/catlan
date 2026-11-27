Object.assign(views, {
  async redes(id) {
    const ro = ME.readonly;
    const subnetDialog = async (n = {}) => {
      const f = await dialog(`<h3>${n.id ? 'Editar red' : 'Nueva red'}</h3><div class="fields two">
        <div class="field"><label for="n-c">Red</label><input id="n-c" name="cidr" class="mono" required placeholder="10.0.0.0/24" value="${esc(n.cidr || '')}" spellcheck="false" autofocus></div>
        <div class="field"><label for="n-v">VLAN <span class="dim">· opcional</span></label><input id="n-v" name="vlan" maxlength="40" value="${esc(n.vlan || '')}"></div>
        <div class="field full"><label for="n-n">Nombre</label><input id="n-n" name="name" maxlength="200" value="${esc(n.name || '')}" placeholder="Oficina, servidores, cámaras…"></div>
        <div class="field full"><label for="n-o">Notas</label><textarea id="n-o" name="notes" rows="3">${esc(n.notes || '')}</textarea></div></div>`, {ok: 'Guardar'});
      if (!f) return;
      const d = Object.fromEntries(['cidr', 'vlan', 'name', 'notes'].map(k => [k, f.get(k).trim()]));
      try { const r = await (n.id ? api('subnets/' + n.id, 'PUT', d) : api('subnets', 'POST', d)); location.hash = '#/redes/' + r.id; route(false); } catch {}
    };
    if (!id) {
      const nets = await Promise.all((await api('subnets')).map(n => api(`subnets/${n.id}/ips`)));
      crumbs([['Redes']]);
      app.innerHTML = head('Redes', 'Subredes, IPs libres y en uso, y conflictos con el inventario', ro ? '' : `<button class="btn" id="add">${ui('plus', 16)}Nueva red</button>`)
        + (nets.length ? `<div class="card tbl-wrap"><table class="tbl utbl"><thead><tr><th>Red</th><th>Nombre</th><th class="hide-m">VLAN</th><th>Uso</th><th>Conflictos</th></tr></thead>
          <tbody class="stagger">${nets.map((n, k) => { const bad = n.ips.filter(x => x.conflict).length, pct = Math.round(100 * n.used / n.size);
            return `<tr data-id="${n.id}" tabindex="0" style="--i:${Math.min(k, 14)}"><td class="mono"><b>${esc(n.cidr)}</b></td><td>${esc(n.name)}</td><td class="muted hide-m">${esc(n.vlan)}</td>
              <td><span class="small">${n.used} de ${n.size} · ${pct}%</span><div style="height:5px;border-radius:3px;background:var(--line);margin-top:4px;min-width:90px"><div style="height:100%;width:${Math.min(100, pct)}%;border-radius:3px;background:${pct >= 90 ? 'var(--bad)' : 'var(--acc)'}"></div></div></td>
              <td>${bad ? `<span class="pill warn"><i></i>${bad}</span>` : '<span class="dim">—</span>'}</td></tr>`; }).join('')}</tbody></table></div>`
          : empty('net', 'Aún no hay redes', 'Añade tus subredes y catlan te dirá qué IPs están libres, cuáles usa el inventario y cuáles responden sin estar en él.', ro ? '' : `<button class="btn" id="add2">${ui('plus', 16)}Nueva red</button>`));
      [$('#add'), $('#add2')].forEach(b => b && (b.onclick = () => subnetDialog()));
      app.querySelectorAll('tr[data-id]').forEach(tr => { tr.onclick = () => location.hash = '#/redes/' + tr.dataset.id; tr.onkeydown = e => e.key === 'Enter' && tr.onclick(); });
      return;
    }
    const n = await api(`subnets/${id}/ips`), ip2n = a => a.split('.').reduce((x, y) => x * 256 + +y, 0), n2ip = v => [24, 16, 8, 0].map(b => Math.floor(v / 2 ** b) % 256).join('.');
    const byIp = Object.fromEntries(n.ips.map(x => [x.ip, x])), [base, bits] = n.cidr.split('/'), total = 2 ** (32 - +bits), small = total <= 1024;
    const bad = n.ips.filter(x => x.conflict);
    crumbs([['Redes', '#/redes'], [n.cidr]]);
    const who = x => x.items.length ? x.items.map(i => `<a href="#/inv/${i.id}">${esc(i.name)}</a>`).join(', ') : `<span class="dim">${esc(x.seen || 'sin nombre')}</span>`;
    app.innerHTML = head(`<span class="mono">${esc(n.cidr)}</span>${n.name ? ' · ' + esc(n.name) : ''}`,
        [`${n.used} en uso`, `${n.free} libres`, n.vlan && 'VLAN ' + esc(n.vlan), n.scanned ? `escaneada ${esc(ago(n.scanned))}` : 'sin escanear'].filter(Boolean).join(' &nbsp;·&nbsp; '),
        (ro ? '' : `${small ? `<button class="btn" id="scan">${ui('search', 16)}Escanear</button>` : ''}<button class="btn ghost" id="ed">${ui('edit', 15)}Editar</button>`) + moreBtn)
      + (n.notes ? `<p class="muted">${esc(n.notes)}</p>` : '')
      + (bad.length ? `<section class="card pad" style="margin-bottom:16px"><h3 class="card-t">${ui('alert', 15)}Conflictos <span class="count">${bad.length}</span></h3><table class="tbl"><tbody>${bad.map(x => `<tr>
          <td style="width:1%"><span class="pill ${x.conflict === 'duplicada' ? 'bad' : 'warn'}"><i></i>${x.conflict}</span></td><td class="mono" style="width:1%;white-space:nowrap">${esc(x.ip)}</td><td>${who(x)}</td></tr>`).join('')}</tbody></table>
          <p class="muted small">«Duplicada»: dos equipos del inventario con la misma IP. «Sin registrar»: responde en la red y no está en el inventario (añádelo desde Inventario → Descubrir red).</p></section>` : '')
      + (n.next_free.length ? `<p class="small">Libres: ${n.next_free.map(x => `<button class="chip mono" data-ip="${x}" title="Copiar">${x}</button>`).join(' ')}${n.free > n.next_free.length ? ' …' : ''}</p>` : '')
      + (small ? `<section class="card pad mt"><div id="ipgrid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(30px,1fr));gap:3px">${Array.from({length: total}, (_, k) => {
          const a = n2ip(ip2n(base) + k), x = byIp[a], edge = total > 2 && (k === 0 || k === total - 1);
          const c = edge ? 'transparent' : !x ? 'var(--line)' : x.conflict === 'duplicada' ? 'var(--bad)' : x.conflict ? 'var(--warn)' : 'var(--ok)';
          return `<button class="ipc" data-ip="${a}" title="${a}${x ? ' · ' + esc(x.items.map(i => i.name).join(', ') || x.seen || 'responde') : edge ? (k ? ' · difusión' : ' · red') : ' · libre'}" style="height:22px;border:0;border-radius:4px;background:${c};font-size:9px;color:${x ? '#fff' : 'var(--tx3)'};cursor:pointer">${a.split('.')[3]}</button>`; }).join('')}</div>
          <p class="dim small" style="margin:10px 0 0">Verde: en el inventario · amarillo: responde sin estar en él · rojo: IP duplicada · gris: libre. Pulsa una IP libre para copiarla.</p></section>` : '')
      + (n.ips.length ? `<div class="card tbl-wrap mt"><table class="tbl"><thead><tr><th>IP</th><th>Equipo</th><th>${n.scanned ? 'Responde' : ''}</th><th></th></tr></thead><tbody>${n.ips.map(x => `<tr><td class="mono">${esc(x.ip)}</td><td>${who(x)}</td>
          <td>${x.up == null ? '' : x.up ? '<span class="pill ok"><i></i>sí</span>' : '<span class="pill"><i></i>no</span>'}</td><td>${x.conflict ? `<span class="pill ${x.conflict === 'duplicada' ? 'bad' : 'warn'}"><i></i>${x.conflict}</span>` : ''}</td></tr>`).join('')}</tbody></table></div>` : '');
    app.querySelectorAll('[data-ip]').forEach(b => b.onclick = () => { const x = byIp[b.dataset.ip]; if (x?.items.length) location.hash = '#/inv/' + x.items[0].id; else copy(b.dataset.ip); });
    $('#ed') && ($('#ed').onclick = () => subnetDialog(n));
    $('#scan') && ($('#scan').onclick = async e => { e.currentTarget.disabled = true; toast(`Escaneando ${n.cidr}…`); try { await api(`subnets/${n.id}/scan`, 'POST'); toast('Escaneo terminado'); } catch {} route(false); });
    $('#more').onclick = e => menu(e.currentTarget, [['Copiar red', () => copy(n.cidr), {icon: 'copy'}], ...(ro ? [] : ['-',
      ['Borrar red', async () => { if (await delUndo([['subnet', 'subnets/' + n.id]], 'Red borrada')) location.hash = '#/redes'; }, {icon: 'trash', danger: true}]])]);
  },
  async maps(id) {
    if (!id) {
      const maps = (await api('maps')).filter(m => m.type !== 'rack' && m.name.toLowerCase().includes(qv()));
      crumbs([['Esquemas']]);
      app.innerHTML = head('Esquemas', 'Diagramas de red y planos con iconos conectados', `<button class="btn" id="autotopo">${ui('nodes', 16)}Topología automática</button>`)
        + `<div class="grid stagger">${maps.map((m, i) => `<a class="tile" style="--i:${Math.min(i, 14)}" href="#/maps/${m.id}"><span class="tile-art">${ui('nodes', 34)}</span>
          <span class="tile-t">${esc(m.name)}</span><span class="tile-s">${m.n || 0} ${m.n === 1 ? 'icono' : 'iconos'}</span></a>`).join('')}
          <button class="tile add" style="--i:${Math.min(maps.length, 14)}" id="add">${ui('plus', 18)}Nuevo esquema</button></div>`;
      $('#add').onclick = create.map;
      $('#autotopo').onclick = autoTopoDialog;
      return;
    }
    const [m, items, all] = await Promise.all([api('maps/' + id), api('items'), api('maps')]);
    const racks = Object.fromEntries(all.filter(x => x.type === 'rack').map(r => [r.id, r]));
    const rackData = {}, rackOf = id => rackData[id] ||= api('maps/' + id).catch(() => null); // vista previa, una vez por sesión
    const byId = Object.fromEntries(items.map(i => [i.id, i])), d = {nodes: [], links: [], ...m.data};
    let selN = null, selL = null, connecting = false, drag = null, pan = null, timer, first = true, saving = Promise.resolve(); // saving: un guardado detrás de otro, con la versión que devolvió el anterior
    const save = () => { clearTimeout(timer); timer = setTimeout(() => saving = saving.then(() => putFresh('maps/' + m.id, {name: $('#mname').value, data: d}, m.version)).then(x => m.version = x.version, () => {}), 400); };
    app.dataset.w = 'fill';
    crumbs([['Esquemas', '#/maps'], [m.name]]);
    app.innerHTML = `<div class="ed-head"><input id="mname" class="title-in" value="${esc(m.name)}" aria-label="Nombre del esquema"><span class="dim small" id="count"></span>${moreBtn}</div>
      <div class="stage card" id="stage">
        <svg id="cv" viewBox="0 0 1200 800" tabindex="0" role="application" aria-label="Lienzo del esquema. Flechas mueven el icono seleccionado, Supr lo borra, + y - hacen zoom, 0 encuadra.">
          ${m.has_image ? `<image href="/api/maps/${m.id}/image" width="1200" height="800" class="bgimg"/>` : ''}<g id="links"></g><line id="ghost" class="ghostln" visibility="hidden"/><g id="nodes"></g></svg>
        <div class="dock${S.dock ? '' : ' closed'}" id="dock"><button class="dock-tg" id="dock-tg" aria-expanded="${!!S.dock}" title="Paleta de iconos" aria-label="Paleta de iconos">${ui('layers', 19)}</button>
          <div class="dock-tools"><div>${Object.entries(ICONS).map(([k, [n]]) => `<button data-icon="${k}" title="Añadir ${n}" aria-label="Añadir ${n}"><svg width="22" height="22" aria-hidden="true"><use href="#i-${k}"/></svg></button>`).join('')}</div></div></div>
        <div class="insp" id="panel"></div><div class="hint-pill" id="hint"></div></div>`;
    const cv = $('#cv'), stage = $('#stage'), ghost = $('#ghost'), node = nid => d.nodes.find(n => n.id === nid);
    const pt = e => { const p = new DOMPoint(e.clientX, e.clientY).matrixTransform(cv.getScreenCTM().inverse()); return [p.x, p.y]; };
    const clamp = (v, max) => Math.round(Math.min(max - 34, Math.max(34, v)));
    // Vista: rueda = zoom hacia el cursor, arrastrar el fondo = moverse, doble clic o 0 = encuadrar
    const vb = cv.viewBox.baseVal;
    function fit() { // con plano de fondo se ve el plano entero; si no, el contenido
      let v = {x: 0, y: 0, width: 1200, height: 800};
      if (!m.has_image && d.nodes.length) {
        const xs = d.nodes.map(n => +n.x), ys = d.nodes.map(n => +n.y);
        const x0 = Math.min(...xs) - 110, x1 = Math.max(...xs) + 110, y0 = Math.min(...ys) - 100, y1 = Math.max(...ys) + 130;
        const w = Math.max(x1 - x0, 600), h = Math.max(y1 - y0, 400);
        v = {x: (x0 + x1 - w) / 2, y: (y0 + y1 - h) / 2, width: w, height: h};
      }
      Object.assign(vb, v);
    }
    const zoom = (f, [px, py]) => { // el punto bajo el cursor se queda quieto
      f = Math.min(4800, Math.max(150, vb.width * f)) / vb.width;
      Object.assign(vb, {x: px - (px - vb.x) * f, y: py - (py - vb.y) * f, width: vb.width * f, height: vb.height * f});
    };
    const center = () => [vb.x + vb.width / 2, vb.y + vb.height / 2];
    fit();
    function draw() {
      const q = qv();
      $('#links').innerHTML = d.links.map(([a, b, port], i) => { const A = node(a), B = node(b); if (!A || !B) return '';
        const xy = `x1="${+A.x}" y1="${+A.y}" x2="${+B.x}" y2="${+B.y}"`;
        return `<g data-link="${i}" class="lkg${selL === i ? ' sel' : ''}"><line class="hit" ${xy}/><line class="lk" ${xy}/>${port ? `<text class="lkt" x="${+A.x + (B.x - A.x) * .78}" y="${+A.y + (B.y - A.y) * .78 - 4}">${esc(port)}</text>` : ''}</g>`; }).join('');
      // Nodos con clave estable: persisten entre dibujos para que las transiciones fluyan
      const layer = $('#nodes'), seen = new Set();
      d.nodes.forEach((n, k) => {
        let g = [...layer.children].find(x => x.dataset.node === n.id && !x.dataset.gone);
        const fresh = !g;
        if (fresh) { g = document.createElementNS('http://www.w3.org/2000/svg', 'g'); g.dataset.node = n.id; layer.append(g); }
        const it = byId[n.item], rk = n.t === 'rack' && racks[n.rack];
        const name = n.label || (n.t === 'rack' ? rk?.name || 'Rack borrado' : it?.name) || ICONS[n.t]?.[0] || n.t;
        const ip = n.t === 'rack' ? (rk ? `${rk.height || 42}U · ${rk.n || 0} eq.` : '') : it?.ip || '';
        g.setAttribute('class', `nd${selN === n.id ? ' sel' : ''}${!q || (name + ' ' + ip).toLowerCase().includes(q) ? '' : ' dim'}`);
        g.setAttribute('transform', `translate(${+n.x} ${+n.y})`);
        const key = [n.t, name, ip].join('|');
        if (g.dataset.k !== key) {
          g.dataset.k = key;
          g.innerHTML = `<g class="in"><rect class="halo" x="-39" y="-39" width="78" height="78" rx="19"/><rect class="box" x="-32" y="-32" width="64" height="64" rx="15"/>
            <use href="#i-${esc(n.t)}" x="-20" y="-20" width="40" height="40"/><text y="53" text-anchor="middle">${esc(name)}</text>${ip ? `<text y="69" text-anchor="middle" class="ip">${esc(ip)}</text>` : ''}</g>`;
        }
        if (fresh) pop(g.firstChild, first ? k : 0);
        seen.add(g);
      });
      [...layer.children].forEach(g => seen.has(g) || g.dataset.gone || vanish(g));
      $('#count').textContent = `${d.nodes.length} ${d.nodes.length === 1 ? 'icono' : 'iconos'} · ${d.links.length} ${d.links.length === 1 ? 'conexión' : 'conexiones'}`;
      first = false;
    }
    function panel() {
      const p = $('#panel'), n = node(selN), h = $('#hint');
      h.classList.toggle('on', connecting);
      h.textContent = connecting ? 'Elige el icono de destino · Esc cancela' : d.nodes.length ? 'Rueda: zoom · arrastra el fondo para moverte · doble clic: encuadrar' : 'Añade iconos desde la paleta';
      p.classList.toggle('show', !!n || selL !== null);
      if (n) {
        p.innerHTML = `<div class="insp-h"><span class="insp-ic"><svg width="22" height="22" aria-hidden="true"><use href="#i-${esc(n.t)}"/></svg></span>
            <div><b>${esc(ICONS[n.t]?.[0] || n.t)}</b><span class="dim small">Icono seleccionado</span></div><button class="btn icon ghost sm" id="desel" aria-label="Cerrar">${ui('x', 16)}</button></div>
          <div class="fields"><div class="field"><label for="lbl">Etiqueta</label><input id="lbl" value="${esc(n.label || '')}" placeholder="${esc((n.t === 'rack' ? racks[n.rack]?.name : byId[n.item]?.name) || 'Sin etiqueta')}"></div>
          ${n.t === 'rack' ? `<div class="field"><label for="rks">Rack</label><select id="rks">${Object.values(racks).map(r => `<option value="${r.id}" ${r.id === n.rack ? 'selected' : ''}>${esc(r.name)} · ${r.height || 42}U</option>`).join('')}</select></div></div>
            ${racks[n.rack] ? `<a class="linkrow" href="#/racks/${+n.rack}">${ui('rack', 16)}Abrir rack</a>` : ''}`
          : `<div class="field"><label for="itm">Equipo del inventario</label><select id="itm"><option value="">Sin enlazar</option>
            ${items.map(i => `<option value="${i.id}" ${i.id === n.item ? 'selected' : ''}>${esc(i.name)}${i.ip ? ' · ' + esc(i.ip) : ''}</option>`).join('')}</select></div></div>
          ${n.item ? `<a class="linkrow" href="#/inv/${+n.item}">${ui('box', 16)}Abrir ficha del equipo</a>` : ''}`}
          <div class="insp-a"><button class="btn${connecting ? ' pri' : ''}" id="con">${ui('link', 16)}${connecting ? 'Elige destino…' : 'Conectar'}</button><button class="btn icon danger" id="rm" aria-label="Borrar icono" title="Borrar icono">${ui('trash', 16)}</button></div>`;
        $('#lbl').oninput = e => { n.label = e.target.value; draw(); save(); };
        $('#itm') && ($('#itm').onchange = e => { n.item = e.target.value ? +e.target.value : null; draw(); panel(); save(); });
        $('#rks') && ($('#rks').onchange = e => { n.rack = +e.target.value; draw(); panel(); save(); });
        $('#con').onclick = () => { connecting = !connecting; ghost.setAttribute('visibility', 'hidden'); panel(); };
      } else if (selL !== null) {
        const [a, b] = d.links[selL] || [], nm = x => esc(x?.label || byId[x?.item]?.name || ICONS[x?.t]?.[0] || '');
        p.innerHTML = `<div class="insp-h"><span class="insp-ic">${ui('link', 20)}</span><div><b>Conexión</b><span class="dim small">${nm(node(a))} ↔ ${nm(node(b))}</span></div>
          <button class="btn icon ghost sm" id="desel" aria-label="Cerrar">${ui('x', 16)}</button></div><div class="insp-a"><button class="btn danger" id="rm">${ui('trash', 16)}Borrar conexión</button></div>`;
      } else return;
      $('#desel').onclick = () => select(null);
      $('#rm').onclick = remove;
    }
    const select = (n, l = null) => { selN = n; selL = l; draw(); panel(); };
    function remove() {
      if (selN) { d.nodes = d.nodes.filter(n => n.id !== selN); d.links = d.links.filter(l => !l.includes(selN)); }
      else if (selL !== null) d.links.splice(selL, 1);
      else return;
      connecting = false; select(null); save();
    }
    $('#dock-tg').onclick = () => { S.dock = !$('#dock').classList.toggle('closed'); $('#dock-tg').setAttribute('aria-expanded', S.dock); applySettings(); };
    $('#dock').onclick = e => {
      const b = e.target.closest('[data-icon]'); if (!b) return;
      const add = extra => {
        const vb = cv.viewBox.baseVal, off = d.nodes.length % 8 * 24 - 84; // en el centro de lo que se ve
        const n = {id: Math.random().toString(36).slice(2, 10), t: b.dataset.icon, x: clamp(vb.x + vb.width / 2 + off, 1200), y: clamp(vb.y + vb.height / 2 + off, 800), ...extra};
        d.nodes.push(n); select(n.id); save(); cv.focus({preventScroll: true});
      };
      if (b.dataset.icon !== 'rack') return add();
      const list = Object.values(racks);
      menu(b, list.length ? list.map(r => [`${r.name} · ${r.height || 42}U`, () => add({rack: r.id}), {icon: 'rack'}]) : [['Aún no hay racks: crear uno', create.rack, {icon: 'plus'}]]);
    };
    // Al pasar por un rack: ficha con sus datos y el rack en miniatura
    $('#nodes').onmouseover = e => {
      const g = e.target.closest('[data-node]'), n = g && node(g.dataset.node);
      if (n?.t !== 'rack' || drag || pan || hcard?.dataset.for === n.id) return;
      clearTimeout(hcT);
      hcT = setTimeout(async () => { const r = await rackOf(n.rack); if (r && g.matches(':hover') && !drag && !pan) floatCard(g, rackCard(r, byId), n.id); }, 220);
    };
    $('#nodes').onmouseout = e => { if (e.target.closest('[data-node]')) { clearTimeout(hcT); hcT = setTimeout(hideCard, 150); } };
    cv.onpointerdown = e => {
      hideCard();
      const ng = e.target.closest('[data-node]'), lg = e.target.closest('[data-link]');
      if (!ng) {
        connecting = false; ghost.setAttribute('visibility', 'hidden');
        if (!lg) { pan = {x: e.clientX, y: e.clientY, vx: vb.x, vy: vb.y, s: cv.getScreenCTM().a}; cv.setPointerCapture(e.pointerId); stage.classList.add('dragging'); }
        return select(null, lg ? +lg.dataset.link : null);
      }
      const nid = ng.dataset.node, n = node(nid);
      if (connecting && selN && selN !== nid) {
        if (!d.links.some(([a, b]) => (a === selN && b === nid) || (a === nid && b === selN))) { d.links.push([selN, nid]); toast('Conectados'); }
        connecting = false; ghost.setAttribute('visibility', 'hidden'); save();
      }
      const [x, y] = pt(e);
      drag = {n, dx: x - n.x, dy: y - n.y, moved: false};
      cv.setPointerCapture(e.pointerId); stage.classList.add('dragging');
      select(nid);
    };
    cv.onpointermove = e => {
      if (pan) { vb.x = pan.vx - (e.clientX - pan.x) / pan.s; vb.y = pan.vy - (e.clientY - pan.y) / pan.s; return; }
      const [x, y] = pt(e);
      if (connecting && node(selN)) { const s = node(selN); Object.entries({x1: s.x, y1: s.y, x2: x, y2: y, visibility: 'visible'}).forEach(([k, v]) => ghost.setAttribute(k, v)); }
      if (!drag) return;
      Object.assign(drag.n, {x: clamp(x - drag.dx, 1200), y: clamp(y - drag.dy, 800)}); drag.moved = true; draw();
    };
    cv.onpointerup = () => { if (drag?.moved) save(); drag = pan = null; stage.classList.remove('dragging'); };
    cv.onwheel = e => { e.preventDefault(); zoom(Math.exp(e.deltaY * .0015), pt(e)); };
    cv.ondblclick = e => {
      const g = e.target.closest('[data-node]'), n = g && node(g.dataset.node);
      if (n?.t === 'rack' && racks[n.rack]) location.hash = '#/racks/' + n.rack; // doble clic en un rack: abrirlo
      else if (!e.target.closest('[data-node],[data-link]')) fit();
    };
    cv.onkeydown = e => {
      const n = node(selN), step = e.shiftKey ? 1 : 10;
      if (e.key === 'Escape') { connecting = false; ghost.setAttribute('visibility', 'hidden'); return select(null); }
      if (e.key === 'Delete' || e.key === 'Backspace') { e.preventDefault(); return remove(); }
      if (e.key === '+' || e.key === '=') return zoom(1 / 1.25, center());
      if (e.key === '-') return zoom(1.25, center());
      if (e.key === '0') return fit();
      const mv = {ArrowLeft: [-step, 0], ArrowRight: [step, 0], ArrowUp: [0, -step], ArrowDown: [0, step]}[e.key];
      if (n && mv) { e.preventDefault(); n.x = clamp(n.x + mv[0], 1200); n.y = clamp(n.y + mv[1], 800); draw(); save(); }
    };
    $('#mname').oninput = save;
    if (d.auto) $('#count').insertAdjacentHTML('afterend', `<span class="dim small"> · dibujado del switch el ${esc(date(d.auto.at).toLocaleString('es'))}</span>`);
    $('#more').onclick = e => menu(e.currentTarget, [
      ...(d.auto ? [['Volver a leer del switch', () => autoTopo(d.auto.source), {icon: 'redo'}], '-'] : []),
      ['Borrar esquema', async () => { if (!m.has_image) { clearTimeout(timer); if (await delUndo([['map', 'maps/' + m.id]], 'Esquema borrado')) location.hash = '#/maps'; return; } if (await ask('¿Borrar este esquema?', `«${esc($('#mname').value)}» y sus conexiones se borrarán. En Actividad queda una foto de sus iconos y conexiones.` + (m.has_image ? `<br><br><b>La imagen de fondo no se guarda.</b> <a href="/api/maps/${+m.id}/image" download="${esc($('#mname').value)}">Descárgala antes</a> si la necesitas.` : ''))) { clearTimeout(timer); await api('maps/' + m.id, 'DELETE'); toast('Esquema borrado'); location.hash = '#/maps'; } }, {icon: 'trash', danger: true}]]);
    redraw = draw; draw(); panel();
  },
});
