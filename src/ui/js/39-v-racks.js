Object.assign(views, {
  async racks(id) {
    if (!id) {
      const racks = (await api('maps')).filter(m => m.type === 'rack' && m.name.toLowerCase().includes(qv()));
      crumbs([['Racks']]);
      app.innerHTML = head('Racks', 'Armarios simulados, montados U a U')
        + `<div class="grid stagger">${racks.map((r, i) => `<a class="tile" style="--i:${Math.min(i, 14)}" href="#/racks/${r.id}"><span class="tile-art">${ui('rack', 34)}</span>
          <span class="tile-t">${esc(r.name)}</span><span class="tile-s">${r.height || 42}U · ${r.n || 0} ${r.n === 1 ? 'equipo' : 'equipos'}</span></a>`).join('')}
          <button class="tile add" style="--i:${Math.min(racks.length, 14)}" id="add">${ui('plus', 18)}Nuevo rack</button></div>`;
      $('#add').onclick = create.rack;
      return;
    }
    const [r, items] = await Promise.all([api('maps/' + id), api('items')]);
    const byId = Object.fromEntries(items.map(i => [i.id, i])), d = {height: 42, devices: [], ...r.data, type: 'rack'};
    const UH = 24; // px por U
    let sel = null, drag = null, timer, first = true, saving = Promise.resolve();
    const save = () => { clearTimeout(timer); timer = setTimeout(() => saving = saving.then(() => putFresh('maps/' + r.id, {name: $('#mname').value, data: d}, r.version)).then(x => r.version = x.version, () => {}), 400); };
    // ¿cabe un equipo de h U con su U inferior en u, sin pisar a otro?
    const free = (u, h, skip) => u >= 1 && u + h - 1 <= d.height && !d.devices.some(x => x !== skip && u < x.u + x.h && x.u < u + h);
    const dev = () => d.devices.find(x => x.id === sel);
    const props = s => (s || '').split('\n').filter(l => l.trim()).map(l => { const i = l.indexOf(':'); return i < 0 ? ['', l.trim()] : [l.slice(0, i).trim(), l.slice(i + 1).trim()]; });
    const label = x => x.label || byId[x.item]?.name || RACK_TYPES[x.t]?.[0] || x.t;
    app.dataset.w = 'wide';
    crumbs([['Racks', '#/racks'], [r.name]]);
    app.innerHTML = `<div class="ed-head"><input id="mname" class="title-in" value="${esc(r.name)}" aria-label="Nombre del rack">
        <div class="rk-cap"><div class="meter" aria-hidden="true"><i id="meter"></i></div><span id="used" class="small muted mono"></span></div>
        <label class="hgt small muted">Altura <input id="rh" type="number" min="1" max="60" value="${d.height}" class="mono"> U</label>${moreBtn}</div>
      <div class="rk-layout stagger"><section class="card pad rk-pal" style="--i:0">${collapsible('Añadir equipo', `<div class="pal-list" id="pal">${Object.entries(RACK_TYPES).map(([k, [n, h]]) =>
          `<button class="pal-item" data-t="${k}" title="Añadir ${n} (${h}U)"><span class="sw t-${k}"></span>${n}<span class="u">${h}U</span></button>`).join('')}</div>`, {open: true})}</section>
        <div class="rack-frame" style="--i:1"><div class="rack" id="rack" tabindex="0" role="application" aria-label="Rack. Flechas mueven el equipo seleccionado, Supr lo quita."></div></div>
        <section class="card pad rk-insp" id="panel" style="--i:2"></section></div>`;
    const rack = $('#rack');
    function draw() {
      const q = qv();
      if (+rack.dataset.h !== d.height) {
        rack.style.height = d.height * UH + 'px';
        rack.querySelectorAll('.ru').forEach(e => e.remove());
        rack.insertAdjacentHTML('afterbegin', Array.from({length: d.height}, (_, i) => `<div class="ru" style="bottom:${i * UH}px"><span>${i + 1}</span></div>`).join(''));
        rack.dataset.h = d.height;
      }
      // Equipos con clave estable: al cambiar de U se deslizan en vez de reaparecer
      const seen = new Set();
      [...d.devices].sort((a, b) => a.u - b.u).forEach((x, k) => {
        let el = [...rack.children].find(e => e.dataset.id === x.id && !e.dataset.gone);
        const fresh = !el;
        if (fresh) { el = document.createElement('div'); el.dataset.id = x.id; rack.append(el); }
        const it = byId[x.item], name = label(x), hit = !q || [name, it?.ip, x.props, ...Object.values(x.pmap || {}).map(v => refName(v, byId))].join(' ').toLowerCase().includes(q);
        el.className = `dev t-${x.t}${x.id === sel ? ' sel' : ''}${drag?.x === x ? ' lift' : ''}${hit ? '' : ' dim'}${(x.ports || 0) > 24 ? ' many' : ''}`;
        el.style.bottom = (x.u - 1) * UH + 'px'; el.style.height = x.h * UH + 'px';
        el.title = x.props || '';
        const key = [x.t, name, x.h, it?.ip, x.ports, sfpCount(x), JSON.stringify(x.pmap || {})].join('|');
        if (el.dataset.k !== key) { el.dataset.k = key; el.innerHTML = face(x, name, it?.ip, byId); }
        if (fresh) pop(el, first ? k : 0);
        seen.add(el);
      });
      rack.querySelectorAll('.dev').forEach(el => seen.has(el) || el.dataset.gone || vanish(el));
      const used = d.devices.reduce((s, x) => s + x.h, 0);
      $('#used').textContent = `${used} / ${d.height} U`;
      $('#meter').style.width = Math.min(100, used / d.height * 100) + '%';
      first = false;
    }
    function panel() {
      const p = $('#panel'), x = dev();
      if (!x) {
        const list = [...d.devices].sort((a, b) => b.u - a.u);
        p.innerHTML = `<h3 class="card-t">Contenido <span class="count">${list.length}</span></h3>` + (list.length
          ? `<ul class="rk-list">${list.map(x => `<li data-id="${esc(x.id)}" tabindex="0"><span class="mono">U${x.h > 1 ? `${x.u}–${x.u + x.h - 1}` : x.u}</span><span class="sw t-${x.t}"></span>${esc(label(x))}</li>`).join('')}</ul>`
          : `<p class="muted small">Rack vacío. Añade equipos desde la paleta y arrástralos a su U.</p>`);
        p.querySelectorAll('li[data-id]').forEach(li => { li.onclick = () => select(li.dataset.id); li.onkeydown = e => e.key === 'Enter' && li.click(); });
        return;
      }
      p.innerHTML = `<div class="insp-h"><span class="sw t-${x.t}" style="width:30px;height:18px"></span><div><b>${esc(label(x))}</b><span class="dim small mono">U${x.u}${x.h > 1 ? '–' + (x.u + x.h - 1) : ''} · ${x.h}U</span></div>
          <button class="btn icon ghost sm" id="x-close" aria-label="Cerrar">${ui('x', 16)}</button></div>
        <div class="fields two">
          <div class="field full"><label for="x-label">Nombre</label><input id="x-label" value="${esc(x.label || '')}" placeholder="${esc(byId[x.item]?.name || RACK_TYPES[x.t]?.[0] || '')}"></div>
          <div class="field full"><label for="x-t">Tipo</label><select id="x-t">${Object.entries(RACK_TYPES).map(([k, [n]]) => `<option value="${k}" ${k === x.t ? 'selected' : ''}>${n}</option>`).join('')}</select></div>
          <div class="field"><label for="x-h">Tamaño (U)</label><input id="x-h" class="mono" type="number" min="1" max="${d.height}" value="${x.h}"></div>
          <div class="field"><label for="x-u">U inferior</label><input id="x-u" class="mono" type="number" min="1" max="${d.height}" value="${x.u}"></div>
          ${hasPorts(x.t) ? `<div class="field"><label for="x-np">${x.t === 'pdu' ? 'Enchufes' : 'Bocas'}</label><select id="x-np" class="mono">${PORT_OPTS.map(o => `<option ${o === nPorts(x) ? 'selected' : ''}>${o}</option>`).join('')}</select></div>
            <div class="field"><label>&nbsp;</label><button class="btn" id="x-ports" style="width:100%">${ui('eye', 16)}Ver ${pw(x, 1)}</button></div>
            ${x.t === 'switch' ? `<div class="field full"><label for="x-sfp">Puertos SFP</label><select id="x-sfp" class="mono">${SFP_OPTS.map(o => `<option ${o === sfpCount(x) ? 'selected' : ''}>${o}</option>`).join('')}</select></div>` : ''}
            <div class="field full np">${ui('link', 14)}${portSeq(x).filter(p => x.pmap?.[p]).length} de ${portSeq(x).length} anotad${x.t === 'pdu' ? 'os' : 'as'} · clic en un${x.t === 'pdu' ? ' enchufe' : 'a boca'} del rack para editarl${x.t === 'pdu' ? 'o' : 'a'}</div>` : ''}
          <div class="field full"><label for="x-item">Equipo del inventario</label><select id="x-item"><option value="">Sin enlazar</option>
            ${items.map(i => `<option value="${i.id}" ${i.id === x.item ? 'selected' : ''}>${esc(i.name)}${i.ip ? ' · ' + esc(i.ip) : ''}</option>`).join('')}</select></div>
          <div class="field full"><label for="x-props">Características</label><textarea id="x-props" rows="4" class="mono" placeholder="CPU: 2x Xeon Silver&#10;RAM: 128 GB&#10;Puertos: 24x 1G + 4x SFP+&#10;Consumo: 450 W">${esc(x.props || '')}</textarea></div></div>
        ${x.item ? `<a class="linkrow" href="#/inv/${+x.item}">${ui('box', 16)}Abrir ficha del equipo</a>` : ''}
        <table class="props" id="x-tab"></table>
        <div class="insp-a"><button class="btn danger" id="x-rm">${ui('trash', 16)}Quitar del rack</button></div>`;
      const tab = () => $('#x-tab').innerHTML = props(x.props).map(([k, v]) => `<tr><th>${esc(k)}</th><td>${refHTML(v, byId)}</td></tr>`).join('');
      tab();
      $('#x-label').oninput = e => { x.label = e.target.value; draw(); save(); };
      $('#x-props').oninput = e => { x.props = e.target.value; tab(); draw(); save(); };
      $('#x-t').onchange = e => { x.t = e.target.value; draw(); panel(); save(); };
      $('#x-item').onchange = e => { x.item = e.target.value ? +e.target.value : null; draw(); panel(); save(); };
      if (hasPorts(x.t)) {
        $('#x-np').onchange = e => { x.ports = +e.target.value; draw(); panel(); save(); };
        $('#x-ports').onclick = () => openPorts(x);
        $('#x-sfp') && ($('#x-sfp').onchange = e => { x.sfp = +e.target.value; draw(); panel(); save(); });
      }
      for (const k of ['h', 'u']) $('#x-' + k).onchange = e => {
        const v = Math.round(+e.target.value), h = k === 'h' ? v : x.h, u = k === 'u' ? v : x.u;
        if (!free(u, h, x)) { toast('No cabe ahí: se sale del rack o pisa otro equipo', 'bad'); shake(e.target); e.target.value = x[k]; return; }
        x[k] = v; draw(); save();
      };
      $('#x-close').onclick = () => select(null);
      $('#x-rm').onclick = remove;
    }
    const select = sid => { sel = sid; draw(); panel(); };
    const openPorts = (x, p) => portsDialog(x, label(x), p, byId, closed => { draw(); closed ? panel() : save(); });
    function remove() { if (!dev()) return; d.devices = d.devices.filter(x => x.id !== sel); select(null); save(); }
    $('#pal').onclick = e => {
      const b = e.target.closest('[data-t]'); if (!b) return;
      const t = b.dataset.t, h = RACK_TYPES[t][1];
      let u = d.height - h + 1; while (u >= 1 && !free(u, h)) u--; // primer hueco desde arriba
      if (u < 1) { toast(`No queda hueco de ${h}U en el rack`, 'bad'); return shake($('.rack-frame')); }
      const x = {id: Math.random().toString(36).slice(2, 10), t, u, h, label: '', props: ''};
      d.devices.push(x); select(x.id); save();
    };
    rack.onpointerdown = e => {
      const el = e.target.closest('.dev'); if (!el) return select(null);
      const pt = e.target.closest('.pt,.sf');
      if (pt) { select(el.dataset.id); e.preventDefault(); return openPorts(dev(), pkey(pt.dataset.p)); } // clic en una boca: abre sus bocas
      sel = el.dataset.id; drag = {x: dev(), y: e.clientY, u: dev().u, moved: false};
      rack.setPointerCapture(e.pointerId); draw(); panel();
    };
    rack.onpointermove = e => {
      if (!drag) return;
      const u = drag.u + Math.round((drag.y - e.clientY) / UH);
      if (u !== drag.x.u && free(u, drag.x.h, drag.x)) { drag.x.u = u; drag.moved = true; draw(); }
    };
    rack.onpointerup = () => { const moved = drag?.moved; drag = null; draw(); if (moved) { save(); panel(); } };
    rack.onkeydown = e => {
      const x = dev();
      if (e.key === 'Escape') return select(null);
      if (!x) return;
      if (e.key === 'Delete' || e.key === 'Backspace') { e.preventDefault(); return remove(); }
      const u = x.u + (e.key === 'ArrowUp' ? 1 : e.key === 'ArrowDown' ? -1 : 0);
      if (u !== x.u) { e.preventDefault(); if (free(u, x.h, x)) { x.u = u; draw(); panel(); save(); } else shake($('.rack-frame')); }
    };
    $('#rh').onchange = e => {
      const h = Math.min(60, Math.max(1, Math.round(+e.target.value)));
      if (d.devices.some(x => x.u + x.h - 1 > h)) { toast('Hay equipos por encima de esa altura; muévelos antes', 'bad'); shake(e.target); e.target.value = d.height; return; }
      d.height = h; e.target.value = h; draw(); save();
    };
    $('#mname').oninput = save;
    $('#more').onclick = e => menu(e.currentTarget, [
      ['Programar mantenimiento…', () => maintDialog({rack: r.id}, $('#mname').value), {icon: 'bell'}], '-',
      ['Borrar rack', async () => { clearTimeout(timer); if (await delUndo([['rack', 'maps/' + r.id]], 'Rack borrado')) location.hash = '#/racks'; }, {icon: 'trash', danger: true}]]);
    redraw = draw; draw(); panel();
  },
});

