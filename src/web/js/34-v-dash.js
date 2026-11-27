Object.assign(views, {
  async dash() {
    crumbs([['Dashboard']]);
    app.dataset.w = 'wide';
    const D = await api('dashboard') || DASH_DEF(), G = 14, ROW = 84, pos = new Map(), els = {};
    app.innerHTML = head('Dashboard', 'Tu tablero: elige qué ver, arrastra, agranda y cambia cada gráfico entre líneas, barras o tarta',
      `<button class="btn" id="dadd" hidden>${ui('plus', 16)}Añadir</button><button class="btn" id="dedit" aria-pressed="false">${ui('grid', 16)}<span>Personalizar</span></button>`)
      + `<div class="dash" id="dash"><div class="dghost" hidden></div></div>`;
    const box = $('#dash'), ghost = box.firstChild;
    let edit = false, memo = {}, saveT, cw = 0;
    const get = p => memo[p] ||= fetch('/api/' + p).then(r => r.ok ? r.json() : Promise.reject(r.status));
    const save = () => { clearTimeout(saveT); saveT = setTimeout(() => { saveT = null; api('dashboard', 'PUT', D); }, 450); };
    const byId = id => D.widgets.find(w => w.id === id);
    const hit = (a, b) => a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;
    // Encaje: lo que pisa la tarjeta movida baja; después todo sube a ocupar huecos (sin cambiar el orden)
    function settle(moved) {
      for (const first of moved ? [moved, null] : [null]) {
        const placed = first ? [first] : [];
        for (const w of [...D.widgets].sort((a, b) => a.y - b.y || a.x - b.x)) {
          if (w === first) continue;
          while (w.y > 0 && !placed.some(p => hit({...w, y: w.y - 1}, p))) w.y--;
          while (placed.some(p => hit(w, p))) w.y++;
          placed.push(w);
        }
      }
    }
    function layout(skip) {
      const W = box.clientWidth, nar = W < 720;
      cw = (W - G * 11) / 12; box.style.setProperty('--cw', cw + 'px'); box.classList.toggle('narrow', nar);
      let ny = 0;
      for (const w of nar ? [...D.widgets].sort((a, b) => a.y - b.y || a.x - b.x) : D.widgets) {
        const g = nar ? {x: 0, y: ny, w: W, h: Math.min(w.h, 4) * (ROW + G) - G} : {x: w.x * (cw + G), y: w.y * (ROW + G), w: w.w * cw + (w.w - 1) * G, h: w.h * ROW + (w.h - 1) * G};
        if (nar) ny += g.h + G;
        pos.set(w, g);
        const el = els[w.id];
        if (el && el !== skip) Object.assign(el.style, {transform: `translate(${g.x}px,${g.y}px)`, width: g.w + 'px', height: g.h + 'px'});
      }
      box.style.height = (nar ? ny : Math.max(2, ...D.widgets.map(w => w.y + w.h)) * (ROW + G) - G) + 'px';
      $('#dedit').hidden = nar;
      if (nar && edit) setEdit(false);
    }
    const placeGhost = w => { const g = pos.get(w); Object.assign(ghost.style, {transform: `translate(${g.x}px,${g.y}px)`, width: g.w + 'px', height: g.h + 'px'}); };
    // Rebote al soltar o agrandar: aplastar y estirar, anclado donde tiene sentido
    const jelly = (el, origin, k) => squish(el.firstChild, origin, k);
    function draw(w, force) {
      const el = els[w.id], d = el?._d, g = pos.get(w); if (!d || !g) return;
      const bw = Math.round(g.w - 28), bh = Math.round(g.h - 62), view = w.view || DW[w.kind].view, key = [bw, bh, view, d.v].join();
      if (!force && el._k === key) return;
      el._k = key;
      const b = el.querySelector('.dw-b'); Object.assign(b.style, {width: bw + 'px', height: bh + 'px'});
      el.querySelectorAll('[data-view]').forEach(x => { x.classList.toggle('on', x.dataset.view === view); x.setAttribute('aria-pressed', x.dataset.view === view); });
      if (d.empty || d.series && !d.cats && !d.series.some(x => x.points.length)) return void (b.innerHTML = `<p class="muted small chart-empty">${esc(d.empty || 'Sin datos todavía.')}</p>`);
      if (d.map) return mapPreview(b, d.map, bw, bh);
      if ('stat' in d) {
        const txt = d.stat.toLocaleString('es'), fs = Math.max(26, Math.min(96, bh * .78, bw / (txt.length * .62 + (d.crit ? .9 : 0))));
        b.innerHTML = `<div class="dstat${d.crit ? ' crit' : ''}" style="font-size:${fs}px">${d.crit ? ui('alert', fs * .7) : ''}<span>${txt}</span></div>`;
        return;
      }
      if (view === 'line' && d.series) return lineChart(b, d.series, {h: bh - (d.series.length > 1 ? 34 : 0), unit: d.unit, limit: d.limit, title: d.title});
      const cats = d.cats && (view !== 'line' || !d.series) ? d.cats : d.series.map(x => ({label: x.label, value: x.points.at(-1)?.[1] ?? 0})); // sin categorías: el último valor de cada serie
      ({bar: barChart, pie: pieChart, line: catLine})[view](b, cats, d.unit, bw, bh, d.title, !!d.cats && !d.unit);
    }
    async function fill(w) {
      let d;
      try { d = await dwData(w, get); } catch { d = {title: DW[w.kind].name, empty: 'No se han podido leer los datos.'}; }
      const el = els[w.id]; if (!el) return;
      d.v = (el._d?.v || 0) + 1; el._d = d;
      const t = el.querySelector('.dw-t'); t.textContent = w.title || d.title; t.href = d.href || '#/dash';
      el.querySelector('.dw-tt small').textContent = d.sub || '';
      draw(w);
    }
    function mount(w) {
      const el = document.createElement('div'), views = DW[w.kind].view && !(w.kind === 'stat' || w.kind === 'map');
      el.className = 'dw'; el.dataset.id = w.id;
      el.innerHTML = `<div class="dw-in"><div class="dw-h"><span class="dw-ic">${ui(DW[w.kind].icon, 15)}</span><div class="dw-tt"><a class="dw-t" href="#/dash">${esc(w.title || DW[w.kind].name)}</a><small></small></div>
        <div class="dw-a">${views ? Object.entries(DVIEWS).map(([k, [n, ic]]) => `<button data-view="${k}" title="${n}" aria-label="Ver como ${n.toLowerCase()}">${ui(ic, 15)}</button>`).join('') : ''}
          <button class="dw-ed" data-act="more" title="Opciones" aria-label="Opciones de la tarjeta" aria-haspopup="menu">${ui('more', 15)}</button></div></div>
        <div class="dw-b"></div><span class="dw-rz" title="Arrastra para cambiar el tamaño"></span></div>`;
      if (edit) el.tabIndex = 0;
      box.append(el); els[w.id] = el;
      return el;
    }
    function setEdit(on) {
      edit = on; box.classList.toggle('edit', on);
      $('#dedit').setAttribute('aria-pressed', on); $('#dedit span').textContent = on ? 'Listo' : 'Personalizar'; $('#dedit').classList.toggle('pri', on);
      $('#dadd').hidden = !on;
      Object.values(els).forEach((el, i) => { el.tabIndex = on ? 0 : -1; if (on) setTimeout(() => jelly(el, '50% 50%', .6), i * 35); });
    }
    function remove(w) {
      const el = els[w.id]; delete els[w.id];
      D.widgets.splice(D.widgets.indexOf(w), 1); el.style.pointerEvents = 'none';
      const a = anim(el.firstChild, [{opacity: 1}, {opacity: 0, transform: 'scale(.85)'}], {duration: 220, easing: 'ease-in', fill: 'forwards'}); // el transform de .dw es su posición
      a ? a.finished.then(() => el.remove()) : el.remove();
      settle(); layout(); save();
    }
    async function configure(w, fresh) {
      const [health, maps] = await Promise.all([w.kind === 'health' ? get('health') : [], w.kind === 'map' ? get('maps') : []]);
      const schemas = maps.filter(m => m.type !== 'rack');
      if (w.kind === 'health' && !health.length) return void toast('Primero añade un equipo en Salud', 'bad');
      if (w.kind === 'map' && !schemas.length) return void toast('Primero crea un esquema', 'bad');
      const sel = (name, label, opts, cur) => `<div class="field"><label for="dw-${name}">${label}</label><select id="dw-${name}" name="${name}">${opts.map(([v, t]) => `<option value="${esc(v)}" ${String(v) === String(cur) ? 'selected' : ''}>${esc(t)}</option>`).join('')}</select></div>`;
      const fields = {
        stat: () => sel('stat', 'Qué cifra', Object.entries(DSTATS).map(([k, [n]]) => [k, n]), w.stat),
        inv: () => sel('by', 'Agrupar equipos por', Object.entries(DBY), w.by),
        lat: () => sel('hours', 'Rango', Object.entries(DRANGE), w.hours || 24),
        health: () => sel('source', 'Equipo', health.map(h => [h.id, h.label || h.item_name || h.host]), w.source) + sel('group', 'Qué ver', Object.entries(DGROUPS), w.group)
          + sel('hours', 'Rango', Object.entries(DRANGE), w.hours || 24),
        map: () => sel('map', 'Esquema', schemas.map(m => [m.id, m.name]), w.map),
      }[w.kind];
      const f = await dialog(`<h3>${fresh ? 'Añadir' : 'Ajustar'}: ${esc(DW[w.kind].name)}</h3><div class="fields">${fields ? fields() : ''}
        <div class="field"><label for="dw-title">Título <span class="dim">· opcional</span></label><input id="dw-title" name="title" maxlength="80" value="${esc(w.title || '')}"></div></div>`, {ok: fresh ? 'Añadir' : 'Guardar'});
      if (!f) return false;
      for (const k of ['stat', 'by', 'group']) if (f.has(k)) w[k] = f.get(k);
      for (const k of ['hours', 'source', 'map']) if (f.has(k)) w[k] = +f.get(k);
      const t = f.get('title').trim(); if (t) w.title = t; else delete w.title;
      return true;
    }
    async function add(kind) {
      const [sw, sh] = DW[kind].size, w = {id: Math.random().toString(36).slice(2, 12), kind, x: 0, y: Math.max(0, ...D.widgets.map(x => x.y + x.h)), w: sw, h: sh};
      if (DW[kind].view) w.view = DW[kind].view;
      if (['stat', 'inv', 'lat', 'health', 'map'].includes(kind) && !await configure(w, true)) return;
      D.widgets.push(w); const el = mount(w); settle(); layout(); fill(w); save();
      pop(el.firstChild); el.scrollIntoView({behavior: motionOn() ? 'smooth' : 'auto', block: 'nearest'});
    }
    const change = (w, el, origin) => { settle(w); layout(); draw(w); jelly(el, origin); save(); };
    D.widgets.forEach(mount); settle(); layout();
    D.widgets.forEach((w, i) => { pop(els[w.id].firstChild, i); fill(w); });
    $('#dedit').onclick = () => setEdit(!edit);
    $('#dadd').onclick = e => menu(e.currentTarget, Object.entries(DW).map(([k, x]) => [x.name, () => add(k), {icon: x.icon}]));
    box.onclick = e => {
      const el = e.target.closest('.dw'), w = el && byId(el.dataset.id); if (!w) return;
      const vb = e.target.closest('[data-view]');
      if (vb) { // cambiar de gráfico: el contenido nuevo entra con rebote
        w.view = vb.dataset.view; draw(w, true); save();
        anim(el.querySelector('.dw-b'), [{opacity: 0, transform: 'scale(.94)'}, {opacity: 1, transform: 'none'}], {duration: 520, easing: 'cubic-bezier(.34,1.45,.64,1)'});
        return;
      }
      if (e.target.closest('[data-act=more]')) return menu(e.target.closest('button'), [
        ...(w.kind === 'mon' || w.kind === 'log' ? [] : [['Ajustar…', async () => { if (await configure(w)) { el.querySelector('.dw-t').textContent = w.title || DW[w.kind].name; fill(w); save(); } }, {icon: 'sliders'}]]),
        ['Quitar', () => remove(w), {icon: 'trash', danger: true}]]);
      if (!edit && !e.target.closest('a,button') && el._d?.href) location.hash = el._d.href;
    };
    // Arrastrar para mover (la tarjeta se inclina según la velocidad) o desde la esquina para agrandar
    box.onpointerdown = e => {
      const el = e.target.closest('.dw'); if (!edit || !el || e.button || e.target.closest('button')) return;
      const w = byId(el.dataset.id), rz = !!e.target.closest('.dw-rz'), g0 = {...pos.get(w)}, sx = e.clientX, sy = e.clientY, was = [w.x, w.y, w.w, w.h].join();
      e.preventDefault(); el.setPointerCapture(e.pointerId); el.focus({preventScroll: true});
      el.classList.add(rz ? 'sizing' : 'drag'); ghost.hidden = false; placeGhost(w);
      let x = g0.x, y = g0.y, vx = 0, lx = sx, live = true;
      const tiltLoop = () => { if (!live) return; vx *= .86; el.style.transform = `translate(${x}px,${y}px) rotate(${Math.max(-8, Math.min(8, vx * .7))}deg) scale(1.03)`; requestAnimationFrame(tiltLoop); };
      if (!rz) tiltLoop();
      el.onpointermove = ev => {
        const dx = ev.clientX - sx, dy = ev.clientY - sy;
        if (rz) {
          const nw = Math.max(cw, g0.w + dx), nh = Math.max(ROW, g0.h + dy);
          Object.assign(el.style, {width: nw + 'px', height: nh + 'px'});
          const sw = Math.max(1, Math.min(12 - w.x, Math.round((nw + G) / (cw + G)))), sh = Math.max(1, Math.min(8, Math.round((nh + G) / (ROW + G))));
          if (sw !== w.w || sh !== w.h) { w.w = sw; w.h = sh; settle(w); layout(el); placeGhost(w); draw(w); }
        } else {
          vx += ev.clientX - lx; lx = ev.clientX; x = g0.x + dx; y = g0.y + dy;
          const nx = Math.max(0, Math.min(12 - w.w, Math.round(x / (cw + G)))), ny = Math.max(0, Math.round(y / (ROW + G)));
          if (nx !== w.x || ny !== w.y) { w.x = nx; w.y = ny; settle(w); layout(el); placeGhost(w); }
        }
      };
      el.onpointerup = el.onpointercancel = () => {
        live = false; el.onpointermove = el.onpointerup = el.onpointercancel = null;
        el.classList.remove('drag', 'sizing'); ghost.hidden = true;
        layout(); draw(w); jelly(el, rz ? '0 0' : '50% 50%', rz ? 1.3 : 1); // vuelve a su celda con el muelle
        if ([w.x, w.y, w.w, w.h].join() !== was) save();
      };
    };
    // Teclado en modo personalizar: flechas mueven, Mayús+flechas cambian el tamaño, Supr quita
    box.onkeydown = e => {
      const el = e.target.closest('.dw'); if (!edit || !el || e.target !== el) return;
      const w = byId(el.dataset.id), d = {ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1]}[e.key];
      if (e.key === 'Delete' || e.key === 'Backspace') { e.preventDefault(); return remove(w); }
      if (!d) return;
      e.preventDefault();
      if (e.shiftKey) { w.w = Math.max(1, Math.min(12 - w.x, w.w + d[0])); w.h = Math.max(1, Math.min(8, w.h + d[1])); change(w, el, '0 0'); }
      else { w.x = Math.max(0, Math.min(12 - w.w, w.x + d[0])); w.y = Math.max(0, w.y + d[1]); change(w, el); }
    };
    let lastW = box.clientWidth;
    const ro = new ResizeObserver(() => { if (Math.abs(box.clientWidth - lastW) < 2) return; lastW = box.clientWidth; layout(); D.widgets.forEach(w => draw(w)); });
    ro.observe(box);
    const t = setInterval(() => { if (box.querySelector('.drag,.sizing')) return; memo = {}; D.widgets.forEach(fill); }, 30000); // datos al día sin recargar
    cleanup = () => { clearInterval(t); ro.disconnect(); if (saveT) { clearTimeout(saveT); api('dashboard', 'PUT', D); } }; // no perder el último cambio al salir
    redraw = () => {}; // el buscador no filtra el dashboard
  },
  // Home: la hora y el gato de catlan (pixel art 40×24)
  async home() {
    crumbs([]);
    const h = new Date().getHours();
    app.innerHTML = `<section class="home"><p class="hi">${h < 6 || h >= 21 ? 'Buenas noches' : h < 14 ? 'Buenos días' : 'Buenas tardes'}</p>
      <h1 class="clock" id="clock"></h1><p class="today" id="today"></p>
      <button class="cat" id="cat" title="Clic para despertarlo o dormirlo"><svg viewBox="0 0 40 24" shape-rendering="crispEdges" role="img" aria-labelledby="cap"><g id="scene"></g><g id="paws"></g></svg></button>
      <p class="cat-cap" id="cap" aria-live="polite"></p></section>`;
    const tick = () => {
      const d = new Date(), z = n => String(n).padStart(2, '0');
      $('#clock').innerHTML = `${z(d.getHours())}<span class="colon">:</span>${z(d.getMinutes())}<span class="sec">${z(d.getSeconds())}</span>`;
      $('#clock').setAttribute('aria-label', d.toLocaleTimeString('es', {hour: '2-digit', minute: '2-digit'}));
      $('#today').textContent = d.toLocaleDateString('es', {weekday: 'long', day: 'numeric', month: 'long', year: 'numeric'});
    };
    let state = 'type', frame = 0, since = Date.now();
    const paint = () => {
      $('#scene').innerHTML = state === 'type' ? CAT.typing : CAT.sleeping;
      $('#paws').innerHTML = state === 'type' ? CAT.paws[frame] : '';
      $('#cap').textContent = state === 'type' ? 'Tecleando…' : 'Siesta sobre el portátil · zzz';
    };
    const swap = () => { state = state === 'type' ? 'sleep' : 'type'; since = Date.now(); paint(); anim($('#cat svg'), [{opacity: 0, transform: 'translateY(4px)'}, {opacity: 1, transform: 'none'}], {duration: 500, easing: 'cubic-bezier(.22,.8,.24,1)'}); };
    const t1 = setInterval(tick, 1000), t2 = setInterval(() => {
      if (state === 'type' && motionOn() && Math.random() < .7) { frame ^= 1; $('#paws').innerHTML = CAT.paws[frame]; } // tecleo irregular, como de verdad
      if (Date.now() - since > (state === 'type' ? 9000 : 7000)) swap();
    }, 170);
    $('#cat').onclick = swap;
    tick(); paint();
    cleanup = () => { clearInterval(t1); clearInterval(t2); };
    redraw = () => {}; // el buscador no afecta al home
  },
});
