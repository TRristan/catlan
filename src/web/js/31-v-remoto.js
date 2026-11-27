Object.assign(views, {
  async remoto(sid) {
    const st0 = sid && await api('remote/' + sid).catch(() => null);
    if (!st0) { app.innerHTML = empty('alert', 'Esta sesión ya no existe', 'Pide otra desde la ficha del equipo o desde Salud.'); return crumbs([['Control remoto']]); }
    crumbs([['Salud', '#/salud'], [st0.pc], ['Control remoto']]);
    app.dataset.w = 'wide';
    app.innerHTML = `<div class="rm" id="rm">
        <header class="rm-bar"><span class="pill" id="rm-st"><i></i><span></span></span><b>${esc(st0.pc)}</b><span class="dim small" id="rm-t"></span><span class="grow"></span>
          <div class="seg" id="rm-mode" role="group" aria-label="Modo"><button data-v="ctl" class="on">${ui('edit', 15)}Controlar</button><button data-v="view">${ui('eye', 15)}Solo ver</button></div>
          <button class="btn sm" id="rm-fs" title="Pantalla completa">${ui('layers', 15)}<span class="hide-s">Pantalla completa</span></button>
          <button class="btn sm danger" id="rm-end">${ui('x', 15)}Terminar</button></header>
        <div class="rm-stage"><canvas id="rm-cv" tabindex="0" aria-label="Pantalla de ${esc(st0.pc)}: con el foco aquí, el teclado va al PC"></canvas>
          <div class="rm-wait" id="rm-wait"><span class="rm-pulse">${ui('screen', 30)}</span><h3 id="rm-w-t"></h3><p class="muted" id="rm-w-x"></p></div></div></div>`;
    const cv = $('#rm-cv'), cx = cv.getContext('2d');
    let alive = true, done = false, seq = 0, ctl = true, q = [], lastMove = 0, since = null;
    const show = st => {
      const [tone, txt] = {pedida: ['warn', 'Esperando permiso'], aceptada: ['ok', 'Conectado'], rechazada: ['bad', 'Rechazada'], cerrada: ['', 'Terminada']}[st.state] || ['', st.state];
      $('#rm-st').className = 'pill ' + tone; $('#rm-st span').textContent = txt;
      if (st.state === 'aceptada' && st.secs != null) since ??= Date.now() - st.secs * 1000;
      const w = $('#rm-wait');
      if (st.state === 'pedida') { $('#rm-w-t').textContent = `Esperando a que acepten en ${st.pc}`; $('#rm-w-x').textContent = 'A la persona del PC le ha salido un aviso de Kitty; tiene 60 segundos para permitirlo.'; w.hidden = false; }
      else if (st.state === 'rechazada' || st.state === 'cerrada') {
        done = true; w.hidden = false; w.classList.add('end');
        $('#rm-w-t').textContent = st.state === 'rechazada' ? 'No se ha podido conectar' : 'Sesión terminada';
        $('#rm-w-x').innerHTML = `${esc(st.why || '')}<br><button class="btn mt" id="rm-back">Volver</button>`;
        $('#rm-back').onclick = () => history.back();
        $('#rm-end').hidden = true; $('#rm-mode').hidden = true;
      }
    };
    show(st0); seg($('#rm-mode'));
    const clock = setInterval(() => { if (since && !done) { const s = Math.floor((Date.now() - since) / 1000); $('#rm-t').textContent = `· ${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`; } }, 1000);
    // la pantalla: cada petición espera (hasta 15 s) al siguiente fotograma
    (async () => {
      while (alive && !done) {
        let r;
        try { r = await fetch(`/api/remote/${sid}/frame?after=${seq}`); } catch { await new Promise(ok => setTimeout(ok, 1000)); continue; }
        if (r.status === 404) { show({state: 'cerrada', why: 'La sesión ya no existe.'}); break; }
        if ((r.headers.get('content-type') || '').startsWith('image/')) {
          seq = +r.headers.get('x-seq');
          const bmp = await createImageBitmap(await r.blob()).catch(() => null); if (!bmp || !alive) continue;
          if (cv.width !== bmp.width || cv.height !== bmp.height) { cv.width = bmp.width; cv.height = bmp.height; }
          cx.drawImage(bmp, 0, 0); bmp.close();
          if (!$('#rm-wait').hidden) { $('#rm-wait').hidden = true; show({state: 'aceptada', pc: st0.pc, secs: 0}); cv.focus(); }
        } else show(await r.json());
      }
    })();
    // ratón y teclado: en tandas cada 50 ms
    const flush = () => { if (!q.length || done) return; const evs = q.splice(0); fetch(`/api/remote/${sid}/input`, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(evs)}).catch(() => {}); };
    const pump = setInterval(flush, 50);
    const at = e => { const r = cv.getBoundingClientRect(); return {x: +((e.clientX - r.left) / r.width).toFixed(4), y: +((e.clientY - r.top) / r.height).toFixed(4)}; };
    cv.onpointermove = e => { if (!ctl || performance.now() - lastMove < 30) return; lastMove = performance.now(); q.push({t: 'm', ...at(e)}); };
    cv.onpointerdown = e => { if (!ctl) return; e.preventDefault(); cv.focus(); cv.setPointerCapture(e.pointerId); q.push({t: 'd', b: e.button, ...at(e)}); flush(); };
    cv.onpointerup = e => { if (!ctl) return; q.push({t: 'u', b: e.button, ...at(e)}); flush(); };
    cv.oncontextmenu = e => e.preventDefault();
    cv.addEventListener('wheel', e => { if (!ctl) return; e.preventDefault(); q.push({t: 'w', d: Math.round(e.deltaY)}); }, {passive: false});
    // con el foco en la pantalla, todas las teclas van al PC (también /, Alt+C o Ctrl+S, que catlan usa para lo suyo)
    cv.onkeydown = cv.onkeyup = e => { if (!ctl) return; e.preventDefault(); e.stopPropagation(); q.push({t: 'k', c: e.code, k: e.key, d: e.type === 'keydown'}); flush(); };
    $('#rm-mode').onclick = e => { const b = e.target.closest('[data-v]'); if (!b) return; ctl = b.dataset.v === 'ctl';
      $('#rm-mode').querySelectorAll('button').forEach(x => x.classList.toggle('on', x === b)); seg($('#rm-mode')); cv.classList.toggle('view', !ctl); };
    $('#rm-fs').onclick = () => document.fullscreenElement ? document.exitFullscreen() : $('#rm').requestFullscreen?.();
    const stop = () => { if (!done) { done = true; fetch('/api/remote/' + sid, {method: 'DELETE', keepalive: true}).catch(() => {}); } };
    $('#rm-end').onclick = async () => { stop(); show({state: 'cerrada', why: 'La has terminado tú.'}); };
    addEventListener('pagehide', stop);
    cleanup = () => { stop(); alive = false; clearInterval(pump); clearInterval(clock); removeEventListener('pagehide', stop); if (document.fullscreenElement) document.exitFullscreen(); };
  },
});
