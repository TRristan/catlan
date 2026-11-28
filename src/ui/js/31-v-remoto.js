Object.assign(views, {
  async remoto(sid) {
    const st0 = sid && await api('remote/' + sid).catch(() => null);
    if (!st0) { app.innerHTML = empty('alert', 'Esta sesión ya no existe', 'Pide otra desde la ficha del equipo o desde PCs (Kitty).'); return crumbs([['Control remoto']]); }
    crumbs([['PCs (Kitty)', '#/pcs'], [st0.pc], ['Control remoto']]);
    app.dataset.w = 'wide';
    app.innerHTML = `<div class="rm" id="rm">
        <header class="rm-bar"><span class="pill" id="rm-st"><i></i><span></span></span><b>${esc(st0.pc)}</b><span class="dim small" id="rm-t"></span><span class="grow"></span>
          <div class="seg" id="rm-mode" role="group" aria-label="Modo"><button data-v="ctl" class="on">${ui('edit', 15)}Controlar</button><button data-v="view">${ui('eye', 15)}Solo ver</button></div>
          <button class="btn sm" id="rm-up" title="Enviar un archivo a la carpeta Descargas del usuario (hasta 20 MB)">${ui('redo', 15)}<span class="hide-s">Enviar archivo</span></button>
          <button class="btn sm" id="rm-get" title="Copiar un archivo del PC (hasta 20 MB)">${ui('copy', 15)}<span class="hide-s">Pedir archivo</span></button>
          <input type="file" id="rm-file" hidden>
          <button class="btn sm" id="rm-fs" title="Pantalla completa">${ui('layers', 15)}<span class="hide-s">Pantalla completa</span></button>
          <button class="btn sm danger" id="rm-end">${ui('x', 15)}Terminar</button></header>
        <div class="rm-stage"><canvas id="rm-cv" tabindex="0" aria-label="Pantalla de ${esc(st0.pc)}: con el foco aquí, el teclado va al PC"></canvas>
          <div class="rm-files" id="rm-files" hidden></div>
          <div class="rm-wait" id="rm-wait"><span class="rm-pulse">${ui('screen', 30)}</span><h3 id="rm-w-t"></h3><p class="muted" id="rm-w-x"></p></div></div></div>`;
    const cv = $('#rm-cv'), cx = cv.getContext('2d');
    let alive = true, done = false, ctl = true, q = [], lastMove = 0, since = null;
    // archivos que llegan del PC: para descargar
    const files = list => {
      const box = $('#rm-files'); box.hidden = !list?.length; if (!list?.length) return;
      box.innerHTML = `<b class="small">Del PC</b>` + list.map(f => f.error ? `<span class="small t-bad" title="${esc(f.error)}">${ui('alert', 13)}${esc(f.name)}: ${esc(f.error)}</span>`
        : `<a class="small" href="/api/remote/${encodeURIComponent(sid)}/files/${+f.id}" download>${ui('layers', 13)}${esc(f.name)} <span class="dim">${(f.size / 1048576).toFixed(1)} MB</span></a>`).join('');
    };
    const show = st => {
      files(st.files);
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
        $('#rm-end').hidden = true; $('#rm-mode').hidden = true; $('#rm-up').hidden = true; $('#rm-get').hidden = true;
      }
    };
    show(st0); seg($('#rm-mode'));
    const clock = setInterval(() => { if (since && !done) { const s = Math.floor((Date.now() - since) / 1000); $('#rm-t').textContent = `· ${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`; } }, 1000);
    // un WebSocket: la pantalla (binario) y el estado (texto) llegan en cuanto cambian; el ratón y el teclado van de vuelta
    let ws, painting = Promise.resolve();
    const connect = () => {
      ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/api/remote/${sid}/ws`);
      ws.onmessage = e => {
        if (typeof e.data === 'string') { const m = JSON.parse(e.data); if (m.state) show(m); return; }
        painting = painting.then(async () => { // en orden: un fotograma viejo no pisa a uno nuevo
          const bmp = await createImageBitmap(e.data).catch(() => null); if (!bmp || !alive) return;
          if (cv.width !== bmp.width || cv.height !== bmp.height) { cv.width = bmp.width; cv.height = bmp.height; }
          cx.drawImage(bmp, 0, 0); bmp.close();
          if (!$('#rm-wait').hidden) { $('#rm-wait').hidden = true; show({state: 'aceptada', pc: st0.pc, secs: 0}); cv.focus(); }
        });
      };
      ws.onclose = () => { if (alive && !done) setTimeout(connect, 1000); }; // la red se ha cortado: la sesión sigue un rato, se vuelve a entrar
    };
    connect();
    // ratón y teclado: en tandas cada 50 ms
    const flush = () => { if (!q.length || done || ws.readyState !== 1) return; ws.send(JSON.stringify(q.splice(0))); };
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
    $('#rm-up').onclick = () => $('#rm-file').click();
    $('#rm-file').onchange = async () => {
      const f = $('#rm-file').files[0]; $('#rm-file').value = ''; if (!f) return;
      if (f.size > 20 << 20) return toast('Como mucho 20 MB por archivo', 'bad');
      toast(`Enviando ${f.name}…`);
      const r = await fetch(`/api/remote/${encodeURIComponent(sid)}/files`, {method: 'POST', headers: {'x-nombre': encodeURIComponent(f.name)}, body: f}).catch(() => null);
      if (r?.ok) toast(`${f.name} enviado: lo tiene en Descargas`); else toast((await r?.json().catch(() => null))?.error || 'No se ha podido enviar', 'bad');
    };
    $('#rm-get').onclick = async () => {
      const f = await dialog(`<h3>Pedir un archivo del PC</h3><p>Kitty lo copia con los permisos del usuario del PC, que verá un aviso. Hasta 20 MB.</p>
        <div class="field"><label for="rg-p">Ruta en el PC</label><input id="rg-p" name="p" class="mono" required spellcheck="false" placeholder="C:\\Users\\ana\\Desktop\\informe.pdf" autofocus></div>`, {ok: 'Pedir'});
      if (!f) return;
      q.push({t: 'get', path: f.get('p').trim()}); flush();
      toast('Pedido: saldrá arriba a la derecha cuando llegue');
    };
    $('#rm-fs').onclick = () => document.fullscreenElement ? document.exitFullscreen() : $('#rm').requestFullscreen?.();
    const stop = () => { if (!done) { done = true; fetch('/api/remote/' + sid, {method: 'DELETE', keepalive: true}).catch(() => {}); } };
    $('#rm-end').onclick = async () => { stop(); show({state: 'cerrada', why: 'La has terminado tú.'}); };
    addEventListener('pagehide', stop);
    cleanup = () => { stop(); alive = false; ws.close(); clearInterval(pump); clearInterval(clock); removeEventListener('pagehide', stop); if (document.fullscreenElement) document.exitFullscreen(); };
  },
});
