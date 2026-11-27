Object.assign(views, {
  // Descubrir red: ping a toda la red, SNMP y DNS a quien responde; lo elegido va al inventario y al monitor
  async discover() {
    crumbs([['Inventario', '#/inv'], ['Descubrir red']]);
    const kinds = Object.entries(ICONS).filter(([k]) => !['cloud', 'user', 'rack'].includes(k));
    app.innerHTML = head('Descubrir red', 'Busca equipos por ping y SNMP, y añádelos al inventario y al monitor de una vez')
      + `<form class="card pad" id="d-form" style="display:flex;flex-wrap:wrap;gap:12px;align-items:flex-end">
        <div class="field" style="flex:2 1 200px;margin:0"><label for="d-net">Red</label><input id="d-net" name="net" class="mono" required placeholder="10.0.0.0/24" value="${esc(S.lastNet || '')}" spellcheck="false"></div>
        <div class="field" style="flex:1 1 150px;margin:0"><label for="d-c">Comunidad SNMP <span class="dim">· opcional</span></label><input id="d-c" name="community" type="password" placeholder="public" autocomplete="off"></div>
        <button class="btn pri" id="d-go">${ui('search', 16)}Escanear</button></form><div id="d-out" class="mt"></div>`;
    let found = [];
    const out = $('#d-out');
    const paint = () => {
      const todo = found.filter(r => !(r.item && r.watched));
      out.innerHTML = !found.length ? empty('search', 'Nadie ha respondido', 'Comprueba la red. Algunos equipos (Windows, móviles) no responden al ping por su cortafuegos.')
        : `<div class="card tbl-wrap"><table class="tbl"><thead><tr><th><input type="checkbox" id="d-all" aria-label="Seleccionar todos" ${todo.length ? 'checked' : 'disabled'}></th>
          <th>IP</th><th>Nombre</th><th>Tipo</th><th class="hide-m">Qué es</th><th>En catlan</th></tr></thead><tbody class="stagger">${found.map((r, i) => {
            const done = r.item && r.watched, what = [r.vendor, r.descr].filter(Boolean).join(' · ');
            return `<tr data-i="${i}" style="--i:${Math.min(i, 14)}"><td><input type="checkbox" class="d-sel" aria-label="Elegir ${esc(r.ip)}" ${done ? 'disabled' : 'checked'}></td>
              <td class="mono">${esc(r.ip)}<div class="dim small">${r.rtt != null ? `${+(+r.rtt).toFixed(1)} ms` : ''}</div></td>
              <td><input class="d-name" value="${esc(r.name || r.ip)}" aria-label="Nombre de ${esc(r.ip)}" ${r.item ? 'disabled' : ''} style="min-width:140px"></td>
              <td><select class="d-kind" aria-label="Tipo de ${esc(r.ip)}" ${r.item ? 'disabled' : ''}><option value="">—</option>${kinds.map(([k, [n]]) => `<option value="${k}" ${k === r.kind ? 'selected' : ''}>${n}</option>`).join('')}</select></td>
              <td class="muted hide-m" title="${esc(what)}" style="max-width:280px;overflow:hidden;text-overflow:ellipsis">${esc(what) || (r.snmp ? '' : '<span class="dim">sin SNMP</span>')}</td>
              <td>${r.item ? `<a class="pill" href="#/inv/${+r.item}"><i></i>Inventario</a>` : ''} ${r.watched ? '<span class="pill ok"><i></i>Vigilado</span>' : ''}</td></tr>`; }).join('')}</tbody></table></div>
          <div class="actionbar" style="align-items:center;flex-wrap:wrap"><span class="small muted" style="margin-right:auto">${found.length} ${found.length === 1 ? 'equipo encontrado' : 'equipos encontrados'}</span>
            <label class="small" style="display:flex;gap:6px;align-items:center"><input type="checkbox" id="d-inv" checked>Añadir al inventario</label>
            <label class="small" style="display:flex;gap:6px;align-items:center"><input type="checkbox" id="d-mon" checked>Vigilar con ping</label>
            <button class="btn pri" id="d-add">${ui('plus', 16)}Añadir</button></div>`;
      if (!found.length) return;
      const sels = () => [...out.querySelectorAll('.d-sel:checked')].map(c => c.closest('tr'));
      const count = () => { const n = sels().length; $('#d-add').disabled = !n || !$('#d-inv').checked && !$('#d-mon').checked; $('#d-add').lastChild.textContent = n ? `Añadir ${n}` : 'Añadir'; };
      $('#d-all').onchange = e => { out.querySelectorAll('.d-sel:not(:disabled)').forEach(c => c.checked = e.target.checked); count(); };
      out.onchange = e => e.target.matches('.d-sel,#d-inv,#d-mon') && count();
      count();
      $('#d-add').onclick = async () => {
        const pick = sels().map(tr => ({r: found[+tr.dataset.i], name: tr.querySelector('.d-name').value.trim() || found[+tr.dataset.i].ip, kind: tr.querySelector('.d-kind').value}));
        const newItems = $('#d-inv').checked ? pick.filter(x => !x.r.item) : [];
        const made = newItems.length ? await api('items', 'POST', newItems.map(x => ({name: x.name, kind: x.kind ? ICONS[x.kind][0].toLowerCase() : '', ip: x.r.ip,
          notes: ['Descubierto por catlan', x.r.vendor, x.r.descr].filter(Boolean).join(' · ')}))) : [];
        made.forEach((m, i) => newItems[i].r.item = m.id);
        const watch = $('#d-mon').checked ? pick.filter(x => !x.r.watched) : [];
        // con ficha, el nombre del monitor sale del inventario (y sigue sus cambios)
        if (watch.length) await api('checks', 'POST', watch.map(x => ({host: x.r.ip, label: x.r.item ? '' : x.name, item: x.r.item || null, every: 60})));
        watch.forEach(x => x.r.watched = true);
        toast(`${made.length} al inventario · ${watch.length} vigilados`); pollMonitor(); paint();
      };
    };
    $('#d-form').onsubmit = async e => {
      e.preventDefault();
      const net = $('#d-net').value.trim(), n = /\/(\d+)$/.exec(net)?.[1];
      out.innerHTML = `<div class="card pad" aria-live="polite"><p class="muted" style="margin:0">${ui('signal', 16)} Escaneando ${n ? 2 ** (32 - n) : ''} direcciones… suele tardar unos 10 segundos.</p></div>`;
      $('#d-go').disabled = true;
      try { found = await api('discover', 'POST', {net, community: $('#d-c').value}); S.lastNet = net; applySettings(); paint(); }
      catch { out.innerHTML = ''; }
      finally { $('#d-go').disabled = false; }
    };
  },
  // Usuarios y grupos: altas de uno o de muchos (pegando una lista) y acciones sobre varios a la vez
  async opts() {
    const [us, gs] = await Promise.all([api('users'), api('groups')]); // sin sesión, esto ya lleva al login
    crumbs([['Opciones']]);
    if (!ME.admin) {
      app.innerHTML = empty('cog', 'Solo para administradores', 'Aquí están los usuarios, los grupos y lo que afecta a todo catlan.');
      return;
    }
    app.innerHTML = head('Opciones', 'Lo que afecta a todo catlan · solo administradores', '')
      + `<div class="rows stagger">
          <a class="rowlink" href="#/users" style="--i:0"><span class="badge-ic">${ui('users', 18)}</span><div class="grow"><b>Usuarios y grupos</b>
            <span class="ex">${us.length} ${us.length === 1 ? 'usuario' : 'usuarios'} · ${gs.length} ${gs.length === 1 ? 'grupo' : 'grupos'} · quién entra y quién puede editar</span></div><span style="display:flex;transform:rotate(-90deg)" class="dim">${ui('chev', 16)}</span></a>
          <a class="rowlink" href="#/inv" style="--i:1"><span class="badge-ic">${ui('signal', 18)}</span><div class="grow"><b>Kitty en los PCs</b>
            <span class="ex">En Inventario: «Añadir con Kitty» y aceptar los que piden entrar</span></div><span style="display:flex;transform:rotate(-90deg)" class="dim">${ui('chev', 16)}</span></a>
          <a class="rowlink" href="#/apps" style="--i:2"><span class="badge-ic">${ui('box', 18)}</span><div class="grow"><b>Programas en los PCs</b>
            <span class="ex">Lo que Kitty instala y mantiene actualizado en todos los PCs con winget</span></div><span style="display:flex;transform:rotate(-90deg)" class="dim">${ui('chev', 16)}</span></a>
          <a class="rowlink" href="#/sistema" style="--i:2"><span class="badge-ic">${ui('pulse', 18)}</span><div class="grow"><b>Salud de catlan</b>
            <span class="ex">Tamaño de la base de datos, copias diarias, estado del monitor y comprobaciones atrasadas</span></div><span style="display:flex;transform:rotate(-90deg)" class="dim">${ui('chev', 16)}</span></a>
          <a class="rowlink" href="/api/backup" id="bk" style="--i:3"><span class="badge-ic">${ui('layers', 18)}</span><div class="grow"><b>Descargar copia de seguridad</b>
            <span class="ex">Toda la base de datos, cifrada con una contraseña (lleva las credenciales de SNMP y avisos). Para restaurarla: <code>catlan descifrar copia.catlan data/catlan.db</code> con catlan parado.</span></div>${ui('redo', 16)}</a></div>
        <section class="card pad mt" aria-labelledby="al-t"><h3 class="card-t" id="al-t">${ui('bell', 16)}Avisos fuera de catlan <span class="dim small" id="al-ch" style="font-weight:400"></span></h3>
          <p class="small muted" style="margin:0 0 12px">Cuando algo cae y cuando vuelve, avisos de Salud, incidencias críticas y garantías. Las contraseñas y tokens guardados no se vuelven a mostrar: déjalos en blanco para conservarlos.</p>
          <form id="al-f" class="fields two" autocomplete="off">
            <div class="field full"><b class="small">Correo</b></div>
            <div class="field"><label for="al-h">Servidor SMTP</label><input id="al-h" name="SMTP_HOST" class="mono" placeholder="smtp.empresa.com"></div>
            <div class="field"><label for="al-po">Puerto</label><input id="al-po" name="SMTP_PORT" class="mono" inputmode="numeric" placeholder="587 (465 = SSL)"></div>
            <div class="field"><label for="al-u">Usuario</label><input id="al-u" name="SMTP_USER" autocomplete="off"></div>
            <div class="field"><label for="al-p">Contraseña</label><input id="al-p" name="SMTP_PASS" type="password" autocomplete="new-password"></div>
            <div class="field"><label for="al-fr">Remitente</label><input id="al-fr" name="MAIL_FROM" type="email" placeholder="catlan@empresa.com"></div>
            <div class="field"><label for="al-to">Para</label><input id="al-to" name="MAIL_TO" placeholder="it@empresa.com, guardia@empresa.com"></div>
            <div class="field full"><b class="small">Telegram</b></div>
            <div class="field"><label for="al-tt">Token del bot</label><input id="al-tt" name="TELEGRAM_TOKEN" type="password" autocomplete="off" class="mono"></div>
            <div class="field"><label for="al-tc">Chat</label><input id="al-tc" name="TELEGRAM_CHAT" class="mono" placeholder="-1001234567890 o @canal"></div>
            <div class="field full"><label for="al-w"><b class="small">Webhook</b> <span class="dim">· Slack, Teams, Mattermost, Google Chat o Discord</span></label><input id="al-w" name="WEBHOOK_URL" type="password" autocomplete="off" class="mono"></div>
            <div class="field full" style="display:flex;gap:8px;flex-wrap:wrap"><button class="btn pri">${ui('check', 16)}Guardar avisos</button><button type="button" class="btn" id="al-test">Enviar aviso de prueba</button></div>
          </form></section>
        <section class="card pad mt" aria-labelledby="sso-t"><h3 class="card-t" id="sso-t">${ui('key', 16)}Inicio de sesión con el dominio</h3>
          <p class="small muted" style="margin:0 0 12px">Usuarios de Active Directory (LDAP) o de Entra ID, Google Workspace o Keycloak (OIDC). Entran si alguno de sus grupos está abajo; sus grupos mandan su admin y lo que pueden editar en cada entrada. Los usuarios locales, <code>admin</code> incluido, entran siempre con su contraseña de catlan, aunque el dominio no conteste.</p>
          <form id="sso-f" class="fields two" autocomplete="off">
            <div class="field full"><b class="small">Active Directory / LDAP</b> <span class="dim small">· la contraseña la comprueba el dominio (bind con el propio usuario)</span></div>
            <div class="field"><label for="sso-u">Servidor</label><input id="sso-u" name="ldap_url" class="mono" placeholder="ldaps://dc1.empresa.local"></div>
            <div class="field"><label for="sso-d">Dominio</label><input id="sso-d" name="ldap_domain" class="mono" placeholder="empresa.local"></div>
            <div class="field"><label for="sso-b">Base de búsqueda <span class="dim">· opcional</span></label><input id="sso-b" name="ldap_base" class="mono" placeholder="DC=empresa,DC=local"></div>
            <div class="field"><label for="sso-pin">Huella del certificado <span class="dim">· si es autofirmado</span></label><input id="sso-pin" name="ldap_pin" class="mono" placeholder="SHA-256 en hex"></div>
            <div class="field full"><b class="small">OIDC</b> <span class="dim small">· dirección de vuelta para dar de alta en el proveedor: <code id="sso-cb"></code></span></div>
            <div class="field"><label for="sso-i">Emisor</label><input id="sso-i" name="oidc_issuer" class="mono" placeholder="https://login.microsoftonline.com/&lt;tenant&gt;/v2.0"></div>
            <div class="field"><label for="sso-n">Texto del botón</label><input id="sso-n" name="oidc_name" placeholder="Microsoft"></div>
            <div class="field"><label for="sso-c">Id de cliente</label><input id="sso-c" name="oidc_client" class="mono"></div>
            <div class="field"><label for="sso-s">Secreto de cliente</label><input id="sso-s" name="oidc_secret" type="password" autocomplete="new-password" class="mono"></div>
            <div class="field"><label for="sso-g">Claim de los grupos</label><input id="sso-g" name="oidc_groups" class="mono" placeholder="groups"></div>
            <div class="field full"><label for="sso-m">Grupos del dominio con acceso <span class="dim">· uno por línea: <code>grupo del dominio | grupo de catlan</code> o <code>| admin</code>. Vale el nombre (IT), el DN entero o, en Google, <code>@empresa.com</code></span></label>
              <textarea id="sso-m" name="map" rows="4" class="mono" placeholder="Administradores de catlan | admin&#10;IT | Técnicos&#10;Dirección | Lectura"></textarea></div>
            <div class="field full"><button class="btn pri">${ui('check', 16)}Guardar inicio de sesión</button></div>
          </form></section>
        <section class="card pad mt" style="border-color:color-mix(in oklab,var(--bad) 45%,var(--line))" aria-labelledby="dz-t">
          <h3 class="card-t" id="dz-t" style="color:var(--bad)">${ui('alert', 16)} Zona de peligro</h3>
          <p class="small" style="margin:0 0 12px">Borra todo el contenido de catlan: wiki, inventario, esquemas, racks, monitor, salud, incidencias, Kittys, dashboard, sonidos y actividad. Se quedan los usuarios y los grupos.</p>
          <button class="btn danger" id="wipe">${ui('trash', 16)}Borrar la base de datos</button></section>
        <p class="dim small mt" style="text-align:center">catlan ${VERSION}</p>`;
    const paintAlerts = a => {
      const f = $('#al-f');
      ['SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'MAIL_FROM', 'MAIL_TO', 'TELEGRAM_CHAT'].forEach(k => f.elements[k].value = a[k] || '');
      ['SMTP_PASS', 'TELEGRAM_TOKEN', 'WEBHOOK_URL'].forEach(k => { f.elements[k].value = ''; f.elements[k].placeholder = a.set[k] ? (k === 'WEBHOOK_URL' ? `Guardado (${a.webhook_host}) · escribe para cambiarlo` : 'Guardado · escribe para cambiarlo') : ''; });
      $('#al-ch').textContent = a.channels.length ? `· activos: ${a.channels.join(', ')}` : '· ninguno activo';
      $('#al-test').disabled = !a.channels.length;
      f.querySelectorAll('.env-note').forEach(n => n.remove());
      a.env.forEach(k => f.elements[k]?.insertAdjacentHTML('afterend', '<small class="dim env-note">Viene de una variable de entorno: lo que guardes aquí manda.</small>'));
    };
    paintAlerts(await api('alerts'));
    const gid = Object.fromEntries(gs.map(g => [g.name.toLowerCase(), g.id])), gnm = Object.fromEntries(gs.map(g => [g.id, g.name]));
    const paintSso = c => {
      const f = $('#sso-f');
      ['ldap_url', 'ldap_domain', 'ldap_base', 'ldap_pin', 'oidc_issuer', 'oidc_name', 'oidc_client', 'oidc_groups'].forEach(k => f.elements[k].value = c[k] || '');
      f.oidc_secret.value = ''; f.oidc_secret.placeholder = c.set.oidc_secret ? 'Guardado · escribe para cambiarlo' : '';
      f.map.value = c.map.map(m => `${m.from} | ${m.to === 'admin' ? 'admin' : gnm[m.to] || '?'}`).join('\n');
    };
    $('#sso-cb').textContent = location.origin + '/api/sso/callback';
    paintSso(await api('sso/config'));
    $('#sso-f').onsubmit = async e => {
      e.preventDefault();
      const body = Object.fromEntries(new FormData(e.target)), map = [];
      for (const l of body.map.split('\n').map(l => l.trim()).filter(Boolean)) {
        const i = l.lastIndexOf('|'), from = l.slice(0, i).trim(), to = l.slice(i + 1).trim().toLowerCase();
        if (i < 0 || !from || !(to === 'admin' || gid[to])) return toast(`«${l}»: escribe «grupo del dominio | grupo de catlan» o «| admin» (los grupos de catlan están en Usuarios y grupos)`, 'bad');
        map.push({from, to: to === 'admin' ? 'admin' : gid[to]});
      }
      try { paintSso(await api('sso/config', 'PUT', {...body, map})); toast('Inicio de sesión guardado'); } catch {}
    };
    $('#bk').onclick = async e => { // cifrada: la copia lleva las credenciales de SNMP y de los avisos
      e.preventDefault();
      const f = await dialog(`<h3>Copia de seguridad cifrada</h3><p>Sin esta contraseña no se puede abrir: guárdala aparte (si se pierde, la copia no sirve).</p>
        <div class="fields"><div class="field"><label for="bk-p">Contraseña de la copia <span class="dim">· mínimo 8 caracteres</span></label><input id="bk-p" name="p" type="password" minlength="8" autocomplete="new-password" required autofocus></div>
        <div class="field"><label for="bk-r">Repítela</label><input id="bk-r" name="r" type="password" minlength="8" autocomplete="new-password" required></div></div>`, {ok: 'Descargar'});
      if (!f) return;
      if (f.get('p') !== f.get('r')) return toast('Las contraseñas no coinciden', 'bad');
      toast('Preparando la copia…');
      const r = await fetch('/api/backup', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({password: f.get('p')})}).catch(() => null);
      if (!r?.ok) return toast(r ? (await r.json().catch(() => ({}))).error || 'No se pudo hacer la copia' : 'Sin conexión con el servidor', 'bad');
      const a = Object.assign(document.createElement('a'), {href: URL.createObjectURL(await r.blob()), download: r.headers.get('Content-Disposition').match(/filename="(.+)"/)[1]});
      a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 5000);
    };
    $('#al-f').onsubmit = async e => {
      e.preventDefault();
      const body = Object.fromEntries(new FormData(e.target));
      try { paintAlerts(await api('alerts', 'PUT', body)); toast('Avisos guardados'); } catch {}
    };
    $('#al-test').onclick = testAlerts;
    $('#wipe').onclick = async () => {
      const f = await dialog(`<h3 style="display:flex;align-items:center;gap:8px;color:var(--bad)">${ui('alert', 20)}¿Borrar la base de datos?</h3>
        <p><b>Se borrará todo el contenido de catlan para todos los usuarios</b>: wiki, inventario, esquemas, racks, monitor, salud, incidencias, Kittys, dashboard, sonidos y actividad.</p>
        <p class="small muted">Se quedan los usuarios y los grupos. Antes se guarda una copia completa en la carpeta de datos del servidor, por si hay que volver atrás.</p>
        <div class="field"><label for="w-pass">Escribe tu contraseña para confirmar</label><input id="w-pass" name="pass" type="password" required autocomplete="current-password"></div>`,
        {ok: 'Borrar todo', danger: true});
      if (!f) return;
      try {
        const r = await api('wipe', 'POST', {pass: f.get('pass')});
        toast(`Base de datos borrada. Copia en el servidor: ${r.copy}`);
        location.hash = '#/dash';
      } catch {} // contraseña mal o sin permiso: el aviso ya sale
    };
  },
  async users() {
    crumbs([['Opciones', '#/opts'], ['Usuarios']]);
    const [us, gs] = await Promise.all([api('users'), api('groups')]);
    const gname = Object.fromEntries(gs.map(g => [g.id, g.name])), groupsOf = id => gs.filter(g => g.members.includes(id));
    const sel = new Set();
    app.innerHTML = head('Usuarios', `${us.length} ${us.length === 1 ? 'usuario' : 'usuarios'} · ${gs.length} ${gs.length === 1 ? 'grupo' : 'grupos'}`,
        `<button class="btn" id="gadd">${ui('users', 16)}Añadir grupos</button><button class="btn pri" id="add">${ui('plus', 16)}Añadir usuarios</button>`)
      + `<div class="ufil"><input id="ufil" type="search" placeholder="Filtrar usuarios…" aria-label="Filtrar usuarios" autocomplete="off"></div>
      <div class="card tbl-wrap"><table class="tbl utbl"><thead><tr><th style="width:36px"><input type="checkbox" id="uall" aria-label="Seleccionar todos"></th><th>Usuario</th><th>Grupos</th><th class="hide-m">Estado</th><th style="width:44px"></th></tr></thead>
        <tbody>${us.map(u => `<tr data-id="${u.id}" data-n="${esc(u.name.toLowerCase())}"><td><input type="checkbox" class="usel" value="${u.id}" aria-label="Seleccionar ${esc(u.name)}"></td>
          <td><b>${esc(u.name)}</b>${u.id === ME.id ? ' <span class="dim">(tú)</span>' : ''}<div class="dim small">Desde ${esc(date(u.created).toLocaleDateString('es'))}</div></td>
          <td>${groupsOf(u.id).map(g => `<span class="gchip${g.role === 'view' ? ' view' : ''}">${esc(g.name)}</span>`).join('') || '<span class="dim small">—</span>'}</td>
          <td class="hide-m">${u.admin ? '<span class="badge">Admin</span> ' : ''}${u.ext ? `<span class="badge dim" title="Entra con su cuenta del dominio (${u.ext === 'ldap' ? 'LDAP' : 'OIDC'}): sus grupos mandan">dominio</span> ` : ''}${u.must_change ? '<span class="badge dim" title="Se le pedirá cambiar la contraseña al entrar">provisional</span>' : ''}</td>
          <td><button class="btn icon ghost sm" data-more aria-label="Acciones de ${esc(u.name)}" aria-haspopup="menu">${ui('more')}</button></td></tr>`).join('')}</tbody></table></div>
      <div class="actionbar ubar" id="ubar" hidden><b id="ucount"></b><span class="grow"></span>
        <button class="btn" data-bulk="add" aria-haspopup="menu">${ui('plus', 15)}Añadir a grupo</button><button class="btn" data-bulk="rm" aria-haspopup="menu">Quitar de grupo</button>
        <button class="btn" data-bulk="admin" aria-haspopup="menu">${ui('user', 15)}Admin</button><button class="btn" data-bulk="pass">${ui('edit', 15)}Contraseña nueva</button>
        <button class="btn danger" data-bulk="del">${ui('trash', 15)}Borrar</button><button class="btn icon ghost" data-bulk="none" aria-label="Quitar la selección">${ui('x', 16)}</button></div>
      <div class="ph" style="margin-top:36px"><div><h1 style="font-size:22px">Grupos</h1><p class="sub">Técnicos N1, N2… para repartir incidencias. Quien solo está en grupos de «solo vista» no puede cambiar nada.</p></div></div>
      <div class="rows" id="glist">${gs.map(g => `<div class="rowlink urow" data-g="${g.id}"><span class="badge-ic">${ui('users', 18)}</span>
        <div class="grow"><b>${esc(g.name)}</b><span class="ex">${g.members.length ? `${g.members.length} · ` + g.members.map(m => esc(us.find(u => u.id === m)?.name || '?')).join(', ') : 'Sin miembros'}</span></div>
        <span class="badge ${g.role === 'view' ? 'dim' : ''}">${g.role === 'view' ? 'Solo vista' : 'Pueden editar'}</span>
        <button class="btn icon ghost sm" data-gmore aria-label="Acciones de ${esc(g.name)}" aria-haspopup="menu">${ui('more')}</button></div>`).join('') || '<p class="muted small">Aún no hay grupos.</p>'}</div>`;
    const rows = [...app.querySelectorAll('.utbl tbody tr')], shown = () => rows.filter(r => !r.hidden);
    const paintSel = () => {
      rows.forEach(r => { const on = sel.has(+r.dataset.id); r.querySelector('.usel').checked = on; r.classList.toggle('on', on); });
      const vis = shown(), all = vis.length && vis.every(r => sel.has(+r.dataset.id));
      $('#uall').checked = all; $('#uall').indeterminate = !all && vis.some(r => sel.has(+r.dataset.id));
      $('#ubar').hidden = !sel.size; $('#ucount').textContent = `${sel.size} ${sel.size === 1 ? 'seleccionado' : 'seleccionados'}`;
    };
    $('#ufil').oninput = e => { const q = e.target.value.toLowerCase().trim(); rows.forEach(r => r.hidden = !!q && !r.dataset.n.includes(q) && !r.textContent.toLowerCase().includes(q)); paintSel(); };
    $('#uall').onchange = e => { shown().forEach(r => e.target.checked ? sel.add(+r.dataset.id) : sel.delete(+r.dataset.id)); paintSel(); };
    app.querySelector('.utbl tbody').onchange = e => { if (e.target.matches('.usel')) { e.target.checked ? sel.add(+e.target.value) : sel.delete(+e.target.value); paintSel(); } };
    const picked = () => us.filter(u => sel.has(u.id)), others = () => picked().filter(u => u.id !== ME.id); // a uno mismo no se le borra ni se le quita el admin
    const done = msg => { toast(msg); route(false); };
    const setMembers = async (g, ids, add) => { const m = new Set(g.members); ids.forEach(i => add ? m.add(i) : m.delete(i)); await api('groups/' + g.id, 'PUT', {members: [...m]}); };
    $('#ubar').onclick = async e => {
      const b = e.target.closest('[data-bulk]'); if (!b) return;
      const k = b.dataset.bulk, ids = [...sel];
      if (k === 'none') { sel.clear(); return paintSel(); }
      if (k === 'add' || k === 'rm') return menu(b, gs.length ? gs.map(g => [g.name, async () => { await setMembers(g, ids, k === 'add'); done(`${ids.length} ${k === 'add' ? 'añadidos a' : 'quitados de'} ${g.name}`); }, {icon: 'users'}])
        : [['Primero crea un grupo', () => $('#gadd').click(), {icon: 'plus'}]]);
      if (k === 'admin') return menu(b, [['Hacer administradores', async () => { await Promise.all(picked().filter(u => !u.admin).map(u => api('users/' + u.id, 'PUT', {admin: true}))); done('Ahora son administradores'); }, {icon: 'user'}],
        ['Quitar el admin', async () => { await Promise.all(others().filter(u => u.admin).map(u => api('users/' + u.id, 'PUT', {admin: false}))); done('Ya no son administradores'); }, {icon: 'x'}]]);
      const list = others();
      if (!list.length) return toast('A ti mismo no: usa «Cambiar mi contraseña»', 'bad');
      if (k === 'pass') {
        if (!await ask(`¿Contraseña nueva para ${list.length}?`, 'Se les genera una provisional, se cierran sus sesiones y tendrán que cambiarla al entrar.', 'Generar')) return;
        const res = list.map(u => ({name: u.name, pass: genPass()}));
        await Promise.all(res.map((r, i) => api('users/' + list[i].id, 'PUT', {pass: r.pass})));
        await credsDialog('Contraseñas provisionales nuevas', res); return route(false);
      }
      if (k === 'del' && await ask(`¿Borrar ${list.length} ${list.length === 1 ? 'usuario' : 'usuarios'}?`, `${list.slice(0, 6).map(u => esc(u.name)).join(', ')}${list.length > 6 ? '…' : ''} ya no podrán entrar. Lo que hicieron sigue en Actividad.`)) {
        await Promise.all(list.map(u => api('users/' + u.id, 'DELETE'))); done(`${list.length} borrados`);
      }
    };
    $('#add').onclick = () => usersDialog(us, gs);
    $('#gadd').onclick = () => groupsDialog(gs, us);
    $('#glist').onclick = e => {
      const b = e.target.closest('[data-gmore]'), g = b && gs.find(x => x.id === +b.closest('[data-g]').dataset.g); if (!g) return;
      menu(b, [['Editar y miembros', async () => { if (await groupDialog(g, us)) route(false); }, {icon: 'edit'}],
        ['Seleccionar sus miembros', () => { sel.clear(); g.members.forEach(m => sel.add(m)); paintSel(); $('#ubar').scrollIntoView({block: 'nearest', behavior: 'smooth'}); }, {icon: 'check'}], '-',
        ['Borrar grupo', async () => { if (await ask('¿Borrar este grupo?', `«${esc(g.name)}» desaparece y sus incidencias se quedan sin grupo. Las personas no se borran.`)) { await api('groups/' + g.id, 'DELETE'); route(false); } }, {icon: 'trash', danger: true}]]);
    };
    app.querySelector('.utbl tbody').onclick = e => {
      const b = e.target.closest('[data-more]'), u = b && us.find(x => x.id === +b.closest('[data-id]').dataset.id); if (!u) return;
      if (u.ext && u.id !== ME.id) return menu(b, [['Borrar usuario', async () => { if (await ask('¿Borrar este usuario?', `«${esc(u.name)}» es del dominio: si sus grupos siguen dándole acceso, se volverá a crear al entrar.`)) { await api('users/' + u.id, 'DELETE'); toast('Usuario borrado'); route(false); } }, {icon: 'trash', danger: true}]]);
      menu(b, u.id === ME.id ? (u.ext ? [] : [['Cambiar mi contraseña', () => passDialog(false), {icon: 'edit'}]]) : [
        [u.admin ? 'Quitar administrador' : 'Hacer administrador', async () => { await api('users/' + u.id, 'PUT', {admin: !u.admin}); route(false); }, {icon: 'user'}],
        ...(u.totp ? [['Quitar verificación en dos pasos', async () => { if (await ask('¿Quitar su verificación en dos pasos?', `«${esc(u.name)}» entrará solo con su contraseña hasta que la vuelva a activar.`, 'Quitar')) { await api('users/' + u.id, 'PUT', {totp: false}); toast('Verificación en dos pasos quitada'); route(false); } }, {icon: 'key'}]] : []),
        ['Contraseña nueva', async () => { const pw = genPass(); await api('users/' + u.id, 'PUT', {pass: pw}); await credsDialog('Contraseña provisional nueva', [{name: u.name, pass: pw}]); route(false); }, {icon: 'edit'}], '-',
        ['Borrar usuario', async () => { if (await ask('¿Borrar este usuario?', `«${esc(u.name)}» ya no podrá entrar. Lo que hizo sigue en Actividad.`)) { await api('users/' + u.id, 'DELETE'); toast('Usuario borrado'); route(false); } }, {icon: 'trash', danger: true}]]);
    };
  },
});
