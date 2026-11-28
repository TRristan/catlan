// ── Sesión: login, contraseña provisional y usuarios ──
let ME = null;
function showLogin() {
  if ($('#login')) return;
  const el = document.createElement('div');
  el.className = 'login'; el.id = 'login';
  el.innerHTML = `<form class="login-card"><span class="login-logo">${ui('cat', 30)}</span><h1><svg class="wm" viewBox="0 0 541 137.5" width="94" height="24" role="img" aria-label="catlan"><use href="#wm-catlan"/></svg></h1><p>El gato amigo de los IT</p>
    <label>Usuario<input name="name" autocomplete="username" required autofocus></label>
    <label>Contraseña<input name="pass" type="password" autocomplete="current-password" required></label>
    <label hidden>Código de tu app de autenticación<input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{6,7}" maxlength="7"></label>
    <p class="login-err" role="alert"></p><button class="btn pri">Entrar</button>
    <details class="small muted" style="margin-top:12px"><summary style="cursor:pointer">¿Has olvidado la contraseña?</summary><p style="margin:8px 0 0">Pide a un administrador una nueva (Administración → Usuarios y grupos). Si eres el único administrador, en el servidor de catlan ejecuta <code>catlan restablecer tu-usuario</code> con su misma carpeta de datos (si lo arrancas con <code>CATLAN_DATA</code>, ponla igual). Con Docker: <code>docker compose exec catlan catlan restablecer tu-usuario</code>.</p></details></form>`;
  document.body.append(el);
  const off = [...document.querySelectorAll('body > :not(#login):not([inert])')]; // detrás no se llega con el teclado
  off.forEach(x => x.inert = true);
  const f = el.firstChild;
  f.querySelector('input').focus();
  const why = new URLSearchParams(location.search).get('sso') || '';
  if (why) history.replaceState(null, '', location.pathname + location.hash);
  fetch('/api/sso?e=' + encodeURIComponent(why)).then(r => r.json()).then(s => {
    if (s.error) f.querySelector('.login-err').textContent = s.error;
    if (s.ldap) f.elements.namedItem('name').previousSibling.textContent = 'Usuario de catlan o del dominio';
    if (s.oidc) f.querySelector('.btn.pri').insertAdjacentHTML('afterend', `<a class="btn" href="/api/sso/start" style="height:40px">${ui('key', 16)}Entrar con ${esc(s.oidc)}</a>`);
  }).catch(() => {});
  f.onsubmit = async e => {
    e.preventDefault();
    const r = await fetch('/api/login', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(Object.fromEntries(new FormData(f)))}).catch(() => null);
    if (!r?.ok) { // sacudida y mensaje: nunca se dice si fallaba el usuario o la contraseña
      const e = r ? await r.json().catch(() => ({})) : {};
      f.querySelector('.login-err').textContent = r ? e.error || 'No se pudo entrar' : 'Sin conexión con el servidor';
      if (e.totp) { f.code.parentNode.hidden = false; f.code.required = true; f.code.select(); } // la contraseña valía: falta el código
      f.classList.remove('bad'); void f.offsetWidth; f.classList.add('bad'); if (!e.totp) f.pass.select(); return;
    }
    off.forEach(x => x.inert = false);
    anim(el, [{opacity: 1}, {opacity: 0}], {duration: 250, fill: 'forwards'})?.finished.then(() => el.remove()) ?? el.remove();
    boot();
  };
}
async function passDialog(forced) {
  for (;;) {
    const p = dialog(`<h3>${forced ? 'Elige tu contraseña' : 'Cambiar contraseña'}</h3>${forced ? '<p>Estás usando una contraseña provisional. Cámbiala para empezar.</p>' : ''}
      <div class="fields"><div class="field"><label for="pw-o">Contraseña actual</label><input id="pw-o" name="old" type="password" autocomplete="current-password" required autofocus></div>
      <div class="field"><label for="pw-n">Nueva contraseña <span class="dim">· mínimo 8 caracteres</span></label><input id="pw-n" name="new" type="password" minlength="8" autocomplete="new-password" required></div>
      <div class="field"><label for="pw-r">Repite la nueva</label><input id="pw-r" name="rep" type="password" minlength="8" autocomplete="new-password" required></div></div>`, {ok: 'Guardar'});
    const dl = document.querySelector('dialog[open]:last-of-type');
    if (forced) { dl.querySelector('.dlg-a .ghost').remove(); dl.addEventListener('cancel', e => e.preventDefault()); } // obligatorio: sin cancelar ni Escape
    const f = await p; if (!f) return false;
    if (f.get('new') !== f.get('rep')) { toast('Las contraseñas nuevas no coinciden', 'bad'); continue; }
    try { await api('me/password', 'POST', {old: f.get('old'), new: f.get('new')}); toast('Contraseña cambiada'); return true; } catch {} // el error ya sale en un aviso
  }
}
let booted = false;
async function boot() {
  const r = await fetch('/api/me').catch(() => null);
  if (r?.status === 401) return showLogin();
  ME = await r.json();
  if (ME.must_change) { await passDialog(true); ME.must_change = 0; }
  $('[data-v="cuenta"]').title = `Mi cuenta · ${ME.name}${ME.readonly ? ' · solo vista' : ''}`;
  document.body.classList.toggle('ro', !!ME.readonly);
  $('#nav-opts').hidden = !ME.admin;
  await loadPeople();
  if (booted) return route();
  booted = true; route(); pollMonitor(); setInterval(pollMonitor, 10000);
  if (!tourSeen()) setTimeout(() => tour(), 700); // primera vez de este usuario: el paseo
}
// Verificación en dos pasos: secreto para la app (Google Authenticator, Aegis, 1Password…) y un código para confirmar
async function totpDialog() {
  if (ME.totp) {
    const f = await dialog(`<h3>Quitar la verificación en dos pasos</h3><p>Al entrar ya solo te pedirá la contraseña.</p>
      <div class="field"><label for="tf-p">Tu contraseña</label><input id="tf-p" name="pass" type="password" autocomplete="current-password" required autofocus></div>`, {ok: 'Quitar', danger: true});
    if (f) { ME = await api('me/totp', 'POST', {off: true, pass: f.get('pass')}).catch(() => ME); if (!ME.totp) toast('Verificación en dos pasos quitada'); }
    return;
  }
  const {secret, uri} = await api('me/totp', 'POST', {});
  for (;;) {
    const f = await dialog(`<h3>Verificación en dos pasos</h3><p>En tu app de autenticación, añade una cuenta con esta clave (o abre el enlace en el móvil). Desde entonces, al entrar te pedirá también su código de 6 cifras.</p>
      <p><code style="user-select:all;font-size:15px;letter-spacing:1px">${esc(secret.match(/.{4}/g).join(' '))}</code> · <a href="${esc(uri)}">abrir en la app</a></p>
      <div class="field"><label for="tf-c">Código que muestra la app</label><input id="tf-c" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{6,7}" maxlength="7" required autofocus></div>
      <p class="small muted">Por Basic (scripts) ya no podrás entrar con este usuario. Si pierdes el móvil, un administrador te la quita.</p>`, {ok: 'Activar'});
    if (!f) return;
    try { ME = await api('me/totp', 'POST', {secret, code: f.get('code')}); toast('Verificación en dos pasos activada'); return; } catch {}
  }
}
Object.assign(views, {
  // Mi cuenta: lo de este navegador (antes el cajón de Ajustes) y lo de tu usuario
  async cuenta() {
    crumbs([['Mi cuenta']]);
    const sw = k => `<button class="switch" role="switch" data-k="${k}" aria-label="${k === 'rail' ? 'Barra lateral compacta' : 'Paleta de esquemas abierta'}"></button>`;
    app.innerHTML = head('Mi cuenta', `${esc(ME.name)}${ME.admin ? ' · administrador' : ''}${ME.readonly ? ' · solo vista' : ''}${ME.ext ? ' · del dominio' : ''}`, '<button class="btn" id="logout">' + ui('x', 16) + 'Cerrar sesión</button>')
      + `<div id="settings" class="split stagger"><div>
        <section class="card pad" style="--i:0"><h3 class="card-t">${ui('sliders', 15)}Apariencia <span class="dim small" style="font-weight:400;margin-left:auto">en este navegador</span></h3>
          <div class="set"><span>Tema</span><div class="seg" data-k="theme"><button data-v="auto">Sistema</button><button data-v="light">Claro</button><button data-v="dark">Oscuro</button></div></div>
          <div class="set"><span>Acento</span><div class="swatches" data-k="accent">${ACCENTS.map(([n, c]) => `<button data-v="${c}" style="--c:${c}" title="${n}" aria-label="Acento ${n}"></button>`).join('')}</div></div>
          <div class="set"><span>Densidad</span><div class="seg" data-k="density"><button data-v="comfy">Cómoda</button><button data-v="compact">Compacta</button></div></div>
          <div class="set"><span>Animaciones<small>«Sistema» respeta «reducir movimiento»</small></span><div class="seg" data-k="motion"><button data-v="auto">Sistema</button><button data-v="on">Sí</button><button data-v="off">No</button></div></div>
          <div class="set"><span>Barra lateral compacta<small>Solo iconos</small></span>${sw('rail')}</div>
          <div class="set"><span>Paleta de esquemas abierta</span>${sw('dock')}</div>
          <div class="set"><span>Sonidos de alerta<small>Están en Monitor, junto a lo que vigilas</small></span><a class="btn sm" href="#/monitor">Abrir Monitor</a></div>
          <div class="set"><span class="small muted">Se guardan en este navegador</span><button class="btn ghost sm" id="reset-settings">Restablecer</button></div></section></div>
        <aside class="side-col">
          <section class="card pad" style="--i:1"><h3 class="card-t">${ui('user', 15)}Foto de perfil</h3>
            <div class="me-ph"><span id="me-av">${avatar(ME.name)}</span><div><button class="btn sm" id="ph-up">${ui('image', 15)}${ME.photo_v ? 'Cambiar' : 'Subir foto'}</button>
              ${ME.photo_v ? '<button class="btn ghost sm" id="ph-del">Quitar</button>' : ''}<small class="dim">Sale junto a lo que haces en Actividad e historiales.</small></div></div></section>
          <section class="card pad" style="--i:1"><h3 class="card-t">${ui('key', 15)}Acceso</h3>
            ${ME.ext ? '<p class="small muted" style="margin:0">Tu usuario es del dominio: la contraseña y la verificación en dos pasos se cambian allí.</p>'
              : `<div class="set"><span>Contraseña</span><button class="btn sm" id="pw">Cambiar</button></div>
                 <div class="set"><span>Verificación en dos pasos<small>${ME.totp ? 'Activada' : 'Desactivada'}</small></span><button class="btn sm" id="totp">${ME.totp ? 'Quitar' : 'Activar'}</button></div>`}</section>
          <section class="card pad" style="--i:2"><h3 class="card-t">${ui('book', 15)}Ayuda</h3>
            <div class="set"><span>Tutorial<small>Un paseo de un minuto por catlan</small></span><button class="btn sm" id="tour-again">Ver el tutorial</button></div>
            <div class="set"><span>Guía de uso<small>Funciones, trucos y qué hace con tus datos</small></span><a class="btn sm" href="#/guia">Abrir la guía</a></div></section>
        </aside></div>`;
    applySettings();
    $('#settings').onclick = e => {
      const sw = e.target.closest('.switch');
      if (sw) { S[sw.dataset.k] = !S[sw.dataset.k]; return applySettings(); }
      const b = e.target.closest('[data-v]'), g = b?.closest('[data-k]');
      if (g) { S[g.dataset.k] = b.dataset.v; applySettings(); }
    };
    $('#reset-settings').onclick = () => { S = {...DEF}; applySettings(); toast('Ajustes restablecidos'); };
    $('#tour-again').onclick = () => tour();
    // la foto, recortada al centro en un cuadrado de 256 px: ligera y sin datos de la cámara (EXIF, GPS…)
    $('#ph-up').onclick = () => {
      const inp = Object.assign(document.createElement('input'), {type: 'file', accept: 'image/*'});
      inp.onchange = async () => {
        const f = inp.files[0]; if (!f) return;
        const bmp = await createImageBitmap(f).catch(() => null);
        if (!bmp) return toast('Esa imagen no se puede abrir', 'bad');
        const s = Math.min(bmp.width, bmp.height), cv = Object.assign(document.createElement('canvas'), {width: 256, height: 256});
        cv.getContext('2d').drawImage(bmp, (bmp.width - s) / 2, (bmp.height - s) / 2, s, s, 0, 0, 256, 256);
        const blob = await new Promise(ok => cv.toBlob(ok, 'image/jpeg', .88));
        try { ME = await api('me/photo', 'PUT', blob, 'image/jpeg'); } catch { return; }
        await loadPeople(); toast('Foto de perfil cambiada'); route(false);
      };
      inp.click();
    };
    $('#ph-del') && ($('#ph-del').onclick = async () => { try { ME = await api('me/photo', 'DELETE'); } catch { return; } await loadPeople(); toast('Foto quitada'); route(false); });
    $('#logout').onclick = async () => { await api('logout', 'POST'); location.reload(); };
    if (!ME.ext) { $('#pw').onclick = () => passDialog(false); $('#totp').onclick = async () => { await totpDialog(); route(false); }; }
  },
  async guia() {
    const g = (await api('pages').catch(() => [])).find(x => x.title === 'Guía de catlan');
    if (g) return location.replace('#/wiki/' + g.id); // sin dejar #/guia en el historial: «Atrás» no vuelve a saltar
    crumbs([['Guía de catlan']]);
    app.innerHTML = empty('book', 'No encuentro la «Guía de catlan»', 'Se crea en la Wiki al instalar catlan; quizá se borró.', '<a class="btn" href="#/wiki">Ir a la Wiki</a>');
  },
});
applySettings();
boot();
