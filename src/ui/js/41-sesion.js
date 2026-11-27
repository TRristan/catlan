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
    <details class="small muted" style="margin-top:12px"><summary style="cursor:pointer">¿Has olvidado la contraseña?</summary><p style="margin:8px 0 0">Pide a un administrador una nueva (Opciones → Usuarios). Si eres el único administrador, en el servidor de catlan ejecuta <code>catlan restablecer tu-usuario</code> con su misma carpeta de datos (si lo arrancas con <code>CATLAN_DATA</code>, ponla igual). Con Docker: <code>docker compose exec catlan catlan restablecer tu-usuario</code>.</p></details></form>`;
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
  $('#user-name').textContent = ME.name + (ME.readonly ? ' · solo vista' : '');
  document.body.classList.toggle('ro', !!ME.readonly);
  $('#nav-opts').hidden = !ME.admin;
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
$('#user-btn').onclick = e => menu(e.currentTarget, [...(ME?.ext ? [] : [['Cambiar contraseña', () => passDialog(false), {icon: 'edit'}], // los del dominio, allí
  [ME?.totp ? 'Quitar verificación en dos pasos' : 'Verificación en dos pasos', totpDialog, {icon: 'key'}],
  '-']),
  ['Cerrar sesión', async () => { await api('logout', 'POST'); location.reload(); }, {icon: 'x'}]]);
applySettings();
boot();
