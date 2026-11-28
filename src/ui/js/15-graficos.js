// ── Salud de equipos: gráficos SVG hechos a mano ───────
const V3_AUTH = {sha: 'SHA-1', sha256: 'SHA-256', sha384: 'SHA-384', sha512: 'SHA-512', sha224: 'SHA-224', md5: 'MD5', none: 'Sin autenticación'};
const PROFILES = {generic: 'SNMP genérico', synology: 'Synology', qnap: 'QNAP', cisco: 'Cisco', hp: 'HP / Aruba', ubiquiti: 'Ubiquiti', mikrotik: 'MikroTik', hikvision: 'Grabador Hikvision'};
const srcName = h => h.label || h.item_name || h.host;
const everyTxt = s => s < 60 ? `${s} s` : s < 3600 ? `${s / 60} min` : `${s / 3600} h`;
const SRC_KIND = {...PROFILES, kitty: 'Kitty'}, osShort = d => (d || 'Kitty').split(' · ')[0].replace(/^Microsoft /, '').replace(/ \d+(\.\d+)+$/, ''), gb = n => n ? `${+(n / 2 ** 30).toFixed(n < 10 * 2 ** 30 ? 1 : 0)} GB` : '—';
// PCs con Kitty: semáforo de seguridad y estado de parches
const secPill = i => i?.seclight ? `<span class="pill ${i.seclight}" title="${esc(i.secwhy?.length ? i.secwhy.join(' · ') : 'Seguridad en orden')}"><i></i>${{ok: 'seguro', warn: 'revisar', bad: 'en riesgo'}[i.seclight]}</span>` : '';
const patchTxt = p => {
  const d = p.last ? Math.floor((Date.now() - new Date(p.last + 'T00:00')) / 864e5) : null;
  return [d == null ? 'sin datos del último' : `<span class="pill ${d > 30 ? 'bad' : 'ok'}"><i></i>último hace ${d} ${d === 1 ? 'día' : 'días'}</span> <span class="mono dim small">${esc(p.kb)}</span>`,
    p.pending == null ? '' : p.pending ? `${p.pending} pendientes` : 'ninguno pendiente', p.reboot ? '<span class="pill warn"><i></i>reinicio pendiente</span>' : ''].filter(Boolean).join(' · ');
};
const upTxt = s => s >= 86400 ? `${Math.floor(s / 86400)} d` : s >= 3600 ? `${Math.floor(s / 3600)} h` : `${Math.floor(s / 60)} min`;
const fmtV = (v, u) => `${+(+v).toFixed(v >= 100 || u === 'rpm' ? 0 : 1)} ${u}`;
const fmtBw = v => v >= 1000 ? `${+(v / 1000).toFixed(2)} Gbps` : v >= 1 ? `${+v.toFixed(1)} Mbps` : `${Math.round(v * 1000)} kbps`;
const fmtT = (ms, long) => new Date(ms).toLocaleString('es', long ? {day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit'} : {hour: '2-digit', minute: '2-digit'});
const niceStep = r => { const e = 10 ** Math.floor(Math.log10(r || 1)), f = r / e; return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * e; };
const kpi = (label, value, sub = '', crit = false) => `<div class="kpi${crit ? ' crit' : ''}"><span>${label}</span><b>${crit ? ui('alert', 18) : ''}${value}</b><small>${esc(sub)}</small></div>`;
// Línea temporal: una sola escala, crosshair con tooltip de todas las series, legend con ≥2 series, teclado ←/→
function lineChart(box, series, o = {}) {
  if (!series.some(s => s.points.length)) return void (box.innerHTML = `<p class="muted small chart-empty">${o.empty || 'Aún no hay lecturas en este rango.'}</p>`);
  const W = Math.max(260, box.clientWidth), H = o.h || 210, L = 40, R = 14, T = 16, B = 26;
  const t = series.map(s => s.points.map(([ts, v]) => [date(ts).getTime(), v]));
  const xs = t.flat().map(p => p[0]), vs = t.flat().map(p => p[1]).concat(o.limit != null && !o.hi ? [o.limit] : []);
  const x0 = Math.min(...xs), x1 = Math.max(...xs, x0 + 6e4);
  let y0 = o.lo ?? Math.min(...vs), y1 = o.hi ?? Math.max(...vs);
  const st = niceStep((y1 - y0) / 4 || Math.abs(y1) / 4 || 1);
  y0 = Math.floor(y0 / st) * st; y1 = Math.max(Math.ceil(y1 / st) * st, y0 + st);
  const X = v => L + (v - x0) / (x1 - x0) * (W - L - R), Y = v => T + (1 - (v - y0) / (y1 - y0)) * (H - T - B);
  const yt = []; for (let v = y0; v <= y1 + st / 1e3; v += st) yt.push(v);
  const long = x1 - x0 > 864e5 * 1.5, nt = W < 420 ? 3 : 4, xt = Array.from({length: nt}, (_, i) => x0 + (x1 - x0) * (i + .5) / nt);
  box.innerHTML = `<div class="chart"><svg width="${W}" height="${H}" tabindex="0" role="img" aria-label="${esc(o.title || 'Gráfico')}: flechas para recorrer">
      ${yt.map(v => `<line class="grid-l" x1="${L}" x2="${W - R}" y1="${Y(v)}" y2="${Y(v)}"/><text class="tick" x="${L - 8}" y="${Y(v) + 4}" text-anchor="end">${+v.toFixed(1)}</text>`).join('')}
      ${xt.map(v => `<text class="tick" x="${X(v)}" y="${H - 6}" text-anchor="middle">${esc(fmtT(v, long))}</text>`).join('')}
      ${o.limit != null && o.limit >= y0 && o.limit <= y1 ? `<line class="lim" x1="${L}" x2="${W - R}" y1="${Y(o.limit)}" y2="${Y(o.limit)}"/><text class="lim-t" x="${L + 6}" y="${Y(o.limit) - 6}">límite ${esc(fmtV(o.limit, o.unit))}</text>` : ''}
      ${t.map((p, i) => `<path class="ln" style="--c:var(--k${i + 1})" d="${p.map(([a, b], k) => (k ? 'L' : 'M') + X(a).toFixed(1) + ' ' + Y(b).toFixed(1)).join('')}"/>`).join('')}
      ${t.map((p, i) => p.length ? `<circle class="end" style="--c:var(--k${i + 1})" cx="${X(p.at(-1)[0])}" cy="${Y(p.at(-1)[1])}" r="4"/>` : '').join('')}
      <g class="xh" visibility="hidden"><line y1="${T}" y2="${H - B}"/>${t.map((_, i) => `<circle r="4" style="--c:var(--k${i + 1})"/>`).join('')}</g></svg>
      <div class="tip" hidden></div></div>
    ${series.length > 1 ? `<div class="legend">${series.map((s, i) => `<span><i style="--c:var(--k${i + 1})"></i>${esc(s.label)}</span>`).join('')}</div>` : ''}
    ${o.more ? `<p class="dim small" style="margin:6px 0 0">${o.more}</p>` : ''}`;
  const svg = box.querySelector('svg'), xh = svg.querySelector('.xh'), tip = box.querySelector('.tip');
  let kx = x1;
  const show = ms => {
    kx = Math.min(x1, Math.max(x0, ms));
    const near = t.map(p => p.length ? p.reduce((a, b) => Math.abs(b[0] - kx) < Math.abs(a[0] - kx) ? b : a) : null), ref = near.find(Boolean);
    xh.setAttribute('visibility', 'visible');
    xh.firstElementChild.setAttribute('x1', X(ref[0])); xh.firstElementChild.setAttribute('x2', X(ref[0]));
    [...xh.querySelectorAll('circle')].forEach((c, i) => near[i] ? (c.setAttribute('cx', X(near[i][0])), c.setAttribute('cy', Y(near[i][1])), c.removeAttribute('visibility')) : c.setAttribute('visibility', 'hidden'));
    tip.hidden = false;
    tip.innerHTML = `<b>${esc(fmtT(ref[0], true))}</b>` + near.map((p, i) => p && [p[1], `<div><i style="--c:var(--k${i + 1})"></i><strong>${esc(fmtV(p[1], o.unit))}</strong><span>${esc(series[i].label)}</span></div>`])
      .filter(Boolean).sort((a, b) => b[0] - a[0]).map(x => x[1]).join('');
    tip.style.left = Math.min(Math.max(X(ref[0]) + 12, 0), W - tip.offsetWidth) + 'px';
  };
  const hide = () => { xh.setAttribute('visibility', 'hidden'); tip.hidden = true; };
  svg.onpointermove = e => show(x0 + (e.clientX - svg.getBoundingClientRect().left - L) / (W - L - R) * (x1 - x0));
  svg.onpointerleave = svg.onblur = hide;
  svg.onfocus = () => show(kx);
  svg.onkeydown = e => { const d = {ArrowLeft: -1, ArrowRight: 1}[e.key]; if (d) { e.preventDefault(); show(kx + d * (x1 - x0) / 40); } if (e.key === 'Escape') hide(); };
  const w0 = box.clientWidth; // al cambiar el ancho de la tarjeta, se vuelve a dibujar
  box._ro?.disconnect(); box._ro = new ResizeObserver(() => Math.abs(box.clientWidth - w0) > 4 && lineChart(box, series, o)); box._ro.observe(box);
}
// Ocupación actual: barras finas con la marca del límite; el estado lleva icono y texto, no solo color
function diskBars(box, disks, limit) {
  box.innerHTML = disks.length ? `<div class="bars">${disks.map(d => {
    const v = d.value, st = v > limit ? 'crit' : v > limit - 10 ? 'warn' : '';
    return `<div class="bar-row ${st}"><span class="bl" title="${esc(d.label)}">${esc(d.label)}</span>
      <div class="track" role="img" aria-label="${esc(d.label)}: ${esc(fmtV(v, '%'))}"><i style="width:${Math.min(100, v)}%"></i>${limit <= 100 ? `<b class="mark" style="left:${limit}%" title="Límite ${limit} %"></b>` : ''}</div>
      <span class="bv">${st ? ui('alert', 14) : ''}${esc(fmtV(v, '%'))}${st === 'crit' ? ' · lleno' : st === 'warn' ? ' · casi' : ''}</span></div>`; }).join('')}</div>`
    : '<p class="muted small chart-empty">Este equipo no informa de discos.</p>';
}
async function sourceDialog(h, items) {
  const ip = items.filter(i => i.ip);
  const p = dialog(`<h3>${h.id ? 'Editar equipo' : 'Leer la salud de un equipo'}</h3><p>catlan leerá sus temperaturas, discos y estado cada cierto tiempo, y te avisará si algo pasa del límite.</p>
    <div class="fields two">
      <div class="field full"><label for="s-it">Del inventario <span class="dim">· opcional</span></label><select id="s-it" name="item"><option value="">Otro equipo</option>
        ${ip.map(i => `<option value="${i.id}" ${i.id === h.item ? 'selected' : ''}>${esc(i.name)} · ${esc(i.ip)}</option>`).join('')}</select></div>
      <div class="field"><label for="s-k">Tipo</label><select id="s-k" name="kind">${Object.entries(PROFILES).map(([k, n]) => `<option value="${k}" ${k === (h.kind || 'generic') ? 'selected' : ''}>${n}</option>`).join('')}</select></div>
      <div class="field"><label for="s-h">IP o nombre</label><input id="s-h" name="host" class="mono" required value="${esc(h.host || '')}" placeholder="10.0.0.20"></div>
      <div class="field full"><label for="s-l">Nombre <span class="dim">· opcional</span></label><input id="s-l" name="label" value="${esc(h.label || '')}"></div>
      <div class="field snmp"><label for="s-v">Versión SNMP</label><select id="s-v" name="v3"><option value="">v2c · comunidad</option><option value="1" ${h.v3 ? 'selected' : ''}>v3 · usuario y contraseña</option></select></div>
      <div class="field snmp"><label for="s-p">Puerto</label><input id="s-p" name="port" type="number" min="1" max="65535" value="${h.port || 161}" class="mono"></div>
      <div class="field full v2"><label for="s-c">Comunidad SNMP</label><input id="s-c" name="community" type="password" autocomplete="off" placeholder="${h.id ? 'sin cambios' : 'public'}"></div>
      <div class="field full v3"><label for="s-vu">Usuario SNMPv3</label><input id="s-vu" name="user" required value="${esc(h.v3 ? h.user || '' : '')}" autocomplete="off" class="mono"></div>
      <div class="field v3"><label for="s-va">Autenticación</label><select id="s-va" name="auth">${Object.entries(V3_AUTH).map(([k, n]) => `<option value="${k}" ${k === (h.auth || 'sha') ? 'selected' : ''}>${n}</option>`).join('')}</select></div>
      <div class="field v3 v3a"><label for="s-vp">Contraseña de autenticación</label><input id="s-vp" name="pass" type="password" minlength="8" ${h.id && h.v3 ? '' : 'required'} autocomplete="new-password" placeholder="${h.id && h.v3 ? 'sin cambios' : 'mínimo 8 caracteres'}"></div>
      <div class="field v3 v3a"><label for="s-vc">Cifrado</label><select id="s-vc" name="priv"><option value="aes">AES-128</option><option value="none" ${h.priv === 'none' ? 'selected' : ''}>Sin cifrar</option></select></div>
      <div class="field v3 v3a v3p"><label for="s-vk">Contraseña de cifrado</label><input id="s-vk" name="priv_pass" type="password" minlength="8" ${h.id && h.v3 ? '' : 'required'} autocomplete="new-password" placeholder="${h.id && h.v3 ? 'sin cambios' : 'mínimo 8 caracteres'}"></div>
      <div class="field hik"><label for="s-u">Usuario</label><input id="s-u" name="user" value="${esc(h.user || 'admin')}" autocomplete="off"></div>
      <div class="field hik"><label for="s-pw">Contraseña</label><input id="s-pw" name="pass" type="password" autocomplete="new-password" placeholder="${h.id ? 'sin cambios' : ''}"></div>
      <div class="field"><label for="s-t">Avisar sobre (°C)</label><input id="s-t" name="temp_max" type="number" min="1" max="200" value="${h.temp_max || 65}" class="mono"></div>
      <div class="field"><label for="s-d">Avisar con disco al (%)</label><input id="s-d" name="disk_max" type="number" min="1" max="200" value="${h.disk_max || 90}" class="mono"></div>
      <div class="field"><label for="s-e">Leer cada</label><select id="s-e" name="every">${[[60, '1 minuto'], [300, '5 minutos'], [900, '15 minutos'], [3600, '1 hora']].map(([v, t]) => `<option value="${v}" ${v === (h.every || 300) ? 'selected' : ''}>${t}</option>`).join('')}</select></div>
      <div class="field"><label>&nbsp;</label><button type="button" class="btn" id="s-test" style="width:100%">${ui('signal', 16)}Probar conexión</button></div>
      <p class="field full small muted" id="s-hint" style="margin:0"></p><div class="field full test-out" id="s-out" aria-live="polite"></div></div>`, {ok: h.id ? 'Guardar' : 'Empezar a leer'});
  const dl = document.querySelector('dialog[open]:last-of-type'), $d = x => dl.querySelector(x);
  const show = (sel, on) => dl.querySelectorAll(sel).forEach(f => { f.hidden = !on; f.querySelectorAll('input,select').forEach(i => i.disabled = !on); }); // desactivado = no va en el formulario
  const kind = () => {
    const hik = $d('#s-k').value === 'hikvision', v3 = !hik && $d('#s-v').value === '1', auth = v3 && $d('#s-va').value !== 'none';
    show('.snmp', !hik); show('.hik', hik); show('.v2', !hik && !v3); show('.v3', v3); show('.v3a', auth); show('.v3p', auth && $d('#s-vc').value !== 'none');
    $d('#s-hint').textContent = hik ? 'Usa un usuario del grabador con permiso de consulta. Los grabadores llenan el disco a propósito (sobrescriben lo antiguo): con 100 % solo avisa de discos con error.'
      : v3 ? 'Crea en el equipo un usuario SNMPv3 de solo lectura con los mismos algoritmos y contraseñas. Lo más habitual y seguro: SHA y AES.'
      : 'Activa SNMP v2c en el equipo con una comunidad de solo lectura (Synology: Panel de control › Terminal y SNMP · QNAP: Panel de control › SNMP · MikroTik: /snmp set enabled=yes).';
  };
  $d('#s-k').onchange = () => { kind(); if ($d('#s-k').value === 'hikvision' && !h.id) $d('#s-d').value = 100; };
  ['#s-v', '#s-va', '#s-vc'].forEach(x => $d(x).onchange = kind);
  $d('#s-it').onchange = e => { const i = ip.find(x => x.id === +e.target.value); if (i) { $d('#s-h').value = i.ip; $d('#s-l').placeholder = i.name; } };
  kind();
  const body = () => {
    const f = new FormData($d('form')), b = Object.fromEntries(['host', 'label', 'kind', 'community', 'user', 'pass', 'priv_pass'].map(k => [k, (f.get(k) || '').trim()]));
    const v3 = f.get('v3') === '1' ? {auth: f.get('auth'), priv: f.get('auth') === 'none' ? 'none' : f.get('priv')} : {};
    return {...b, ...v3, v3: f.get('v3') === '1', item: f.get('item') ? +f.get('item') : null, port: +f.get('port') || 161, every: +f.get('every'), temp_max: +f.get('temp_max'), disk_max: +f.get('disk_max')};
  };
  $d('#s-test').onclick = async () => {
    const out = $d('#s-out'); out.innerHTML = '<span class="dim">Probando… (hasta 5 s)</span>';
    const r = await fetch('/api/sources/test', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({...body(), id: h.id})})
      .then(x => x.json()).catch(() => ({error: 'sin conexión con catlan'}));
    out.innerHTML = r.error ? `<span class="t-bad">${ui('alert', 14)}${esc(r.error)}</span>`
      : `<span class="t-ok">${ui('check', 14)}Conectado${r.info?.name ? ' a ' + esc(r.info.name) : ''} · ${r.metrics.length} lecturas</span>
         <span class="dim">${esc(r.metrics.slice(0, 6).map(m => `${m[1]} ${fmtV(m[2], m[3])}`).join(' · '))}${r.metrics.length > 6 ? ' …' : ''}</span>
         ${r.problems.length ? `<span class="t-bad">${ui('alert', 14)}${esc(r.problems.join(' · '))}</span>` : ''}`;
  };
  if (!await p) return;
  const b = body();
  if (!b.community && !h.id) b.community = 'public';
  const saved = await (h.id ? api('sources/' + h.id, 'PUT', b) : api('sources', 'POST', b));
  toast(h.id ? 'Guardado' : `Leyendo ${b.label || b.host}`);
  location.hash === '#/salud/' + saved.id ? route(false) : location.hash = '#/salud/' + saved.id;
}

