// ── Gato en pixel art ───────────────────────────────────
// Cada pieza es [x, y, filas]; cada carácter es un píxel ('.' = vacío). Ver clases .c-* para los colores.
const CAT = (() => {
  const W = 40, H = 24;
  const draw = parts => {
    const g = Array.from({length: H}, () => Array(W).fill('.'));
    for (const [x, y, rows] of parts) rows.forEach((r, j) => [...r].forEach((c, i) => { if (c !== '.' && g[y + j] && x + i < W) g[y + j][x + i] = c; }));
    let out = '';
    g.forEach((row, y) => { for (let x = 0; x < W;) { let w = 1; while (row[x + w] === row[x]) w++; if (row[x] !== '.') out += `<rect class="c-${row[x]}" x="${x}" y="${y}" width="${w}" height="1"/>`; x += w; } });
    return out;
  };
  const floor = [0, 22, ['.FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF']];
  const laptopOpen = [6, 7, ['KK', 'KSY', 'KSY', 'KSY', 'KSY', 'KSY', '.KSY', '.KSY', '.KSY', '.KSY', '..KSY', '..KSY', '..KS',
    '..LLLLLLLLLLLLLL', '..GGGGGGGGGGGGGG']];
  const body = [19, 12, ['..KOOOKKKK.....', '.KWOOOOOOOKK...', '.KWOOOODOOOOOK.', 'KWWOOOOODOOOOOK', 'KWWOOOOOODOOOOK',
    'KWOOOOOOODOOOOK', 'KWOOOOOOOOOOOOK', 'KWOOOOOOOOOOOOK', '.KOOOOOOOOOOOK.', '..KKKKKKKKKKK..']];
  const tail = [33, 13, ['...KK', '..KOK', '..KOK', '..KDK', '..KOK', '.KOK.', '.KOK.', 'KOK..', 'KK...']];
  const head = [16, 4, ['....K..K....', '...KOKKOK...', '..KOOOOOOK..', '.KOOOOOOOOK.', 'KOEOOOODOOOK', 'KWWOOOOODOOK',
    'PWWOOOOOOOOK', '.KWWOOOOOOK.', '..KKWOOOKK..']];
  const typing = draw([floor, laptopOpen, body, tail, head])
    + '<g class="glyph"><text x="10" y="7">{}</text><text x="13" y="6">01</text><text x="9" y="5">&lt;/&gt;</text></g>';
  // Patas: la cercana (blanca) y la lejana (oscura) se alternan sobre el teclado
  const paws = [draw([[15, 16, ['....KO', '..KOOK', '.KOOK.', 'KWWK..']], [11, 17, ['KDDK']]]),
                draw([[15, 16, ['....KO', '..KOOK', 'KWWK..']], [11, 18, ['KDDK']]])];
  const laptopClosed = [3, 19, ['GGGGGGGGGGGGGGGGGGGGGG', 'LLLLLLLLLLLLLLLLLLLLLL', 'GGGGGGGGGGGGGGGGGGGGGG']];
  const loaf = [5, 9, ['...K..K...........', '..KOKKOK..........', '.KOOOOOOKKKKKKKK..', 'KOOOOOOOOOOODOOOOK',
    'KOKKOOKKOOOOODOOOK', 'KWWPWWOOOOOOOODOOK', 'KWWWWOOOOOOOOOOOOK', '.KOOOOOOOOOOOOOOOK', '.KDDDDDDDDDDDDDDK.', '..KKKKKKKKKKKKKK..']];
  const sleeping = draw([floor, laptopClosed]) + `<g class="breath">${draw([loaf])}</g>`
    + '<g class="zz"><text x="21" y="9">z</text><text x="24" y="6">z</text><text x="27" y="4">z</text></g>';
  return {typing, paws, sleeping};
})();

// ── Alertas sonoras ─────────────────────────────────────
// 4 sonidos sintetizados en el navegador (sin archivos) + los audios que subas ("u:<id>")
let actx = null;
const audioCtx = () => (actx ||= new (window.AudioContext || window.webkitAudioContext)());
addEventListener('pointerdown', () => actx?.state === 'suspended' && actx.resume(), {passive: true}); // el navegador solo deja sonar tras un clic
function blip(c, at, type, freqs, dur, vol) { // un tono con envolvente; varias frecuencias = glissando
  const o = c.createOscillator(), g = c.createGain();
  o.type = type; o.frequency.setValueAtTime(freqs[0], at);
  freqs.slice(1).forEach((f, i) => o.frequency.linearRampToValueAtTime(f, at + dur * (i + 1) / (freqs.length - 1 || 1)));
  g.gain.setValueAtTime(0, at); g.gain.linearRampToValueAtTime(vol, at + .02); g.gain.exponentialRampToValueAtTime(.001, at + dur);
  o.connect(g).connect(c.destination); o.start(at); o.stop(at + dur + .05);
}
const SOUNDS = {
  bell: ['Campana', (c, t, v) => [880, 1318, 1760].forEach((f, i) => blip(c, t + i * .12, 'sine', [f], 1.4, v / (i + 1.5)))],
  beep: ['Bip-bip', (c, t, v) => [0, .18, .36].forEach(d => blip(c, t + d, 'square', [1046], .12, v * .3))],
  siren: ['Sirena', (c, t, v) => [0, .8].forEach(d => blip(c, t + d, 'sawtooth', [520, 1040, 520], .8, v * .22))],
  meow: ['Miau', (c, t, v) => blip(c, t, 'triangle', [420, 760, 900, 520], .7, v * .7)],
};
async function playSound(key = S.sound, vol = S.vol) {
  const blocked = () => toast('Haz clic en la página para permitir el sonido', 'bad');
  if (String(key).startsWith('u:')) { const a = new Audio(`/api/sounds/${key.slice(2)}/audio`); a.volume = vol; return a.play().catch(blocked); }
  const c = audioCtx();
  if (c.state === 'suspended') await c.resume().catch(() => {});
  if (c.state !== 'running') return blocked();
  (SOUNDS[key] || SOUNDS.bell)[1](c, c.currentTime + .02, vol);
}
// Sondeo del monitor (cada 10 s, en cualquier sección): avisa al caer y al volver
let monData = null, monPrev = null, monPaint = null, srcPrev = null, healthRange = 24;
const monName = c => c.label || c.item_name || c.host;
const CHECK_KINDS = {ping: 'Ping', tcp: 'Puerto TCP', http: 'Web (HTTP/HTTPS)', ssl: 'Certificado SSL', dns: 'DNS'};
const checkTarget = c => c.kind === 'http' ? c.url : c.kind === 'tcp' || c.kind === 'ssl' ? `${c.host}:${c.port || 443}` : c.host;
const isMuted = x => !!x.mute_until && date(x.mute_until) > Date.now() && (!x.mute_from || date(x.mute_from) <= Date.now());
const isPlanned = x => !!x.mute_from && date(x.mute_from) > Date.now() && date(x.mute_until) > Date.now(); // mantenimiento que aún no ha empezado
const whenTxt = t => date(t).toLocaleString('es', {weekday: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'});
const muteTxt = x => isPlanned(x) ? `mantenimiento ${whenTxt(x.mute_from)} – ${whenTxt(x.mute_until)}` : (x.mute_from ? 'en mantenimiento hasta ' : 'silenciado hasta ') + whenTxt(x.mute_until);
async function testAlerts() { // Opciones → Avisos y Monitor: el mismo aviso de prueba
  try {
    const r = await api('monitor/test', 'POST'), bad = Object.entries(r).filter(([, err]) => err);
    toast(bad.length ? `Falló: ${bad.map(([ch, err]) => `${ch} (${err})`).join(' · ')}` : `Aviso de prueba enviado por ${Object.keys(r).join(', ')}`, bad.length ? 'bad' : undefined);
  } catch {}
}
async function muteDialog(title) {
  const f = await dialog(`<h3>${title}</h3><p>Mientras dure no sonará ni llegarán avisos. Si al acabar sigue fallando, avisa en ese momento.</p>
    <div class="fields"><div class="field"><label for="m-t">Durante</label><select id="m-t" name="m">${[[30, '30 minutos'], [60, '1 hora'], [120, '2 horas'], [240, '4 horas'], [480, '8 horas'], [1440, '24 horas'], [10080, '7 días']]
      .map(([v, t]) => `<option value="${v}" ${v === 60 ? 'selected' : ''}>${t}</option>`).join('')}</select></div></div>`, {ok: 'Silenciar'});
  return f && +f.get('m');
}
const mute = async (res, x, name) => { // x silenciado: quita el silencio; si no, pregunta cuánto
  const m = isMuted(x) ? 0 : await muteDialog(`Silenciar «${esc(name)}»`);
  if (m === null) return;
  await api(`${res}/${x.id}/mute`, 'POST', {minutes: m}); toast(m ? `${name}: avisos silenciados` : `${name}: avisos activados de nuevo`); await pollMonitor();
};
async function pollMonitor() {
  try { const r = await fetch('/api/monitor'); if (!r.ok) return; monData = await r.json(); } catch { return; }
  const md = monData.monitor, dead = md && md.age > 30; // late cada 2 s: medio minuto sin latido es que algo va mal
  let bn = $('#mon-dead');
  if (dead && !bn) { bn = Object.assign(document.createElement('div'), {id: 'mon-dead', className: 'mon-dead', role: 'alert'}); app.before(bn); }
  if (bn) { bn.hidden = !dead; if (dead) bn.innerHTML = `${ui('alert', 16)}El monitor no da señales desde hace ${esc(upTxt(md.age))}: no se está vigilando nada.${md.error ? ` Último error: ${esc(md.error)}` : ''}`; }
  const down = monData.checks.filter(c => c.state === 'down' && !c.dep), b = $('#mon-badge'); // los que caen por otro no suman
  b.hidden = !down.length; b.textContent = down.length;
  if (monPrev) for (const c of monData.checks) {
    if (isMuted(c) || c.dep) continue; // en mantenimiento, o cae porque cae otro: ni sonido ni aviso
    if (c.state === 'down' && monPrev[c.id] !== 'down') { toast(`${monName(c)}: ${c.detail || 'no responde'}`, 'bad'); if (S.soundOn && c.sound !== 'none') playSound(c.sound || S.sound); } // el suyo, o el general
    if (c.state === 'up' && monPrev[c.id] === 'down') toast(`${monName(c)} vuelve a funcionar`);
  }
  monPrev = Object.fromEntries(monData.checks.map(c => [c.id, c.state]));
  // Salud: avisos por temperatura, disco, RAID… con el mismo sonido
  const srcs = monData.sources || [], sick = srcs.filter(x => x.state === 'warn' || x.state === 'error'), hb = $('#hl-badge');
  hb.hidden = !sick.length; hb.textContent = sick.length;
  if (srcPrev) for (const x of srcs) {
    if (isMuted(x)) continue;
    if ((x.state === 'warn' || x.state === 'error') && srcPrev[x.id] !== x.state) { toast(`${x.name}: ${x.problems[0] || x.error}`, 'bad'); if (S.soundOn) playSound(); }
    if (x.state === 'ok' && (srcPrev[x.id] === 'warn' || srcPrev[x.id] === 'error')) toast(`${x.name} vuelve a estar bien`);
  }
  srcPrev = Object.fromEntries(srcs.map(x => [x.id, x.state]));
  fetch('/api/incidents').then(r => r.ok ? r.json() : []).then(all => {
    const n = all.filter(x => incOpen(x) && incMine(x)).length, ib = $('#inc-badge'); ib.hidden = !n; ib.textContent = n;
  }).catch(() => {});
  monPaint?.();
}

