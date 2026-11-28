// ── Dashboard: rejilla bento de 12 columnas que se puede montar a mano ──
// --jelly: muelle amortiguado (rebasa ~25 % y vuelve), así encajar o agrandar una tarjeta tiene rebote
(() => {
  const k = Array.from({length: 61}, (_, i) => i === 60 ? 1 : +(1 - Math.exp(-5.2 * i / 60) * Math.cos(13 * i / 60)).toFixed(3));
  document.documentElement.style.setProperty('--jelly', CSS.supports('transition-timing-function', 'linear(0, 1)') ? `linear(${k.join(',')})` : 'cubic-bezier(.34,1.56,.64,1)');
})();
const DW = {
  stat: {name: 'Cifra destacada', icon: 'pulse', size: [3, 2]},
  mon: {name: 'Disponibilidad', icon: 'signal', size: [4, 4], view: 'pie'},
  inv: {name: 'Inventario', icon: 'box', size: [4, 4], view: 'bar'},
  lat: {name: 'Latencia del monitor', icon: 'signal', size: [8, 4], view: 'line'},
  health: {name: 'Salud de un equipo', icon: 'thermo', size: [6, 4], view: 'line'},
  log: {name: 'Actividad', icon: 'pulse', size: [4, 4], view: 'line'},
  map: {name: 'Acceso a un esquema', icon: 'nodes', size: [4, 4]},
};
const DVIEWS = {line: ['Líneas', 'line'], bar: ['Barras', 'bars'], pie: ['Tarta', 'pie']};
const DSTATS = {items: ['Equipos', '#/inv'], pages: ['Páginas de wiki', '#/wiki'], maps: ['Esquemas', '#/maps'], racks: ['Racks', '#/racks'],
  down: ['Dispositivos caídos', '#/monitor'], warn: ['Equipos con avisos', '#/salud']};
const DBY = {kind: 'tipo', status: 'estado', location: 'ubicación'};
const DGROUPS = {temp: 'Temperatura', disk: 'Discos', load: 'CPU y memoria', fan: 'Ventiladores', net: 'Tráfico (los 8 puertos con más)'};
const DRANGE = {6: 'últimas 6 h', 24: 'últimas 24 h', 168: 'últimos 7 días', 720: 'últimos 30 días', 2160: 'últimos 90 días'};
const DASH_DEF = () => ({widgets: [
  {id: 'd1', kind: 'stat', stat: 'items', x: 0, y: 0, w: 3, h: 2}, {id: 'd2', kind: 'stat', stat: 'down', x: 3, y: 0, w: 3, h: 2},
  {id: 'd3', kind: 'stat', stat: 'warn', x: 6, y: 0, w: 3, h: 2}, {id: 'd4', kind: 'stat', stat: 'pages', x: 9, y: 0, w: 3, h: 2},
  {id: 'd5', kind: 'mon', view: 'pie', x: 0, y: 2, w: 4, h: 4}, {id: 'd6', kind: 'inv', by: 'kind', view: 'bar', x: 4, y: 2, w: 4, h: 4},
  {id: 'd7', kind: 'log', view: 'line', x: 8, y: 2, w: 4, h: 4}, {id: 'd8', kind: 'lat', view: 'line', hours: 24, x: 0, y: 6, w: 12, h: 4}]});
const fmtN = (v, u) => u ? fmtV(v, u) : (+(+v).toFixed(1)).toLocaleString('es');
// Más de 8 categorías se agrupan en «Otros»: nunca se inventa un noveno color
const topCats = cats => { cats.sort((a, b) => b.value - a.value); return cats.length > 8 ? [...cats.slice(0, 7), {label: 'Otros', value: cats.slice(7).reduce((t, c) => t + c.value, 0)}] : cats; };
// El color sigue a la categoría (orden alfabético), no a su posición en el ranking
const catColor = cats => { const ord = cats.map(c => c.label).sort((a, b) => a.localeCompare(b)); return c => c.c || `var(--k${ord.indexOf(c.label) % 8 + 1})`; };

// Qué dibuja cada tarjeta: título, enlace y los datos como series (tiempo) y/o categorías
async function dwData(w, get) {
  if (w.kind === 'stat') {
    const k = w.stat || 'items', maps = () => get('maps'), n = await {
      items: async () => (await get('items')).length, pages: async () => (await get('pages')).length,
      maps: async () => (await maps()).filter(m => m.type !== 'rack').length, racks: async () => (await maps()).filter(m => m.type === 'rack').length,
      down: async () => (await get('monitor')).checks.filter(c => c.state === 'down').length,
      warn: async () => (await get('health')).filter(h => h.state === 'warn' || h.state === 'error').length}[k]();
    return {title: DSTATS[k][0], href: DSTATS[k][1], stat: n, crit: (k === 'down' || k === 'warn') && n > 0};
  }
  if (w.kind === 'inv') {
    const by = w.by || 'kind', cnt = {};
    for (const i of await get('items')) { const k = String(i[by] || '').trim() || 'Sin ' + DBY[by]; cnt[k] = (cnt[k] || 0) + 1; }
    return {title: 'Inventario por ' + DBY[by], href: '#/inv', cats: topCats(Object.entries(cnt).map(([label, value]) => ({label, value}))), empty: !Object.keys(cnt).length && 'El inventario está vacío.'};
  }
  if (w.kind === 'mon') {
    const cs = (await get('monitor')).checks, n = st => cs.filter(c => c.state === st).length;
    return {title: 'Disponibilidad', sub: `${cs.length} ${cs.length === 1 ? 'dispositivo' : 'dispositivos'}`, href: '#/monitor', empty: !cs.length && 'Aún no vigilas ningún dispositivo.',
      cats: [{label: 'Responden', value: n('up'), c: 'var(--ok)'}, {label: 'Caídos', value: n('down'), c: 'var(--st-crit)'},
        {label: 'Sin datos', value: cs.length - n('up') - n('down'), c: 'var(--tx3)'}].filter(c => c.value)};
  }
  if (w.kind === 'lat') {
    const hours = w.hours || 24, [mon, lat] = await Promise.all([get('monitor'), get('latency?hours=' + hours)]);
    const series = mon.checks.filter(c => lat[c.id]).slice(0, 8).map(c => ({label: monName(c), points: lat[c.id]}));
    return {title: 'Latencia', sub: DRANGE[hours], href: '#/monitor', unit: 'ms', series, empty: !series.length && 'Sin pings en este rango.'};
  }
  if (w.kind === 'health') {
    const h = (await get('health')).find(x => x.id === w.source);
    if (!h) return {title: DW.health.name, empty: 'Este equipo ya no está en Hardware ni en PCs.'};
    const g = w.group || 'temp', hours = w.hours || 24, m = await get(`metrics?source=${h.id}&hours=${hours}`);
    const keep = k => g === 'load' ? k === 'cpu' || k === 'mem' : g === 'net' ? /^(rx|tx):/.test(k) : k.startsWith(g + ':');
    const last = x => x.points.at(-1)?.[1] ?? 0;
    const series = Object.entries(m).filter(([k]) => keep(k)).map(([, x]) => x).sort((a, b) => g === 'net' ? last(b) - last(a) : 0).slice(0, 8);
    return {title: `${h.label || h.item_name || h.host} · ${DGROUPS[g]}`, sub: DRANGE[hours], href: '#/salud/' + h.id, unit: series[0]?.unit || '', series,
      limit: g === 'temp' ? h.temp_max : g === 'disk' ? h.disk_max : null, empty: !series.length && 'Este equipo no informa de esto.'};
  }
  if (w.kind === 'log') {
    const day = 864e5, t0 = new Date().setHours(0, 0, 0, 0) - 13 * day, per = Array(14).fill(0), kinds = {};
    for (const x of await get('log')) {
      const t = date(x.ts).getTime(); if (t < t0) continue;
      per[Math.min(13, Math.floor((t - t0) / day))]++; const k = KINDS[x.kind]?.[0] || x.kind; kinds[k] = (kinds[k] || 0) + 1;
    }
    return {title: 'Actividad', sub: 'últimos 14 días', href: '#/log', unit: '',
      series: [{label: 'Cambios', points: per.map((v, i) => [new Date(t0 + i * day).toISOString().slice(0, 19).replace('T', ' '), v])}],
      cats: topCats(Object.entries(kinds).map(([label, value]) => ({label, value}))), empty: !per.some(Boolean) && 'Sin cambios en 14 días.'};
  }
  const m = await get('maps/' + w.map).catch(() => null); // esquema
  if (!m) return {title: DW.map.name, empty: 'Este esquema ya no existe.'};
  const n = (m.data.nodes || []).length;
  return {title: m.name, sub: `Esquema · ${n} ${n === 1 ? 'icono' : 'iconos'}`, href: '#/maps/' + m.id, map: m};
}
function barChart(box, cats, unit, W, H, title) {
  const max = Math.max(...cats.map(c => c.value), 1), list = cats.slice(0, Math.max(1, Math.floor((H + 10) / 30))), col = catColor(cats);
  box.innerHTML = `<div class="hbars" role="list" aria-label="${esc(title)}">${list.map((c, i) => `<div class="hb" role="listitem" style="--c:${col(c)};--i:${i}">
    <span class="hb-l" title="${esc(c.label)}">${esc(c.label)}</span><span class="hb-t"><i style="width:${c.value / max * 100}%"></i></span><b>${esc(fmtN(c.value, unit))}</b></div>`).join('')}</div>`;
}
function pieChart(box, cats, unit, W, H, title, total) {
  const sum = cats.reduce((t, c) => t + c.value, 0) || 1, R = Math.max(28, Math.min(H, W * .46) / 2 - 4), r = R * .6, col = catColor(cats);
  const pt = (a, rad) => `${(rad * Math.cos(a)).toFixed(2)} ${(rad * Math.sin(a)).toFixed(2)}`, pct = v => Math.round(v / sum * 100);
  let a = -Math.PI / 2;
  const arcs = cats.map((c, i) => {
    const a0 = a, da = Math.min(c.value / sum * Math.PI * 2, Math.PI * 2 - 1e-4), big = da > Math.PI ? 1 : 0; a += da; // 100 %: casi círculo, si no el arco desaparece
    return `<path style="--c:${col(c)};--i:${i}" d="M${pt(a0, R)}A${R} ${R} 0 ${big} 1 ${pt(a, R)}L${pt(a, r)}A${r} ${r} 0 ${big} 0 ${pt(a0, r)}Z"><title>${esc(c.label)}: ${esc(fmtN(c.value, unit))} (${pct(c.value)} %)</title></path>`;
  }).join('');
  box.innerHTML = `<div class="pie"><svg width="${2 * R}" height="${2 * R}" viewBox="${-R} ${-R} ${2 * R} ${2 * R}" role="img" aria-label="${esc(title)}">${arcs}
    ${total ? `<text class="pie-t" y="4">${esc(fmtN(sum))}</text><text class="pie-s" y="20">total</text>` : ''}</svg>
    <div class="pie-l">${cats.map(c => `<span><i style="--c:${col(c)}"></i><em title="${esc(c.label)}">${esc(c.label)}</em><b>${esc(fmtN(c.value, unit))}</b><small>${pct(c.value)} %</small></span>`).join('')}</div></div>`;
}
function catLine(box, cats, unit, W, H, title) { // categorías unidas por una línea, para quien la prefiera
  const L = 36, R = 12, T = 12, B = 22, max = Math.max(...cats.map(c => c.value), 1), st = niceStep(max / 3), top = Math.ceil(max / st) * st;
  const X = i => L + (cats.length < 2 ? (W - L - R) / 2 : i * (W - L - R) / (cats.length - 1)), Y = v => T + (1 - v / top) * (H - T - B), col = catColor(cats);
  const yt = []; for (let v = 0; v <= top + st / 1e3; v += st) yt.push(v);
  const every = Math.ceil(cats.length / Math.max(1, Math.floor((W - L) / 70)));
  box.innerHTML = `<div class="chart"><svg width="${W}" height="${H}" role="img" aria-label="${esc(title)}">
    ${yt.map(v => `<line class="grid-l" x1="${L}" x2="${W - R}" y1="${Y(v)}" y2="${Y(v)}"/><text class="tick" x="${L - 8}" y="${Y(v) + 4}" text-anchor="end">${+v.toFixed(1)}</text>`).join('')}
    ${cats.map((c, i) => i % every ? '' : `<text class="tick" x="${X(i)}" y="${H - 6}" text-anchor="middle">${esc(c.label.length > 12 ? c.label.slice(0, 11) + '…' : c.label)}</text>`).join('')}
    <path class="ln" style="--c:var(--k1)" d="${cats.map((c, i) => (i ? 'L' : 'M') + X(i).toFixed(1) + ' ' + Y(c.value).toFixed(1)).join('')}"/>
    ${cats.map((c, i) => `<circle class="cl-pt" style="--c:${col(c)}" cx="${X(i)}" cy="${Y(c.value)}" r="5"><title>${esc(c.label)}: ${esc(fmtN(c.value, unit))}</title></circle>`).join('')}</svg></div>`;
}
function mapPreview(box, m, W, H) {
  const d = {nodes: [], links: [], ...m.data}, node = id => d.nodes.find(n => n.id === id);
  let v = [0, 0, 1200, 800];
  if (!m.has_image && d.nodes.length) { // mismo encuadre que el editor
    const xs = d.nodes.map(n => +n.x), ys = d.nodes.map(n => +n.y), x0 = Math.min(...xs) - 70, x1 = Math.max(...xs) + 70, y0 = Math.min(...ys) - 70, y1 = Math.max(...ys) + 70;
    v = [x0, y0, x1 - x0, y1 - y0];
  }
  box.innerHTML = `<svg class="dmap" width="${W}" height="${H}" viewBox="${v.join(' ')}" preserveAspectRatio="xMidYMid meet" role="img" aria-label="Vista previa de ${esc(m.name)}">
    ${m.has_image ? `<image href="/api/maps/${+m.id}/image" width="1200" height="800"/>` : ''}
    ${d.links.map(([a, b]) => { const A = node(a), B = node(b); return A && B ? `<line x1="${+A.x}" y1="${+A.y}" x2="${+B.x}" y2="${+B.y}"/>` : ''; }).join('')}
    ${d.nodes.map((n, i) => `<g style="--i:${Math.min(i, 30)}" transform="translate(${+n.x} ${+n.y})"><rect x="-30" y="-30" width="60" height="60" rx="14"/><use href="#i-${esc(n.t)}" x="-19" y="-19" width="38" height="38"/></g>`).join('')}
    ${d.nodes.length ? '' : `<text x="600" y="400" text-anchor="middle" class="tick" style="font-size:40px">Esquema vacío</text>`}</svg>`;
}
