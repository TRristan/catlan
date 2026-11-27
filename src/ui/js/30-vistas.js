// ── Vistas ──────────────────────────────────────────────
const findPage = (pages, t) => pages.find(p => esc(p.title).toLowerCase() === t.toLowerCase()); // [[título]] llega escapado
let logFilter = 'all', saludTab = 'all';
// Rebote de gelatina al soltar algo en su sitio (Dashboard y tableros)
const squish = (el, origin = '50% 50%', k = 1) => { el.style.transformOrigin = origin; anim(el, [{transform: 'none'},
  {transform: `scale(${1 + .045 * k},${1 - .04 * k})`}, {transform: `scale(${1 - .03 * k},${1 + .03 * k})`}, {transform: `scale(${1 + .012 * k},${1 - .01 * k})`}, {transform: 'none'}],
  {duration: 680, easing: 'cubic-bezier(.3,.7,.4,1)'}); };
// Control remoto: desde Salud (Kitty) y desde la ficha del equipo, el mismo camino
async function remoteStart(agent) {
  try { location.hash = '#/remoto/' + (await api('remote', 'POST', {agent})).id; } catch {} // el porqué (Kitty cerrado, ya hay otra…) ya sale en un aviso
}
const TASK_COLS = {notas: 'Notas', pendiente: 'Por hacer', hoy: 'Hoy', hecho: 'Hecho'};
let kbLand = null; // {board, id, from: rect antes de moverla | null = nueva}: se anima al volver a pintar el tablero
const kbMark = (board, id, card) => { kbLand = {board, id: String(id), from: card?.getBoundingClientRect() || null}; };
function kbLanded() {
  const l = kbLand; kbLand = null;
  const c = l && document.querySelector(`#kb-${l.board} .kc[data-id="${l.id}"]`); if (!c) return;
  const acc = getComputedStyle(c).getPropertyValue('--acc').trim(), r = c.getBoundingClientRect(), dx = l.from ? l.from.left - r.left : 0, dy = l.from ? l.from.top - r.top : -8;
  if (l.from && Math.abs(dx) < 4 && Math.abs(dy) < 4) squish(c); else anim(c, [{transform: `translate(${dx}px,${dy}px) scale(${l.from ? 1.04 : .94})`, opacity: l.from ? 1 : 0}, {transform: 'none', opacity: 1}], {duration: 450, easing: 'cubic-bezier(.34,1.3,.64,1)'});
  anim(c, [{boxShadow: `0 0 0 2px ${acc}`}, {boxShadow: '0 0 0 2px transparent'}], {duration: 1100, delay: 250, easing: 'ease-out'});
  const n = c.closest('.kb-col').querySelector('header .count'); anim(n, [{transform: 'scale(1.5)', color: acc}, {transform: 'none'}], {duration: 450, easing: 'cubic-bezier(.34,1.45,.64,1)'});
}
const kbGone = async card => { await anim(card, [{opacity: 1}, {opacity: 0, transform: 'scale(.92)'}], {duration: 170, easing: 'ease-in', fill: 'forwards'})?.finished; };
// Arrastrar tarjetas .kc[data-drag] entre las .kb-list de un tablero, como en el Dashboard: la tarjeta flota bajo el ratón y se inclina
// según la velocidad; en su sitio queda el hueco y las demás se apartan. Al soltarla en otro sitio, commit(tarjeta, lista).
function kanban(root, commit) {
  root.addEventListener('pointerdown', e => {
    const card = e.target.closest('.kc[data-drag]');
    // shortcut: con el dedo no se arrastra (taparía el desplazamiento de la página); en el móvil se mueve con el menú ⋯
    if (!card || e.button || e.pointerType === 'touch' || e.target.closest('button,input')) return;
    e.preventDefault(); // sin seleccionar texto ni arrastrar el enlace
    const sx = e.clientX, sy = e.clientY, from = [card.parentNode, card.nextSibling];
    let fly = null, ox = 0, oy = 0, x = sx, y = sy, vx = 0, lx = sx, live = true;
    const start = () => {
      const rc = card.getBoundingClientRect(); ox = sx - rc.left; oy = sy - rc.top;
      fly = card.cloneNode(true); fly.classList.add('kc-fly'); fly.removeAttribute('data-drag'); fly.style.width = rc.width + 'px';
      document.body.append(fly); card.classList.add('drag'); document.body.classList.add('kb-dragging');
      const tilt = () => { if (!live) return; vx *= .86; fly.style.transform = `translate(${x - ox}px,${y - oy}px) rotate(${Math.max(-8, Math.min(8, vx * .7))}deg) scale(1.04)`; requestAnimationFrame(tilt); };
      tilt();
    };
    const move = ev => {
      x = ev.clientX; y = ev.clientY;
      if (!fly) { if (Math.hypot(x - sx, y - sy) < 5) return; start(); } // un clic no es arrastrar
      vx += x - lx; lx = x;
      const col = document.elementFromPoint(x, y)?.closest('.kb-col'), list = col && root.contains(col) ? col.querySelector('.kb-list') : null;
      root.querySelectorAll('.kb-col.over').forEach(c => c !== col && c.classList.remove('over'));
      if (!list) return;
      col.classList.add('over');
      const before = [...list.querySelectorAll('.kc:not(.drag)')].find(c => { const rc = c.getBoundingClientRect(); return y < rc.top + rc.height / 2; });
      if (before ? card.nextSibling === before : list.lastElementChild === card) return;
      const near = [...new Set([list, card.parentNode])].flatMap(l => [...l.querySelectorAll('.kc:not(.drag)')]), was = new Map(near.map(c => [c, c.getBoundingClientRect().top]));
      list.insertBefore(card, before || null);
      near.forEach(c => { const d = was.get(c) - c.getBoundingClientRect().top; if (d) anim(c, [{transform: `translateY(${d}px)`}, {transform: 'none'}], {duration: 220, easing: 'cubic-bezier(.2,.8,.2,1)'}); });
    };
    const up = ev => {
      removeEventListener('pointermove', move); removeEventListener('pointerup', up); removeEventListener('pointercancel', up);
      live = false;
      if (!fly) return; // fue un clic
      addEventListener('click', stop, true); setTimeout(() => removeEventListener('click', stop, true)); // el clic de soltar no abre el enlace
      if (ev.type === 'pointercancel') from[0].insertBefore(card, from[1]);
      const rc = card.getBoundingClientRect(), moved = card.parentNode !== from[0] || card.nextSibling !== from[1];
      const done = () => {
        fly.remove(); card.classList.remove('drag'); document.body.classList.remove('kb-dragging');
        root.querySelectorAll('.kb-col.over').forEach(c => c.classList.remove('over'));
        if (moved && ev.type !== 'pointercancel') commit(card, card.parentNode); else squish(card);
      };
      const a = anim(fly, [{transform: fly.style.transform}, {transform: `translate(${rc.left}px,${rc.top}px)`}], {duration: 240, easing: 'cubic-bezier(.2,.8,.2,1)', fill: 'forwards'});
      a ? a.finished.then(done) : done();
    };
    const stop = ev => { ev.preventDefault(); ev.stopPropagation(); };
    addEventListener('pointermove', move); addEventListener('pointerup', up); addEventListener('pointercancel', up);
  });
}
// Cada vista es un método de views; los archivos 3x-v-*.js las van añadiendo
const views = {};
