const $ = s => document.querySelector(s), app = $('#app');
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

// ── Ajustes (por navegador) ─────────────────────────────
const ACCENTS = [['Mandarina', '#e8772e'], ['Cobalto', '#4f6ef7'], ['Jade', '#1f9d6a'], ['Lavanda', '#8b6cf0'], ['Coral', '#e5566b'], ['Grafito', '#7d828c']];
const DEF = {theme: 'auto', accent: '#e8772e', density: 'comfy', motion: 'auto', rail: false, dock: true, fold: {}, sound: 'bell', soundOn: true, vol: .7};
let S = {...DEF};
try { S = {...DEF, ...JSON.parse(localStorage.getItem('catlan') || '{}')}; } catch {}
function applySettings() {
  const h = document.documentElement;
  Object.assign(h.dataset, {theme: S.theme, density: S.density, motion: S.motion});
  h.toggleAttribute('data-rail', !!S.rail);
  h.style.setProperty('--acc', S.accent);
  try { localStorage.setItem('catlan', JSON.stringify(S)); } catch {}
  document.querySelectorAll('#settings [data-k]').forEach(g => {
    const k = g.dataset.k;
    if (g.classList.contains('switch')) g.setAttribute('aria-checked', !!S[k]);
    else g.querySelectorAll('[data-v]').forEach(b => { b.classList.toggle('on', b.dataset.v === S[k]); b.setAttribute('aria-pressed', b.dataset.v === S[k]); });
    if (g.classList.contains('seg')) seg(g);
  });
  requestAnimationFrame(moveInd);
}
const motionOn = () => S.motion === 'on' || (S.motion === 'auto' && !matchMedia('(prefers-reduced-motion: reduce)').matches);
const anim = (el, kf, o) => motionOn() && el.animate ? el.animate(kf, o) : null;
const pop = (el, i = 0) => anim(el, [{opacity: 0, transform: 'scale(.82)'}, {opacity: 1, transform: 'none'}], {duration: 520, delay: i * 32, easing: 'cubic-bezier(.34,1.45,.64,1)', fill: 'backwards'});
const shake = el => anim(el, [{}, {transform: 'translateX(-5px)'}, {transform: 'translateX(4px)'}, {transform: 'translateX(-2px)'}, {}], {duration: 360});
function vanish(el) {
  el.dataset.gone = 1; el.style.pointerEvents = 'none';
  // en SVG el transform es la posición: ahí solo se desvanece
  const a = anim(el, [{opacity: 1}, {opacity: 0, ...(el instanceof SVGElement ? {} : {transform: 'scale(.92)'})}], {duration: 200, easing: 'ease-in', fill: 'forwards'});
  a ? a.finished.then(() => el.remove()) : el.remove();
}

