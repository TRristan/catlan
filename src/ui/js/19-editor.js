// ── Editor visual: se escribe como en un procesador de textos y se guarda en Markdown (lo que entiende md()) ──
const BLOCKS = /^(P|DIV|H[1-6]|UL|OL|PRE|BLOCKQUOTE)$/;
function toMd(root) {
  const inl = n => [...n.childNodes].map(c => {
    if (c.nodeType === 3) return c.nodeValue.replace(/[\u00a0]/g, ' ').replace(/\u200b/g, '');
    if (c.nodeType !== 1) return '';
    const t = c.tagName, x = inl(c), href = c.getAttribute('href') || '';
    if (t === 'BR') return '\n';
    if (t === 'CODE') return '`' + c.textContent.replace(/\u200b/g, '') + '`';
    if ((t === 'B' || t === 'STRONG') && x.trim()) return `**${x}**`;
    if ((t === 'I' || t === 'EM') && x.trim()) return `*${x}*`;
    if (t === 'A' && c.classList.contains('ref')) return `[[#${href.split('/').pop()}]]`;
    if (t === 'S' && /^#\d+$/.test(c.textContent)) return `[[${c.textContent}]]`; // equipo borrado: se conserva su id
    if (t === 'A' && c.classList.contains('iref')) return `[[${incId(+href.split('/').pop())}]]`;
    if (t === 'A' && href.startsWith('#/p/')) return `[[${c.textContent}]]`;
    if (t === 'A' && href) return `[${x}](${href})`;
    return x; // span, font, u…: solo su texto
  }).join('');
  const out = [];
  const walk = n => {
    let buf = [];
    const flush = () => { if (buf.length) { const sp = document.createElement('span'); buf.forEach(c => sp.append(c.cloneNode(true))); out.push(...inl(sp).split('\n')); buf = []; } };
    for (const c of n.childNodes) {
      if (c.nodeType !== 1 || !BLOCKS.test(c.tagName)) { buf.push(c); continue; }
      flush();
      const t = c.tagName;
      if (/^H\d$/.test(t)) out.push('#'.repeat(Math.max(1, Math.min(4, +t[1] - 1))) + ' ' + inl(c).replace(/\n/g, ' ').trim());
      else if (t === 'UL' || t === 'OL') { [...c.children].forEach((li, i) => out.push((t === 'OL' ? `${i + 1}. ` : '- ') + inl(li).replace(/\n/g, ' ').trim())); out.push(''); }
      else if (t === 'PRE') out.push('```', c.textContent.replace(/\u200b/g, '').replace(/\n$/, ''), '```');
      else if ([...c.children].some(k => BLOCKS.test(k.tagName))) walk(c);
      else out.push(...inl(c).split('\n'));
    }
    flush();
  };
  walk(root);
  return out.map(l => l.replace(/\s+$/, '')).join('\n').replace(/\n{3,}/g, '\n\n').trim();
}
const RTE = [['bold', 'Negrita (Ctrl+B)', 'B'], ['italic', 'Cursiva (Ctrl+I)', 'I'], '|', ['h2', 'Título', 'H1'], ['h3', 'Subtítulo', 'H2'], '|',
  ['ul', 'Lista', 'ul'], ['ol', 'Lista numerada', 'ol'], ['code', 'Código', 'code'], '|', ['link', 'Enlace (Ctrl+K)', 'link'], ['item', 'Enlazar un equipo', 'box'], ['inc', 'Enlazar una incidencia', 'ticket'], ['page', 'Enlazar una página de la wiki', 'book'], '|',
  ['undo', 'Deshacer (Ctrl+Z)', 'undo'], ['redo', 'Rehacer', 'redo']];
function richEditor(ta, names = {}) {
  const w = document.createElement('div');
  w.className = 'rte' + (ta.classList.contains('mdin') ? ' big' : '');
  w.innerHTML = `<div class="rte-bar" role="toolbar" aria-label="Formato del texto">${RTE.map(b => b === '|' ? '<span class="rte-sep"></span>'
      : `<button type="button" data-c="${b[0]}" title="${b[1]}" aria-label="${b[1]}">${/^[BIH]/.test(b[2]) && b[2].length <= 2 ? `<b class="rte-l${b[2] === 'I' ? ' it' : ''}">${b[2]}</b>` : ui(b[2], 16)}</button>`).join('')}</div>
    <div class="rte-ed prose" contenteditable="true" role="textbox" aria-multiline="true" spellcheck="true" data-ph="${esc((ta.placeholder || 'Escribe…').replace(/ ?\(Markdown[^)]*\)|Markdown[^·]*·?/g, ''))}"></div>`;
  ta.hidden = true; ta.required = false; ta.after(w); // el textarea sigue en el formulario con el Markdown
  const ed = w.lastElementChild, bar = w.firstElementChild;
  const lab = ta.id && document.querySelector(`label[for="${ta.id}"]`);
  if (lab) { lab.id ||= ta.id + '-lab'; ed.setAttribute('aria-labelledby', lab.id); lab.onclick = () => ed.focus(); } else ed.setAttribute('aria-label', ta.getAttribute('aria-label') || 'Texto');
  ed.innerHTML = md(ta.value, names);
  const sync = () => { ta.value = toMd(ed); ed.classList.toggle('empty', !ed.textContent.trim() && !ed.querySelector('li,pre')); ta.dispatchEvent(new Event('input', {bubbles: true})); };
  ed.classList.toggle('empty', !ed.textContent.trim());
  ed.oninput = sync;
  ed.onpaste = e => { e.preventDefault(); document.execCommand('insertText', false, e.clipboardData.getData('text/plain')); }; // texto limpio, sin estilos de otras webs
  let range = null;
  const keep = () => { const sel = getSelection(); if (sel.rangeCount && ed.contains(sel.anchorNode)) range = sel.getRangeAt(0).cloneRange(); };
  const back = () => { ed.focus(); if (range) { const sel = getSelection(); sel.removeAllRanges(); sel.addRange(range); } };
  const html = h => { back(); document.execCommand('insertHTML', false, h); sync(); };
  const block = tag => { const cur = (document.queryCommandValue('formatBlock') || '').toLowerCase(); document.execCommand('formatBlock', false, cur === tag ? 'p' : tag); };
  const pick = async (title, opts) => { // equipo o página: un desplegable con buscador nativo
    keep();
    const f = await dialog(`<h3>${title}</h3><div class="fields"><div class="field"><label for="rp">Elige</label><input id="rp" name="v" list="rp-l" required autocomplete="off" autofocus>
      <datalist id="rp-l">${opts.map(([v, t]) => `<option value="${esc(t)}">`).join('')}</datalist></div></div>`, {ok: 'Insertar'});
    return f && opts.find(([, t]) => t === f.get('v').trim());
  };
  const run = async c => {
    if (c === 'bold' || c === 'italic' || c === 'undo' || c === 'redo') document.execCommand(c);
    else if (c === 'h2' || c === 'h3') block(c);
    else if (c === 'ul') document.execCommand('insertUnorderedList');
    else if (c === 'ol') document.execCommand('insertOrderedList');
    else if (c === 'code') { const t = getSelection().toString(); t.includes('\n') ? block('pre') : html(`<code>${esc(t || 'código')}</code>\u200b`); return; }
    else if (c === 'link') {
      keep(); const sel = getSelection().toString();
      const f = await dialog(`<h3>Enlace</h3><div class="fields"><div class="field"><label for="lk">Dirección</label><input id="lk" name="u" required placeholder="https://…" autofocus></div>
        ${sel ? '' : '<div class="field"><label for="lt">Texto</label><input id="lt" name="t" required></div>'}</div>`, {ok: 'Insertar'});
      if (!f) return back();
      const u = f.get('u').trim(), url = /^(https?:|\/|#)/.test(u) ? u : 'https://' + u;
      return html(`<a href="${esc(url)}">${esc(sel || f.get('t'))}</a>`);
    }
    else if (c === 'item') { const items = await api('items'), r = await pick('Enlazar un equipo', items.map(i => [i.id, `${i.name}${i.ip ? ' · ' + i.ip : ''}`]));
      if (!r) return back(); names[r[0]] = items.find(i => i.id === r[0]).name;
      return html(`<a class="ref" href="#/inv/${r[0]}" contenteditable="false">${esc(names[r[0]])}</a>&nbsp;`); }
    else if (c === 'inc') { const incs = await api('incidents'), r = await pick('Enlazar una incidencia', incs.map(x => [x.id, `${incId(x.id)} ${x.title}`]));
      if (!r) return back(); return html(`<a class="iref" href="#/inc/${r[0]}" contenteditable="false">${incId(r[0])}</a>&nbsp;`); }
    else if (c === 'page') { const ps = await api('pages'), r = await pick('Enlazar una página', ps.map(x => [x.id, x.title || 'Sin título']));
      if (!r) return back(); return html(`<a href="#/p/${encodeURIComponent(r[1])}">${esc(r[1])}</a>&nbsp;`); }
    ed.focus(); sync(); state();
  };
  const state = () => bar.querySelectorAll('[data-c]').forEach(b => {
    const c = b.dataset.c, f = (document.queryCommandValue('formatBlock') || '').toLowerCase();
    const on = c === 'bold' || c === 'italic' ? document.queryCommandState(c) : c === 'ul' ? document.queryCommandState('insertUnorderedList')
      : c === 'ol' ? document.queryCommandState('insertOrderedList') : c === 'h2' || c === 'h3' ? f === c : null;
    if (on !== null) b.setAttribute('aria-pressed', ed.contains(getSelection().anchorNode) && on);
  });
  bar.onmousedown = e => e.preventDefault(); // no perder la selección al pulsar un botón
  bar.onclick = e => { const b = e.target.closest('[data-c]'); if (b) run(b.dataset.c); };
  ed.onkeydown = e => { if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); run('link'); } };
  ed.onkeyup = ed.onmouseup = state;
  return ed;
}
