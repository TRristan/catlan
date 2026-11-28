Object.assign(views, {
  async tablero() {
    crumbs([['Mis tareas']]);
    const [all, tasks, n] = await Promise.all([api('incidents'), api('tasks'), names()]);
    const week = Date.now() - 7 * 864e5, ro = ME.readonly;
    const incs = all.filter(x => incMine(x) && (incOpen(x) || date(x.updated) > week)); // lo resuelto o cerrado, solo la última semana
    const col = (k, title, cards, extra = '') => `<section class="kb-col" data-col="${k}"><header>${title} <span class="count">${cards.length}</span>${extra}</header>
      <div class="kb-list" role="list">${cards.join('')}</div>${k in TASK_COLS ? `<form class="kb-add" data-col="${k}"><input name="t" maxlength="2000" placeholder="+ Añadir ${k === 'notas' ? 'nota' : 'tarea'}" aria-label="Añadir en ${TASK_COLS[k]}"></form>` : ''}</section>`;
    const more = t => `<button class="btn icon ghost sm kc-more" aria-label="Opciones de ${esc(t)}" aria-haspopup="menu">${ui('more', 15)}</button>`;
    const incCard = (x, i) => `<div class="kc" role="listitem"${ro ? '' : ' data-drag'} data-id="${x.id}" data-col="${esc(x.status)}" style="--i:${Math.min(i, 12)}">
        <a class="kc-t" href="#/inc/${x.id}" draggable="false"><span class="dim mono">${incId(x.id)}</span> ${esc(x.title)}</a>
        <div class="kc-m">${prioPill(x.priority)}${x.item_name ? `<span class="dim small">${esc(x.item_name)}</span>` : ''}${x.assignee !== ME.id && x.grp_name ? `<span class="dim small">${ui('users', 13)} ${esc(x.grp_name)}</span>` : ''}</div>${ro ? '' : more(incId(x.id))}</div>`;
    const taskCard = (t, i) => `<div class="kc" role="listitem" data-drag data-id="${t.id}" data-col="${t.col}" data-pos="${t.pos}" title="Doble clic para editar" style="--i:${Math.min(i, 12)}"><div class="prose">${md(t.text, n)}</div>${more(t.text.slice(0, 40))}</div>`;
    const byCol = k => tasks.filter(t => t.col === k).map(taskCard);
    app.innerHTML = head('Mis tareas', `${incs.filter(incOpen).length} incidencias abiertas para ti o tus grupos · ${tasks.filter(t => t.col === 'pendiente' || t.col === 'hoy').length} tareas pendientes`,
        `<button class="btn pri" id="add">${ui('plus', 16)}Nueva incidencia</button>`)
      + `<h2 class="kb-h">${ui('ticket', 17)}Mis incidencias</h2>
        <div class="kb" id="kb-inc">${INC_STATUS.map(st => col(st, statusPill(st), incs.filter(x => x.status === st).map(incCard))).join('')}</div>
        <p class="dim small" style="margin:8px 0 0">Asignadas a ti o a tus grupos. Arrastra una tarjeta para cambiar su estado: queda en el historial de la incidencia. Las resueltas y cerradas salen una semana.</p>
        <h2 class="kb-h">${ui('check', 17)}Mis tareas y notas <span class="dim small" style="font-weight:400">· solo las ves tú</span></h2>
        <div class="kb" id="kb-task">${Object.entries(TASK_COLS).map(([k, t]) => col(k, esc(t), byCol(k), k === 'hecho' && byCol(k).length ? '<button class="btn ghost sm" id="kb-clear">Vaciar</button>' : '')).join('')}</div>`;
    const setStatus = async (id, st, card) => {
      kbMark('inc', id, card);
      try { const r = await api('incidents/' + id, 'PUT', {status: st}); toast(`${incId(id)} pasa a «${st}»` + (r.closed_children ? ` con ${r.closed_children} ${r.closed_children === 1 ? 'hija' : 'hijas'}` : '')); } catch {}
      await route(false); kbLanded(); pollMonitor(); // también el contador de Incidencias del menú
    };
    const endPos = k => Math.max(-1, ...tasks.filter(t => t.col === k).map(t => t.pos)) + 1;
    const moveTask = async (id, k, pos, card) => { kbMark('task', id, card); try { await api('tasks/' + id, 'PUT', {col: k, pos}); } catch {} await route(false); kbLanded(); };
    const editTask = async t => {
      const f = await dialog(`<h3>Editar</h3><div class="field"><label for="tk-t">Texto <span class="dim">· Markdown; enlaza equipos con [[#id]]</span></label><textarea id="tk-t" name="t" rows="6" maxlength="2000" required>${esc(t.text)}</textarea></div>`, {ok: 'Guardar'});
      if (f) { try { await api('tasks/' + t.id, 'PUT', {text: f.get('t')}); } catch {} route(false); }
    };
    $('#add').onclick = () => incidentDialog();
    kanban($('#kb-inc'), (c, list) => c.dataset.col !== list.parentNode.dataset.col ? setStatus(c.dataset.id, list.parentNode.dataset.col, c) : route(false)); // dentro de la columna manda la prioridad
    kanban($('#kb-task'), (c, list) => { // la posición queda entre sus vecinas
      const p = c.previousElementSibling?.dataset.pos, q = c.nextElementSibling?.dataset.pos;
      moveTask(c.dataset.id, list.parentNode.dataset.col, p != null && q != null ? (+p + +q) / 2 : p != null ? +p + 1 : q != null ? +q - 1 : 0, c); // shortcut: tras ~50 cambios en el mismo hueco se acaban los decimales; renumerar si pasa
    });
    app.querySelectorAll('.kc-more').forEach(b => b.onclick = () => {
      const c = b.closest('.kc'), id = +c.dataset.id, k = c.dataset.col;
      if (c.closest('#kb-inc')) return menu(b, [['Abrir', () => { location.hash = '#/inc/' + id; }, {icon: 'ticket'}], '-',
        ...INC_STATUS.filter(st => st !== k).map(st => [`Pasar a «${st}»`, () => setStatus(id, st, c), {icon: 'chev'}])]);
      const t = tasks.find(x => x.id === id);
      menu(b, [['Editar', () => editTask(t), {icon: 'edit'}], ['Crear incidencia con esto', () => incidentDialog({title: t.text.split('\n')[0].slice(0, 200)}), {icon: 'ticket'}], '-',
        ...Object.entries(TASK_COLS).filter(([to]) => to !== k).map(([to, name]) => [`Mover a «${name}»`, () => moveTask(id, to, endPos(to), c), {icon: 'chev'}]), '-',
        ['Borrar', async () => { await kbGone(c); await api('tasks/' + id, 'DELETE').catch(() => {}); route(false); }, {icon: 'trash', danger: true}]]);
    });
    $('#kb-task').ondblclick = e => { const c = e.target.closest('.kc'); if (c && !e.target.closest('a,button')) editTask(tasks.find(x => x.id === +c.dataset.id)); };
    app.querySelectorAll('.kb-add').forEach(f => f.onsubmit = async e => {
      e.preventDefault(); const k = f.dataset.col, text = f.t.value.trim(); if (!text) return;
      try { kbMark('task', (await api('tasks', 'POST', {text, col: k})).id); } catch { return; }
      await route(false); kbLanded(); app.querySelector(`.kb-add[data-col="${k}"] input`)?.focus(); // seguir añadiendo en la misma columna
    });
    $('#kb-clear') && ($('#kb-clear').onclick = async () => {
      const hechas = tasks.filter(t => t.col === 'hecho');
      if (!await ask('¿Vaciar «Hecho»?', `Se borrarán ${hechas.length} ${hechas.length === 1 ? 'tarea hecha' : 'tareas hechas'}. No se puede deshacer.`, 'Vaciar')) return;
      const cards = [...app.querySelectorAll('#kb-task [data-col="hecho"] .kc')];
      await Promise.all(cards.map((c, i) => new Promise(ok => setTimeout(ok, i * 50)).then(() => kbGone(c))));
      await Promise.all(hechas.map(t => api('tasks/' + t.id, 'DELETE').catch(() => {}))); route(false);
    });
  },
  async inc(id) {
    if (!id) {
      const all = await api('incidents'), q = qv(), sets = {open: all.filter(incOpen), mine: all.filter(n => incOpen(n) && incMine(n)), all, closed: all.filter(n => !incOpen(n))};
      const shown = sets[incFilter].filter(n => [n.title, n.assignee_name, n.grp_name, n.item_name, incId(n.id)].join(' ').toLowerCase().includes(q));
      const ids = new Set(shown.map(n => n.id)), kidsOf = {};
      shown.forEach(n => n.parent && ids.has(n.parent) && (kidsOf[n.parent] ||= []).push(n));
      const roots = shown.filter(n => !(n.parent && ids.has(n.parent)));
      const node = (n, i = 0) => {
        const ks = kidsOf[n.id] || [], open = incOpenTree.has(n.id);
        return `<div class="inc-node" style="--i:${Math.min(i, 14)}"><div class="inc-row">
            ${ks.length ? `<button class="inc-tg" data-tg="${n.id}" aria-expanded="${open}" aria-label="${open ? 'Ocultar' : 'Ver'} sus ${ks.length} incidencias hijas">${ui('chev', 15)}</button>` : '<span class="inc-tg"></span>'}
            <a class="rowlink" href="#/inc/${n.id}"><span class="badge-ic">${ui('ticket', 18)}</span>
            <div class="grow"><b><span class="dim mono">${incId(n.id)}</span> ${esc(n.title)}</b><span class="ex">${n.assignee_name ? esc(n.assignee_name) : 'Sin asignar'}${n.grp_name ? ' · ' + esc(n.grp_name) : ''}${n.item_name ? ' · ' + esc(n.item_name) : ''} · ${n.notes} ${n.notes === 1 ? 'nota' : 'notas'} · ${esc(ago(n.updated))}${n.parent && !ids.has(n.parent) ? ` · cuelga de #${n.parent}` : ''}</span></div>
            ${ks.length ? `<span class="inc-n" title="Incidencias hijas">${ui('ticket', 13)}${ks.length}</span>` : ''}${prioPill(n.priority)}${statusPill(n.status)}</a></div>
          ${ks.length ? `<div class="inc-kids${open ? ' open' : ''}"><div>${ks.map(k => node(k)).join('')}</div></div>` : ''}</div>`;
      };
      crumbs([['Incidencias']]);
      app.innerHTML = head('Incidencias', `${sets.open.length} abiertas · ${sets.mine.length} para ti o tus grupos`, `<button class="btn pri" id="add">${ui('plus', 16)}Nueva incidencia</button>`)
        + `<div class="seg" id="if" style="margin-bottom:16px">${[['open', 'Abiertas'], ['mine', 'Mías'], ['all', 'Todas'], ['closed', 'Cerradas']].map(([k, t]) => `<button data-v="${k}" class="${k === incFilter ? 'on' : ''}">${t} <span class="dim">${sets[k].length}</span></button>`).join('')}</div>`
        + (shown.length ? `<div class="rows stagger inc-tree" id="itree">${roots.map((n, i) => node(n, i)).join('')}</div>`
          : empty('ticket', incFilter === 'mine' ? 'Nada pendiente para ti' : incFilter === 'closed' ? 'Aún no hay ninguna cerrada' : 'Sin incidencias', all.length ? 'Nada coincide con este filtro.' : 'Abre una cuando algo falle y asígnala a una persona o a un grupo; cada cambio y cada nota quedan en su historial.'));
      seg($('#if'));
      $('#if').onclick = e => { const b = e.target.closest('[data-v]'); if (b) { incFilter = b.dataset.v; route(false); } };
      $('#add').onclick = () => incidentDialog();
      $('#itree')?.addEventListener('click', e => { // desplegar / plegar las hijas sin recargar la lista
        const t = e.target.closest('[data-tg]'); if (!t) return;
        const id = +t.dataset.tg, open = !incOpenTree.has(id);
        open ? incOpenTree.add(id) : incOpenTree.delete(id);
        t.setAttribute('aria-expanded', open); t.setAttribute('aria-label', `${open ? 'Ocultar' : 'Ver'} sus incidencias hijas`);
        t.closest('.inc-node').querySelector(':scope > .inc-kids').classList.toggle('open', open);
      });
      return;
    }
    const [n, users, groups, items, incs] = await Promise.all([api('incidents/' + id), api('users'), api('groups'), api('items'), api('incidents')]);
    const names = Object.fromEntries(items.map(i => [i.id, i.name]));
    const mention = [...n.mentions.pages.map(p => ['book', `#/wiki/${p.id}`, p.title || 'Sin título', 'Página de la wiki']), ...n.mentions.items.map(i => ['box', `#/inv/${i.id}`, i.name, 'Notas del equipo']),
      ...n.mentions.incidents.map(x => ['ticket', `#/inc/${x.id}`, `${incId(x.id)} ${x.title}`, 'Incidencia · ' + x.status])];
    crumbs([['Incidencias', '#/inc'], [incId(n.id)]]);
    // abierta desde Kitty: se puede contestar al usuario del PC (lo ve en «Mis avisos»)
    const fromKitty = n.history.find(h => h.change && h.text === 'abrió la incidencia' && (h.who || '').startsWith('Kitty · '))?.who.slice(8) || '';
    app.innerHTML = head(`<span class="dim">${incId(n.id)}</span> ${esc(n.title)}`, `Abierta por ${esc(n.author_name || '—')} ${esc(ago(n.created))} · ${statusPill(n.status)} ${prioPill(n.priority)}${n.parent ? ` · cuelga de <a href="#/inc/${+n.parent}">${incId(+n.parent)} ${esc(n.parent_title)}</a>` : ''}`,
      `<button class="chip" id="iref" title="Copiar la referencia para enlazarla desde la wiki">${ui('link', 14)}<span class="mono">[[${incId(n.id)}]]</span></button>${moreBtn}`)
      + `<div class="split stagger"><section class="card pad" style="--i:0">
          <article class="prose">${md(n.body, names) || '<p class="muted">Sin descripción.</p>'}</article>
          <h3 class="card-t mt">Incidencias hijas</h3>${n.kids.length ? '<p class="small muted" style="margin:-4px 0 6px">Al resolver o cerrar esta, se resuelven también las abiertas.</p>' : ''}
          ${n.kids.length ? `<div class="rows">${n.kids.map(k => `<a class="rowlink" href="#/inc/${k.id}"><div class="grow"><b><span class="dim mono">${incId(k.id)}</span> ${esc(k.title)}</b><span class="ex">${k.assignee_name ? esc(k.assignee_name) : 'Sin asignar'}${k.children ? ` · ${k.children} ${k.children === 1 ? 'hija' : 'hijas'}` : ''}</span></div>${statusPill(k.status)}</a>`).join('')}</div>` : ''}
          <button class="btn ghost sm" id="kid" type="button">${ui('plus', 15)}Crear incidencia hija</button>
          <h3 class="card-t mt">Seguimiento</h3>
          <form id="nf"><div class="field"><label for="nt">Actualización</label><textarea id="nt" rows="3" required maxlength="5000" placeholder="Qué se ha hecho, qué falta…"></textarea></div>
            <div style="display:flex;justify-content:flex-end;align-items:center;gap:12px;margin-top:8px">${fromKitty ? `<label class="small" style="display:flex;gap:6px;align-items:center;margin-right:auto"><input type="checkbox" id="npub" checked> Que la vea ${esc(fromKitty)} en Kitty</label>` : ''}<button class="btn pri">${ui('check', 16)}Añadir al seguimiento</button></div></form>
          <ol class="itl">${[...n.history].reverse().map(h => `<li class="${h.change ? 'ch' : 'nt'}"><span><b>${esc(h.who || '—')}</b> ${h.change ? esc(h.text) : 'escribió'} <time class="dim">${esc(ago(h.ts))}</time>${fromKitty && !h.change && h.public && !(h.who || '').startsWith('Kitty · ') ? ' <span class="pill" title="La ve el usuario en Kitty"><i></i>en Kitty</span>' : ''}</span>
            ${h.change ? '' : `<div class="prose tl-note">${md(h.text, names)}</div>`}</li>`).join('')}</ol>
</section>
        <aside class="side-col"><section class="card pad" style="--i:1"><div class="fields" id="inc-f">
          <div class="field"><label for="f-st">Estado</label><select id="f-st" data-k="status">${optList(INC_STATUS, n.status)}</select></div>
          <div class="field"><label for="f-pr">Prioridad</label><select id="f-pr" data-k="priority">${optList(INC_PRIO, n.priority)}</select></div>
          <div class="field"><label for="f-as">Asignada a</label><select id="f-as" data-k="assignee">${optList(users, n.assignee, 'Nadie')}</select></div>
          <div class="field"><label for="f-gr">Grupo</label><select id="f-gr" data-k="grp">${optList(groups, n.grp, 'Ninguno')}</select></div>
          <div class="field"><label for="f-it">Equipo</label><select id="f-it" data-k="item">${optList(items, n.item, 'Ninguno')}</select></div>
          <div class="field"><label for="f-pa">Cuelga de</label><select id="f-pa" data-k="parent">${optList(incs.filter(x => x.id !== n.id).map(x => ({id: x.id, name: `${incId(x.id)} ${x.title}`})), n.parent, 'Ninguna (es principal)')}</select></div>
          ${n.item ? `<a class="linkrow" href="#/inv/${+n.item}">${ui('box', 16)}Abrir ficha del equipo</a>` : ''}</div></section>
        <section class="card pad" style="--i:2"><h3 class="card-t">${ui('link', 15)}Enlazada desde <span class="count">${mention.length}</span></h3>
          ${mention.length ? `<ul class="rel">${mention.map(([ic, h, t, s]) => `<li><a href="${h}"><span class="badge-ic">${ui(ic, 16)}</span><span><b>${esc(t)}</b><small>${s}</small></span></a></li>`).join('')}</ul>`
            : `<p class="muted small" style="margin:0">Pega <code class="mono">[[${incId(n.id)}]]</code> en una página de la wiki, en las notas de un equipo o en otra incidencia y saldrá aquí.</p>`}</section></aside></div>`;
    $('#iref').onclick = () => copy(`[[${incId(n.id)}]]`);
    if (ME.readonly) app.querySelectorAll('#inc-f select').forEach(x => x.disabled = true);
    $('#inc-f').onchange = async e => { // cada cambio queda en el seguimiento
      const k = e.target.dataset.k, v = e.target.value;
      const r = await api('incidents/' + n.id, 'PUT', {[k]: ['assignee', 'grp', 'item', 'parent'].includes(k) ? (v ? +v : null) : v}).catch(() => null);
      if (r?.closed_children) toast(`También ${r.closed_children === 1 ? 'ha pasado 1 incidencia hija' : `han pasado ${r.closed_children} incidencias hijas`} a «${r.status}»`);
      route(false);
    };
    if (!ME.readonly) richEditor($('#nt'), names);
    $('#kid').onclick = () => incidentDialog({parent: n.id, item: n.item, grp: n.grp, priority: n.priority});
    $('#nf').onsubmit = async e => { e.preventDefault(); if (!$('#nt').value.trim()) return toast('Escribe algo antes de añadirlo', 'bad'); await api(`incidents/${n.id}/notes`, 'POST', {text: $('#nt').value, public: !!$('#npub')?.checked}); route(false); };
    $('#more').onclick = e => menu(e.currentTarget, [
      ['Editar título y descripción', async () => {
        const p = dialog(`<h3>Editar incidencia</h3><div class="fields"><div class="field"><label for="e-t">Título</label><input id="e-t" name="title" required maxlength="200" value="${esc(n.title)}"></div>
          <div class="field"><label for="e-b">Descripción</label><textarea id="e-b" name="body" rows="6">${esc(n.body)}</textarea></div></div>`, {ok: 'Guardar'});
        richEditor(document.querySelector('dialog[open] #e-b'), names);
        const f = await p;
        if (f) { try { await putFresh('incidents/' + n.id, {title: f.get('title').trim(), body: f.get('body')}, n.version); } catch { return; } route(false); }
      }, {icon: 'edit'}],
      ...(ME.admin ? ['-', ['Borrar incidencia', async () => { if (await ask('¿Borrar esta incidencia?', `«${esc(n.title)}» y su seguimiento se borrarán. Quedará una copia en Actividad.`)) { await api('incidents/' + n.id, 'DELETE'); toast('Incidencia borrada'); location.hash = '#/inc'; } }, {icon: 'trash', danger: true}]] : [])]);
  },
});
