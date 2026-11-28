Object.assign(views, {
  async wiki(id) {
    if (!id) {
      const pages = (await api('pages')).sort((a, b) => (b.updated || '').localeCompare(a.updated || '')), q = qv();
      const hits = pages.filter(p => (p.title + ' ' + p.body).toLowerCase().includes(q));
      crumbs([['Wiki']]);
      app.innerHTML = head('Wiki', pages.length ? `${pages.length} ${pages.length === 1 ? 'página' : 'páginas'} · las más recientes primero` : 'El conocimiento de tu equipo, en un sitio',
        pages.length ? `<button class="btn" id="add">${ui('plus', 16)}Nueva página</button>` : '')
        + (hits.length ? `<div class="rows stagger">${hits.map((p, i) => `<a class="rowlink" style="--i:${Math.min(i, 14)}" href="#/wiki/${p.id}">
            <span class="badge-ic">${ui('book', 18)}</span><span class="grow"><b>${esc(p.title) || 'Sin título'}</b><span class="ex">${esc(excerpt(p.body)) || '<span class="dim">Vacía</span>'}</span></span>
            <time datetime="${esc(p.updated)}" title="${esc(when(p.updated))}">${esc(ago(p.updated))}</time></a>`).join('')}</div>`
        : pages.length ? empty('search', 'Sin resultados', `Nada coincide con «${esc(q)}».`)
        : empty('book', 'Tu wiki está vacía', 'Documenta redes, procedimientos y contraseñas de la impresora (bueno, eso no). Enlaza equipos con [[#id]].', `<button class="btn pri" id="add">${ui('plus', 16)}Crear la primera página</button>`));
      $('#add') && ($('#add').onclick = create.page);
      return;
    }
    const [pid, mode] = id.split('/'), p = await api('pages/' + pid);
    if (mode !== 'edit') {
      const [n, log] = await Promise.all([names(), api(`log?kind=page&ref=${p.id}`)]);
      crumbs([['Wiki', '#/wiki'], [p.title || 'Sin título']]);
      app.innerHTML = `<div class="read">${head(esc(p.title) || 'Sin título', `<span title="${esc(when(p.updated))}">Actualizada ${esc(ago(p.updated))}</span>${p.kitty ? ' · <span class="pill ok" title="Kitty la sugiere a los usuarios de los PCs"><i></i>autoayuda en Kitty</span>' : ''}`,
          `<a class="btn" href="#/wiki/${p.id}/edit">${ui('edit', 16)}Editar</a>${moreBtn}`)}
        <article class="prose">${md(p.body, n) || `<p class="muted">Página vacía. <a href="#/wiki/${p.id}/edit">Empieza a escribir</a>.</p>`}</article>
        <div class="read-foot">${collapsible(`${ui('clock', 16)}Historial <span class="count">${log.length}</span>`, timeline(log))}</div></div>`;
      $('#more').onclick = e => menu(e.currentTarget, [
        ['Copiar enlace', () => copy(`[[${p.title}]]`), {icon: 'link'}], '-',
        ['Borrar página', async () => { if (await delUndo([['page', 'pages/' + p.id]], 'Página borrada')) location.hash = '#/wiki'; }, {icon: 'trash', danger: true}]]);
      return;
    }
    crumbs([['Wiki', '#/wiki'], [p.title || 'Sin título', '#/wiki/' + p.id], ['Editar']]);
    app.innerHTML = `<div class="read"><input id="t" class="title-in big" value="${esc(p.title)}" placeholder="Título" aria-label="Título">
      <div class="ed-bar"><span class="dim small">Escribe como en un procesador de textos · <kbd>Ctrl</kbd> <kbd>S</kbd> guarda</span></div>
      <textarea id="b" class="mdin" aria-label="Contenido" placeholder="Escribe aquí…">${esc(p.body)}</textarea>
      <div class="actionbar"><label class="small" style="display:flex;gap:8px;align-items:center;margin-right:auto" title="Kitty la sugiere al usuario del PC antes de abrir un aviso, si encaja con lo que escribe. Mejor sin datos internos: la verá cualquiera."><input type="checkbox" id="kt"${p.kitty ? ' checked' : ''}> Sugerir en Kitty como autoayuda</label><a class="btn ghost" href="#/wiki/${p.id}">Cancelar</a><button class="btn pri" id="save">${ui('check', 16)}Guardar</button></div></div>`;
    const b = $('#b');
    richEditor(b, await names()).focus();
    onSave = async () => { try { await putFresh('pages/' + p.id, {title: $('#t').value, body: b.value, kitty: $('#kt').checked}, p.updated); } catch { return; } toast('Página guardada'); location.hash = '#/wiki/' + p.id; };
    $('#save').onclick = onSave;
  },
  async p(t) { // abrir o crear página por título
    t = decodeURIComponent(t);
    const p = findPage(await api('pages'), t);
    const title = new DOMParser().parseFromString(t, 'text/html').body.textContent; // des-escapar sin ejecutar nada
    location.replace('#/wiki/' + (p ? p.id : (await api('pages', 'POST', {title})).id + '/edit'));
  },
});
