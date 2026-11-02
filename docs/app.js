// SBOM vyhledávač – čistý JavaScript, bez závislostí a bez externích CDN.
(() => {
  'use strict';
  const $ = (s) => document.querySelector(s);
  const el = { q: $('#q'), format: $('#format'), sbom: $('#sbom'), eco: $('#eco'), group: $('#group'),
    csv: $('#csv'), reset: $('#reset'), tbody: $('#tbl tbody'), ths: document.querySelectorAll('th[data-key]'),
    stats: $('#stats'), count: $('#count'), msg: $('#msg'), list: $('#sbomlist'), foot: $('#foot') };

  const MAX_ROWS = 2000;
  let data = { sboms: [], components: [] };
  let sbomById = new Map();
  let sort = { key: 'name', dir: 1 };
  let current = [];

  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const terms = () => el.q.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
  function hl(text, ts) {
    let s = esc(text);
    if (!ts.length || !text) return s;
    const re = new RegExp('(' + ts.map((t) => esc(t).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|') + ')', 'gi');
    return s.replace(re, '<mark>$1</mark>');
  }
  const fmtDate = (d) => { const t = Date.parse(d); return isNaN(t) ? '' : new Date(t).toLocaleString('cs-CZ'); };

  // ---- URL stav ----
  function readUrl() {
    const p = new URLSearchParams(location.search);
    el.q.value = p.get('q') || '';
    el.format.value = p.get('format') || '';
    el.sbom.value = p.get('sbom') || '';
    el.eco.value = p.get('eco') || '';
    el.group.checked = p.get('group') !== '0';
    const s = p.get('sort');
    if (s) { const [k, d] = s.split(':'); sort = { key: k, dir: d === 'desc' ? -1 : 1 }; }
  }
  function writeUrl() {
    const p = new URLSearchParams();
    if (el.q.value.trim()) p.set('q', el.q.value.trim());
    if (el.format.value) p.set('format', el.format.value);
    if (el.sbom.value) p.set('sbom', el.sbom.value);
    if (el.eco.value) p.set('eco', el.eco.value);
    if (!el.group.checked) p.set('group', '0');
    if (sort.key !== 'name' || sort.dir !== 1) p.set('sort', sort.key + ':' + (sort.dir < 0 ? 'desc' : 'asc'));
    const qs = p.toString();
    history.replaceState(null, '', location.pathname + (qs ? '?' + qs : '') + location.hash);
  }

  // ---- filtrování / seskupení ----
  function compute() {
    const ts = terms();
    const f = el.format.value, sb = el.sbom.value, eco = el.eco.value;
    const filtered = data.components.filter((c) => {
      const s = sbomById.get(c.sbom);
      if (f && (!s || s.format !== f)) return false;
      if (sb && c.sbom !== sb) return false;
      if (eco && (c.ecosystem || '') !== eco) return false;
      if (ts.length) {
        const hay = c._hay || (c._hay = [c.name, c.version, c.purl, c.ecosystem, (c.licenses || []).join(' ')].join(' ').toLowerCase());
        return ts.every((t) => hay.includes(t));
      }
      return true;
    });
    let rows;
    if (el.group.checked) {
      const m = new Map();
      for (const c of filtered) {
        const key = [(c.ecosystem || '').toLowerCase(), c.name.toLowerCase(), c.version].join('|');
        let r = m.get(key);
        if (!r) { r = { name: c.name, version: c.version, ecosystem: c.ecosystem || '', licenses: new Set(), purls: new Set(), sbomIds: new Set() }; m.set(key, r); }
        (c.licenses || []).forEach((l) => r.licenses.add(l));
        if (c.purl) r.purls.add(c.purl);
        r.sbomIds.add(c.sbom);
      }
      rows = [...m.values()];
    } else {
      rows = filtered.map((c) => ({ name: c.name, version: c.version, ecosystem: c.ecosystem || '', licenses: new Set(c.licenses || []), purls: new Set(c.purl ? [c.purl] : []), sbomIds: new Set([c.sbom]) }));
    }
    for (const r of rows) {
      r.license = [...r.licenses].join(', ');
      r.purl = [...r.purls].join(' ');
      r.srcs = [...r.sbomIds].map((id) => sbomById.get(id)).filter(Boolean);
      r.sources = r.srcs.map((s) => s.name).join(', ');
      r.count = r.sbomIds.size;
    }
    const k = sort.key, d = sort.dir;
    const coll = new Intl.Collator('cs', { numeric: true, sensitivity: 'base' });
    rows.sort((a, b) => (k === 'count' ? (a.count - b.count) * d : coll.compare(String(a[k] ?? ''), String(b[k] ?? '')) * d)
      || coll.compare(a.name, b.name) || coll.compare(a.version, b.version));
    return { rows, ts, filteredCount: filtered.length };
  }

  function render() {
    const { rows, ts, filteredCount } = compute();
    current = rows;
    el.ths.forEach((th) => { th.classList.remove('asc', 'desc'); if (th.dataset.key === sort.key) th.classList.add(sort.dir > 0 ? 'asc' : 'desc'); });
    const shown = rows.slice(0, MAX_ROWS);
    el.tbody.innerHTML = shown.map((r) => `<tr>
      <td class="name">${hl(r.name, ts)}</td>
      <td>${hl(r.version, ts) || '<span class="muted">–</span>'}</td>
      <td>${hl(r.ecosystem, ts) || '<span class="muted">–</span>'}</td>
      <td>${hl(r.license, ts) || '<span class="muted">neuvedeno</span>'}</td>
      <td class="purl">${[...r.purls].map((p) => hl(p, ts)).join('<br>') || '<span class="muted">–</span>'}</td>
      <td>${r.srcs.map((s) => `<span class="src"><span class="badge ${esc(s.format)}">${esc(s.format)}</span><span title="${esc(s.file)}">${esc(s.name)}</span></span>`).join('')}</td>
      <td class="num">${r.count}</td></tr>`).join('') ||
      `<tr><td colspan="7" class="muted">Nic nenalezeno.</td></tr>`;
    el.count.textContent = `${rows.length} ${el.group.checked ? 'unikátních knihoven' : 'záznamů'} (${filteredCount} výskytů)` +
      (rows.length > MAX_ROWS ? ` – zobrazeno prvních ${MAX_ROWS}, upřesněte hledání nebo použijte Export CSV` : '');
    writeUrl();
  }

  // ---- CSV ----
  function exportCsv() {
    const q = (v) => '"' + String(v ?? '').replace(/"/g, '""') + '"';
    const head = ['library', 'version', 'ecosystem', 'license', 'purl', 'sbom_count', 'sboms', 'sbom_files'];
    const lines = [head.join(',')].concat(current.map((r) => [r.name, r.version, r.ecosystem, r.license, r.purl, r.count,
      r.srcs.map((s) => s.name).join('; '), r.srcs.map((s) => s.file).join('; ')].map(q).join(',')));
    const blob = new Blob(['\ufeff' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `sbom-knihovny-${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  // ---- init ----
  function fillSelects() {
    for (const s of [...data.sboms].sort((a, b) => a.name.localeCompare(b.name))) {
      const o = document.createElement('option'); o.value = s.id; o.textContent = `${s.name} (${s.format})`; el.sbom.appendChild(o);
    }
    const ecos = [...new Set(data.components.map((c) => c.ecosystem).filter(Boolean))].sort();
    for (const e of ecos) { const o = document.createElement('option'); o.value = e; o.textContent = e; el.eco.appendChild(o); }
  }
  function stats() {
    const uniq = new Set(data.components.map((c) => (c.ecosystem || '') + '|' + c.name.toLowerCase()));
    const uniqV = new Set(data.components.map((c) => (c.ecosystem || '') + '|' + c.name.toLowerCase() + '|' + c.version));
    const spdx = data.sboms.filter((s) => s.format === 'SPDX').length;
    const box = (n, t) => `<div class="stat"><b>${n}</b><span>${t}</span></div>`;
    el.stats.innerHTML = box(data.sboms.length, `SBOMů (SPDX ${spdx} / CDX ${data.sboms.length - spdx})`) +
      box(uniq.size, 'unikátních knihoven') + box(uniqV.size, 'knihoven vč. verzí') + box(data.components.length, 'výskytů celkem');
    el.list.innerHTML = data.sboms.map((s) => `<li><span class="badge ${esc(s.format)}">${esc(s.format)}</span>${esc(s.name)} – <code>${esc(s.file)}</code>, ${s.componentCount} komponent${s.created ? ', vytvořeno ' + esc(fmtDate(s.created)) : ''}</li>`).join('');
    el.foot.textContent = data.generatedAt ? `Index vygenerován: ${fmtDate(data.generatedAt)}` : '';
  }

  let timer;
  el.q.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(render, 120); });
  [el.format, el.sbom, el.eco, el.group].forEach((x) => x.addEventListener('change', render));
  el.ths.forEach((th) => th.addEventListener('click', () => {
    const k = th.dataset.key;
    sort = sort.key === k ? { key: k, dir: -sort.dir } : { key: k, dir: k === 'count' ? -1 : 1 };
    render();
  }));
  el.csv.addEventListener('click', exportCsv);
  el.reset.addEventListener('click', () => { el.q.value = ''; el.format.value = ''; el.sbom.value = ''; el.eco.value = ''; el.group.checked = true; sort = { key: 'name', dir: 1 }; render(); el.q.focus(); });

  fetch('index.json', { cache: 'no-cache' })
    .then((r) => { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
    .then((j) => {
      data = { generatedAt: j.generatedAt, sboms: Array.isArray(j.sboms) ? j.sboms : [], components: Array.isArray(j.components) ? j.components : [] };
      data.components.forEach((c) => { c.name = String(c.name ?? ''); c.version = String(c.version ?? ''); });
      sbomById = new Map(data.sboms.map((s) => [s.id, s]));
      fillSelects(); readUrl(); stats(); render();
      if (!data.sboms.length) { el.msg.hidden = false; el.msg.textContent = 'Index neobsahuje žádné SBOMy. Nahrajte JSON soubory do docs/SBOM-spdx-reports/ nebo docs/SBOM-cyclonedx-reports/.'; }
    })
    .catch((e) => {
      el.msg.hidden = false;
      el.msg.textContent = `Nepodařilo se načíst index.json (${e.message}). Spusťte "node scripts/build-index.mjs" a stránku otevřete přes HTTP server, ne jako soubor (file://).`;
    });
})();
