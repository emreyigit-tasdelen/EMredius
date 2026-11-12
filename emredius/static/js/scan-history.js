// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: AGPL-3.0-only
// IP / port scan pages: "Son Taramalar" list. View opens the saved result in a popup and delete removes the
// row via fetch, neither reloads the page.
(function () {
  const modal = document.getElementById('shModal');
  const body = document.getElementById('shBody');
  if (!modal || !body) return;
  const kind = modal.getAttribute('data-kind');
  const rows = document.getElementById('shRows');
  const summary = document.getElementById('shSummary');
  const empty = document.getElementById('shEmpty');
  const STATUS = { running: 'Taranıyor', done: 'Tamamlandı', cancelled: 'Durduruldu', error: 'Hata' };
  const csrf = (document.querySelector('input[name="_csrf_token"]') || {}).value;

  function cells(tr, values) {
    values.forEach(function (v) { const td = document.createElement('td'); td.textContent = v; tr.appendChild(td); });
    rows.appendChild(tr);
  }

  const search = document.getElementById('shSearch');
  function filterRows() {
    const q = (search ? search.value : '').toLowerCase();
    Array.prototype.forEach.call(rows.children, function (tr) { tr.style.display = tr.textContent.toLowerCase().indexOf(q) < 0 ? 'none' : ''; });
  }
  if (search) search.addEventListener('input', filterRows);

  function show(job) {
    rows.textContent = '';
    if (search) search.value = '';
    if (kind === 'ip') {
      job.alive.forEach(function (h) {
        cells(document.createElement('tr'),
          [h.ip, h.rtt_ms === null ? 'ARP' : h.rtt_ms + ' ms', h.mac || '-', h.vendor || '-', h.hostname || '-']);
      });
      summary.textContent = job.network + ' · ' + STATUS[job.status] + ' · ' + job.alive_count + ' aktif host · ' +
        job.done.toLocaleString('tr-TR') + ' / ' + job.total.toLocaleString('tr-TR') + ' adres · ' + job.elapsed + ' sn' +
        (job.truncated ? ' · kayıtlı listede en fazla 5000 host saklanır' : '');
      empty.style.display = job.alive.length ? 'none' : 'block';
    } else {
      job.open.forEach(function (p) { cells(document.createElement('tr'), [p.port + '/tcp', 'açık', p.service || '-']); });
      summary.textContent = job.label + ' (' + job.target + ') · port ' + job.range + ' · ' + STATUS[job.status] +
        ' · ' + job.done + '/' + job.total + ' · ' + job.elapsed + ' sn · açık: ' + job.open.length +
        ' · kapalı: ' + job.closed + ' · filtreli/yanıtsız: ' + job.filtered;
      empty.style.display = job.open.length ? 'none' : 'block';
    }
    modal.classList.add('show');
  }

  function close() { modal.classList.remove('show'); }
  document.getElementById('shClose').addEventListener('click', close);
  modal.addEventListener('click', function (e) { if (e.target === modal) close(); });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') close(); });

  function post(url) {
    return fetch(url, { method: 'POST', headers: { 'Accept': 'application/json', 'X-CSRF-Token': csrf || '' } })
      .then(function (r) { return r.json(); });
  }

  body.addEventListener('click', function (e) {
    const view = e.target.closest('.sh-view');
    const del = e.target.closest('.sh-del');
    if (view) {
      fetch(view.getAttribute('data-url'), { headers: { 'Accept': 'application/json' } })
        .then(function (r) { return r.json(); })
        .then(function (d) { if (d.success) show(d.job); else alert(d.error || 'Tarama bulunamadı.'); })
        .catch(function () { alert('Tarama yüklenemedi.'); });
    } else if (del) {
      if (!confirm('Bu tarama kaydı silinsin mi?')) return;
      del.disabled = true;
      post(del.getAttribute('data-url')).then(function (d) {
        if (!d.success) { del.disabled = false; alert(d.error || 'Silinemedi.'); return; }
        del.closest('tr').remove();
        if (!body.children.length) {
          const t = document.getElementById('shTable'), n = document.getElementById('shNone'), nt = document.getElementById('shNote');
          if (t) t.style.display = 'none';
          if (nt) nt.style.display = 'none';
          if (n) n.style.display = 'block';
        }
      }).catch(function () { del.disabled = false; alert('Silinemedi.'); });
    }
  });

  document.querySelectorAll('.is-ts').forEach(function (td) {
    td.textContent = new Date(parseInt(td.getAttribute('data-ts'), 10) * 1000).toLocaleString('tr-TR');
  });
})();
