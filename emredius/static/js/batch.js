// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: AGPL-3.0-only
// Batch / guest accounts page: source filter + search.
(function() {
  // openModal / closeModal / togglePw come from BASE_LAYOUT.
  var currentSource = 'all';
  var searchEl = document.getElementById('batchSearch');

  function applyBatchFilters() {
    var q = String((searchEl && searchEl.value) || '').toLowerCase().trim();
    var rows = document.querySelectorAll('.batch-row');
    for (var i = 0; i < rows.length; i++) {
      var r = rows[i];
      var okSource = (currentSource === 'all' || r.getAttribute('data-source') === currentSource);
      var okText = (!q || (r.textContent || '').toLowerCase().indexOf(q) !== -1);
      r.style.display = (okSource && okText) ? '' : 'none';
    }
  }

  document.querySelectorAll('.btn-filter').forEach(function(btn) {
    btn.addEventListener('click', function() {
      document.querySelectorAll('.btn-filter').forEach(function(b) {
        b.classList.remove('btn-primary');
        b.classList.add('btn-secondary');
      });
      btn.classList.remove('btn-secondary');
      btn.classList.add('btn-primary');
      currentSource = btn.getAttribute('data-source') || 'all';
      applyBatchFilters();
    });
  });
  if (searchEl) searchEl.addEventListener('input', applyBatchFilters);
})();
