// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: AGPL-3.0-only
/* Dar ekranda tabloları kartlara çevirmek için td'lere başlık etiketi ekler (stil: ui-system.css, table.rt). */
(function () {
  'use strict';
  function prep(root) {
    (root || document).querySelectorAll('.content-body table, .modal-card table').forEach(function (t) {
      if (t.classList.contains('no-stack') || t.classList.contains('rt')) return;
      var head = t.tHead;
      if (!head || head.rows.length !== 1) return;
      var ths = head.rows[0].cells, labels = [];
      for (var i = 0; i < ths.length; i++) {
        if (ths[i].colSpan > 1) return;
        labels.push(ths[i].textContent.trim());
      }
      t.classList.add('rt');
      var apply = function () {
        Array.prototype.forEach.call(t.tBodies, function (b) {
          Array.prototype.forEach.call(b.rows, function (r) {
            if (r.cells.length !== labels.length) return;
            Array.prototype.forEach.call(r.cells, function (c, i) { if (c.getAttribute('data-label') == null) c.setAttribute('data-label', labels[i]); });
          });
        });
      };
      apply();
      if (!t._rtObs) { t._rtObs = new MutationObserver(apply); Array.prototype.forEach.call(t.tBodies, function (b) { t._rtObs.observe(b, { childList: true }); }); }
    });
  }
  var pend = false;
  function schedule() { if (pend) return; pend = true; requestAnimationFrame(function () { pend = false; prep(); }); }
  document.addEventListener('DOMContentLoaded', function () {
    prep();
    new MutationObserver(schedule).observe(document.querySelector('.content-body') || document.body, { childList: true, subtree: true });
  });
})();
