// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: Apache-2.0
// Backups page: custom interval box, quick max-count buttons, copy SCP command
(function() {
  var sel = document.getElementById('selBackupInterval');
  var box = document.getElementById('customIntervalBox');
  if (sel && box) {
    sel.addEventListener('change', function() {
      if (sel.value === 'custom') {
        box.style.display = 'block';
        document.getElementById('inpCustomInterval').focus();
      } else {
        box.style.display = 'none';
      }
    });
  }
  document.querySelectorAll('[data-max-count]').forEach(function(btn) {
    btn.addEventListener('click', function() {
      document.getElementById('inpMaxCount').value = btn.getAttribute('data-max-count');
    });
  });
  document.querySelectorAll('[data-copy]').forEach(function(btn) {
    btn.addEventListener('click', function() {
      window.copyWithFeedback(btn.getAttribute('data-copy'), btn, 'Kopyalama başarılı');
    });
  });
})();
