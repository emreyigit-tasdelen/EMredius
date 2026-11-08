// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Emre Yiğit Taşdelen
// Giriş sonrası destek penceresini kapatır (Kapat, Esc veya arka plana tıklama).
(function () {
  var box = document.getElementById('supportPopup');
  if (!box) return;
  function close() { box.classList.remove('show'); }
  document.getElementById('supportPopupClose').addEventListener('click', close);
  box.addEventListener('click', function (e) { if (e.target === box) close(); });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') close(); });
})();
