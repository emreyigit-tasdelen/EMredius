// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: AGPL-3.0-only
// 2FA setup: QR code rendered locally (the secret never leaves the browser), copy button
(function() {
  var box = document.getElementById('totpQr');
  if (box && window.QRCode) {
    new QRCode(box, { text: box.getAttribute('data-uri'), width: 188, height: 188, correctLevel: QRCode.CorrectLevel.M });
  }
  document.querySelectorAll('[data-copy]').forEach(function(btn) {
    btn.addEventListener('click', function() {
      window.copyWithFeedback(btn.getAttribute('data-copy'), btn, 'Kopyalama başarılı');
    });
  });
})();
