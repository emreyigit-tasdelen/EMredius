// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: AGPL-3.0-only
// Voucher print page: renders one Wi-Fi QR code per card (qrcodejs, global QRCode).
(function() {
  var el = document.getElementById('voucherQrItems');
  var items = [];
  try { items = JSON.parse((el && el.textContent) || '[]'); } catch (e) { items = []; }
  if (typeof QRCode === 'undefined') return;
  for (var i = 0; i < items.length; i++) {
    var box = document.getElementById(items[i].id);
    if (!box) continue;
    try {
      new QRCode(box, { text: items[i].payload, width: 85, height: 85, correctLevel: QRCode.CorrectLevel.M });
    } catch (e) {
      box.textContent = 'QR üretilemedi';
    }
  }
})();
