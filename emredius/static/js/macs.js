// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: Apache-2.0
// MAC whitelist page: vendor (OUI) hint and quick approve of rejected devices.
function quickApproveMac(mac) {
  document.getElementById('inputMacField').value = mac;
  detectVendor(mac);
  openModal('addMacModal');
}
function detectVendor(mac) {
  var vText = document.getElementById('detectedVendorText');
  var clean = mac.replace(/[^a-fA-F0-9]/g, '').toUpperCase();
  if (clean.length >= 6) {
    var prefix = clean.substring(0, 2) + ':' + clean.substring(2, 4) + ':' + clean.substring(4, 6);
    var map = {"00:1A:2B":"Apple","00:0C:29":"VMware","B8:27:EB":"Raspberry Pi","AC:67:B2":"HP / Aruba","00:1E:13":"Cisco","00:0E:8E":"Mikrotik","F0:9F:C2":"Ubiquiti UniFi","A4:14:37":"Hikvision Kamera","E0:50:8B":"Dahua Kamera","00:1A:11":"Dell","00:1B:21":"Intel","EC:08:6B":"TP-Link","00:23:D7":"Samsung"};
    vText.textContent = 'Üretici Tespiti: ' + (map[prefix] || 'Ağ Donanımı');
  } else {
    vText.textContent = '';
  }
}
