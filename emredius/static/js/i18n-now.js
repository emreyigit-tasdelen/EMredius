// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: AGPL-3.0-only
// O ana kadar ayrıştırılan sayfayı ilk boyamadan önce seçili dile çevirir (app.js head'de yüklü).
try {
  var _l = window.CURRENT_APP_LANG;
  if (_l && _l !== 'tr' && window.translateDOMTree && document.body) {
    translateDOMTree(document.body, _l);
    var _m = (typeof LANG_META !== 'undefined') && LANG_META[_l];
    var _f = document.getElementById('currentLangFlag'), _n = document.getElementById('currentLangName');
    if (_m && _f) _f.textContent = _m.flag;
    if (_m && _n) _n.textContent = _m.name;
  }
} catch (e) {}
