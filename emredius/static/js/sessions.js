// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: Apache-2.0
// Sessions page: optional 10 s auto refresh (state kept in localStorage).
(function() {
  var KEY = 'emredius_sessions_autorefresh';
  var timer = null;
  function saveState(on) { try { window.localStorage.setItem(KEY, on ? '1' : '0'); } catch (e) {} }
  function loadState() { try { return window.localStorage.getItem(KEY) === '1'; } catch (e) { return false; } }
  window.toggleAutoRefresh = function(on) {
    if (timer) { clearInterval(timer); timer = null; }
    saveState(on);
    if (on) {
      timer = setInterval(function() {
        // do not reload a hidden tab or while a dialog is open
        if (document.hidden) return;
        if (document.querySelector('.modal-backdrop.show')) return;
        (window.EM ? window.EM.refresh() : location.reload());
      }, 10000);
    }
  };
  // the checkbox state survives the reload, so auto refresh keeps running until it is switched off
  var cb = document.getElementById('autoRefreshCheck');
  if (cb && loadState()) {
    cb.checked = true;
    window.toggleAutoRefresh(true);
  }
})();
