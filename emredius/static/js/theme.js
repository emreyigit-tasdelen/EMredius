// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: AGPL-3.0-only
(function() {
  try {
    var savedTheme = localStorage.getItem('app_theme') || 'light';
    document.documentElement.setAttribute('data-theme', savedTheme);
    if (localStorage.getItem('sidebar_collapsed') === 'true' && window.innerWidth > 1024) {
      document.documentElement.classList.add('sidebar-collapsed');
    }
  } catch(e) {}
})();
