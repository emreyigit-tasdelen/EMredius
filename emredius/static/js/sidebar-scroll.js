// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: AGPL-3.0-only
  (function restoreSidebarScrollEarly() {
    try {
      var nav = document.getElementById('sidebarNav');
      if (!nav) return;
      var saved = sessionStorage.getItem('sidebar_scroll_top');
      if (saved !== null) {
        nav.scrollTop = parseInt(saved, 10);
      } else {
        var active = nav.querySelector('.nav-item.active');
        if (active) {
          active.scrollIntoView({ block: 'nearest', behavior: 'instant' });
        }
      }
    } catch(e) {}
  })();
  
