// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: AGPL-3.0-only
document.addEventListener('submit', function (e) {
  if (e.target.classList.contains('t-del') && !window.confirm('Kiracı silinsin mi? (Verisi olan kiracı silinmez)')) e.preventDefault();
});
