// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: Apache-2.0
function togglePw(id) {
  var raw = document.getElementById('raw-' + id);
  var mask = document.getElementById('mask-' + id);
  if (raw.style.display === 'none') {
    raw.style.display = 'inline';
    mask.style.display = 'none';
  } else {
    raw.style.display = 'none';
    mask.style.display = 'inline';
  }
}
