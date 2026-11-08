// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: Apache-2.0
// /security page: password-reset modal (user data comes from data-* attributes, never from inline JS)
function openResetPasswordModal(username, authType) {
  document.getElementById('lblResetUsername').innerText = username;
  document.getElementById('inpResetUsername').value = username;
  document.getElementById('formResetPassword').action = '/api/security/password/reset/' + encodeURIComponent(username);
  var isSys = (authType === 'system');
  document.getElementById('sysUserNotice').style.display = isSys ? 'block' : 'none';
  document.getElementById('webUserPwGroup').style.display = isSys ? 'none' : 'block';
  document.getElementById('btnSubmitResetPw').style.display = isSys ? 'none' : 'inline-block';
  if (isSys) document.getElementById('sysUsernameSpan').innerText = username;
  else document.getElementById('inpNewPassword').value = '';
  openModal('modalResetPassword');
}
document.addEventListener('click', function(ev) {
  var b = ev.target.closest ? ev.target.closest('[data-reset-pw]') : null;
  if (b) openResetPasswordModal(b.getAttribute('data-reset-pw'), b.getAttribute('data-auth-type'));
});
