// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: Apache-2.0
// Admins & roles page: add/edit admin and role modals (data from JSON script tags)
var ALL_ADMINS = JSON.parse(document.getElementById('adminsData').textContent);
    var ALL_ROLES = JSON.parse(document.getElementById('rolesData').textContent);

    function setRoleEmoji(inputId, emoji) {
      var el = document.getElementById(inputId);
      if (el) el.value = emoji;
    }

    function toggleAdminAuthType(t) {
      var isSys = (t === 'system');
      var passGrp = document.getElementById('groupAdminPassword');
      var passInp = document.getElementById('inpAdminPassword');
      if (passGrp) passGrp.style.display = isSys ? 'none' : 'block';
      if (passInp) {
        passInp.required = !isSys;
        passInp.disabled = isSys;
        if (isSys) passInp.value = '';
      }

      var lblU = document.getElementById('lblAdminUsername');
      var inpU = document.getElementById('inpAdminUsername');
      var hintU = document.getElementById('hintAdminUsername');
      var descA = document.getElementById('authTypeDesc');

      if (lblU) lblU.textContent = isSys ? 'AlmaLinux Sistem Kullanıcı Adı' : 'Kullanıcı Adı';
      if (inpU) {
        inpU.placeholder = isSys ? 'Örn: admin veya noc' : 'Örn: ahmet.yilmaz';
        if (isSys) inpU.setAttribute('list', 'linuxUserList'); else inpU.removeAttribute('list');
      }
      if (hintU) hintU.textContent = isSys ? 'AlmaLinux sunucusundaki geçerli bir kullanıcı adını yazınız (PAM ile doğrulanır).' : 'Kullanıcı adı sadece harf, rakam, nokta ve tire içerebilir.';
      if (descA) descA.textContent = isSys ? 'Kullanıcı AlmaLinux sunucusundaki mevcut Linux şifresi ile oturum açar (PAM Hibrit Kimlik Doğrulama).' : 'Bağımsız web hesabı oluşturulur; şifre veritabanında güvenli hash olarak saklanır.';
    }

    function openEditRoleModal(roleKey) {
      if (!Object.prototype.hasOwnProperty.call(ALL_ROLES, roleKey)) return;
      var r = ALL_ROLES[roleKey];
      document.getElementById('inpEditRoleKey').value = r.role_key;
      document.getElementById('lblEditRoleName').textContent = (r.icon || '🛡️') + ' ' + (r.role_name || r.role_key) + ' (' + r.role_key + ')';
      document.getElementById('lblEditRoleDesc').textContent = r.description || '';
      var iconInp = document.getElementById('inpEditRoleIcon');
      if (iconInp) iconInp.value = r.icon || '🛡️';

      var allowedStr = r.allowed_pages || '';
      var allowedList = allowedStr.split(',').map(function(s) { return s.trim(); });
      var isAll = (allowedStr === '*');

      var checkboxes = document.querySelectorAll('#boxEditRolePages input[type="checkbox"]');
      checkboxes.forEach(function(cb) {
        cb.checked = isAll || (allowedList.indexOf(cb.value) !== -1);
      });
      openModal('modalEditRole');
    }

    function openEditAdminModal(uname) {
      if (!Object.prototype.hasOwnProperty.call(ALL_ADMINS, uname)) return;
      var a = ALL_ADMINS[uname];
      document.getElementById('editAdminTitle').textContent = a.username;
      document.getElementById('editAdminUsername').value = a.username;
      document.getElementById('editAdminFullName').value = a.full_name || '';
      document.getElementById('editAdminEmail').value = a.email || '';
      document.getElementById('editAdminRole').value = a.role || 'network_admin';
      document.getElementById('editAdminStatus').value = (a.status === 'disabled') ? 'disabled' : 'active';

      var isSys = (a.auth_type === 'system');
      var passInp = document.getElementById('editAdminNewPassword');
      if (passInp) {
        passInp.value = '';
        passInp.disabled = isSys;
      }
      var passNote = document.getElementById('editAdminPassNote');
      if (passNote) {
        if (isSys) {
          passNote.textContent = 'Not: Bu hesap Linux OS hesabıdır. Şifresini sunucu terminalinde passwd komutu ile değiştirebilirsiniz.';
        } else {
          passNote.textContent = 'Web hesabı şifresini doğrudan buradan sıfırlayabilirsiniz (en az ' + (passInp ? passInp.minLength : 8) + ' karakter).';
        }
      }
      openModal('editAdminModal');
    }
    
document.addEventListener('click', function(ev) {
  var b = ev.target.closest ? ev.target.closest('[data-edit-admin],[data-edit-role]') : null;
  if (!b) return;
  if (b.hasAttribute('data-edit-admin')) openEditAdminModal(b.getAttribute('data-edit-admin'));
  else openEditRoleModal(b.getAttribute('data-edit-role'));
});
