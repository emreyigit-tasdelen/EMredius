// Copyright (c) 2026 Emre Yiğit Taşdelen
// SPDX-License-Identifier: AGPL-3.0-only
// ==================== I18N MULTI-LANGUAGE ENGINE (6 LANGUAGES) ====================
window.I18N_RAW = {
"CA kurulum yönergesi": {"en": "CA installation guide", "zh": "CA 安装指南", "ru": "Инструкция по установке CA", "es": "Guía de instalación de la CA", "fr": "Guide d'installation de la CA"},
"Windows: tek tıkla kurulum (.bat)": {"en": "Windows: one-click install (.bat)", "zh": "Windows：一键安装 (.bat)", "ru": "Windows: установка в один клик (.bat)", "es": "Windows: instalación con un clic (.bat)", "fr": "Windows : installation en un clic (.bat)"},
"Windows: .bat dosyasını indirip çift tıklayın; sertifika kullanıcı güvenilir kök deposuna eklenir. Alternatif: .crt dosyasına çift tıklayın > Sertifika Yükle > Güvenilen Kök Sertifika Yetkilileri.": {"en": "Windows: download the .bat file and double-click it; the certificate is added to your trusted root store. Alternative: double-click the .crt > Install Certificate > Trusted Root Certification Authorities.", "zh": "Windows：下载 .bat 文件并双击运行，证书将添加到用户受信任的根证书存储。或者：双击 .crt > 安装证书 > 受信任的根证书颁发机构。", "ru": "Windows: скачайте .bat и дважды щёлкните по нему; сертификат будет добавлен в доверенные корневые. Вариант: дважды щёлкните .crt > Установить сертификат > Доверенные корневые центры сертификации.", "es": "Windows: descargue el .bat y haga doble clic; el certificado se añade a las raíces de confianza. Alternativa: doble clic en el .crt > Instalar certificado > Entidades de certificación raíz de confianza.", "fr": "Windows : téléchargez le .bat et double-cliquez ; le certificat est ajouté aux racines de confiance. Sinon : double-clic sur le .crt > Installer le certificat > Autorités de certification racines de confiance."},
"macOS: .crt dosyasına çift tıklayın, Anahtar Zinciri'nde sertifikayı açıp Güven > Her Zaman Güven seçin.": {"en": "macOS: double-click the .crt, open the certificate in Keychain Access and choose Trust > Always Trust.", "zh": "macOS：双击 .crt，在钥匙串中打开证书，选择“信任 > 始终信任”。", "ru": "macOS: дважды щёлкните .crt, откройте сертификат в «Связке ключей» и выберите «Доверять > Всегда доверять».", "es": "macOS: doble clic en el .crt, abra el certificado en Llavero y elija Confiar > Confiar siempre.", "fr": "macOS : double-cliquez sur le .crt, ouvrez le certificat dans Trousseau d'accès et choisissez Faire confiance > Toujours faire confiance."},
"Firefox: Ayarlar > Gizlilik ve Güvenlik > Sertifikalar > Sertifikaları Görüntüle > Yetkililer > İçe Aktar; web siteleri için güven kutusunu işaretleyin.": {"en": "Firefox: Settings > Privacy & Security > Certificates > View Certificates > Authorities > Import; tick the trust-websites box.", "zh": "Firefox：设置 > 隐私与安全 > 证书 > 查看证书 > 证书颁发机构 > 导入；勾选信任网站。", "ru": "Firefox: Настройки > Приватность и защита > Сертификаты > Просмотр сертификатов > Центры сертификации > Импорт; отметьте доверие сайтам.", "es": "Firefox: Ajustes > Privacidad y seguridad > Certificados > Ver certificados > Autoridades > Importar; marque confiar en sitios web.", "fr": "Firefox : Paramètres > Vie privée et sécurité > Certificats > Afficher les certificats > Autorités > Importer ; cochez la confiance pour les sites web."},
"Telefon: iPhone'da dosyayı açıp Ayarlar > Genel > VPN ve Aygıt Yönetimi'nden yükleyin, sonra Genel > Hakkında > Sertifika Güven Ayarları'nı açın. Android'de Ayarlar > Güvenlik > Sertifika yükle > CA sertifikası.": {"en": "Phone: on iPhone open the file, install it in Settings > General > VPN & Device Management, then enable it in General > About > Certificate Trust Settings. On Android: Settings > Security > Install certificate > CA certificate.", "zh": "手机：iPhone 打开文件后在 设置 > 通用 > VPN 与设备管理 中安装，再在 通用 > 关于本机 > 证书信任设置 中启用。Android：设置 > 安全 > 安装证书 > CA 证书。", "ru": "Телефон: на iPhone откройте файл, установите в Настройки > Основные > VPN и управление устройством, затем включите в Основные > Об этом устройстве > Доверие сертификатам. На Android: Настройки > Безопасность > Установить сертификат > Сертификат CA.", "es": "Teléfono: en iPhone abra el archivo, instálelo en Ajustes > General > VPN y gestión de dispositivos y actívelo en General > Información > Ajustes de confianza de certificados. En Android: Ajustes > Seguridad > Instalar certificado > Certificado de CA.", "fr": "Téléphone : sur iPhone ouvrez le fichier, installez-le dans Réglages > Général > VPN et gestion de l'appareil, puis activez-le dans Général > Informations > Réglages de confiance des certificats. Sur Android : Paramètres > Sécurité > Installer un certificat > Certificat CA."},
"Kaspersky: HTTPS taraması kendi sertifikasını araya koyuyorsa uyarı sürebilir; Kaspersky > Ayarlar > Ağ > Güvenli bağlantıları tara bölümünden bu paneli hariç tutun veya Kaspersky kök sertifikasını da güvenilir yapın.": {"en": "Kaspersky: if HTTPS scanning injects its own certificate the warning may persist; exclude this panel under Kaspersky > Settings > Network > Scan encrypted connections, or trust the Kaspersky root as well.", "zh": "Kaspersky：如果 HTTPS 扫描插入自己的证书，警告可能仍会出现；请在 Kaspersky > 设置 > 网络 > 扫描加密连接 中排除此面板，或同时信任 Kaspersky 根证书。", "ru": "Kaspersky: если проверка HTTPS подменяет сертификат, предупреждение может остаться; исключите панель в Kaspersky > Настройки > Сеть > Проверка защищённых соединений или доверьте корневой сертификат Kaspersky.", "es": "Kaspersky: si el análisis HTTPS inserta su propio certificado, la advertencia puede persistir; excluya este panel en Kaspersky > Configuración > Red > Analizar conexiones cifradas o confíe también en la raíz de Kaspersky.", "fr": "Kaspersky : si l'analyse HTTPS injecte son propre certificat, l'alerte peut persister ; excluez ce panneau dans Kaspersky > Paramètres > Réseau > Analyser les connexions chiffrées ou approuvez aussi la racine Kaspersky."},
"Kurulum Betiğini İndir (.bat)": {"en": "Download Install Script (.bat)", "zh": "下载安装脚本 (.bat)", "ru": "Скачать скрипт установки (.bat)", "es": "Descargar script de instalación (.bat)", "fr": "Télécharger le script d'installation (.bat)"},
"Web Terminal & CLI": {"en": "Web Terminal & CLI", "zh": "Web 终端与 CLI", "ru": "Веб-терминал и CLI", "es": "Terminal Web y CLI", "fr": "Terminal Web & CLI"},
"Web Terminal (CLI)": {"en": "Web Terminal (CLI)", "zh": "Web 终端 (CLI)", "ru": "Веб-терминал (CLI)", "es": "Terminal Web (CLI)", "fr": "Terminal Web (CLI)"},
"Komut Satırı / Web CLI": {"en": "Command Line / Web CLI", "zh": "命令行 / Web CLI", "ru": "Командная строка / Web CLI", "es": "Línea de comandos / Web CLI", "fr": "Ligne de commande / Web CLI"},
"Doğrudan FreeRADIUS ve Linux sunucu konsolu; komut yürütme, teşhis ve sistem kontrolü.": {"en": "Direct FreeRADIUS and Linux server console; command execution, diagnostics, and system control.", "zh": "直接的 FreeRADIUS 和 Linux 服务器控制台；命令执行、诊断和系统控制。", "ru": "Прямая консоль FreeRADIUS и Linux; выполнение команд, диагностика и контроль системы.", "es": "Consola directa de FreeRADIUS y servidor Linux; ejecución de comandos, diagnósticos y control del sistema.", "fr": "Console directe FreeRADIUS et serveur Linux; exécution de commandes, diagnostics et contrôle système."},
"Hızlı Komutlar": {"en": "Quick Commands", "zh": "快捷命令", "ru": "Быстрые команды", "es": "Comandos Rápidos", "fr": "Commandes Rapides"},
"Çıktıyı Temizle": {"en": "Clear Output", "zh": "清除输出", "ru": "Очистить вывод", "es": "Limpiar Salida", "fr": "Effacer la Sortie"},
"Çıktıyı Kopyala": {"en": "Copy Output", "zh": "复制输出", "ru": "Копировать вывод", "es": "Copiar Salida", "fr": "Copier la Sortie"},
"Log İndir": {"en": "Download Log", "zh": "下载日志", "ru": "Скачать журнал", "es": "Descargar Registro", "fr": "Télécharger le Journal"},
"Komut yazın ve Enter'a basın...": {"en": "Type command and press Enter...", "zh": "输入命令并按回车...", "ru": "Введите команду и нажмите Enter...", "es": "Escriba un comando y presione Enter...", "fr": "Tapez une commande et appuyez sur Entrée..."},
"CLI Çevrimiçi": {"en": "CLI Online", "zh": "CLI 在线", "ru": "CLI Онлайн", "es": "CLI En Línea", "fr": "CLI En Ligne"},
"Geçmiş Komutlar": {"en": "Command History", "zh": "命令历史", "ru": "История команд", "es": "Historial de Comandos", "fr": "Historique des Commandes"},
"Çalıştır": {"en": "Execute", "zh": "执行", "ru": "Выполнить", "es": "Ejecutar", "fr": "Exécuter"},
"Komuta tıkladığınızda otomatik olarak terminale aktarılır ve yürütülür.": {"en": "Clicking a command automatically pastes and executes it in the terminal.", "zh": "点击命令将自动粘贴并在终端中执行。", "ru": "Нажатие команды автоматически вставляет и выполняет ее в терминале.", "es": "Al hacer clic en un comando, se pega y ejecuta automáticamente en la terminal.", "fr": "Cliquer sur une commande la colle et l'exécute automatiquement dans le terminal."},
"Geliştirici": {"en": "Developer", "zh": "开发者", "ru": "Разработчик", "es": "Desarrollador", "fr": "Développeur"}, "Projeyi Destekle": {"en": "Support the Project", "zh": "支持本项目", "ru": "Поддержать проект", "es": "Apoyar el proyecto", "fr": "Soutenir le projet"}, "EMREDIUS açık kaynaklıdır. Beğendiyseniz geliştirmesine destek olabilirsiniz.": {"en": "EMREDIUS is open source. If you find it useful, you can support its development.", "zh": "EMREDIUS 是开源项目。如果它对您有帮助,欢迎支持其开发。", "ru": "EMREDIUS — проект с открытым исходным кодом. Если он вам полезен, вы можете поддержать его развитие.", "es": "EMREDIUS es de código abierto. Si le resulta útil, puede apoyar su desarrollo.", "fr": "EMREDIUS est open source. S'il vous est utile, vous pouvez soutenir son développement."}, "Genel Bakış": {"en": "Overview", "zh": "概览", "ru": "Обзор системы", "es": "Visión General", "fr": "Vue d'ensemble"}, "Kullanıcılar & Hız": {"en": "Users & Bandwidth", "zh": "用户与带宽", "ru": "Пользователи и скорость", "es": "Usuarios y Ancho de Banda", "fr": "Utilisateurs & Débit"}, "Gruplar & Profiller": {"en": "Groups & Profiles", "zh": "用户组与配置文件", "ru": "Группы и профили", "es": "Grupos y Perfiles", "fr": "Groupes & Profils"}, "Ağ Donanımı (NAS)": {"en": "Network Hardware (NAS)", "zh": "网络设备 (NAS)", "ru": "Сетевое оборудование (NAS)", "es": "Hardware de Red (NAS)", "fr": "Matériel Réseau (NAS)"}, "MAC Whitelist / IoT": {"en": "MAC Whitelist / IoT", "zh": "MAC白名单 / 物联网", "ru": "Белый список MAC / IoT", "es": "Lista Blanca MAC / IoT", "fr": "Liste Blanche MAC / IoT"}, "Misafir Kuponları": {"en": "Guest Vouchers", "zh": "访客优惠券", "ru": "Гостевые ваучеры", "es": "Vales de Invitado", "fr": "Coupons Invités"}, "Canlı Oturumlar & CoA": {"en": "Live Sessions & CoA", "zh": "实时会话与CoA", "ru": "Активные сессии и CoA", "es": "Sesiones en Vivo y CoA", "fr": "Sessions en Direct & CoA"}, "5651 Yasal Denetim": {"en": "5651 Legal Audit", "zh": "5651法律审计", "ru": "Юридический аудит 5651", "es": "Auditoría Legal 5651", "fr": "Audit Légal 5651"}, "Canlı Loglar": {"en": "Live Logs", "zh": "实时日志", "ru": "Журналы в реальном времени", "es": "Registros en Vivo", "fr": "Journaux en Direct"}, "Yöneticiler & Yetkiler": {"en": "Admins & Permissions", "zh": "管理员与权限", "ru": "Администраторы и роли", "es": "Administradores y Roles", "fr": "Administrateurs & Rôles"}, "Yedekleme & Kurtarma": {"en": "Backup & Recovery", "zh": "备份与恢复", "ru": "Резервное копирование", "es": "Copia de Seguridad", "fr": "Sauvegarde & Restauration"}, "Ayarlar & Webhook": {"en": "Settings & Webhooks", "zh": "系统设置与Webhook", "ru": "Настройки и Webhook", "es": "Configuración y Webhooks", "fr": "Paramètres & Webhooks"}, "Swagger API Dokümantasyonu": {"en": "Swagger API Documentation", "zh": "Swagger API文档", "ru": "Документация Swagger API", "es": "Documentación Swagger API", "fr": "Documentation Swagger API"}, "Doğrulama Testi": {"en": "Diagnostic Test", "zh": "RADIUS验证测试", "ru": "Тест проверки RADIUS", "es": "Prueba de Diagnóstico", "fr": "Test de Diagnostic"}, "radiusd: Çalışıyor": {"en": "radiusd: Running", "zh": "radiusd: 运行中", "ru": "radiusd: Работает", "es": "radiusd: En línea", "fr": "radiusd: En ligne"}, "radiusd: Durduruldu": {"en": "radiusd: Stopped", "zh": "radiusd: 已停止", "ru": "radiusd: Остановлен", "es": "radiusd: Detenido", "fr": "radiusd: Arrêté"}, "Yeniden Başlat": {"en": "Restart", "zh": "重启服务", "ru": "Перезапуск", "es": "Reiniciar", "fr": "Redémarrer"}, "Çıkış Yap": {"en": "Logout", "zh": "退出登录", "ru": "Выход", "es": "Cerrar Sesión", "fr": "Déconnexion"}, "Profilimi Görüntüle": {"en": "View My Profile", "zh": "查看个人资料", "ru": "Мой профиль", "es": "Ver mi Perfil", "fr": "Voir mon profil"}, "Menüyü Göster / Gizle": {"en": "Toggle Sidebar", "zh": "切换侧边栏", "ru": "Показать/Скрыть меню", "es": "Mostrar/Ocultar Menú", "fr": "Afficher/Masquer le menu"}, "Sistem Özeti & Canlı Metrikler": {"en": "System Summary & Live Metrics", "zh": "系统摘要与实时指标", "ru": "Сводка системы и живые метрики", "es": "Resumen del Sistema y Métricas", "fr": "Résumé du Système & Métriques"}, "Kullanıcı & Dinamik Yetkilendirme": {"en": "User & Dynamic Authorization", "zh": "用户与动态授权", "ru": "Пользователи и авторизация", "es": "Usuarios y Autorización Dinámica", "fr": "Utilisateurs & Autorisation Dynamique"}, "Grup & Profil Yönetimi (RBAC)": {"en": "Group & Profile Management (RBAC)", "zh": "用户组与配置文件管理", "ru": "Управление группами и профилями", "es": "Gestión de Grupos y Perfiles", "fr": "Gestion des Groupes & Profils"}, "Ağ Donanımı (NAS) Yönetimi": {"en": "Network Hardware (NAS) Management", "zh": "网络设备 (NAS) 管理", "ru": "Управление сетевым оборудованием (NAS)", "es": "Gestión de Hardware de Red (NAS)", "fr": "Gestion du Matériel Réseau (NAS)"}, "MAC Authentication Bypass (MAB & IoT)": {"en": "MAC Authentication Bypass (MAB & IoT)", "zh": "MAC认证绕过 (MAB与物联网)", "ru": "Обход аутентификации MAC (MAB и IoT)", "es": "Bypass de Autenticación MAC (MAB e IoT)", "fr": "Contournement d'authentification MAC (MAB & IoT)"}, "Ziyaretçi & Kupon (Voucher) Sistemi": {"en": "Guest & Voucher System", "zh": "访客与优惠券系统", "ru": "Система гостевых ваучеров", "es": "Sistema de Vales de Invitado", "fr": "Système de Coupons Visiteurs"}, "Canlı Oturumlar & CoA / Disconnect": {"en": "Live Sessions & CoA / Disconnect", "zh": "实时会话与CoA断开", "ru": "Активные сессии и CoA / Отключение", "es": "Sesiones en Vivo y CoA / Desconexión", "fr": "Sessions en Direct & Déconnexion CoA"}, "5651 Yasal IP / MAC Adli Arama": {"en": "5651 Legal IP / MAC Forensic Search", "zh": "5651法律 IP/MAC 取证搜索", "ru": "Судебный поиск IP / MAC по закону 5651", "es": "Búsqueda Forense Legal 5651 IP/MAC", "fr": "Recherche Judiciaire Légale 5651 IP/MAC"}, "Sistem Logları & Teşhis": {"en": "System Logs & Diagnostics", "zh": "系统日志与诊断", "ru": "Системные журналы и диагностика", "es": "Registros del Sistema y Diagnóstico", "fr": "Journaux Système & Diagnostics"}, "Yönetici Kullanıcılar & RBAC Yetkilendirme": {"en": "Admin Users & RBAC Authorization", "zh": "管理员用户与RBAC授权", "ru": "Администраторы и авторизация RBAC", "es": "Usuarios Administradores y Roles RBAC", "fr": "Utilisateurs Administrateurs & Rôles RBAC"}, "Yedekleme & Felaket Kurtarma": {"en": "Backup & Disaster Recovery", "zh": "备份与灾难恢复", "ru": "Резервное копирование и восстановление", "es": "Copia de Seguridad y Recuperación", "fr": "Sauvegarde & Reprise après sinistre"}, "Sistem Ayarları & Entegrasyon": {"en": "System Settings & Integration", "zh": "系统设置与集成", "ru": "Настройки системы и интеграция", "es": "Ajustes del Sistema e Integración", "fr": "Paramètres Système & Intégration"}, "Canlı RADIUS Doğrulama Aracı": {"en": "Live RADIUS Verification Tool", "zh": "实时RADIUS验证工具", "ru": "Инструмент проверки RADIUS", "es": "Herramienta de Verificación RADIUS", "fr": "Outil de Diagnostic RADIUS en Direct"}, "Profil & Hesap Ayarları": {"en": "Profile & Account Settings", "zh": "个人资料与账户设置", "ru": "Профиль и настройки аккаунта", "es": "Perfil y Ajustes de Cuenta", "fr": "Profil & Paramètres du Compte"}, "Toplam Kullanıcı": {"en": "Total Users", "zh": "用户总数", "ru": "Всего пользователей", "es": "Usuarios Totales", "fr": "Total Utilisateurs"}, "Canlı Oturumlar": {"en": "Live Sessions", "zh": "实时在线会话", "ru": "Активные сессии", "es": "Sesiones en Vivo", "fr": "Sessions en Direct"}, "Kayıtlı NAS Cihazı": {"en": "Registered NAS Devices", "zh": "已注册NAS设备", "ru": "Зарегистрировано NAS", "es": "Dispositivos NAS Registrados", "fr": "Appareils NAS Enregistrés"}, "Toplam Ağ Trafiği": {"en": "Total Network Traffic", "zh": "网络总流量", "ru": "Общий сетевой трафик", "es": "Tráfico Total de Red", "fr": "Trafic Réseau Total"}, "Toplam Yönetici": {"en": "Total Admins", "zh": "管理员总数", "ru": "Всего администраторов", "es": "Total de Administradores", "fr": "Total Administrateurs"}, "Bağımsız Web Hesabı": {"en": "Independent Web Accounts", "zh": "独立Web账户", "ru": "Веб-аккаунты", "es": "Cuentas Web", "fr": "Comptes Web"}, "AlmaLinux OS Hesabı": {"en": "AlmaLinux OS Accounts", "zh": "AlmaLinux系统账户", "ru": "Аккаунты AlmaLinux", "es": "Cuentas AlmaLinux OS", "fr": "Comptes AlmaLinux OS"}, "Aktif Hesaplar": {"en": "Active Accounts", "zh": "活跃账户", "ru": "Активные аккаунты", "es": "Cuentas Activas", "fr": "Comptes Actifs"}, "Canlı Bağlı Cihazlar": {"en": "Live Connected Devices", "zh": "当前在线连接设备", "ru": "Активные подключенные устройства", "es": "Dispositivos Conectados en Vivo", "fr": "Appareils Connectés en Direct"}, "Şu Anda Canlı Bağlı Cihazlar": {"en": "Currently Connected Live Devices", "zh": "当前在线连接设备", "ru": "Текущие активные устройства", "es": "Dispositivos Conectados Actualmente", "fr": "Appareils Actuellement Connectés"}, "En Çok Trafik (MB)": {"en": "Top Traffic Consumers (MB)", "zh": "流量最高排行 (MB)", "ru": "Топ по трафику (MB)", "es": "Mayor Consumo de Tráfico (MB)", "fr": "Plus Gros Consommateurs (MB)"}, "Kayıtlı Kullanıcılar": {"en": "Registered Users", "zh": "已注册用户", "ru": "Зарегистрированные пользователи", "es": "Usuarios Registrados", "fr": "Utilisateurs Enregistrés"}, "Yeni Kullanıcı Tanımla": {"en": "Define New User", "zh": "添加新用户", "ru": "Создать пользователя", "es": "Definir Nuevo Usuario", "fr": "Créer un Nouvel Utilisateur"}, "Toplu Kullanıcı İçe Aktarma (CSV)": {"en": "Bulk User Import (CSV)", "zh": "批量用户导入 (CSV)", "ru": "Импорт пользователей (CSV)", "es": "Importación Masiva de Usuarios (CSV)", "fr": "Importation Groupée d'Utilisateurs (CSV)"}, "Tanımlı Gruplar & Profiller": {"en": "Defined Groups & Profiles", "zh": "已定义组与配置文件", "ru": "Определенные группы и профили", "es": "Grupos y Perfiles Definidos", "fr": "Groupes & Profils Définis"}, "Yeni Grup & Yetki Profili": {"en": "New Group & Authorization Profile", "zh": "新建组与授权配置文件", "ru": "Создать группу и профиль", "es": "Nuevo Grupo y Perfil de Acceso", "fr": "Nouveau Groupe & Profil d'Accès"}, "Tanımlı Ağ Donanımları (NAS)": {"en": "Defined Network Hardware (NAS)", "zh": "已定义网络硬件 (NAS)", "ru": "Сетевые устройства (NAS)", "es": "Hardware de Red Definido (NAS)", "fr": "Équipements Réseau Définis (NAS)"}, "Yeni Ağ Cihazı (NAS) Tanımla": {"en": "Define New Network Device (NAS)", "zh": "定义新网络设备 (NAS)", "ru": "Добавить устройство NAS", "es": "Definir Nuevo Dispositivo NAS", "fr": "Définir un Nouvel Appareil NAS"}, "İzin Verilen Donanım Adresleri (MAC Whitelist)": {"en": "Allowed Hardware Addresses (MAC Whitelist)", "zh": "允许的硬件地址 (MAC白名单)", "ru": "Разрешенные MAC-адреса (Белый список)", "es": "Direcciones MAC Permitidas (Lista Blanca)", "fr": "Adresses Matérielles Autorisées (Liste Blanche MAC)"}, "Yeni Cihaz MAC Adresi Ekle": {"en": "Add New Device MAC Address", "zh": "添加新设备MAC地址", "ru": "Добавить MAC-адрес устройства", "es": "Agregar Dirección MAC", "fr": "Ajouter Adresse MAC d'un Appareil"}, "Onay Bekleyen / Reddedilen Bilinmeyen Cihazlar": {"en": "Pending / Rejected Unknown Devices", "zh": "待审核 / 拒绝的未知设备", "ru": "Ожидающие / Отклоненные устройства", "es": "Dispositivos Pendientes / Rechazados", "fr": "Appareils en Attente / Rejetés"}, "Aktif Misafir Kuponları": {"en": "Active Guest Vouchers", "zh": "有效访客优惠券", "ru": "Активные гостевые ваучеры", "es": "Vales de Invitado Activos", "fr": "Coupons Invités Actifs"}, "Misafir Kuponu Üret": {"en": "Generate Guest Vouchers", "zh": "生成访客优惠券", "ru": "Генерация гостевых ваучеров", "es": "Generar Vales de Invitado", "fr": "Générer des Coupons Invités"}, "Geçmiş Oturum Kayıtları (Son 50)": {"en": "Historical Session Logs (Last 50)", "zh": "历史会话记录 (前50条)", "ru": "История сессий (последние 50)", "es": "Historial de Sesiones (Últimas 50)", "fr": "Historique des Sessions (50 Dernières)"}, "5651 Yasal IP & MAC Denetim Sorgulama": {"en": "5651 Legal IP & MAC Forensic Query", "zh": "5651法律 IP与MAC取证查询", "ru": "Запрос аудита 5651 по IP и MAC", "es": "Consulta Forense 5651 IP y MAC", "fr": "Requête Judiciaire 5651 IP & MAC"}, "FreeRADIUS Canlı Log Akışı (Son 200 Satır)": {"en": "FreeRADIUS Live Log Stream (Last 200 Lines)", "zh": "FreeRADIUS实时日志流 (前200行)", "ru": "Журнал FreeRADIUS (последние 200 строк)", "es": "Transmisión de Registros FreeRADIUS (200 Líneas)", "fr": "Flux de Journaux FreeRADIUS (200 Dernières Lignes)"}, "Yetkili Yöneticiler & Erişim Rolleri": {"en": "Authorized Administrators & Access Roles", "zh": "授权管理员与访问角色", "ru": "Администраторы и роли доступа", "es": "Administradores Autorizados y Roles de Acceso", "fr": "Administrateurs Autorisés & Rôles d'Accès"}, "Yeni Bağımsız Web Yöneticisi Ekle": {"en": "Add Independent Web Admin", "zh": "添加独立Web管理员", "ru": "Добавить веб-администратора", "es": "Agregar Admin Web", "fr": "Ajouter Admin Web"}, "AlmaLinux Kullanıcısına Panel Yetkisi Ver": {"en": "Grant Panel Access to AlmaLinux User", "zh": "为AlmaLinux用户授予面板权限", "ru": "Дать доступ пользователю AlmaLinux", "es": "Autorizar Usuario AlmaLinux al Panel", "fr": "Accorder Accès Panneau à Utilisateur AlmaLinux"}, "Yönetici Denetim İzi (Son İşlemler)": {"en": "Admin Audit Trail (Recent Actions)", "zh": "管理员操作审计 (最近操作)", "ru": "Аудит действий администраторов (последние)", "es": "Pista de Auditoría de Administradores", "fr": "Piste d'Audit des Administrateurs"}, "Mevcut Yedek Dosyaları": {"en": "Available Backup Files", "zh": "现有备份文件", "ru": "Доступные резервные копии", "es": "Archivos de Respaldo Disponibles", "fr": "Fichiers de Sauvegarde Disponibles"}, "Wi-Fi Kupon Marka & API Ayarları": {"en": "Wi-Fi Voucher Branding & API Settings", "zh": "Wi-Fi优惠券品牌与API设置", "ru": "Брендинг ваучеров Wi-Fi и настройки API", "es": "Marca de Vales Wi-Fi y Ajustes API", "fr": "Marque des Coupons Wi-Fi & Paramètres API"}, "Bildirim Kanalları (Telegram & Slack)": {"en": "Notification Channels (Telegram & Slack)", "zh": "通知渠道 (Telegram与Slack)", "ru": "Каналы уведомлений (Telegram и Slack)", "es": "Canales de Notificación (Telegram y Slack)", "fr": "Canaux de Notification (Telegram & Slack)"}, "Anlık RADIUS Testi Yap": {"en": "Run Instant RADIUS Test", "zh": "运行即时RADIUS测试", "ru": "Выполнить мгновенный тест RADIUS", "es": "Ejecutar Prueba RADIUS Instantánea", "fr": "Exécuter un Test RADIUS Instantané"}, "Test Sonucu & Paket Yanıtı": {"en": "Test Result & Packet Response", "zh": "测试结果与数据包响应", "ru": "Результат теста и ответ пакета", "es": "Resultado de la Prueba y Respuesta", "fr": "Résultat du Test & Réponse du Paquet"}, "Yönetici Profil Bilgileri": {"en": "Admin Profile Information", "zh": "管理员个人信息", "ru": "Информация профиля администратора", "es": "Información de Perfil de Administrador", "fr": "Informations du Profil Administrateur"}, "Kullanıcılar, Dinamik VLAN, Statik IP, Hız Sınırları ve Hesap Durumu.": {"en": "Users, Dynamic VLAN, Static IP, Bandwidth Limits and Account Status.", "zh": "用户、动态VLAN、静态IP、速率限制与账户状态。", "ru": "Пользователи, динамический VLAN, статический IP, лимиты скорости и статус.", "es": "Usuarios, VLAN Dinámica, IP Estática, Límites de Velocidad y Estado.", "fr": "Utilisateurs, VLAN Dynamique, IP Statique, Limites de Débit et Statut."}, "Departman veya rol bazlı şablonlar (Gruptaki tüm kullanıcılar VLAN ve hız sınırını devralır).": {"en": "Department or role-based templates (All users in the group inherit VLAN and rate limits).", "zh": "部门或基于角色的模板 (组内所有用户继承VLAN与速度限制)。", "ru": "Шаблоны на основе отделов или ролей (все пользователи наследуют VLAN и лимит).", "es": "Plantillas por departamento o rol (todos los usuarios heredan VLAN y velocidad).", "fr": "Modèles par département ou rôle (tous les utilisateurs héritent du VLAN et débit)."}, "RADIUS ile konuşan Access Point, Switch ve Güvenlik Duvarları (Canlı Heartbeat Denetimi).": {"en": "Access Points, Switches and Firewalls communicating with RADIUS (Live Heartbeat Check).", "zh": "与RADIUS通信的AP、交换机和防火墙 (实时心跳检测)。", "ru": "Точки доступа, коммутаторы и брандмауэры RADIUS (Живой Heartbeat опрос).", "es": "Puntos de Acceso, Switches y Firewalls con RADIUS (Verificación Heartbeat en Vivo).", "fr": "Points d'Accès, Commutateurs et Pare-feu avec RADIUS (Vérification Heartbeat en Direct)."}, "Yazıcılar, Kameralar ve Akıllı Cihazlar için MAC Yetkilendirmesi (OUI Marka Tanıma ile).": {"en": "MAC Authorization for Printers, Cameras and Smart Devices (with OUI Vendor Lookup).", "zh": "针对打印机、摄像头和智能设备的MAC认证 (支持OUI厂商识别)。", "ru": "Авторизация MAC для принтеров, камер и IoT-устройств (с определением вендора OUI).", "es": "Autorización MAC para Impresoras, Cámaras y Dispositivos Inteligentes (con OUI).", "fr": "Autorisation MAC pour Imprimantes, Caméras et Appareils Intelligents (avec OUI)."}, "Misafir Wi-Fi Kuponları (QR Kodlu Yazdırma & İlk Bağlantıda Başlayan Sayaç Desteği).": {"en": "Guest Wi-Fi Vouchers (Print with QR Codes & First-Login accounting trigger).", "zh": "访客Wi-Fi优惠券 (支持二维码打印及首次连接计时触发)。", "ru": "Гостевые Wi-Fi ваучеры (Печать с QR-кодом и запуск по первому входу).", "es": "Vales Wi-Fi de Invitado (Impresión QR y activación en primer inicio).", "fr": "Coupons Wi-Fi Invités (Impression avec QR Code et activation à la 1ère connexion)."}, "Canlı Oturumlar & RFC 3576 / RFC 5176 Change of Authorization (CoA) ile Anında Bağlantıyı Kesme.": {"en": "Live Sessions & Instant Disconnection via RFC 3576 / RFC 5176 Change of Authorization (CoA).", "zh": "实时会话及基于 RFC 3576 / RFC 5176 CoA 的即时断开连接。", "ru": "Активные сессии и мгновенный сброс через RFC 3576 / RFC 5176 Change of Authorization (CoA).", "es": "Sesiones en Vivo y Desconexión Instantánea mediante RFC 3576 / RFC 5176 CoA.", "fr": "Sessions en Direct & Déconnexion Instantanée via RFC 3576 / RFC 5176 CoA."}, "SHA256 Bütünlük Korumalı Tam Sistem & SQL Yedek Arşivi.": {"en": "Full System & SQL Backup Archive with SHA256 Integrity Protection.", "zh": "具有SHA256完整性校验的完整系统与SQL备份归档。", "ru": "Архив полного бэкапа системы и SQL с защитой целостности SHA256.", "es": "Archivo de Respaldo Completo y SQL con Protección de Integridad SHA256.", "fr": "Archive de Sauvegarde Complète et SQL avec Protection d'Intégrité SHA256."}, "Web yönetim paneline erişebilecek bağımsız kullanıcıları ve yetkili AlmaLinux kullanıcılarını yönetin.": {"en": "Manage independent users and authorized AlmaLinux users who can access the web management panel.", "zh": "管理能够访问Web管理面板的独立用户及授权AlmaLinux用户。", "ru": "Управление независимыми веб-пользователями и авторизованными системными пользователями AlmaLinux.", "es": "Administre usuarios web independientes y usuarios autorizados de AlmaLinux en el panel.", "fr": "Gérez les utilisateurs web indépendants et les utilisateurs AlmaLinux autorisés."}, "Sol taraftaki formu doldurup test butonuna basarak anlık RADIUS paket cevabını görüntüleyin.": {"en": "Fill out the form on the left and click the test button to view the instant RADIUS packet response.", "zh": "填写左侧表单并点击测试按钮以查看即时RADIUS数据包响应。", "ru": "Заполните форму слева и нажмите кнопку тестирования, чтобы увидеть ответ пакета RADIUS.", "es": "Complete el formulario a la izquierda y presione el botón para ver la respuesta RADIUS.", "fr": "Remplissez le formulaire à gauche et cliquez pour voir la réponse du paquet RADIUS."}, "Bu hesap doğrudan AlmaLinux işletim sistemine bağlıdır. Şifrenizi sunucu terminalinde": {"en": "This account is linked directly to the AlmaLinux operating system. Change your password in the server terminal with", "zh": "此账户直接关联AlmaLinux操作系统。请在服务器终端中使用以下命令修改密码：", "ru": "Этот аккаунт напрямую связан с ОС AlmaLinux. Измените пароль в терминале сервера с помощью", "es": "Esta cuenta está vinculada directamente al sistema AlmaLinux. Cambie su contraseña en terminal con", "fr": "Ce compte est lié directement au système AlmaLinux. Modifiez votre mot de passe dans le terminal avec"}, "komutu ile değiştirebilirsiniz. Terminalde değiştirdiğiniz anda web paneli şifreniz sıfır gecikmeyle otomatik güncellenecektir.": {"en": "command. As soon as you change it in the terminal, your web panel password will update automatically with zero latency.", "zh": "命令。在终端中更改后，Web面板密码将即时自动更新，零延迟。", "ru": "команды. Как только вы измените его в терминале, пароль в веб-панели обновится мгновенно.", "es": "comando. Tan pronto como lo cambie en la terminal, se actualizará en el panel automáticamente.", "fr": "commande. Dès que vous le modifiez dans le terminal, il sera mis à jour instantanément."}, "Bu kullanıcı sadece web arayüzünde geçerli olur; AlmaLinux sunucusunda Linux hesabı açılmaz.": {"en": "This user is only valid in the web interface; no Linux account is created on the AlmaLinux server.", "zh": "此用户仅在Web界面中生效；不会在AlmaLinux服务器上创建Linux系统账户。", "ru": "Этот пользователь действует только в веб-интерфейсе; Linux-аккаунт на сервере не создается.", "es": "Este usuario solo es válido en la interfaz web; no se crea cuenta Linux en el servidor.", "fr": "Cet utilisateur n'est valable que sur le web; aucun compte Linux n'est créé sur le serveur."}, "Kullanıcı Adı": {"en": "Username", "zh": "用户名", "ru": "Имя пользователя", "es": "Nombre de Usuario", "fr": "Nom d'utilisateur"}, "Kullanıcı": {"en": "User", "zh": "用户", "ru": "Пользователь", "es": "Usuario", "fr": "Utilisateur"}, "Şifre": {"en": "Password", "zh": "密码", "ru": "Пароль", "es": "Contraseña", "fr": "Mot de passe"}, "Ad Soyad": {"en": "Full Name", "zh": "姓名", "ru": "Имя Фамилия", "es": "Nombre Completo", "fr": "Nom Complet"}, "Hesap Türü": {"en": "Account Type", "zh": "账户类型", "ru": "Тип аккаунта", "es": "Tipo de Cuenta", "fr": "Type de Compte"}, "Yetki Rolü": {"en": "Role", "zh": "权限角色", "ru": "Роль", "es": "Rol de Acceso", "fr": "Rôle"}, "Durum": {"en": "Status", "zh": "状态", "ru": "Статус", "es": "Estado", "fr": "Statut"}, "Son Giriş": {"en": "Last Login", "zh": "最后登录", "ru": "Последний вход", "es": "Último Acceso", "fr": "Dernière Connexion"}, "İşlemler": {"en": "Actions", "zh": "操作", "ru": "Действия", "es": "Acciones", "fr": "Actions"}, "İşlem": {"en": "Action", "zh": "操作", "ru": "Действие", "es": "Acción", "fr": "Action"}, "Grup": {"en": "Group", "zh": "用户组", "ru": "Группа", "es": "Grupo", "fr": "Groupe"}, "Grup Adı": {"en": "Group Name", "zh": "组名称", "ru": "Имя группы", "es": "Nombre del Grupo", "fr": "Nom du Groupe"}, "Hız Limiti": {"en": "Speed Limit", "zh": "速度限制", "ru": "Ограничение скорости", "es": "Límite de Velocidad", "fr": "Limite de Vitesse"}, "Hız Sınırı": {"en": "Speed Cap", "zh": "速率上限", "ru": "Лимит скорости", "es": "Tope de Velocidad", "fr": "Débit Max"}, "Grup Hız Limiti": {"en": "Group Speed Limit", "zh": "组速度限制", "ru": "Лимит скорости группы", "es": "Límite de Velocidad del Grupo", "fr": "Limite de Vitesse du Groupe"}, "Grup VLAN": {"en": "Group VLAN", "zh": "组VLAN", "ru": "VLAN группы", "es": "VLAN de Grupo", "fr": "VLAN du Groupe"}, "VLAN": {"en": "VLAN", "zh": "VLAN", "ru": "VLAN", "es": "VLAN", "fr": "VLAN"}, "Statik IP": {"en": "Static IP", "zh": "静态IP", "ru": "Статический IP", "es": "IP Estática", "fr": "IP Statique"}, "IP Adresi": {"en": "IP Address", "zh": "IP地址", "ru": "IP-адрес", "es": "Dirección IP", "fr": "Adresse IP"}, "IP Adresi / CIDR": {"en": "IP Address / CIDR", "zh": "IP地址 / CIDR", "ru": "IP-адрес / CIDR", "es": "Dirección IP / CIDR", "fr": "Adresse IP / CIDR"}, "İstemci IP": {"en": "Client IP", "zh": "客户端IP", "ru": "IP клиента", "es": "IP del Cliente", "fr": "IP Client"}, "Atanan IP": {"en": "Assigned IP", "zh": "分配的IP", "ru": "Назначенный IP", "es": "IP Asignada", "fr": "IP Assignée"}, "Atanan VLAN": {"en": "Assigned VLAN", "zh": "分配的VLAN", "ru": "Назначенный VLAN", "es": "VLAN Asignada", "fr": "VLAN Assigné"}, "MAC Adresi": {"en": "MAC Address", "zh": "MAC地址", "ru": "MAC-адрес", "es": "Dirección MAC", "fr": "Adresse MAC"}, "Cihaz MAC": {"en": "Device MAC", "zh": "设备MAC", "ru": "MAC устройства", "es": "MAC del Dispositivo", "fr": "MAC de l'Appareil"}, "Cihaz Adı": {"en": "Device Name", "zh": "设备名称", "ru": "Имя устройства", "es": "Nombre del Dispositivo", "fr": "Nom de l'Appareil"}, "Cihaz Tanımı": {"en": "Device Definition", "zh": "设备描述", "ru": "Описание устройства", "es": "Definición del Dispositivo", "fr": "Description de l'Appareil"}, "Üretici Marka": {"en": "Vendor / Brand", "zh": "设备厂商", "ru": "Производитель", "es": "Fabricante / Marca", "fr": "Fabricant / Marque"}, "Tahmini Üretici": {"en": "Estimated Vendor", "zh": "推测厂商", "ru": "Ориентировочный производитель", "es": "Fabricante Estimado", "fr": "Fabricant Estimé"}, "Denediği AP/Switch": {"en": "Attempted AP/Switch", "zh": "尝试连接的AP/交换机", "ru": "Целевая AP/Коммутатор", "es": "AP/Switch Intentado", "fr": "AP/Commutateur Tenté"}, "Kupon Kodu": {"en": "Voucher Code", "zh": "优惠券代码", "ru": "Код ваучера", "es": "Código de Vale", "fr": "Code du Coupon"}, "Süre": {"en": "Duration", "zh": "时长", "ru": "Длительность", "es": "Duración", "fr": "Durée"}, "Geçerlilik Kuralı": {"en": "Validity Rule", "zh": "有效性规则", "ru": "Правило действия", "es": "Regla de Validez", "fr": "Règle de Validité"}, "Oturum Süresi": {"en": "Session Time", "zh": "在线时长", "ru": "Время сессии", "es": "Tiempo de Sesión", "fr": "Temps de Session"}, "Trafik": {"en": "Traffic", "zh": "流量", "ru": "Трафик", "es": "Tráfico", "fr": "Trafic"}, "Trafik (Up / Down)": {"en": "Traffic (Up / Down)", "zh": "流量 (上传 / 下载)", "ru": "Трафик (Отдача / Прием)", "es": "Tráfico (Subida / Bajada)", "fr": "Trafic (Montant / Descendant)"}, "Toplam Veri": {"en": "Total Data", "zh": "总数据量", "ru": "Всего данных", "es": "Datos Totales", "fr": "Données Totales"}, "Bağlandığı NAS": {"en": "Connected NAS", "zh": "连接的NAS", "ru": "Подключенный NAS", "es": "NAS Conectado", "fr": "NAS Connecté"}, "AP / Switch": {"en": "AP / Switch", "zh": "AP / 交换机", "ru": "AP / Коммутатор", "es": "AP / Switch", "fr": "AP / Commutateur"}, "Canlı Durum": {"en": "Live Status", "zh": "实时状态", "ru": "Живой статус", "es": "Estado en Vivo", "fr": "Statut en Direct"}, "Başlangıç": {"en": "Start", "zh": "开始时间", "ru": "Начало", "es": "Inicio", "fr": "Début"}, "Bitiş": {"en": "End", "zh": "结束时间", "ru": "Окончание", "es": "Fin", "fr": "Fin"}, "Ayrılma Sebebi": {"en": "Termination Cause", "zh": "下线原因", "ru": "Причина завершения", "es": "Causa de Desconexión", "fr": "Cause de Déconnexion"}, "Zaman": {"en": "Time", "zh": "时间", "ru": "Время", "es": "Hora / Fecha", "fr": "Heure / Date"}, "Yönetici": {"en": "Admin", "zh": "管理员", "ru": "Администратор", "es": "Administrador", "fr": "Administrateur"}, "Eylem": {"en": "Action", "zh": "动作", "ru": "Действие", "es": "Acción", "fr": "Action"}, "Hedef": {"en": "Target", "zh": "目标", "ru": "Цель", "es": "Destino", "fr": "Cible"}, "Detaylar": {"en": "Details", "zh": "详情", "ru": "Подробности", "es": "Detalles", "fr": "Détails"}, "Açıklama": {"en": "Description", "zh": "说明", "ru": "Описание", "es": "Descripción", "fr": "Description"}, "Dosya Adı": {"en": "Filename", "zh": "文件名", "ru": "Имя файла", "es": "Nombre de Archivo", "fr": "Nom de Fichier"}, "Boyut": {"en": "Size", "zh": "大小", "ru": "Размер", "es": "Tamaño", "fr": "Taille"}, "Yedek Türü": {"en": "Backup Type", "zh": "备份类型", "ru": "Тип копии", "es": "Tipo de Respaldo", "fr": "Type de Sauvegarde"}, "SHA256 Bütünlük": {"en": "SHA256 Integrity", "zh": "SHA256完整性", "ru": "Целостность SHA256", "es": "Integridad SHA256", "fr": "Intégrité SHA256"}, "Oluşturulma": {"en": "Created At", "zh": "创建时间", "ru": "Создано", "es": "Creado el", "fr": "Créé le"}, "Eklenme Tarihi": {"en": "Added Date", "zh": "添加日期", "ru": "Дата добавления", "es": "Fecha de Alta", "fr": "Date d'Ajout"}, "Üye Sayısı": {"en": "Member Count", "zh": "成员数量", "ru": "Количество членов", "es": "Número de Miembros", "fr": "Nombre de Membres"}, "Tip / CoA Port": {"en": "Type / CoA Port", "zh": "类型 / CoA端口", "ru": "Тип / Порт CoA", "es": "Tipo / Puerto CoA", "fr": "Type / Port CoA"}, "Shared Secret": {"en": "Shared Secret", "zh": "共享密钥", "ru": "Общий ключ (Secret)", "es": "Clave Secreta Compartida", "fr": "Secret Partagé"}, "Yeni Kullanıcı Ekle": {"en": "Add New User", "zh": "添加新用户", "ru": "Добавить пользователя", "es": "Agregar Nuevo Usuario", "fr": "Ajouter Nouvel Utilisateur"}, "Toplu CSV Yükle": {"en": "Bulk CSV Upload", "zh": "批量CSV上传", "ru": "Массовая загрузка CSV", "es": "Cargar CSV Masivo", "fr": "Téléverser CSV Groupé"}, "CSV Dışa Aktar": {"en": "Export CSV", "zh": "导出CSV", "ru": "Экспорт в CSV", "es": "Exportar CSV", "fr": "Exporter CSV"}, "CSV Olarak İndir": {"en": "Download as CSV", "zh": "下载为CSV", "ru": "Скачать как CSV", "es": "Descargar como CSV", "fr": "Télécharger en CSV"}, "Düzenle": {"en": "Edit", "zh": "编辑", "ru": "Редактировать", "es": "Editar", "fr": "Modifier"}, "Sil": {"en": "Delete", "zh": "删除", "ru": "Удалить", "es": "Eliminar", "fr": "Supprimer"}, "Kaydet": {"en": "Save", "zh": "保存", "ru": "Сохранить", "es": "Guardar", "fr": "Enregistrer"}, "İptal": {"en": "Cancel", "zh": "取消", "ru": "Отмена", "es": "Cancelar", "fr": "Annuler"}, "Değişiklikleri Kaydet": {"en": "Save Changes", "zh": "保存更改", "ru": "Сохранить изменения", "es": "Guardar Cambios", "fr": "Enregistrer les modifications"}, "Ayarları Kaydet": {"en": "Save Settings", "zh": "保存设置", "ru": "Сохранить настройки", "es": "Guardar Ajustes", "fr": "Enregistrer les paramètres"}, "Yeni Grup Oluştur": {"en": "Create New Group", "zh": "创建新组", "ru": "Создать новую группу", "es": "Crear Nuevo Grupo", "fr": "Créer un Nouveau Groupe"}, "Yeni Ağ Cihazı Ekle": {"en": "Add Network Device", "zh": "添加网络设备", "ru": "Добавить сетевое устройство", "es": "Agregar Dispositivo de Red", "fr": "Ajouter Équipement Réseau"}, "Yeni MAC Adresi Ekle": {"en": "Add MAC Address", "zh": "添加MAC地址", "ru": "Добавить MAC-адрес", "es": "Agregar Dirección MAC", "fr": "Ajouter une Adresse MAC"}, "Kupon Üret": {"en": "Generate Vouchers", "zh": "生成优惠券", "ru": "Создать ваучеры", "es": "Generar Vales", "fr": "Générer des Coupons"}, "Süresi Dolanları Temizle": {"en": "Purge Expired", "zh": "清理过期券", "ru": "Очистить истекшие", "es": "Limpiar Expirados", "fr": "Purger les Expirés"}, "QR Kodlu Yazdır": {"en": "Print with QR Codes", "zh": "带二维码打印", "ru": "Печать с QR-кодом", "es": "Imprimir con Códigos QR", "fr": "Imprimer avec Codes QR"}, "Hayalet Oturumları Temizle": {"en": "Clean Ghost Sessions", "zh": "清理幽灵会话", "ru": "Очистить зависшие сессии", "es": "Limpiar Sesiones Fantasma", "fr": "Nettoyer Sessions Fantômes"}, "Ağdan At": {"en": "Disconnect", "zh": "强制下线", "ru": "Отключить", "es": "Desconectar", "fr": "Déconnecter"}, "Ağdan At (CoA)": {"en": "Disconnect (CoA)", "zh": "强制下线 (CoA)", "ru": "Отключить (CoA)", "es": "Desconectar (CoA)", "fr": "Déconnecter (CoA)"}, "Kayıtları Ara": {"en": "Search Records", "zh": "搜索记录", "ru": "Поиск записей", "es": "Buscar Registros", "fr": "Rechercher des Enregistrements"}, "Güncel Logları Al": {"en": "Fetch Latest Logs", "zh": "获取最新日志", "ru": "Обновить логи", "es": "Obtener Registros Recientes", "fr": "Actualiser les Journaux"}, "Yeni Web Yöneticisi Ekle": {"en": "Add Web Admin", "zh": "添加Web管理员", "ru": "Добавить веб-админа", "es": "Agregar Admin Web", "fr": "Ajouter Admin Web"}, "AlmaLinux Kullanıcısı Ekle": {"en": "Add AlmaLinux User", "zh": "添加AlmaLinux用户", "ru": "Добавить пользователя AlmaLinux", "es": "Agregar Usuario AlmaLinux", "fr": "Ajouter Utilisateur AlmaLinux"}, "Sadece SQL Yedeği Al": {"en": "Take SQL Backup Only", "zh": "仅备份SQL数据库", "ru": "Создать SQL-бэкап", "es": "Copia de Seguridad SQL", "fr": "Sauvegarder SQL Uniquement"}, "Tam Sistem İmajı Al (DB + Config)": {"en": "Full System Backup (DB + Config)", "zh": "完整系统镜像 (数据库+配置)", "ru": "Полный бэкап системы (БД + Конфиг)", "es": "Respaldo Completo (BD + Config)", "fr": "Sauvegarde Complète (BD + Config)"}, "Geri Yükle": {"en": "Restore", "zh": "恢复", "ru": "Восстановить", "es": "Restaurar", "fr": "Restaurer"}, "İndir": {"en": "Download", "zh": "下载", "ru": "Скачать", "es": "Descargar", "fr": "Télécharger"}, "Test Bildirimi Gönder": {"en": "Send Test Notification", "zh": "发送测试通知", "ru": "Отправить тестовое уведомление", "es": "Enviar Notificación de Prueba", "fr": "Envoyer une Notification Test"}, "Doğrula (radtest)": {"en": "Verify (radtest)", "zh": "验证 (radtest)", "ru": "Проверить (radtest)", "es": "Verificar (radtest)", "fr": "Vérifier (radtest)"}, "Şifremi Güncelle": {"en": "Update My Password", "zh": "更新我的密码", "ru": "Обновить мой пароль", "es": "Actualizar Mi Contraseña", "fr": "Mettre à jour mon mot de passe"}, "Tümünü Yönet": {"en": "Manage All", "zh": "管理全部", "ru": "Управлять всеми", "es": "Administrar Todo", "fr": "Gérer Tout"}, "Whitelist'e Al": {"en": "Add to Whitelist", "zh": "加入白名单", "ru": "В белый список", "es": "Añadir a Lista Blanca", "fr": "Ajouter en Liste Blanche"}, "Dondur": {"en": "Freeze / Suspend", "zh": "冻结", "ru": "Заморозить", "es": "Suspender", "fr": "Suspendre"}, "Yenile": {"en": "Refresh", "zh": "刷新", "ru": "Обновить", "es": "Actualizar", "fr": "Actualiser"}, "Yöneticiyi Oluştur": {"en": "Create Administrator", "zh": "创建管理员", "ru": "Создать администратора", "es": "Crear Administrador", "fr": "Créer Administrateur"}, "Yetkiyi Tanımla": {"en": "Define Permission", "zh": "赋予权限", "ru": "Назначить права", "es": "Definir Permiso", "fr": "Définir Permission"}, "Yükle ve İçe Aktar": {"en": "Upload and Import", "zh": "上传并导入", "ru": "Загрузить и импортировать", "es": "Subir e Importar", "fr": "Téléverser et Importer"}, "Oluştur": {"en": "Create", "zh": "创建", "ru": "Создать", "es": "Crear", "fr": "Créer"}, "Üret": {"en": "Generate", "zh": "生成", "ru": "Генерировать", "es": "Generar", "fr": "Générer"}, "Giriş Yap": {"en": "Sign In", "zh": "登录", "ru": "Войти", "es": "Iniciar Sesión", "fr": "Se Connecter"}, "Giriş Şifresi": {"en": "Login Password", "zh": "登录密码", "ru": "Пароль для входа", "es": "Contraseña de Acceso", "fr": "Mot de passe de connexion"}, "E-posta": {"en": "Email", "zh": "电子邮件", "ru": "Электронная почта", "es": "Correo Electrónico", "fr": "Adresse E-mail"}, "E-posta Adresi": {"en": "Email Address", "zh": "电子邮箱", "ru": "Email адрес", "es": "Dirección de Correo", "fr": "Adresse E-mail"}, "Grup / Profil": {"en": "Group / Profile", "zh": "用户组 / 配置文件", "ru": "Группа / Профиль", "es": "Grupo / Perfil", "fr": "Groupe / Profil"}, "Grup / Profil (Opsiyonel)": {"en": "Group / Profile (Optional)", "zh": "用户组 / 配置文件 (可选)", "ru": "Группа / Профиль (опционально)", "es": "Grupo / Perfil (Opcional)", "fr": "Groupe / Profil (Optionnel)"}, "Hız Limiti (Down/Up)": {"en": "Speed Limit (Down/Up)", "zh": "速度限制 (下行/上行)", "ru": "Ограничение скорости (Вх/Исх)", "es": "Límite de Velocidad (Bajada/Subida)", "fr": "Limite de Vitesse (Descendant/Montant)"}, "Dinamik VLAN ID": {"en": "Dynamic VLAN ID", "zh": "动态VLAN ID", "ru": "Динамический VLAN ID", "es": "VLAN ID Dinámico", "fr": "ID VLAN Dynamique"}, "Grup VLAN ID (Opsiyonel)": {"en": "Group VLAN ID (Optional)", "zh": "组VLAN ID (可选)", "ru": "VLAN ID группы (опционально)", "es": "VLAN ID del Grupo (Opcional)", "fr": "ID VLAN du Groupe (Optionnel)"}, "Statik IP (Opsiyonel)": {"en": "Static IP (Optional)", "zh": "静态IP (可选)", "ru": "Статический IP (опционально)", "es": "IP Estática (Opcional)", "fr": "IP Statique (Optionnel)"}, "Grup Hız Sınırı": {"en": "Group Speed Limit", "zh": "组速度限制", "ru": "Лимит скорости группы", "es": "Límite de Velocidad del Grupo", "fr": "Limite de Débit du Groupe"}, "Açıklama / Grup Notu": {"en": "Description / Group Note", "zh": "说明 / 组备注", "ru": "Описание / Заметка группы", "es": "Descripción / Nota de Grupo", "fr": "Description / Note de Groupe"}, "Açıklama / Not": {"en": "Description / Note", "zh": "说明 / 备注", "ru": "Описание / Заметка", "es": "Descripción / Nota", "fr": "Description / Note"}, "IP Adresi veya CIDR Bloğu": {"en": "IP Address or CIDR Block", "zh": "IP地址或CIDR块", "ru": "IP-адрес или подсеть CIDR", "es": "Dirección IP o Bloque CIDR", "fr": "Adresse IP ou Bloc CIDR"}, "Cihaz Kısa Adı": {"en": "Device Short Name", "zh": "设备简短名称", "ru": "Короткое имя устройства", "es": "Nombre Corto del Dispositivo", "fr": "Nom Court de l'Appareil"}, "Cihaz Tipi": {"en": "Device Type", "zh": "设备类型", "ru": "Тип устройства", "es": "Tipo de Dispositivo", "fr": "Type d'Appareil"}, "CoA Portu": {"en": "CoA Port", "zh": "CoA端口", "ru": "Порт CoA", "es": "Puerto CoA", "fr": "Port CoA"}, "Shared Secret (Ortak Gizli Anahtar)": {"en": "Shared Secret (Pre-Shared Key)", "zh": "共享密钥 (Shared Secret)", "ru": "Общий секретный ключ (Shared Secret)", "es": "Clave Secreta Compartida", "fr": "Clave Secreta Compartida (Shared Secret)"}, "Cihaz MAC Adresi": {"en": "Device MAC Address", "zh": "设备MAC地址", "ru": "MAC-адрес устройства", "es": "Dirección MAC del Dispositivo", "fr": "Adresse MAC de l'Appareil"}, "Atanacak VLAN (Opsiyonel)": {"en": "Assigned VLAN (Optional)", "zh": "分配的VLAN (可选)", "ru": "Назначаемый VLAN (опционально)", "es": "VLAN Asignada (Opcional)", "fr": "VLAN Assigné (Optionnel)"}, "Üretilecek Kupon Adedi": {"en": "Voucher Count to Generate", "zh": "生成优惠券数量", "ru": "Количество ваучеров", "es": "Cantidad de Vales a Generar", "fr": "Nombre de Coupons à Générer"}, "Geçerlilik Süresi": {"en": "Validity Duration", "zh": "有效期时长", "ru": "Срок действия", "es": "Duración de Validez", "fr": "Durée de Validité"}, "Sayaç Başlangıç Türü": {"en": "Accounting Start Trigger", "zh": "计费起始类型", "ru": "Тип запуска счетчика", "es": "Disparador de Inicio de Contador", "fr": "Déclencheur de Début de Compteur"}, "Tek Cihaz Kuralı": {"en": "Single Device Rule", "zh": "单一设备规则", "ru": "Правило одного устройства", "es": "Regla de Dispositivo Único", "fr": "Règle d'Appareil Unique"}, "Tek Cihaz Kuralı (Aynı anda 2. cihazla girişi engelle)": {"en": "Single Device Rule (Block simultaneous logins)", "zh": "单一设备规则 (阻止第二台设备同时登录)", "ru": "Правило 1 устройства (запретить одновременный вход)", "es": "Regla de Un Dispositivo (Bloquear 2do dispositivo)", "fr": "Règle d'Appareil Unique (Empêcher multi-connexions)"}, "Sadece Mesai Saatlerinde İzin Ver": {"en": "Allow Working Hours Only", "zh": "仅限工作时间允许", "ru": "Разрешать только в рабочие часы", "es": "Permitir Solo en Horario Laboral", "fr": "Autoriser Seulement Heures de Bureau"}, "Sadece Mesai Saatlerinde İzin Ver (Hafta içi 08:00 - 18:00)": {"en": "Working Hours Only (Mon-Fri 08:00 - 18:00)", "zh": "仅限工作时间 (周一至周五 08:00 - 18:00)", "ru": "Только в рабочие часы (Пн-Пт 08:00 - 18:00)", "es": "Solo Horario Laboral (Lun-Vie 08:00 - 18:00)", "fr": "Heures de Bureau Uniquement (Lun-Ven 08:00 - 18:00)"}, "Kurum / Şirket Başlığı": {"en": "Company / Organization Title", "zh": "企业 / 公司名称", "ru": "Название организации / компании", "es": "Título de Empresa / Organización", "fr": "Nom de l'Entreprise / Organisation"}, "Yayınlanan Wi-Fi SSID Adı (QR Kod İçin)": {"en": "Wi-Fi SSID Name (For QR Code)", "zh": "Wi-Fi SSID广播名称 (用于二维码)", "ru": "Имя Wi-Fi SSID (для QR-кода)", "es": "Nombre SSID de Wi-Fi (Para Código QR)", "fr": "Nom SSID Wi-Fi (Pour Code QR)"}, "Misafir VLAN ID": {"en": "Guest VLAN ID", "zh": "访客VLAN ID", "ru": "VLAN ID гостей", "es": "VLAN ID de Invitados", "fr": "ID VLAN Invités"}, "Sistem REST API Anahtarı (X-API-Key)": {"en": "System REST API Key (X-API-Key)", "zh": "系统REST API密钥 (X-API-Key)", "ru": "Ключ REST API системы (X-API-Key)", "es": "Clave REST API del Sistema (X-API-Key)", "fr": "Clé REST API Système (X-API-Key)"}, "Telegram Bot Token": {"en": "Telegram Bot Token", "zh": "Telegram Bot令牌", "ru": "Telegram Bot Token", "es": "Token del Bot de Telegram", "fr": "Jeton Bot Telegram"}, "Telegram Chat ID": {"en": "Telegram Chat ID", "zh": "Telegram聊天ID", "ru": "Telegram Chat ID", "es": "Chat ID de Telegram", "fr": "ID Chat Telegram"}, "Slack / Discord Webhook URL": {"en": "Slack / Discord Webhook URL", "zh": "Slack / Discord Webhook链接", "ru": "Slack / Discord Webhook URL", "es": "URL de Webhook Slack / Discord", "fr": "URL Webhook Slack / Discord"}, "Local NAS Secret": {"en": "Local NAS Secret", "zh": "本地NAS共享密钥", "ru": "Локальный пароль NAS Secret", "es": "Clave Secreta NAS Local", "fr": "Secret NAS Local"}, "AlmaLinux Sistem Kullanıcısı Seç": {"en": "Select AlmaLinux System User", "zh": "选择AlmaLinux系统用户", "ru": "Выберите пользователя AlmaLinux", "es": "Seleccionar Usuario del Sistema AlmaLinux", "fr": "Sélectionner Utilisateur Système AlmaLinux"}, "Görüntülenecek İsim": {"en": "Display Name", "zh": "显示名称", "ru": "Отображаемое имя", "es": "Nombre a Mostrar", "fr": "Nom Affiché"}, "Web Paneli Rolü": {"en": "Web Panel Role", "zh": "Web面板角色", "ru": "Роль в веб-панели", "es": "Rol en el Panel Web", "fr": "Rôle Panneau Web"}, "Erişim Rolü & Yetkileri": {"en": "Access Role & Permissions", "zh": "访问角色与权限", "ru": "Роль доступа и права", "es": "Rol de Acceso y Permisos", "fr": "Rôle d'Accès et Privilèges"}, "Hesap Durumu": {"en": "Account Status", "zh": "账户状态", "ru": "Статус аккаунта", "es": "Estado de Cuenta", "fr": "Statut du Compte"}, "Mevcut Şifreniz": {"en": "Current Password", "zh": "当前密码", "ru": "Текущий пароль", "es": "Contraseña Actual", "fr": "Mot de passe actuel"}, "Yeni Şifre": {"en": "New Password", "zh": "新密码", "ru": "Новый пароль", "es": "Nueva Contraseña", "fr": "Nouveau mot de passe"}, "Yeni Şifre (Tekrar)": {"en": "New Password (Confirm)", "zh": "确认新密码", "ru": "Подтверждение пароля", "es": "Confirmar Nueva Contraseña", "fr": "Confirmer le Nouveau Mot de Passe"}, "Kullanıcı Adı (veya MAC/Kupon)": {"en": "Username (or MAC/Voucher)", "zh": "用户名 (或MAC/优惠券)", "ru": "Имя пользователя (или MAC/ваучер)", "es": "Usuario (o MAC/Vale)", "fr": "Nom d'utilisateur (ou MAC/Coupon)"}, "İstemci IP Adresi": {"en": "Client IP Address", "zh": "客户端IP地址", "ru": "IP-адрес клиента", "es": "Dirección IP del Cliente", "fr": "Adresse IP Client"}, "CSV Dosyası Seç": {"en": "Select CSV File", "zh": "选择CSV文件", "ru": "Выберите файл CSV", "es": "Seleccionar Archivo CSV", "fr": "Choisir le Fichier CSV"}, "Canlı Otomatik Yenile (10sn)": {"en": "Live Auto Refresh (10s)", "zh": "实时自动刷新 (10秒)", "ru": "Автообновление (10 сек)", "es": "Auto-actualizar (10s)", "fr": "Auto-rafraîchissement (10s)"}, "Şifre Sıfırla (Değiştirmek istemiyorsanız boş bırakın)": {"en": "Reset Password (Leave blank to keep unchanged)", "zh": "重设密码 (如不修改请留空)", "ru": "Сброс пароля (оставьте пустым, если не меняете)", "es": "Restablecer Contraseña (Dejar en blanco si no cambia)", "fr": "Réinitialiser Mot de Passe (Laisser vide si inchangé)"}, "-- Özel Yapılandırma (Grup Yok) --": {"en": "-- Custom Config (No Group) --", "zh": "-- 自定义配置 (无用户组) --", "ru": "-- Пользовательская настройка (без группы) --", "es": "-- Configuración Personalizada (Sin Grupo) --", "fr": "-- Configuration Personnalisée (Sans Groupe) --"}, "1 Saat": {"en": "1 Hour", "zh": "1小时", "ru": "1 час", "es": "1 Hora", "fr": "1 Heure"}, "4 Saat": {"en": "4 Hours", "zh": "4小时", "ru": "4 часа", "es": "4 Horas", "fr": "4 Heures"}, "1 Gün (24 Saat)": {"en": "1 Day (24 Hours)", "zh": "1天 (24小时)", "ru": "1 день (24 часа)", "es": "1 Día (24 Horas)", "fr": "1 Jour (24 Heures)"}, "3 Gün": {"en": "3 Days", "zh": "3天", "ru": "3 дня", "es": "3 Días", "fr": "3 Jours"}, "1 Hafta": {"en": "1 Week", "zh": "1周", "ru": "1 неделя", "es": "1 Semana", "fr": "1 Semaine"}, "1 Ay": {"en": "1 Month", "zh": "1个月", "ru": "1 месяц", "es": "1 Mes", "fr": "1 Mois"}, "1 Adet Tek Kupon": {"en": "1 Single Voucher", "zh": "1张 单张优惠券", "ru": "1 одиночный ваучер", "es": "1 Vale Único", "fr": "1 Coupon Unique"}, "5 Adet Toplu Kupon": {"en": "5 Bulk Vouchers", "zh": "5张 批量优惠券", "ru": "5 ваучеров", "es": "5 Vales en Lote", "fr": "5 Coupons Groupés"}, "10 Adet Toplu Kupon": {"en": "10 Bulk Vouchers", "zh": "10张 批量优惠券", "ru": "10 ваучеров", "es": "10 Vales en Lote", "fr": "10 Coupons Groupés"}, "20 Adet Toplu Kupon": {"en": "20 Bulk Vouchers", "zh": "20张 批量优惠券", "ru": "20 ваучеров", "es": "20 Vales en Lote", "fr": "20 Coupons Groupés"}, "5 Mbps / 2 Mbps (Standart Misafir)": {"en": "5 Mbps / 2 Mbps (Standard Guest)", "zh": "5 Mbps / 2 Mbps (标准访客)", "ru": "5 Мбит/с / 2 Мбит/с (Стандарт)", "es": "5 Mbps / 2 Mbps (Invitado Estándar)", "fr": "5 Mbps / 2 Mbps (Invité Standard)"}, "İlk Bağlantıda Başlat (First-Login) - Masada Bekleyebilir": {"en": "Start on First Connection (First-Login) - Can wait unused", "zh": "首次连接时开始 (First-Login) - 可预先发放", "ru": "Запуск при первом подключении (First-Login) - может храниться", "es": "Iniciar en Primer Uso (First-Login) - Puede esperar", "fr": "Démarrer à la 1ère Connexion (First-Login) - Peut attendre"}, "Şu Andan İtibaren Başlat (Fixed Expiration)": {"en": "Start Immediately (Fixed Expiration)", "zh": "从现在立即开始计时 (固定到期时间)", "ru": "Запустить прямо сейчас (фиксированный срок)", "es": "Iniciar Ahora Mismo (Expiración Fija)", "fr": "Démarrer Immédiatement (Expiration Fixe)"}, "Henüz kayıtlı kullanıcı bulunmuyor.": {"en": "No registered users found yet.", "zh": "暂无已注册用户。", "ru": "Зарегистрированных пользователей пока нет.", "es": "No hay usuarios registrados todavía.", "fr": "Aucun utilisateur enregistré pour le moment."}, "Henüz oluşturulmuş grup bulunmuyor.": {"en": "No groups created yet.", "zh": "暂未创建任何用户组。", "ru": "Созданных групп пока нет.", "es": "No hay grupos creados todavía.", "fr": "Aucun groupe créé pour le moment."}, "Henüz kayıtlı NAS cihazı bulunmuyor.": {"en": "No registered NAS devices yet.", "zh": "暂无已注册的NAS设备。", "ru": "Зарегистрированных устройств NAS пока нет.", "es": "No hay dispositivos NAS registrados todavía.", "fr": "Aucun équipement NAS enregistré pour le moment."}, "Henüz izinli MAC adresi eklenmedi.": {"en": "No allowed MAC addresses added yet.", "zh": "暂未添加任何允许的MAC地址。", "ru": "Разрешенных MAC-адресов пока нет.", "es": "No se han añadido direcciones MAC todavía.", "fr": "Aucune adresse MAC autorisée pour le moment."}, "Henüz üretilmiş kupon bulunmuyor.": {"en": "No generated vouchers yet.", "zh": "暂无已生成的优惠券。", "ru": "Созданных ваучеров пока нет.", "es": "No hay vales generados todavía.", "fr": "Aucun coupon généré pour le moment."}, "Henüz geçmiş oturum kaydı bulunmuyor.": {"en": "No past session logs found yet.", "zh": "暂无历史会话记录。", "ru": "История сессий пока пуста.", "es": "No hay registros de sesiones anteriores.", "fr": "Aucun historique de session pour le moment."}, "Henüz denetim kaydı oluşmadı.": {"en": "No audit records generated yet.", "zh": "暂无审计日志记录。", "ru": "Записей аудита пока нет.", "es": "No hay registros de auditoría todavía.", "fr": "Aucun enregistrement d'audit pour le moment."}, "Henüz yedek dosyası bulunmuyor.": {"en": "No backup files available yet.", "zh": "暂无备份文件。", "ru": "Файлов резервных копий пока нет.", "es": "No hay archivos de respaldo todavía.", "fr": "Aucun fichier de sauvegarde pour le moment."}, "Şu an aktif bağlı cihaz yok.": {"en": "No currently connected active devices.", "zh": "当前无在线连接设备。", "ru": "Сейчас нет активных подключений.", "es": "No hay dispositivos conectados activamente.", "fr": "Aucun appareil connecté activement."}, "Şu an aktif bağlı cihaz bulunmuyor.": {"en": "No currently connected active devices.", "zh": "当前无在线连接设备。", "ru": "Сейчас нет активных подключений.", "es": "No hay dispositivos conectados activamente.", "fr": "Aucun appareil connecté activement."}, "Yönetici kaydı bulunamadı.": {"en": "No administrator records found.", "zh": "未找到管理员记录。", "ru": "Записи администраторов не найдены.", "es": "No se encontraron registros de administrador.", "fr": "Aucun enregistrement d'administrateur trouvé."}, "Süper Yönetici": {"en": "Super Administrator", "zh": "超级管理员", "ru": "Суперадминистратор", "es": "Super Administrador", "fr": "Super Administrateur"}, "Ağ Yöneticisi": {"en": "Network Administrator", "zh": "网络管理员", "ru": "Сетевой администратор", "es": "Administrador de Red", "fr": "Administrateur Réseau"}, "Kupon Operatörü": {"en": "Voucher Operator", "zh": "优惠券操作员", "ru": "Оператор ваучеров", "es": "Operador de Vales", "fr": "Opérateur de Coupons"}, "Denetçi (Salt Okunur)": {"en": "Auditor (Read Only)", "zh": "审计员 (只读)", "ru": "Аудитор (только чтение)", "es": "Auditor (Solo Lectura)", "fr": "Auditeur (Lecture seule)"}, "Denetçi": {"en": "Auditor", "zh": "审计员", "ru": "Аудитор", "es": "Auditor", "fr": "Auditeur"}, "Süper Yönetici (Tüm Sistem Ayarları, Yedekleme ve Yönetici Ekleme)": {"en": "Super Administrator (All System Settings, Backups and Admin Management)", "zh": "超级管理员 (全部系统设置、备份及管理员权限)", "ru": "Суперадминистратор (все настройки, бэкапы и админы)", "es": "Super Administrador (Todos los ajustes, copias y admins)", "fr": "Super Administrateur (Tous paramètres, sauvegardes et admins)"}, "Ağ Yöneticisi (Kullanıcılar, VLAN, NAS, MAC ve Oturum Yönetimi)": {"en": "Network Administrator (Users, VLAN, NAS, MAC and Session Management)", "zh": "网络管理员 (用户、VLAN、NAS、MAC及会话管理)", "ru": "Сетевой администратор (пользователи, VLAN, NAS, MAC и сессии)", "es": "Administrador de Red (Usuarios, VLAN, NAS, MAC y Sesiones)", "fr": "Administrateur Réseau (Utilisateurs, VLAN, NAS, MAC et Sessions)"}, "Kupon Operatörü (Sadece Misafir Wi-Fi Kuponları)": {"en": "Voucher Operator (Guest Wi-Fi Vouchers Only)", "zh": "优惠券操作员 (仅限访客Wi-Fi优惠券)", "ru": "Оператор ваучеров (только гостевые ваучеры Wi-Fi)", "es": "Operador de Vales (Solo Vales Wi-Fi de Invitados)", "fr": "Opérateur de Coupons (Uniquement Coupons Wi-Fi Invités)"}, "Denetçi (Sadece 5651 Yasal Logları ve Oturumları İzleme)": {"en": "Auditor (Monitor 5651 Legal Logs and Sessions Only)", "zh": "审计员 (仅限监控5651法律日志与会话)", "ru": "Аудитор (только мониторинг логов 5651 и сессий)", "es": "Auditor (Solo Monitoreo de Registros 5651 y Sesiones)", "fr": "Auditeur (Surveillance Journaux 5651 et Sessions Uniquement)"}, "Süper Yönetici (Tam Yetkili)": {"en": "Super Administrator (Full Access)", "zh": "超级管理员 (完全控制)", "ru": "Суперадминистратор (полный доступ)", "es": "Super Administrador (Control Total)", "fr": "Super Administrateur (Accès Total)"}, "Aktif": {"en": "Active", "zh": "活跃", "ru": "Активен", "es": "Activo", "fr": "Actif"}, "Devre Dışı": {"en": "Disabled", "zh": "已禁用", "ru": "Отключен", "es": "Desactivado", "fr": "Désactivé"}, "Devre Dışı (Askıya Alınmış)": {"en": "Disabled (Suspended)", "zh": "已禁用 (挂起)", "ru": "Отключен (приостановлен)", "es": "Desactivado (Suspendido)", "fr": "Désactivé (Suspendu)"}, "Kilitli": {"en": "Locked", "zh": "已锁定", "ru": "Заблокирован", "es": "Bloqueado", "fr": "Verrouillé"}, "Web Hesabı": {"en": "Web Account", "zh": "Web账户", "ru": "Веб-аккаунт", "es": "Cuenta Web", "fr": "Compte Web"}, "AlmaLinux OS": {"en": "AlmaLinux OS", "zh": "AlmaLinux系统", "ru": "AlmaLinux OS", "es": "AlmaLinux OS", "fr": "AlmaLinux OS"}, "Canlı": {"en": "Live", "zh": "在线", "ru": "Онлайн", "es": "En Vivo", "fr": "En Ligne"}, "Canlı Bağlı": {"en": "Live Connected", "zh": "在线连接", "ru": "Активно подключен", "es": "Conectado en Vivo", "fr": "Connecté en Direct"}, "Hazır": {"en": "Ready", "zh": "就绪", "ru": "Готов", "es": "Listo", "fr": "Prêt"}, "Askıda": {"en": "Pending / Suspended", "zh": "挂起中", "ru": "В ожидании", "es": "Suspendido", "fr": "En Attente"}, "Erişilebilir": {"en": "Reachable", "zh": "可达", "ru": "Доступен", "es": "Accesible", "fr": "Accessible"}, "Yanıt Yok": {"en": "No Response", "zh": "无响应", "ru": "Нет ответа", "es": "Sin Respuesta", "fr": "Aucune Réponse"}, "Limitsiz": {"en": "Unlimited", "zh": "无限制", "ru": "Безлимитный", "es": "Ilimitado", "fr": "Illimité"}, "SQL Veritabanı": {"en": "SQL Database", "zh": "SQL数据库", "ru": "База данных SQL", "es": "Base de Datos SQL", "fr": "Base de Données SQL"}, "Tam Sistem (DB+Config)": {"en": "Full System (DB+Config)", "zh": "完整系统 (数据库+配置)", "ru": "Полная система (БД+Конфиг)", "es": "Sistema Completo (BD+Config)", "fr": "Système Complet (BD+Config)"}, "Otomatik Keşif Havuzu": {"en": "Auto Discovery Pool", "zh": "自动发现池", "ru": "Пул автообнаружения", "es": "Grupo de Detección Automática", "fr": "Pool de Découverte Automatique"}, "Güvenli Yönetim Paneli": {"en": "Secure Management Console", "zh": "安全管理控制台", "ru": "Панель безопасного управления", "es": "Consola de Gestión Segura", "fr": "Console d'Administration Sécurisée"}, "Kameranızla QR kodu taratın": {"en": "Scan the QR code with your camera", "zh": "请使用手机摄像头扫描二维码", "ru": "Отсканируйте QR-код камерой", "es": "Escanee el código QR con su cámara", "fr": "Scannez le code QR avec votre appareil"}, "Şifre Değiştir": {"en": "Change Password", "zh": "修改密码", "ru": "Изменить пароль", "es": "Cambiar Contraseña", "fr": "Changer le mot de passe"}, "Linux OS Şifre Yönetimi": {"en": "Linux OS Password Management", "zh": "Linux操作系统密码管理", "ru": "Управление паролем Linux OS", "es": "Gestión de Contraseña Linux OS", "fr": "Gestion du Mot de Passe Linux OS"}, "RBAC & Hibrit Doğrulama": {"en": "RBAC & Hybrid Authentication", "zh": "RBAC与混合认证", "ru": "RBAC и гибридная аутентификация", "es": "RBAC y Autenticación Híbrida", "fr": "RBAC & Authentification Hybride"}, "Kullanıcıyı Düzenle": {"en": "Edit User", "zh": "编辑用户", "ru": "Редактировать пользователя", "es": "Editar Usuario", "fr": "Modifier Utilisateur"}, "Yöneticiyi Düzenle": {"en": "Edit Administrator", "zh": "编辑管理员", "ru": "Редактировать администратора", "es": "Editar Administrador", "fr": "Modifier Administrateur"}, "Kullanıcılar": {"en": "Users", "zh": "用户", "ru": "Пользователи", "es": "Usuarios", "fr": "Utilisateurs"}, "Yöneticiler": {"en": "Admins", "zh": "管理员", "ru": "Администраторы", "es": "Administradores", "fr": "Administrateurs"}, "Gruplar": {"en": "Groups", "zh": "用户组", "ru": "Группы", "es": "Grupos", "fr": "Groupes"}, "Oturumlar": {"en": "Sessions", "zh": "会话", "ru": "Сессии", "es": "Sesiones", "fr": "Sessions"}, "Kuponlar": {"en": "Vouchers", "zh": "优惠券", "ru": "Ваучеры", "es": "Vales", "fr": "Coupons"}, "Cihazlar": {"en": "Devices", "zh": "设备", "ru": "Устройства", "es": "Dispositivos", "fr": "Appareils"}, "Loglar": {"en": "Logs", "zh": "日志", "ru": "Журналы", "es": "Registros", "fr": "Journaux"}, "Yedekler": {"en": "Backups", "zh": "备份", "ru": "Резервные копии", "es": "Copias de Seguridad", "fr": "Sauvegardes"}, "Ayarlar": {"en": "Settings", "zh": "设置", "ru": "Настройки", "es": "Configuración", "fr": "Paramètres"}, "Test": {"en": "Diagnostic Test", "zh": "测试", "ru": "Тест", "es": "Prueba", "fr": "Test"}, "Profil": {"en": "Profile", "zh": "个人资料", "ru": "Профиль", "es": "Perfil", "fr": "Profil"}, "5 Mbps / 2 Mbps": {"en": "5 Mbps / 2 Mbps", "zh": "5 Mbps / 2 Mbps", "ru": "5 Мбит/с / 2 Мбит/с", "es": "5 Mbps / 2 Mbps", "fr": "5 Mbps / 2 Mbps"}, "10 Mbps / 5 Mbps": {"en": "10 Mbps / 5 Mbps", "zh": "10 Mbps / 5 Mbps", "ru": "10 Мбит/с / 5 Мбит/с", "es": "10 Mbps / 2 Mbps", "fr": "10 Mbps / 5 Mbps"}, "25 Mbps / 10 Mbps": {"en": "25 Mbps / 10 Mbps", "zh": "25 Mbps / 10 Mbps", "ru": "25 Мбит/с / 10 Мбит/с", "es": "25 Mbps / 10 Mbps", "fr": "25 Mbps / 10 Mbps"}, "50 Mbps / 20 Mbps": {"en": "50 Mbps / 20 Mbps", "zh": "50 Mbps / 20 Mbps", "ru": "50 Мбит/с / 20 Мбит/с", "es": "50 Mbps / 20 Mbps", "fr": "50 Mbps / 20 Mbps"}, "100 Mbps / 50 Mbps": {"en": "100 Mbps / 50 Mbps", "zh": "100 Mbps / 50 Mbps", "ru": "100 Мбит/с / 50 Мбит/с", "es": "100 Mbps / 50 Mbps", "fr": "100 Mbps / 50 Mbps"}, "Ara...": {"en": "Search...", "zh": "搜索...", "ru": "Поиск...", "es": "Buscar...", "fr": "Rechercher..."}, "Kullanıcı adı veya IP ara...": {"en": "Search username or IP...", "zh": "搜索用户名或IP...", "ru": "Поиск по имени или IP...", "es": "Buscar usuario o IP...", "fr": "Rechercher utilisateur ou IP..."}, "Kayıt bulunamadı.": {"en": "No records found.", "zh": "未找到记录。", "ru": "Записей не найдено.", "es": "No se encontraron registros.", "fr": "Aucun enregistrement trouvé."}, "Son 50 İşlem": {"en": "Last 50 Actions", "zh": "最近50条操作", "ru": "Последние 50 действий", "es": "Últimas 50 Acciones", "fr": "50 Dernières Actions"}, "FreeRADIUS": {"en": "FreeRADIUS", "zh": "FreeRADIUS", "ru": "FreeRADIUS", "es": "FreeRADIUS", "fr": "FreeRADIUS"}, "TACACS+ Yönetimi": {"en": "TACACS+ Management", "zh": "TACACS+ 管理", "ru": "Управление TACACS+", "es": "Gestión TACACS+", "fr": "Gestion TACACS+"}, "SNMP NMS / Ağ İzleme": {"en": "SNMP NMS / Network Monitor", "zh": "SNMP NMS / 网络监控", "ru": "SNMP NMS / Мониторинг сети", "es": "SNMP NMS / Monitoreo de Red", "fr": "SNMP NMS / Surveillance Réseau"}, "Cihaz Envanteri": {"en": "Device Inventory", "zh": "设备资产清单", "ru": "Инвентарь устройств", "es": "Inventario de Dispositivos", "fr": "Inventaire des Équipements"}, "Otomatik Ağ Keşfi": {"en": "Auto Network Discovery", "zh": "自动网络发现", "ru": "Автообнаружение сети", "es": "Descubrimiento Automático de Red", "fr": "Découverte Automatique Réseau"}, "Arayüz Trafik Grafiği": {"en": "Interface Traffic Graph", "zh": "接口流量图表", "ru": "График трафика интерфейса", "es": "Gráfico de Tráfico de Interfaz", "fr": "Graphique du Trafic d'Interface"}, "Cihaz Sağlığı & Metrikler": {"en": "Device Health & Metrics", "zh": "设备运行状况与指标", "ru": "Состояние и метрики устройств", "es": "Salud y Métricas del Dispositivo", "fr": "État et Métriques de l'Équipement"}, "Alarm & Uyarı Merkezi": {"en": "Alarm & Alert Center", "zh": "告警与通知中心", "ru": "Центр тревог и предупреждений", "es": "Centro de Alarmas y Alertas", "fr": "Centre d'Alarmes et Alertes"}, "TACACS+ Cihazları (NAS)": {"en": "TACACS+ Clients (NAS)", "zh": "TACACS+ 客户端 (NAS)", "ru": "TACACS+ Клиенты (NAS)", "es": "Clientes TACACS+ (NAS)", "fr": "Clients TACACS+ (NAS)"}, "Komut Yetki Kuralları": {"en": "Command Authorization Rules", "zh": "命令授权规则", "ru": "Правила авторизации команд", "es": "Reglas de Autorización de Comandos", "fr": "Règles d'Autorisation de Commandes"}, "Canlı Komut Denetim Kayıtları": {"en": "Live Command Accounting Logs", "zh": "实时命令审计日志", "ru": "Журнал аудита команд", "es": "Registros de Auditoría de Comandos", "fr": "Journaux d'Audit de Commandes"}, "Yetki Seviyesi (Privilege 0-15)": {"en": "Privilege Level (0-15)", "zh": "特权级别 (0-15)", "ru": "Уровень привилегий (0-15)", "es": "Nivel de Privilegio (0-15)", "fr": "Niveau de Privilège (0-15)"}, "Yeni Cihaz Ekle": {"en": "Add New Device", "zh": "添加新设备", "ru": "Добавить новое устройство", "es": "Agregar Nuevo Dispositivo", "fr": "Ajouter un Équipement"}, "Yeni Kural Ekle": {"en": "Add New Rule", "zh": "添加新规则", "ru": "Добавить новое правило", "es": "Agregar Nueva Regla", "fr": "Ajouter une Règle"}, "Canlı Kural Testi": {"en": "Live Rule Tester", "zh": "实时规则测试", "ru": "Тестирование правил", "es": "Prueba de Reglas en Vivo", "fr": "Testeur de Règles en Direct"}, "Test Et": {"en": "Test", "zh": "测试", "ru": "Тестировать", "es": "Probar", "fr": "Tester"}, "Ağı Tara ve Keşfet": {"en": "Scan and Discover Network", "zh": "扫描并发现网络", "ru": "Сканировать и обнаружить сеть", "es": "Escanear y Descubrir Red", "fr": "Scanner et Découvrir le Réseau"}, "Şimdi Yokla": {"en": "Poll Now", "zh": "立即轮询", "ru": "Опросить сейчас", "es": "Sondear Ahora", "fr": "Interroger Maintenant"}, "Gelen Trafik (Inbound)": {"en": "Inbound Traffic", "zh": "入站流量", "ru": "Входящий трафик", "es": "Tráfico Entrante", "fr": "Trafic Entrant"}, "Giden Trafik (Outbound)": {"en": "Outbound Traffic", "zh": "出站流量", "ru": "Исходящий трафик", "es": "Tráfico Saliente", "fr": "Trafic Sortant"}, "CPU Yükü": {"en": "CPU Load", "zh": "CPU 负载", "ru": "Загрузка ЦП", "es": "Carga de CPU", "fr": "Charge CPU"}, "Bellek Kullanımı": {"en": "Memory Usage", "zh": "内存使用率", "ru": "Использование памяти", "es": "Uso de Memoria", "fr": "Utilisation Mémoire"}, "Sıcaklık": {"en": "Temperature", "zh": "温度", "ru": "Температура", "es": "Temperatura", "fr": "Température"}, "Sistem Uptime": {"en": "System Uptime", "zh": "系统运行时间", "ru": "Время работы системы", "es": "Tiempo de Actividad", "fr": "Temps de Fonctionnement"}, "Aktif Alarmlar": {"en": "Active Alarms", "zh": "活动告警", "ru": "Активные тревоги", "es": "Alarmas Activas", "fr": "Alarmes Actives"}, "Çözülen Alarmlar": {"en": "Resolved Alarms", "zh": "已解决告警", "ru": "Устраненные тревоги", "es": "Alarmas Resueltas", "fr": "Alarmes Résolues"}, "Onayla": {"en": "Acknowledge", "zh": "确认", "ru": "Подтвердить", "es": "Reconocer", "fr": "Acquitter"}, "Webhook Ayarları": {"en": "Webhook Settings", "zh": "Webhook 设置", "ru": "Настройки Webhook", "es": "Configuración de Webhook", "fr": "Paramètres Webhook"}, "Çevrimiçi Cihazlar": {"en": "Online Devices", "zh": "在线设备", "ru": "Устройства онлайн", "es": "Dispositivos en Línea", "fr": "Équipements en Ligne"}, "Çevrimdışı Cihazlar": {"en": "Offline Devices", "zh": "离线设备", "ru": "Офлайн устройства", "es": "Dispositivos Fuera de Línea", "fr": "Équipements Hors Ligne"}, "İzlenen Portlar": {"en": "Monitored Interfaces", "zh": "监控端口", "ru": "Мониторинг портов", "es": "Puertos Monitoreados", "fr": "Ports Surveillés"}, "Komut Deseni (Regex)": {"en": "Command Pattern (Regex)", "zh": "命令模式 (正则表达式)", "ru": "Шаблон команды (Regex)", "es": "Patrón de Comando (Regex)", "fr": "Modèle de Commande (Regex)"}, "İzin Ver": {"en": "Permit", "zh": "允许", "ru": "Разрешить", "es": "Permitir", "fr": "Autoriser"}, "Engelle": {"en": "Deny", "zh": "拒绝", "ru": "Запретить", "es": "Denegar", "fr": "Refuser"}, "Öncelik": {"en": "Priority", "zh": "优先级", "ru": "Приоритет", "es": "Prioridad", "fr": "Priorité"}, "Ortak Parola (Secret)": {"en": "Shared Secret", "zh": "共享密钥", "ru": "Общий секрет", "es": "Clave Secreta Compartida", "fr": "Secret Partagé"}, "Üretici / Marka": {"en": "Vendor / Brand", "zh": "厂商 / 品牌", "ru": "Производитель / Бренд", "es": "Fabricante / Marca", "fr": "Fabricant / Marque"}, "Servis & Daemon Durumu": {"en": "Service & Daemon Status", "zh": "服务与守护进程状态", "ru": "Статус службы и демона", "es": "Estado del Servicio y Demonio", "fr": "État du Service et Démon"}, "Portlar & Trafik": {"en": "Ports & Traffic", "zh": "端口与流量", "ru": "Порты и трафик", "es": "Puertos y Tráfico", "fr": "Ports & Trafic"}, "İnteraktif Ağ Topolojisi": {"en": "Interactive Network Topology", "zh": "交互式网络拓扑", "ru": "Интерактивная топология сети", "es": "Topología de Red Interactiva", "fr": "Topologie de Réseau Interactive"}, "Ağ Topolojisi": {"en": "Network Topology", "zh": "网络拓扑", "ru": "Топология сети", "es": "Topología de Red", "fr": "Topologie du Réseau"}, "Canlı Ağ Topolojisi Haritası": {"en": "Live Network Topology Map", "zh": "实时网络拓扑图", "ru": "Живая карта топологии сети", "es": "Mapa de Topología de Red en Vivo", "fr": "Carte de Topologie Réseau en Direct"}, "Topoloji Lejantı": {"en": "Topology Legend", "zh": "拓扑图例", "ru": "Легенда топологии", "es": "Leyenda de Topología", "fr": "Légende de la Topologie"}, "Cihaz Çevrimiçi (Online)": {"en": "Device Online", "zh": "设备在线", "ru": "Устройство в сети", "es": "Dispositivo En Línea", "fr": "Appareil En Ligne"}, "Cihaz Kesintide (Offline)": {"en": "Device Offline", "zh": "设备离线", "ru": "Устройство отключено", "es": "Dispositivo Desconectado", "fr": "Appareil Hors Ligne"}, "Görünümü Sığdır": {"en": "Fit View", "zh": "适应视图", "ru": "Вместить в экран", "es": "Ajustar Vista", "fr": "Ajuster la Vue"}, "Fizik: Açık": {"en": "Physics: On", "zh": "物理引擎: 开启", "ru": "Физика: Вкл", "es": "Física: Activada", "fr": "Physique: Activée"}, "Fizik: Sabit": {"en": "Physics: Fixed", "zh": "物理引擎: 固定", "ru": "Физика: Фикс", "es": "Física: Fija", "fr": "Physique: Fixée"}, "Trafik Gör": {"en": "View Traffic", "zh": "查看流量", "ru": "Посмотреть трафик", "es": "Ver Tráfico", "fr": "Voir le Trafic"}, "Oturumunuz Kapanmak Üzere!": {"en": "Your Session Is About To Expire!", "zh": "您的会话即将过期！", "ru": "Срок действия вашей сессии истекает!", "es": "¡Su sesión está a punto de caducar!", "fr": "Votre session est sur le point d'expirer !"}, "Hareketsizlik nedeniyle oturumunuz": {"en": "Due to inactivity, your session", "zh": "由于无操作，您的会话", "ru": "Из-за неактивности ваша сессия", "es": "Debido a la inactividad, su sesión", "fr": "En raison de l'inactivité, votre session"}, "saniye içinde otomatik sonlandırılacaktır.": {"en": "will be automatically closed in seconds.", "zh": "将在几秒钟内自动关闭。", "ru": "будет автоматически закрыта через секунд.", "es": "se cerrará automáticamente en segundos.", "fr": "sera automatiquement fermée dans quelques secondes."}, "Oturumu Sonlandır": {"en": "End Session", "zh": "结束会话", "ru": "Завершить сессию", "es": "Finalizar Sesión", "fr": "Terminer la Session"}, "Oturumu Uzat": {"en": "Extend Session", "zh": "延长会话", "ru": "Продлить сессию", "es": "Extender Sesión", "fr": "Prolonger la Session"}, "Tek Dosya Kaynak Kod & Veri Paketi (SCP ve Taşınabilirlik)": {"en": "Single-File Source & Data Bundle (SCP & Portability)", "zh": "单文件源码与数据包（SCP与可移植性）", "ru": "Пакет исходного кода и данных в одном файле (SCP)", "es": "Paquete de Código Fuente y Datos en Archivo Único (SCP)", "fr": "Ensemble Code Source et Données en Fichier Unique (SCP)"}, "Paketi Şimdi Güncelle / Oluştur": {"en": "Update / Generate Bundle Now", "zh": "立即更新/生成数据包", "ru": "Обновить / Создать пакет сейчас", "es": "Actualizar / Generar Paquete Ahora", "fr": "Mettre à jour / Générer le Paquet"}, "Paketi Doğrudan İndir (.tar.gz)": {"en": "Download Bundle Directly (.tar.gz)", "zh": "直接下载数据包 (.tar.gz)", "ru": "Скачать пакет напрямую (.tar.gz)", "es": "Descargar Paquete Directamente (.tar.gz)", "fr": "Télécharger Directement le Paquet (.tar.gz)"}, "FreeRADIUS Kullanıcıları": {"en": "FreeRADIUS Users", "zh": "FreeRADIUS 用户", "ru": "Пользователи FreeRADIUS", "es": "Usuarios FreeRADIUS", "fr": "Utilisateurs FreeRADIUS"}, "Toplu & Misafir Kullanıcılar": {"en": "Bulk & Guest Users", "zh": "批量与访客用户", "ru": "Массовые и гостевые пользователи", "es": "Usuarios Masivos y de Invitados", "fr": "Utilisateurs en Masse et Invités"}, "Rol & Yetki Yönetimi (Erişim Matrisi)": {"en": "Role & Permission Management (Access Matrix)", "zh": "角色与权限管理 (访问矩阵)", "ru": "Управление ролями и правами (Матрица доступа)", "es": "Gestión de Roles y Permisos (Matriz de Acceso)", "fr": "Gestion des Rôles et Permissions (Matrice d'Accès)"}, "Yeni Rol Tanımla": {"en": "Define New Role", "zh": "定义新角色", "ru": "Создать новую роль", "es": "Definir Nuevo Rol", "fr": "Définir un Nouveau Rôle"}, "Rol Adı": {"en": "Role Name", "zh": "角色名称", "ru": "Название роли", "es": "Nombre del Rol", "fr": "Nom du Rôle"}, "Rol Kodu": {"en": "Role Code", "zh": "角色代码", "ru": "Код роли", "es": "Código del Rol", "fr": "Code du Rôle"}, "Erişilebilir Sayfalar": {"en": "Accessible Pages", "zh": "可访问页面", "ru": "Доступные страницы", "es": "Páginas Accesibles", "fr": "Pages Accessibles"}, "Kimlik Doğrulama Türü": {"en": "Authentication Type", "zh": "身份验证类型", "ru": "Тип аутентификации", "es": "Tipo de Autenticación", "fr": "Type d'Authentification"}, "Panel Veritabanı Şifresi": {"en": "Panel Database Password", "zh": "面板数据库密码", "ru": "Пароль базы данных панели", "es": "Contraseña de Base de Datos del Panel", "fr": "Mot de passe de la Base de Données du Panneau"}, "Linux Sistem Hesabı (PAM / OS Auth)": {"en": "Linux System Account (PAM / OS Auth)", "zh": "Linux系统账户 (PAM / 系统认证)", "ru": "Системная учетная запись Linux (PAM / ОС)", "es": "Cuenta de Sistema Linux (PAM / OS Auth)", "fr": "Compte Système Linux (PAM / Authentification OS)"}, "Yeni Yönetici Hesabı Oluştur": {"en": "Create Administrator Account", "zh": "创建管理员账户", "ru": "Создать учетную запись администратора", "es": "Crear Cuenta de Administrador", "fr": "Créer un Compte Administrateur"}, "Kaynak": {"en": "Source", "zh": "来源", "ru": "Источник", "es": "Origen", "fr": "Source"}, "Radius DB": {"en": "Radius DB", "zh": "Radius数据库", "ru": "База Radius", "es": "BD Radius", "fr": "BD Radius"}, "Wireless / Hotspot": {"en": "Wireless / Hotspot", "zh": "无线 / 热点", "ru": "Беспроводной / Хотспот", "es": "Inalámbrico / Hotspot", "fr": "Sans fil / Point d'accès"}, "Kupon / Voucher": {"en": "Coupon / Voucher", "zh": "优惠券 / 凭单", "ru": "Купон / Ваучер", "es": "Cupón / Vale", "fr": "Coupon / Bon"}, "Toplu CSV": {"en": "Bulk CSV", "zh": "批量CSV", "ru": "Массовый CSV", "es": "CSV Masivo", "fr": "CSV en Masse"}, "NTP Zaman Sunucusu": {"en": "NTP Time Server", "zh": "NTP时间服务器", "ru": "NTP-сервер времени", "es": "Servidor de Hora NTP", "fr": "Serveur de Temps NTP"}, "NTP Zaman Sunucusu (Network Time Protocol)": {"en": "NTP Time Server (Network Time Protocol)", "zh": "NTP时间服务器 (网络时间协议)", "ru": "Сервер времени NTP (Network Time Protocol)", "es": "Servidor de Hora NTP (Network Time Protocol)", "fr": "Serveur de Temps NTP (Network Time Protocol)"}, "Oturum Güvenliği": {"en": "Session Security", "zh": "会话安全与2FA", "ru": "Безопасность сессий", "es": "Seguridad de Sesión", "fr": "Sécurité de Session"}, "Oturum Güvenliği & 2FA Yönetim Merkezi": {"en": "Session Security & 2FA Control Center", "zh": "会话安全与2FA管理中心", "ru": "Центр безопасности сессий и 2FA", "es": "Seguridad de Sesión y Centro 2FA", "fr": "Sécurité de Session & Centre 2FA"}, "Sistem Ayarları": {"en": "System Settings", "zh": "系统设置", "ru": "Системные настройки", "es": "Ajustes del Sistema", "fr": "Paramètres Système"}, "Servis & Sistem Yeniden Başlat": {"en": "Service & System Restart", "zh": "服务与系统重启", "ru": "Перезапуск служб и системы", "es": "Reinicio de Servicios y Sistema", "fr": "Redémarrage des Services & Système"}, "Sistem & Ağ Servisleri Yönetimi": {"en": "System & Network Services Management", "zh": "系统与网络服务管理", "ru": "Управление системными и сетевыми службами", "es": "Gestión de Servicios de Sistema y Red", "fr": "Gestion des Services Système & Réseau"}, "Swagger API": {"en": "Swagger API", "zh": "Swagger API接口", "ru": "Swagger API", "es": "Swagger API", "fr": "Swagger API"}, "Kullanıcılar & Privilege (0-15)": {"en": "Users & Privilege (0-15)", "zh": "用户与特权级 (0-15)", "ru": "Пользователи и привилегии (0-15)", "es": "Usuarios y Privilegios (0-15)", "fr": "Utilisateurs & Privilèges (0-15)"}, "Canlı Regex Komut Yetki Doğrulayıcı": {"en": "Live Regex Command Authorization Verifier", "zh": "实时Regex命令授权验证器", "ru": "Проверка авторизации команд через Regex", "es": "Verificador de Autorización de Comandos Regex", "fr": "Vérificateur d'Autorisation de Commandes Regex"}, "Belirli bir kullanıcı ve komut için TACACS+ kural motorunun vereceği izin/ret cevabını anında simüle edin.": {"en": "Simulate the permit/deny decision of the TACACS+ rule engine for a specific user and command in real time.", "zh": "实时模拟TACACS+规则引擎针对特定用户和命令的允许/拒绝决策。", "ru": "Симуляция решений разрешения/запрета правил TACACS+ для конкретного пользователя и команды.", "es": "Simule la decisión de permitir/denegar del motor de reglas TACACS+ para un usuario y comando en tiempo real.", "fr": "Simulez la décision d'autorisation/refus du moteur de règles TACACS+ pour un utilisateur et une commande en temps réel."}, "Test Edilecek Komut (CLI)": {"en": "Command to Test (CLI)", "zh": "待测命令 (CLI)", "ru": "Команда для проверки (CLI)", "es": "Comando para Probar (CLI)", "fr": "Commande à Tester (CLI)"}, "Yetkiyi Test Et": {"en": "Test Authorization", "zh": "测试授权", "ru": "Проверить полномочия", "es": "Probar Autorización", "fr": "Tester l'Autorisation"}, "Yeni TACACS+ Cihazı Ekle": {"en": "Add New TACACS+ Device", "zh": "添加新TACACS+设备", "ru": "Добавить устройство TACACS+", "es": "Agregar Nuevo Dispositivo TACACS+", "fr": "Ajouter un Nouvel Appareil TACACS+"}, "Yeni TACACS+ Kullanıcısı Ekle": {"en": "Add New TACACS+ User", "zh": "添加新TACACS+用户", "ru": "Добавить пользователя TACACS+", "es": "Agregar Nuevo Usuario TACACS+", "fr": "Ajouter un Nouvel Utilisateur TACACS+"}, "Yeni Komut Yetki Kuralı Ekle": {"en": "Add Command Authorization Rule", "zh": "添加命令授权规则", "ru": "Добавить правило авторизации команд", "es": "Agregar Regla de Autorización de Comandos", "fr": "Ajouter Règle d'Autorisation de Commande"}, "Yetkili Cihazlar": {"en": "Authorized Devices", "zh": "已授权设备", "ru": "Авторизованные устройства", "es": "Dispositivos Autorizados", "fr": "Appareils Autorisés"}, "Aktif Kullanıcılar": {"en": "Active Users", "zh": "活跃用户", "ru": "Активные пользователи", "es": "Usuarios Activos", "fr": "Utilisateurs Actifs"}, "Denetim Kayıtları": {"en": "Audit Records", "zh": "审计记录", "ru": "Записи аудита", "es": "Registros de Auditoría", "fr": "Registres d'Audit"}, "Son 50 komut denetim kaydı": {"en": "Last 50 command audit logs", "zh": "最近50条命令审计记录", "ru": "Последние 50 записей аудита команд", "es": "Últimos 50 registros de auditoría de comandos", "fr": "50 derniers journaux d'audit de commandes"}, "Son 50 komut denetim kaydı gösteriliyor.": {"en": "Showing the last 50 command audit logs.", "zh": "正在显示最近50条命令审计记录。", "ru": "Показаны последние 50 записей аудита команд.", "es": "Mostrando los últimos 50 registros de comandos.", "fr": "Affichage des 50 derniers journaux d'audit de commandes."}, "Henüz kayıtlı TACACS+ cihazı bulunamadı.": {"en": "No registered TACACS+ devices found yet.", "zh": "暂无已注册的TACACS+设备。", "ru": "Зарегистрированных устройств TACACS+ пока нет.", "es": "No se encontraron dispositivos TACACS+ registrados.", "fr": "Aucun appareil TACACS+ enregistré pour l'instant."}, "Henüz kayıtlı TACACS+ kullanıcısı bulunamadı.": {"en": "No registered TACACS+ users found yet.", "zh": "暂无已注册的TACACS+用户。", "ru": "Зарегистрированных пользователей TACACS+ пока нет.", "es": "No se encontraron usuarios TACACS+ registrados.", "fr": "Aucun utilisateur TACACS+ enregistré pour l'instant."}, "Henüz tanımlı komut kuralı bulunamadı.": {"en": "No command rules defined yet.", "zh": "暂未定义命令规则。", "ru": "Правила команд еще не определены.", "es": "Aún no se han definido reglas de comando.", "fr": "Aucune règle de commande définie pour l'instant."}, "Henüz komut denetim kaydı oluşmadı.": {"en": "No command audit logs recorded yet.", "zh": "暂无命令审计记录。", "ru": "Записей аудита команд пока нет.", "es": "Aún no se han registrado comandos.", "fr": "Aucun journal d'audit de commande enregistré pour l'instant."}, "Kullanıcı Grubu": {"en": "User Group", "zh": "用户组", "ru": "Группа пользователей", "es": "Grupo de Usuarios", "fr": "Groupe d'Utilisateurs"}, "Hedef Grup": {"en": "Target Group", "zh": "目标组", "ru": "Целевая группа", "es": "Grupo de Destino", "fr": "Groupe Cible"}, "Öncelik (1-1000, küçük olan önce işletilir)": {"en": "Priority (1-1000, lower executes first)", "zh": "优先级 (1-1000, 较小值优先执行)", "ru": "Приоритет (1-1000, меньший выполняется первым)", "es": "Prioridad (1-1000, menor ejecuta primero)", "fr": "Priorité (1-1000, le plus bas s'exécute en premier)"}, "Enable Şifresi (İsteğe Bağlı)": {"en": "Enable Password (Optional)", "zh": "Enable密码 (可选)", "ru": "Пароль Enable (опционально)", "es": "Contraseña Enable (Opcional)", "fr": "Mot de Passe Enable (Optionnel)"}, "Enable Şifresi": {"en": "Enable Password", "zh": "Enable密码", "ru": "Пароль Enable", "es": "Contraseña Enable", "fr": "Mot de Passe Enable"}, "CHAP Secret": {"en": "CHAP Secret", "zh": "CHAP密钥", "ru": "Секрет CHAP", "es": "Secreto CHAP", "fr": "Secret CHAP"}, "Ortak Parola (Shared Secret)": {"en": "Shared Secret Key", "zh": "共享密钥 (Shared Secret)", "ru": "Общий пароль (Shared Secret)", "es": "Clave Secreta Compartida", "fr": "Clé Secrète Partagée"}, "Yetki Seviyesi (Privilege)": {"en": "Privilege Level", "zh": "特权级别", "ru": "Уровень привилегий", "es": "Nivel de Privilegio", "fr": "Niveau de Privilège"}, "Priv": {"en": "Priv", "zh": "特权", "ru": "Прив.", "es": "Priv", "fr": "Priv"}, "Komut": {"en": "Command", "zh": "命令", "ru": "Команда", "es": "Comando", "fr": "Commande"}, "Cihaz IP": {"en": "Device IP", "zh": "设备IP", "ru": "IP устройства", "es": "IP del Dispositivo", "fr": "IP de l'Appareil"}, "IP / CIDR": {"en": "IP / CIDR", "zh": "IP / CIDR掩码", "ru": "IP / CIDR", "es": "IP / CIDR", "fr": "IP / CIDR"}, "Açıklama (İsteğe Bağlı)": {"en": "Description (Optional)", "zh": "描述 (可选)", "ru": "Описание (необязательно)", "es": "Descripción (Opcional)", "fr": "Description (Optionnel)"}, "Yeni SNMP Cihazı Ekle": {"en": "Add SNMP Device", "zh": "添加SNMP设备", "ru": "Добавить SNMP-устройство", "es": "Agregar Dispositivo SNMP", "fr": "Ajouter Appareil SNMP"}, "İzlenen Cihazlar": {"en": "Monitored Devices", "zh": "已监控设备", "ru": "Мониторируемые устройства", "es": "Dispositivos Monitoreados", "fr": "Appareils Supervisés"}, "İzlenen Arayüzler": {"en": "Monitored Interfaces", "zh": "已监控接口", "ru": "Мониторируемые интерфейсы", "es": "Interfaces Monitoreadas", "fr": "Interfaces Supervisées"}, "SNMP Poller Durumu": {"en": "SNMP Poller Status", "zh": "SNMP轮询器状态", "ru": "Состояние SNMP Poller", "es": "Estado de Poller SNMP", "fr": "État du Poller SNMP"}, "Otomatik CIDR Ağ Keşfi": {"en": "Automatic CIDR Network Discovery", "zh": "自动CIDR网络发现", "ru": "Автоматическое обнаружение сети CIDR", "es": "Descubrimiento de Red CIDR Automático", "fr": "Découverte Réseau CIDR Automatique"}, "Alarm & Webhook Ayarları": {"en": "Alarm & Webhook Settings", "zh": "告警与Webhook设置", "ru": "Настройки тревог и Webhook", "es": "Ajustes de Alarmas y Webhook", "fr": "Paramètres d'Alarme & Webhook"}, "Örnek Config": {"en": "Sample Config", "zh": "配置示例", "ru": "Пример конфигурации", "es": "Configuración de Ejemplo", "fr": "Exemple de Configuration"}, "Bulunan Cihazlar": {"en": "Discovered Devices", "zh": "发现的设备", "ru": "Обнаруженные устройства", "es": "Dispositivos Descubiertos", "fr": "Appareils Découverts"}, "Henüz kayıtlı SNMP cihazı bulunamadı.": {"en": "No registered SNMP devices found yet.", "zh": "暂无已注册的SNMP设备。", "ru": "Зарегистрированных SNMP-устройств пока нет.", "es": "No se encontraron dispositivos SNMP registrados.", "fr": "Aucun appareil SNMP enregistré pour l'instant."}, "Aktif alarm bulunmamaktadır. Sistem stabil.": {"en": "No active alarms. System is healthy and stable.", "zh": "暂无活动告警，系统运行稳定。", "ru": "Активных тревог нет. Система стабильна.", "es": "No hay alarmas activas. El sistema está estable.", "fr": "Aucune alarme active. Système stable."}, "Kritik ağ kesintilerinde Telegram veya Slack kanallarına anlık uyarı bildirimleri iletilir.": {"en": "Instant alerts are forwarded to Telegram or Slack channels during critical network incidents.", "zh": "发生关键网络中断时，将即时向Telegram或Slack通道推送告警通知。", "ru": "При критических сетевых сбоях уведомления отправляются в каналы Telegram или Slack.", "es": "Las alertas críticas de red se reenvían al instante a canales de Telegram o Slack.", "fr": "Des alertes instantanées sont envoyées sur Telegram ou Slack en cas d'incident réseau critique."}, "Belirttiğiniz IP bloğundaki tüm ağ cihazlarını SNMP üzerinden otomatik tarar, marka/model parmak izini çıkarır ve envantere kaydeder.": {"en": "Automatically scans all network devices in the specified CIDR block via SNMP, fingerprints vendor/model, and registers them in inventory.", "zh": "通过SNMP自动扫描指定CIDR网段中的所有网络设备，提取厂商/型号指纹并登记到资产库。", "ru": "Автоматически сканирует все устройства в указанной подсети через SNMP, определяет производителя/модель и сохраняет в инвентарь.", "es": "Escanea automáticamente todos los dispositivos en el bloque CIDR por SNMP, detecta fabricante/modelo y los registra en el inventario.", "fr": "Scanne automatiquement tous les appareils réseau du bloc CIDR via SNMP, identifie le fabricant/modèle et les enregistre."}, "Alarm Türü": {"en": "Alarm Type", "zh": "告警类型", "ru": "Тип тревоги", "es": "Tipo de Alarma", "fr": "Type d'Alarme"}, "Önem Derecesi": {"en": "Severity", "zh": "严重程度", "ru": "Уровень важности", "es": "Severidad", "fr": "Gravité"}, "Mesaj": {"en": "Message", "zh": "消息内容", "ru": "Сообщение", "es": "Mensaje", "fr": "Message"}, "CPU %": {"en": "CPU %", "zh": "CPU使用率 %", "ru": "ЦП %", "es": "CPU %", "fr": "CPU %"}, "RAM %": {"en": "RAM %", "zh": "内存使用率 %", "ru": "ОЗУ %", "es": "RAM %", "fr": "RAM %"}, "Community String": {"en": "Community String", "zh": "团体字 (Community String)", "ru": "Community String", "es": "Cadena de Comunidad", "fr": "Chaîne de Communauté"}, "SNMP Sürümü": {"en": "SNMP Version", "zh": "SNMP版本", "ru": "Версия SNMP", "es": "Versión SNMP", "fr": "Version SNMP"}, "SNMP Portu": {"en": "SNMP Port", "zh": "SNMP端口", "ru": "Порт SNMP", "es": "Puerto SNMP", "fr": "Port SNMP"}, "v3 Kullanıcı Adı": {"en": "v3 Username", "zh": "v3 用户名", "ru": "Имя пользователя v3", "es": "Usuario v3", "fr": "Nom d'utilisateur v3"}, "Auth Protokolü": {"en": "Auth Protocol", "zh": "认证协议", "ru": "Протокол аутентификации", "es": "Protocolo de Autenticación", "fr": "Protocole d'Authentification"}, "Auth Parolası": {"en": "Auth Password", "zh": "认证密码", "ru": "Пароль аутентификации", "es": "Contraseña de Autenticación", "fr": "Mot de Passe d'Authentification"}, "Priv Protokolü": {"en": "Privacy Protocol", "zh": "加密协议", "ru": "Протокол шифрования (Priv)", "es": "Protocolo de Privacidad", "fr": "Protocole de Confidentialité"}, "Priv Parolası": {"en": "Privacy Password", "zh": "加密密码", "ru": "Пароль шифрования (Priv)", "es": "Contraseña de Privacidad", "fr": "Mot de Passe de Confidentialité"}, "CIDR / IP Aralığı": {"en": "CIDR / IP Range", "zh": "CIDR / IP网段范围", "ru": "Диапазон CIDR / IP", "es": "Rango CIDR / IP", "fr": "Plage CIDR / IP"}, "Port Sayısı": {"en": "Port Count", "zh": "端口数量", "ru": "Количество портов", "es": "Cantidad de Puertos", "fr": "Nombre de Ports"}, "Cihaz Seçin:": {"en": "Select Device:", "zh": "选择设备:", "ru": "Выберите устройство:", "es": "Seleccionar Dispositivo:", "fr": "Sélectionner un Appareil :"}, "Arayüz (Port):": {"en": "Interface (Port):", "zh": "接口 (端口):", "ru": "Интерфейс (порт):", "es": "Interfaz (Puerto):", "fr": "Interface (Port) :"}, "Canlı Telemetri (Her 5s otomatik güncellenir)": {"en": "Live Telemetry (Auto-updates every 5s)", "zh": "实时遥测 (每5秒自动刷新)", "ru": "Живая телеметрия (обновление каждые 5с)", "es": "Telemetría en Vivo (Actualiza cada 5s)", "fr": "Téléométrie en Direct (Actualisation toutes les 5s)"}, "Tarih, Saat & NTP Zaman Eşitleme": {"en": "Date, Time & NTP Synchronization", "zh": "日期、时间与NTP时间同步", "ru": "Синхронизация даты, времени и NTP", "es": "Sincronización de Fecha, Hora y NTP", "fr": "Synchronisation Date, Heure & NTP"}, "Yukarı Akış Zaman Sunucuları (Upstream NTP Sources)": {"en": "Upstream Time Servers (Upstream NTP Sources)", "zh": "上游时间服务器 (Upstream NTP Sources)", "ru": "Вышестоящие серверы времени (Upstream NTP)", "es": "Servidores de Tiempo Superiores (Upstream NTP)", "fr": "Serveurs de Temps Amont (Sources NTP Amont)"}, "Zamanı Şimdi Eşitle (chronyc makestep)": {"en": "Sync Time Now (chronyc makestep)", "zh": "立即同步时间 (chronyc makestep)", "ru": "Синхронизировать время сейчас (chronyc makestep)", "es": "Sincronizar Hora Ahora (chronyc makestep)", "fr": "Synchroniser l'Heure Maintenant (chronyc makestep)"}, "Şimdi Eşitle (Makestep)": {"en": "Sync Now (Makestep)", "zh": "立即强制同步", "ru": "Синхронизировать (Makestep)", "es": "Sincronizar Ahora (Makestep)", "fr": "Synchroniser (Makestep)"}, "AlmaLinux chrony motoru üzerinden yerel ağdaki tüm Cisco, MikroTik, Huawei, Fortinet ve Linux cihazlarına yetkili saat referansı sağlar.": {"en": "Provides authoritative time reference to all Cisco, MikroTik, Huawei, Fortinet, and Linux devices across the local network via AlmaLinux chrony engine.", "zh": "通过AlmaLinux chrony引擎为局域网内的所有Cisco、MikroTik、华为、Fortinet和Linux设备提供权威时钟源。", "ru": "Предоставляет авторитетный источник времени для всех устройств Cisco, MikroTik, Huawei, Fortinet и Linux через движок AlmaLinux chrony.", "es": "Proporciona referencia horaria autorizada a todos los dispositivos Cisco, MikroTik, Huawei, Fortinet y Linux en la red local mediante chrony de AlmaLinux.", "fr": "Fournit une référence d'horloge faisant autorité à tous les équipements Cisco, MikroTik, Huawei, Fortinet et Linux via chrony d'AlmaLinux."}, "Servis Durumu": {"en": "Service Status", "zh": "服务状态", "ru": "Статус службы", "es": "Estado del Servicio", "fr": "État du Service"}, "Yönetilen Arka Plan Servisleri": {"en": "Managed Background Services", "zh": "受管后台服务", "ru": "Управляемые фоновые службы", "es": "Servicios en Segundo Plano Gestionados", "fr": "Services d'Arrière-plan Gérés"}, "Canlı Servis Durumu ve Log Ekranı": {"en": "Live Service Status and Console Log View", "zh": "实时服务状态与控制台日志", "ru": "Состояние служб и экран живых логов", "es": "Estado de Servicio en Vivo y Pantalla de Registros", "fr": "État du Service en Direct et Écran de Journaux"}, "Arka plan servislerinin durumunu izleyin, bağımsız olarak yeniden başlatın ve anlık konsol loglarını takip edin.": {"en": "Monitor background service health, restart them independently, and track live console logs.", "zh": "监控后台服务运行状况，独立重启服务并实时追踪控制台日志。", "ru": "Отслеживайте состояние фоновых служб, перезапускайте их независимо и просматривайте журналы консоли.", "es": "Monitoree el estado de servicios en segundo plano, reinícielos de forma independiente y siga los logs en vivo.", "fr": "Supervisez l'état des services d'arrière-plan, redémarrez-les indépendamment et suivez les journaux de console en direct."}, "Sunucuyu Yeniden Başlat (Server Reboot)": {"en": "Server Reboot", "zh": "操作系统重启 (Server Reboot)", "ru": "Перезагрузка сервера (Server Reboot)", "es": "Reinicio del Servidor (Server Reboot)", "fr": "Redémarrage du Serveur (Server Reboot)"}, "Sunucuyu Yeniden Başlat": {"en": "Reboot Server", "zh": "重启服务器", "ru": "Перезагрузить сервер", "es": "Reiniciar Servidor", "fr": "Redémarrer le Serveur"}, "Yeniden Başlatma Onayı": {"en": "Restart Confirmation", "zh": "重启确认", "ru": "Подтверждение перезапуска", "es": "Confirmación de Reinicio", "fr": "Confirmation de Redémarrage"}, "Evet, Yeniden Başlat": {"en": "Yes, Restart Now", "zh": "确认立即重启", "ru": "Да, перезапустить", "es": "Sí, Reiniciar Ahora", "fr": "Oui, Redémarrer Maintenant"}, "DİKKAT:": {"en": "ATTENTION:", "zh": "注意：", "ru": "ВНИМАНИЕ:", "es": "ATENCIÓN:", "fr": "ATTENTION :"}, "ÇALIŞIYOR": {"en": "RUNNING", "zh": "运行中", "ru": "РАБОТАЕТ", "es": "EN EJECUCIÓN", "fr": "EN COURS"}, "DURDURULDU": {"en": "STOPPED", "zh": "已停止", "ru": "ОСТАНОВЛЕНО", "es": "DETENIDO", "fr": "ARRÊTÉ"}, "Logları Gör": {"en": "View Logs", "zh": "查看日志", "ru": "Смотреть логи", "es": "Ver Registros", "fr": "Voir les Journaux"}, "Kapat": {"en": "Close", "zh": "关闭", "ru": "Закрыть", "es": "Cerrar", "fr": "Fermer"}, "AlmaLinux Sunucusu Yeniden Başlatılıyor": {"en": "AlmaLinux Server Rebooting", "zh": "AlmaLinux服务器正在重启", "ru": "Сервер AlmaLinux перезагружается", "es": "Reiniciando Servidor AlmaLinux", "fr": "Redémarrage du Serveur AlmaLinux"}, "Web Yönetim Hizmeti Yeniden Başlatılıyor": {"en": "Web Management Service Restarting", "zh": "Web管理服务正在重启", "ru": "Служба веб-управления перезапускается", "es": "Servicio de Gestión Web Reiniciando", "fr": "Service de Gestion Web en Redémarrage"}, "Sunucu donanımsal seviyede yeniden başlatılıyor. Sistem açılana kadar bağlantı bekleniyor... (Yaklaşık 45-60 saniye)": {"en": "Server is rebooting at the OS level. Waiting for connectivity to resume... (Approximately 45-60 seconds)", "zh": "服务器正在操作系统层面执行重启。正在等待网络连接恢复... (大约 45-60 秒)", "ru": "Сервер перезагружается на уровне ОС. Ожидание восстановления связи... (около 45-60 секунд)", "es": "El servidor se está reiniciando a nivel de sistema. Esperando que se restablezca la conexión... (Aprox. 45-60 segundos)", "fr": "Le serveur redémarre au niveau système. En attente de reconnexion... (Environ 45 à 60 secondes)"}, "FreeRADIUS Enterprise web servisi arka planda yeniden başlatılıyor. Oturum ve veriler korunarak sayfa otomatik olarak açılacaktır...": {"en": "FreeRADIUS Enterprise web service is restarting in the background. Session and data are preserved, page will refresh automatically...", "zh": "FreeRADIUS企业版Web服务正在后台重启。登录状态与数据已保留，页面将自动重载...", "ru": "Веб-служба FreeRADIUS Enterprise перезапускается в фоне. Сессия и данные сохранены, страница откроется автоматически...", "es": "El servicio web FreeRADIUS Enterprise se está reiniciando. La sesión y datos se conservan, la página se recargará automáticamente...", "fr": "Le service web FreeRADIUS Enterprise redémarre en arrière-plan. Session et données conservées, la page s'actualisera automatiquement..."}, "CSV İndir": {"en": "Download CSV", "zh": "下载CSV", "ru": "Скачать CSV", "es": "Descargar CSV", "fr": "Télécharger CSV"}, "CSV İçe Aktar": {"en": "Import CSV", "zh": "导入CSV", "ru": "Импортировать CSV", "es": "Importar CSV", "fr": "Importer CSV"}, "CSV İle Toplu Kullanıcı Aktarımı": {"en": "Bulk User Import via CSV", "zh": "通过CSV批量导入用户", "ru": "Массовый импорт пользователей через CSV", "es": "Importación Masiva de Usuarios por CSV", "fr": "Importation Groupée d'Utilisateurs par CSV"}, "Toplu Wi-Fi Kuponu Üret": {"en": "Bulk Generate Wi-Fi Vouchers", "zh": "批量生成Wi-Fi优惠券", "ru": "Массовая генерация ваучеров Wi-Fi", "es": "Generación Masiva de Vales Wi-Fi", "fr": "Génération Groupée de Coupons Wi-Fi"}, "Toplu Kupon Üret": {"en": "Bulk Voucher Generator", "zh": "批量生成优惠券", "ru": "Массовая генерация купонов", "es": "Generar Vales Masivos", "fr": "Générer Coupons Groupés"}, "Hemen Üret": {"en": "Generate Now", "zh": "立即生成", "ru": "Создать сейчас", "es": "Generar Ahora", "fr": "Générer Maintenant"}, "Kuponları Yazdır": {"en": "Print Vouchers", "zh": "打印优惠券", "ru": "Распечатать ваучеры", "es": "Imprimir Vales", "fr": "Imprimer les Coupons"}, "Aktif Bağlı Misafir": {"en": "Active Guest Sessions", "zh": "当前在线访客", "ru": "Активные гостевые сессии", "es": "Invitados Activos Conectados", "fr": "Sessions Invités Actives"}, "Toplam Toplu Hesap": {"en": "Total Batch Accounts", "zh": "批量账户总数", "ru": "Всего пакетных аккаунтов", "es": "Total de Cuentas por Lote", "fr": "Total Comptes Groupés"}, "Kullanım Süresi": {"en": "Usage Duration", "zh": "使用时长", "ru": "Время использования", "es": "Tiempo de Uso", "fr": "Durée d'Utilisation"}, "Süre Kotası": {"en": "Time Quota", "zh": "时间配额", "ru": "Лимит времени", "es": "Cuota de Tiempo", "fr": "Quota de Temps"}, "İndirme / Yükleme Hızı": {"en": "Download / Upload Speed", "zh": "下载 / 上传速率", "ru": "Скорость загрузки / отдачи", "es": "Velocidad de Bajada / Subida", "fr": "Vitesse Descendante / Montante"}, "Şifre / PIN": {"en": "Password / PIN", "zh": "密码 / PIN码", "ru": "Пароль / PIN-код", "es": "Contraseña / PIN", "fr": "Mot de Passe / PIN"}, "Kullanıcı Adı / Kod": {"en": "Username / Code", "zh": "用户名 / 优惠码", "ru": "Имя пользователя / Код", "es": "Usuario / Código", "fr": "Nom d'Utilisateur / Code"}, "Üretilecek Kupon Sayısı": {"en": "Vouchers to Generate", "zh": "生成优惠券数量", "ru": "Количество ваучеров", "es": "Cantidad de Vales a Generar", "fr": "Nombre de Coupons à Générer"}, "Otel, misafirhane, kafe, seminer ve etkinlikler için üretilmiş kuponlar ve wireless hesapları.": {"en": "Vouchers and wireless accounts generated for hotels, guest houses, cafes, seminars, and events.", "zh": "针对酒店、宾馆、咖啡馆、研讨会及大型活动生成的Wi-Fi优惠券和无线临时账户。", "ru": "Ваучеры и беспроводные учетные записи для отелей, гостевых домов, кафе, семинаров и мероприятий.", "es": "Vales y cuentas inalámbricas para hoteles, hospedajes, cafeterías, seminarios y eventos.", "fr": "Coupons et comptes sans fil générés pour les hôtels, maisons d'hôtes, cafés, séminaires et événements."}, "İki Aşamalı Doğrulama (2FA - TOTP)": {"en": "Two-Factor Authentication (2FA - TOTP)", "zh": "双因素身份验证 (2FA - TOTP)", "ru": "Двухфакторная аутентификация (2FA - TOTP)", "es": "Autenticación de Dos Factores (2FA - TOTP)", "fr": "Authentification à Deux Facteurs (2FA - TOTP)"}, "Sistem ve web yöneticilerinin iki aşamalı doğrulama (TOTP) durumlarını denetleyin, kilitlenen veya telefonunu kaybeden yöneticilerin 2FA anahtarlarını sıfırlayın.": {"en": "Manage two-factor authentication (TOTP) status for administrators, reset 2FA keys for locked accounts or lost devices.", "zh": "审核系统及Web管理员的双因素身份验证(TOTP)状态，为被锁或丢失手机的管理员重置2FA密钥。", "ru": "Управляйте статусом двухфакторной аутентификации (TOTP) администраторов, сбрасывайте 2FA при потере телефона.", "es": "Audite el estado de 2FA (TOTP) de los administradores y restablezca claves de cuentas bloqueadas.", "fr": "Gérez l'état de l'authentification à deux facteurs (TOTP) des administrateurs et réinitialisez les clés 2FA."}, "Yeni Rol Ekle": {"en": "Add New Role", "zh": "添加新角色", "ru": "Добавить новую роль", "es": "Agregar Nuevo Rol", "fr": "Ajouter un Nouveau Rôle"}, "Yeni Yönetici Ekle": {"en": "Add Administrator", "zh": "添加管理员", "ru": "Добавить администратора", "es": "Agregar Administrador", "fr": "Ajouter un Administrateur"}, "Yeni Yönetici Tanımla": {"en": "Define New Administrator", "zh": "新建管理员账户", "ru": "Создать администратора", "es": "Definir Nuevo Administrador", "fr": "Définir un Nouvel Administrateur"}, "Tüm Kaynaklar": {"en": "All Resources", "zh": "所有资源", "ru": "Все ресурсы", "es": "Todos los Recursos", "fr": "Toutes les Ressources"}, "Tanımlı Profiller": {"en": "Defined Profiles", "zh": "已定义配置文件", "ru": "Определенные профили", "es": "Perfiles Definidos", "fr": "Profils Définis"}, "Sürüm": {"en": "Version", "zh": "版本", "ru": "Версия", "es": "Versión", "fr": "Version"}, "Açıklama / Etiket": {"en": "Description / Tag", "zh": "说明 / 标签", "ru": "Описание / Тег", "es": "Descripción / Etiqueta", "fr": "Description / Étiquette"}, "Otomatik Yedekleme Politikası & Zamanlama Ayarları": {"en": "Automated Backup Policy & Schedule Settings", "zh": "自动备份策略与定时设置", "ru": "Политика автоматического бэкапа и расписание", "es": "Política de Respaldo Automático y Programación", "fr": "Politique de Sauvegarde Automatique & Planification"}, "Tüm FreeRADIUS yönetim paneli, TACACS+ AAA motoru, SNMP NMS servisi ve veritabanlarını tek bir sıkıştırılmış arşiv (.tar.gz) içinde saklayıp uzaktan SCP ile tek komutla çekebilirsiniz.": {"en": "Save the entire FreeRADIUS management panel, TACACS+ AAA engine, SNMP NMS service, and databases in a single compressed archive (.tar.gz) and retrieve it remotely via SCP with a single command.", "zh": "将整个FreeRADIUS管理面板、TACACS+ AAA引擎、SNMP网络监控服务及所有数据库保存在单个压缩归档包(.tar.gz)中，支持通过SCP单条命令远程提取。", "ru": "Сохраните всю панель FreeRADIUS, движок TACACS+ AAA, службу SNMP NMS и базы данных в едином архиве (.tar.gz) для удаленного скачивания по SCP.", "es": "Guarde todo el panel FreeRADIUS, el motor TACACS+ AAA, SNMP NMS y las bases de datos en un solo archivo comprimido (.tar.gz) y descárguelo por SCP.", "fr": "Enregistrez l'ensemble du panneau FreeRADIUS, du moteur TACACS+ AAA, du service SNMP NMS et des bases de données dans une archive unique (.tar.gz) récupérable par SCP."}, "Cihaz": {"en": "Device", "zh": "设备", "ru": "Устройство", "es": "Dispositivo", "fr": "Appareil"}, "Port": {"en": "Port", "zh": "端口", "ru": "Порт", "es": "Puerto", "fr": "Port"}, "İçe Aktar": {"en": "Import", "zh": "导入", "ru": "Импорт", "es": "Importar", "fr": "Importer"}, "Marka / Üretici": {"en": "Brand / Manufacturer", "zh": "品牌 / 制造商", "ru": "Марка / Производитель", "es": "Marca / Fabricante", "fr": "Marque / Fabricant"}, "2FA Aktif": {"en": "2FA Active", "zh": "2FA已启用", "ru": "2FA Активен", "es": "2FA Activo", "fr": "2FA Actif"}, "2FA Devre Dışı": {"en": "2FA Disabled", "zh": "2FA已禁用", "ru": "2FA Отключен", "es": "2FA Desactivado", "fr": "2FA Désactivé"}, "2FA Durumu": {"en": "2FA Status", "zh": "2FA状态", "ru": "Статус 2FA", "es": "Estado de 2FA", "fr": "Statut 2FA"}, "2FA Kaldır": {"en": "Remove 2FA", "zh": "解绑2FA", "ru": "Сбросить 2FA", "es": "Eliminar 2FA", "fr": "Supprimer 2FA"}, "2FA Yok": {"en": "No 2FA", "zh": "无2FA", "ru": "Без 2FA", "es": "Sin 2FA", "fr": "Sans 2FA"}, "Aktif Filtre:": {"en": "Active Filter:", "zh": "当前筛选:", "ru": "Активный фильтр:", "es": "Filtro Activo:", "fr": "Filtre Actif :"}, "Aktif Servisler": {"en": "Active Services", "zh": "运行中的服务", "ru": "Активные службы", "es": "Servicios Activos", "fr": "Services Actifs"}, "Kopyala": {"en": "Copy", "zh": "复制", "ru": "Копировать", "es": "Copiar", "fr": "Copier"}, "Kopyalandı!": {"en": "Copied!", "zh": "已复制!", "ru": "Скопировано!", "es": "¡Copiado!", "fr": "Copié !"}, "Şifre Sıfırla": {"en": "Reset Password", "zh": "重置密码", "ru": "Сбросить пароль", "es": "Restablecer Contraseña", "fr": "Réinitialiser le mot de passe"}, "Şifre Sıfırla:": {"en": "Reset Password:", "zh": "重置密码:", "ru": "Сбросить пароль:", "es": "Restablecer Contraseña:", "fr": "Réinitialiser le mot de passe :"}, "Şifreyi Güncelle": {"en": "Update Password", "zh": "更新密码", "ru": "Обновить пароль", "es": "Actualizar Contraseña", "fr": "Mettre à jour le mot de passe"}, "Şimdi Yenile": {"en": "Refresh Now", "zh": "立即刷新", "ru": "Обновить сейчас", "es": "Actualizar Ahora", "fr": "Actualiser Maintenant"}, "Son Giriş IP Adresi": {"en": "Last Login IP", "zh": "最后登录IP", "ru": "IP последнего входа", "es": "IP de Último Acceso", "fr": "IP de Dernière Connexion"}, "Son Giriş Zamanı": {"en": "Last Login Time", "zh": "最后登录时间", "ru": "Время последнего входа", "es": "Hora de Último Acceso", "fr": "Heure de Dernière Connexion"}, "Son Güncelleme:": {"en": "Last Updated:", "zh": "最后更新:", "ru": "Последнее обновление:", "es": "Última Actualización:", "fr": "Dernière Mise à Jour :"}, "Boş Disk Alanı:": {"en": "Free Disk Space:", "zh": "剩余磁盘空间:", "ru": "Свободное место:", "es": "Espacio en Disco Libre:", "fr": "Espace Disque Libre :"}, "Boş:": {"en": "Free:", "zh": "空闲:", "ru": "Свободно:", "es": "Libre:", "fr": "Libre :"}, "Kullanılan:": {"en": "Used:", "zh": "已用:", "ru": "Использовано:", "es": "Usado:", "fr": "Utilisé :"}, "Kullanılabilir:": {"en": "Available:", "zh": "可用:", "ru": "Доступно:", "es": "Disponible:", "fr": "Disponible :"}, "Bağlı": {"en": "Connected", "zh": "已连接", "ru": "Подключено", "es": "Conectado", "fr": "Connecté"}, "Kapalı": {"en": "Offline / Closed", "zh": "离线 / 关闭", "ru": "Отключено", "es": "Desconectado", "fr": "Fermé / Hors ligne"}, "Hızlı Örnekler:": {"en": "Quick Examples:", "zh": "快捷示例:", "ru": "Быстрые примеры:", "es": "Ejemplos Rápidos:", "fr": "Exemples Rapides :"}, "Hızlı Seçim:": {"en": "Quick Select:", "zh": "快速选择:", "ru": "Быстрый выбор:", "es": "Selección Rápida:", "fr": "Sélection Rapide :"}, "Yöneticiyi Kaydet": {"en": "Save Administrator", "zh": "保存管理员", "ru": "Сохранить администратора", "es": "Guardar Administrador", "fr": "Enregistrer l'Administrateur"}, "Rolü Oluştur": {"en": "Create Role", "zh": "创建角色", "ru": "Создать роль", "es": "Crear Rol", "fr": "Créer le Rôle"}, "Envantere Ekle": {"en": "Add to Inventory", "zh": "加入资产库", "ru": "Добавить в инвентарь", "es": "Añadir a Inventario", "fr": "Ajouter à l'Inventaire"}, "Yetki Düzenle": {"en": "Edit Permissions", "zh": "编辑权限", "ru": "Изменить права", "es": "Editar Permisos", "fr": "Modifier les Permissions"}, "Son Alım": {"en": "Last Poll", "zh": "最后轮询", "ru": "Последний опрос", "es": "Último Sondeo", "fr": "Dernier Relevé"}, "Sonraki Otomatik Yedek": {"en": "Next Automated Backup", "zh": "下次自动备份", "ru": "Следующий автобэкап", "es": "Siguiente Respaldo Automático", "fr": "Prochaine Sauvegarde Automatique"}, "Yedekleme Aralığı": {"en": "Backup Interval", "zh": "备份间隔", "ru": "Интервал бэкапа", "es": "Intervalo de Respaldo", "fr": "Intervalle de Sauvegarde"}, "Rol Adı & Kod": {"en": "Role Name & Code", "zh": "角色名称与标识代码", "ru": "Имя роли и код", "es": "Nombre de Rol y Código", "fr": "Nom du Rôle & Code"}, "Rol Emojisi": {"en": "Role Emoji", "zh": "角色图标Emoji", "ru": "Эмодзи роли", "es": "Emoji del Rol", "fr": "Emoji du Rôle"}, "Rol Görüntüleme Adı": {"en": "Role Display Name", "zh": "角色显示名称", "ru": "Отображаемое имя роли", "es": "Nombre Visible del Rol", "fr": "Nom d'Affichage du Rôle"}, "Doğrula ve Giriş Yap": {"en": "Verify & Sign In", "zh": "验证并登录", "ru": "Проверить и войти", "es": "Verificar e Iniciar Sesión", "fr": "Vérifier & Se Connecter"}, "Doğrulama Kodu": {"en": "Verification Code", "zh": "验证码", "ru": "Код подтверждения", "es": "Código de Verificación", "fr": "Code de Vérification"}, "Giriş ekranına geri dön": {"en": "Back to Login", "zh": "返回登录界面", "ru": "Вернуться ко входу", "es": "Volver al Inicio de Sesión", "fr": "Retour à la Connexion"}, "İzin Verilen Sayfalar": {"en": "Allowed Pages", "zh": "允许访问的页面", "ru": "Разрешенные страницы", "es": "Páginas Permitidas", "fr": "Pages Autorisées"}, "Erişilebilir Sayfalar & İzinler": {"en": "Accessible Pages & Permissions", "zh": "可访问页面与权限", "ru": "Доступные страницы и права", "es": "Páginas Accesibles y Permisos", "fr": "Pages Accessibles & Permissions"}, "Erişim Rolü": {"en": "Access Role", "zh": "访问角色", "ru": "Роль доступа", "es": "Rol de Acceso", "fr": "Rôle d'Accès"}, "Arama kriterine uygun log satırı bulunamadı.": {"en": "No log lines matching search criteria found.", "zh": "未找到匹配搜索条件的日志行。", "ru": "Строк логов по критериям поиска не найдено.", "es": "No se encontraron líneas de registro que coincidan con la búsqueda.", "fr": "Aucune ligne de journal ne correspond aux critères de recherche."}, "Henüz toplu veya misafir hesabı oluşturulmadı.": {"en": "No bulk or guest accounts created yet.", "zh": "暂未创建批量或访客账户。", "ru": "Пакетные или гостевые аккаунты пока не созданы.", "es": "Aún no se han creado cuentas por lote o de invitado.", "fr": "Aucun compte groupé ou invité créé pour l'instant."}, "Yönetici hesabı bulunamadı.": {"en": "No administrator accounts found.", "zh": "未找到管理员账户。", "ru": "Учетные записи администраторов не найдены.", "es": "No se encontraron cuentas de administrador.", "fr": "Aucun compte administrateur trouvé."}, "Aktif yukarı akış sunucusu bulunamadı.": {"en": "No active upstream servers found.", "zh": "未找到活动的上游服务器。", "ru": "Активные вышестоящие серверы не найдены.", "es": "No se encontraron servidores superiores activos.", "fr": "Aucun serveur amont actif trouvé."}};

window.I18N_DICT = {
  tr: {}, en: {}, zh: {}, ru: {}, es: {}, fr: {}
};
window.I18N_INDEX = {};

// Ek sözlük (i18n_extra.js): satır = [tr, en, zh, ru, es, fr]
(function() {
  var rows = window.I18N_EXTRA_ROWS || [], codes = ['en','zh','ru','es','fr'];
  for (var i = 0; i < rows.length; i++) {
    var r = rows[i];
    if (!r[0] || window.I18N_RAW[r[0]]) continue;
    var o = {};
    for (var j = 0; j < codes.length; j++) { if (r[j + 1]) o[codes[j]] = r[j + 1]; }
    window.I18N_RAW[r[0]] = o;
  }
})();
function i18nNorm(t) { return String(t).replace(/\s+/g, ' ').toLowerCase().trim(); }

// Build bi-directional lookup index for instant O(1) canonical resolution
for (var k in window.I18N_RAW) {
  window.I18N_DICT.tr[k] = k;
  window.I18N_INDEX[i18nNorm(k)] = k;
  var trans = window.I18N_RAW[k];
  for (var l in trans) {
    if (window.I18N_DICT[l]) {
      window.I18N_DICT[l][k] = trans[l];
      window.I18N_INDEX[i18nNorm(trans[l])] = k;
    }
  }
}

var LANG_META = {
  tr: { flag: '🇹🇷', name: 'Türkçe' },
  en: { flag: '🇬🇧', name: 'English' },
  zh: { flag: '🇨🇳', name: '中文' },
  ru: { flag: '🇷🇺', name: 'Русский' },
  es: { flag: '🇪🇸', name: 'Español' },
  fr: { flag: '🇫🇷', name: 'Français' }
};

window.toggleLangDropdown = function(e) {
  if (e) {
    if (e.preventDefault) e.preventDefault();
    if (e.stopPropagation) e.stopPropagation();
  }
  var m = document.getElementById('langDropdownMenu');
  if (m) m.classList.toggle('show');
};
window.toggleLangMenu = window.toggleLangDropdown;
function toggleLangDropdown(e) {
  window.toggleLangDropdown(e);
}
function toggleLangMenu(e) {
  window.toggleLangDropdown(e);
}

document.addEventListener('click', function(e) {
  var m = document.getElementById('langDropdownMenu');
  var btn = document.getElementById('langDropdownBtn');
  if (m && m.classList.contains('show')) {
    if (!m.contains(e.target) && (!btn || !btn.contains(e.target))) {
      m.classList.remove('show');
    }
  }
});

// Not: düğmenin onclick'i (base.html) zaten toggle ediyor; ikinci dinleyici menüyü hemen kapatıyordu.

function getCanonicalKey(text) {
  if (!text) return null;
  var exact = String(text).replace(/\s+/g, ' ').trim();
  if (window.I18N_RAW[exact]) return exact;
  var norm = i18nNorm(text);
  if (window.I18N_INDEX[norm]) return window.I18N_INDEX[norm];
  var stripped = norm.replace(/[:：]$/, '').trim();
  if (window.I18N_INDEX[stripped]) return window.I18N_INDEX[stripped];
  return null;
}

function translateSingleText(text, lang) {
  if (!text) return text;
  var lead = (text.match(/^[\s\uFEFF\xA0]*/) || [''])[0];
  var trail = (text.match(/[\s\uFEFF\xA0]*$/) || [''])[0];
  var clean = text.trim();
  if (!clean) return text;

  var key = getCanonicalKey(clean);
  if (key && window.I18N_DICT[lang] && window.I18N_DICT[lang][key]) {
    return lead + window.I18N_DICT[lang][key] + trail;
  }

  // Sayı içeren kalıplar ve emoji önekli metinler (i18n_extra.js: I18N_PATTERNS)
  var pats = window.I18N_PATTERNS || [];
  for (var pi = 0; pi < pats.length; pi++) {
    var pm = clean.match(pats[pi].re);
    if (pm && pats[pi].t[lang]) {
      var out = pats[pi].t[lang].replace(/\$(\d)/g, function(_, d) { var g = pm[+d] || ''; return (g && g !== clean) ? translateSingleText(g, lang) : g; });
      return lead + out + trail;
    }
  }
  // Sayı içeren metin: sayılar {n} ile değiştirilip sözlükte aranır ("{n} gün" -> "{n} days")
  var numRe = /\d+(?:[.,:\/]\d+)*/g;
  var nums = clean.match(numRe);
  if (nums) {
    var tk = getCanonicalKey(clean.replace(numRe, '{n}'));
    if (tk && window.I18N_DICT[lang] && window.I18N_DICT[lang][tk]) {
      var ni = 0;
      return lead + window.I18N_DICT[lang][tk].replace(/\{n\}/g, function() { return nums[ni++] || ''; }) + trail;
    }
  }
  var mEmoji = clean.match(/^([^A-Za-z0-9ÇĞİÖŞÜçğıöşü(]+)\s+(.+)$/);
  if (mEmoji) {
    var ek = getCanonicalKey(mEmoji[2]);
    if (ek && window.I18N_DICT[lang] && window.I18N_DICT[lang][ek]) {
      return lead + mEmoji[1] + ' ' + window.I18N_DICT[lang][ek] + trail;
    }
  }

  // Dynamic pattern: "X Kullanıcı" / "X Users"
  var mUserCount = clean.match(/^([0-9]+)[ 	]+(kullanıcı|users?|个用户|пользователей|usuarios?|utilisateurs?)$/i);
  if (mUserCount) {
    var uWord = (lang === 'tr') ? 'Kullanıcı' :
                (lang === 'en') ? 'Users' :
                (lang === 'zh') ? '个用户' :
                (lang === 'ru') ? 'Пользователей' :
                (lang === 'es') ? 'Usuarios' : 'Utilisateurs';
    return lead + mUserCount[1] + ' ' + uWord + trail;
  }

  // Dynamic pattern: (X Kayıt Bulundu) / (X Records Found)
  var mCount = clean.match(/^([^(]+)[ 	]*[(]([0-9]+)[ 	]+([^)]+)[)]$/);
  if (mCount) {
    var baseKey = getCanonicalKey(mCount[1]);
    if (baseKey && window.I18N_DICT[lang] && window.I18N_DICT[lang][baseKey]) {
      var recWord = (lang === 'tr') ? 'Kayıt Bulundu' :
                    (lang === 'en') ? 'Records Found' :
                    (lang === 'zh') ? '条记录' :
                    (lang === 'ru') ? 'записей найдено' :
                    (lang === 'es') ? 'Registros Encontrados' : 'Enregistrements Trouvés';
      return lead + window.I18N_DICT[lang][baseKey] + ' (' + mCount[2] + ' ' + recWord + ')' + trail;
    }
  }

  // Dynamic pattern: "Kullanıcıyı Düzenle (username)"
  var mEdit = clean.match(/^([^(:]+)[ 	]*[(]([^)]+)[)]$/);
  if (mEdit) {
    var baseKey2 = getCanonicalKey(mEdit[1]);
    if (baseKey2 && window.I18N_DICT[lang] && window.I18N_DICT[lang][baseKey2]) {
      return lead + window.I18N_DICT[lang][baseKey2] + ' (' + mEdit[2] + ')' + trail;
    }
  }

  return text;
}

function i18nFallbackAttr(el, attr, lang) {
  var sa = 'data-i18n-' + attr + '-src', oa = 'data-i18n-' + attr + '-out';
  var cur = el.getAttribute(attr) || '', src = el.getAttribute(sa);
  if (src === null || el.getAttribute(oa) !== cur) src = cur;  // JS değeri değiştirdiyse yeni kaynak
  var out = translateSingleText(src, lang);
  if (out !== src || src !== cur) {
    el.setAttribute(sa, src);
    el.setAttribute(oa, out);
    if (out !== cur) el.setAttribute(attr, out);
  }
}

function translateDOMTree(root, lang) {
  if (!root) root = document.body;
  if (!root) return;

  // 1. Direct priority pass: All elements explicitly marked with data-i18n
  try {
    var i18nEls = root.querySelectorAll('[data-i18n]');
    for (var k = 0; k < i18nEls.length; k++) {
      var el = i18nEls[k];
      if (el.closest && (el.closest('#langDropdownMenu') || el.closest('#langDropdownBtn'))) continue;
      if (el.closest && el.closest('[translate="no"], .notranslate')) continue;
      var rawKey = el.getAttribute('data-i18n');
      var canKey = getCanonicalKey(rawKey) || rawKey;
      if (canKey && window.I18N_DICT[lang] && window.I18N_DICT[lang][canKey]) {
        var translated = window.I18N_DICT[lang][canKey];
        // If element has only one text node child (or no element children), replace text
        var textNodeCount = 0;
        var elementCount = el.children.length;
        var targetTextNode = null;
        for (var cn = 0; cn < el.childNodes.length; cn++) {
          if (el.childNodes[cn].nodeType === Node.TEXT_NODE && el.childNodes[cn].nodeValue.trim().length > 0) {
            textNodeCount++;
            targetTextNode = el.childNodes[cn];
          }
        }
        if (elementCount === 0) {
          if (el.textContent !== translated) el.textContent = translated;
        } else if (textNodeCount === 1 && targetTextNode) {
          if (targetTextNode.nodeValue !== ' ' + translated) targetTextNode.nodeValue = ' ' + translated;
          targetTextNode._i18n_key = canKey;
        }
      }
    }
  } catch(e) {}

  // 2. Fast DOM TreeWalker for text nodes
  try {
    var walker = document.createTreeWalker(
      root,
      NodeFilter.SHOW_TEXT,
      {
        acceptNode: function(node) {
          if (!node || !node.parentNode) return NodeFilter.FILTER_REJECT;
          var tag = node.parentNode.tagName;
          if (tag === 'SCRIPT' || tag === 'STYLE' || tag === 'NOSCRIPT' || tag === 'TEXTAREA') {
            return NodeFilter.FILTER_REJECT;
          }
          if (node.parentNode.classList && (node.parentNode.classList.contains('lang-item') || node.parentNode.id === 'langDropdownBtn')) {
            return NodeFilter.FILTER_REJECT;
          }
          if (node.parentNode.closest && (node.parentNode.closest('#langDropdownMenu') || node.parentNode.closest('#langDropdownBtn'))) {
            return NodeFilter.FILTER_REJECT;
          }
          // örnek config blokları çevrilmez (translate="no" / .notranslate)
          if (node.parentNode.closest && node.parentNode.closest('[translate="no"], .notranslate')) {
            return NodeFilter.FILTER_REJECT;
          }
          if (node.nodeValue && node.nodeValue.trim().length > 0) {
            return NodeFilter.FILTER_ACCEPT;
          }
          return NodeFilter.FILTER_SKIP;
        }
      },
      false
    );

    var textNodes = [];
    while (walker.nextNode()) {
      textNodes.push(walker.currentNode);
    }

    for (var i = 0; i < textNodes.length; i++) {
      var node = textNodes[i];
      var raw = node.nodeValue;
      var clean = raw.trim();
      if (!clean) continue;

      var pAttrKey = (node.parentNode && node.parentNode.getAttribute) ? node.parentNode.getAttribute('data-i18n') : null;
      var nodeKey = node._i18n_key || (pAttrKey ? getCanonicalKey(pAttrKey) : null) || getCanonicalKey(clean);

      if (nodeKey && window.I18N_DICT[lang] && window.I18N_DICT[lang][nodeKey]) {
        node._i18n_key = nodeKey;
        var lead = (raw.match(/^[\s\uFEFF\xA0]*/) || [''])[0];
        var trail = (raw.match(/[\s\uFEFF\xA0]*$/) || [''])[0];
        node.nodeValue = lead + window.I18N_DICT[lang][nodeKey] + trail;
      } else {
        var srcTxt = (node._i18n_out !== undefined && node._i18n_out === raw && node._i18n_src !== undefined) ? node._i18n_src : raw;
        var trans = translateSingleText(srcTxt, lang);
        if (trans !== raw) {
          node._i18n_src = srcTxt;
          node._i18n_out = trans;
          node.nodeValue = trans;
        }
      }
    }
  } catch(err) {}

  // 3. Translate attribute placeholders
  try {
    var phEls = root.querySelectorAll('input[placeholder], textarea[placeholder]');
    for (var p = 0; p < phEls.length; p++) {
      var pel = phEls[p];
      var ph = pel.getAttribute('placeholder');
      var phKey = pel.getAttribute('data-i18n-ph-key') || getCanonicalKey(ph);
      if (phKey && window.I18N_DICT[lang] && window.I18N_DICT[lang][phKey]) {
        pel.setAttribute('data-i18n-ph-key', phKey);
        pel.setAttribute('placeholder', window.I18N_DICT[lang][phKey]);
      } else {
        i18nFallbackAttr(pel, 'placeholder', lang);
      }
    }
  } catch(e) {}

  // 4. Translate tooltips (title attribute)
  try {
    var titleEls = root.querySelectorAll('[title]');
    for (var t = 0; t < titleEls.length; t++) {
      var tel = titleEls[t];
      if (tel.id === 'langDropdownBtn' || (tel.closest && tel.closest('#langDropdownMenu'))) continue;
      var tval = tel.getAttribute('title');
      var tKey = tel.getAttribute('data-i18n-title-key') || getCanonicalKey(tval);
      if (tKey && window.I18N_DICT[lang] && window.I18N_DICT[lang][tKey]) {
        tel.setAttribute('data-i18n-title-key', tKey);
        tel.setAttribute('title', window.I18N_DICT[lang][tKey]);
      } else {
        i18nFallbackAttr(tel, 'title', lang);
      }
    }
  } catch(e) {}

  // 5. Translate select options
  try {
    var optEls = root.querySelectorAll('select option');
    for (var o = 0; o < optEls.length; o++) {
      var oel = optEls[o];
      var otxt = oel.textContent.trim();
      var oKey = oel.getAttribute('data-i18n-key') || getCanonicalKey(otxt);
      if (oKey && window.I18N_DICT[lang] && window.I18N_DICT[lang][oKey]) {
        oel.setAttribute('data-i18n-key', oKey);
        if (oel.textContent !== window.I18N_DICT[lang][oKey]) oel.textContent = window.I18N_DICT[lang][oKey];
      }
    }
  } catch(e) {}

  // 6. Translate submit/button inputs with value attribute
  try {
    var valEls = root.querySelectorAll('input[type="submit"][value], input[type="button"][value]');
    for (var v = 0; v < valEls.length; v++) {
      var vel = valEls[v];
      var vval = vel.getAttribute('value');
      var vKey = vel.getAttribute('data-i18n-val-key') || getCanonicalKey(vval);
      if (vKey && window.I18N_DICT[lang] && window.I18N_DICT[lang][vKey]) {
        vel.setAttribute('data-i18n-val-key', vKey);
        vel.value = window.I18N_DICT[lang][vKey];
      }
    }
  } catch(e) {}

  // 7. Document Title
  try {
    if (document.title) {
      var tClean = (document.title.split('-')[0] || '').trim();
      var docKey = getCanonicalKey(tClean);
      if (docKey && window.I18N_DICT[lang] && window.I18N_DICT[lang][docKey]) {
        document.title = window.I18N_DICT[lang][docKey] + ' - EMredius';
      }
    }
  } catch(e) {}
}

window.CURRENT_APP_LANG = 'tr';

// alert/confirm mesajlarını seçili dile çevir (satır satır)
window.i18nMsg = function(msg) {
  var l = window.CURRENT_APP_LANG;
  if (!l || l === 'tr' || typeof msg !== 'string') return msg;
  try { return msg.split(String.fromCharCode(10)).map(function(x) { return translateSingleText(x, l); }).join(String.fromCharCode(10)); } catch (e) { return msg; }
};
(function() {
  var _a = window.alert, _c = window.confirm;
  window.alert = function(m) { return _a.call(window, window.i18nMsg(m)); };
  window.confirm = function(m) { return _c.call(window, window.i18nMsg(m)); };
})();

function setAppLanguage(lang) {
  if (!window.I18N_DICT[lang]) lang = 'tr';
  window.CURRENT_APP_LANG = lang;
  var meta = LANG_META[lang] || LANG_META['tr'];

  // Update language selector dropdown button (Flag and Name)
  var flagEl = document.getElementById('currentLangFlag');
  var nameEl = document.getElementById('currentLangName');
  if (flagEl) flagEl.textContent = meta.flag;
  if (nameEl) nameEl.textContent = meta.name;

  // Active state in dropdown
  document.querySelectorAll('.lang-item').forEach(function(item) {
    item.classList.remove('active');
  });
  var activeOpt = document.getElementById('lang-opt-' + lang);
  if (activeOpt) activeOpt.classList.add('active');

  // Close dropdown menu
  var menu = document.getElementById('langDropdownMenu');
  if (menu) menu.classList.remove('show');

  // TRANSLATE ENTIRE DOM TREE IMMEDIATELY WITHOUT RELOADING
  translateDOMTree(document.body, lang);

  // Save preference in localStorage and cookie
  try {
    localStorage.setItem('app_lang', lang);
    document.cookie = 'app_lang=' + lang + ';path=/;max-age=31536000';
  } catch(e) {}
}

// Initialize language preference immediately and on DOMContentLoaded
(function() {
  var saved = 'tr';
  try {
    saved = localStorage.getItem('app_lang') || 'tr';
  } catch(e) {}
  window.CURRENT_APP_LANG = saved;
})();

if (document.body && window.setAppLanguage) { try { setAppLanguage(window.CURRENT_APP_LANG || 'tr'); } catch(e) {} }
document.addEventListener('DOMContentLoaded', function() {
  var saved = window.CURRENT_APP_LANG || 'tr';
  setAppLanguage(saved);

  // MutationObserver for modals and dynamic content
  try {
    var observer = new MutationObserver(function(mutations) {
      if (window.CURRENT_APP_LANG && window.CURRENT_APP_LANG !== 'tr') {
        for (var i = 0; i < mutations.length; i++) {
          var m = mutations[i];
          if (m.type === 'childList' && m.addedNodes.length > 0) {
            for (var j = 0; j < m.addedNodes.length; j++) {
              var n = m.addedNodes[j];
              if (n.nodeType === 1) {
                translateDOMTree(n, window.CURRENT_APP_LANG);
              } else if (n.nodeType === 3 && n.parentNode) {
                translateDOMTree(n.parentNode, window.CURRENT_APP_LANG);
              }
            }
          } else if (m.type === 'attributes' && m.target.classList && m.target.classList.contains('show')) {
            translateDOMTree(m.target, window.CURRENT_APP_LANG);
          }
        }
      }
    });
    observer.observe(document.body, { childList: true, subtree: true, attributes: true, attributeFilter: ['class', 'style'] });
  } catch(e) {}
});


// ==================== 5-DAKİKA OTURUM ZAMAN AŞIMI MOTORU ====================
(function() {
  var TIMEOUT_TOTAL = 300; // 5 dakika = 300 saniye
  var remaining = TIMEOUT_TOTAL;
  var deadline = Date.now() + TIMEOUT_TOTAL * 1000;
  var warningShown = false;

  function updateDisplay() {
    var timerEl = document.getElementById('sessionTimerText');
    var pulseEl = document.getElementById('sessionPulse');
    var modalEl = document.getElementById('sessionWarningModal');
    var modalSecEl = document.getElementById('modalRemainingSec');

    if (!timerEl) return;
    if (remaining > 59) {
      // 5,4,3,2,1 dakika: dakika olarak göster
      timerEl.textContent = 'Time-out: ' + Math.ceil(remaining / 60) + ' dakika';
      if (pulseEl) pulseEl.style.background = remaining > 120 ? '#10b981' : '#f59e0b';
      if (modalEl) modalEl.classList.remove('show');
      warningShown = false;
    } else if (remaining > 0) {
      // Son 1 dakika: saniye göster ve web gui modal uyarısını aç!
      timerEl.textContent = 'Time-out: ' + remaining + ' sn!';
      if (pulseEl) pulseEl.style.background = '#ef4444';
      if (modalSecEl) modalSecEl.textContent = remaining;
      if (modalEl && !warningShown) {
        modalEl.classList.add('show');
        warningShown = true;
      }
    } else {
      // Süre bitti: çıkış yap
      timerEl.textContent = 'Süre Doldu!';
      window.location.href = '/logout';
    }
  }

  // Real user activity extends the server-side session (background polling does not)
  var lastHeartbeat = Date.now();
  function sendHeartbeat() {
    lastHeartbeat = Date.now();
    try {
      fetch('/api/session/heartbeat', { cache: 'no-store' }).then(function(r) {
        if (r.status === 401) { window.location.href = '/login'; }
      }).catch(function() {});
    } catch(e) {}
  }

  function resetActivityTimer() {
    if (!warningShown) {
      deadline = Date.now() + TIMEOUT_TOTAL * 1000;
      remaining = TIMEOUT_TOTAL;
      updateDisplay();
      if (Date.now() - lastHeartbeat > 60000) sendHeartbeat();
    }
  }

  window.extendSession = function() {
    deadline = Date.now() + TIMEOUT_TOTAL * 1000;
    remaining = TIMEOUT_TOTAL;
    warningShown = false;
    var modalEl = document.getElementById('sessionWarningModal');
    if (modalEl) modalEl.classList.remove('show');
    updateDisplay();
    try {
      fetch('/api/session/heartbeat').catch(function() {});
    } catch(e) {}
  };

  // Faaliyet dinleyicileri (tıklama, klavye, fare, dokunma, kaydırma)
  var events = ['mousedown', 'mousemove', 'keydown', 'scroll', 'touchstart'];
  var throttleTimer = null;
  events.forEach(function(evt) {
    window.addEventListener(evt, function() {
      if (!throttleTimer) {
        throttleTimer = setTimeout(function() {
          resetActivityTimer();
          throttleTimer = null;
        }, 1000);
      }
    }, { passive: true });
  });

  setInterval(function() {
    remaining = Math.ceil((deadline - Date.now()) / 1000);
    updateDisplay();
  }, 1000);

  document.addEventListener('DOMContentLoaded', updateDisplay);
})();

// Global Sleek Copy Feedback Tooltip & Clipboard Handler
window.copyWithFeedback = function(text, btnElement, message) {
  var msg = message || 'Kopyalama başarılı';

  function showPopup() {
    if (!btnElement) return;
    var parent = btnElement.parentElement;
    if (parent) {
      var compStyle = window.getComputedStyle(parent);
      if (compStyle.position === 'static') {
        parent.style.position = 'relative';
      }
    }
    btnElement.style.position = 'relative';
    var oldPopups = btnElement.querySelectorAll('.copy-feedback-popup');
    oldPopups.forEach(function(el) { el.remove(); });

    var popup = document.createElement('div');
    popup.className = 'copy-feedback-popup';
    popup.innerHTML = '<i class="fa-solid fa-circle-check"></i> ' + msg;
    btnElement.appendChild(popup);

    requestAnimationFrame(function() {
      popup.classList.add('show');
    });

    setTimeout(function() {
      popup.classList.remove('show');
      setTimeout(function() {
        if (popup.parentElement) {
          popup.parentElement.removeChild(popup);
        }
      }, 220);
    }, 2000);
  }

  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(function() {
      showPopup();
    }).catch(function() {
      fallbackCopy();
    });
  } else {
    fallbackCopy();
  }

  function fallbackCopy() {
    try {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.top = '-9999px';
      ta.style.left = '-9999px';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      var ok = document.execCommand('copy');
      document.body.removeChild(ta);
      if (ok) {
        showPopup();
      } else {
        showPopup();
      }
    } catch(e) {
      showPopup();
    }
  }
};

// Pre-configured NTP Vendor Commands
window.NTP_CONFIGS = {
  cisco: `ntp server 192.0.2.10 prefer
clock timezone TR 3 0`,
  mikrotik: `/system ntp client set enabled=yes servers=192.0.2.10
/system clock set time-zone-name=Europe/Istanbul`,
  huawei: `ntp-service unicast-server 192.0.2.10`,
  fortinet: `config system ntp
  set type custom
  set server "192.0.2.10"
end`,
  juniper: `set system ntp server 192.0.2.10 prefer
set system time-zone Europe/Istanbul`,
  aruba: `sntp server priority 1 192.0.2.10
sntp enable
time timezone 180`,
  paloalto: `set deviceconfig system ntp-servers primary-ntp-server ntp-server-address 192.0.2.10
set deviceconfig system timezone Europe/Istanbul`,
  linux: `[Time]
NTP=192.0.2.10
# veya chrony.conf:
server 192.0.2.10 iburst prefer`,
  windows: `w32tm /config /manualpeerlist:"192.0.2.10,0x8" /syncfromflags:manual /reliable:yes /update
w32tm /resync`,
  pfsense: `Server: 192.0.2.10 (Prefer / Active)
Timezone: Europe/Istanbul`,
  arista: `ntp server 192.0.2.10 prefer iburst
clock timezone Europe/Istanbul`,
  nxos: `ntp server 192.0.2.10 prefer use-vrf management
clock timezone TRT 3 0`,
  iosxr: `ntp
 server 192.0.2.10 prefer
!
clock timezone TRT 3
commit`,
  dell: `ntp server 192.0.2.10 prefer
clock timezone Europe/Istanbul`,
  nokia: `/configure system time ntp server 192.0.2.10 prefer
/configure system time ntp no shutdown
/configure system time zone non-standard TRT hrs-offset 3`,
  exos: `configure ntp server add 192.0.2.10 iburst
enable ntp
configure timezone 180 noautodst`,
  ruckus: `ntp
 server 192.0.2.10
exit
clock timezone gmt GMT+03`,
  checkpoint: `set ntp server primary 192.0.2.10 version 4
set ntp active on
set timezone Europe / Istanbul
save config`,
  sophos: `Administration -> Time
NTP server: 192.0.2.10
Time zone: (GMT+03:00) Istanbul
Apply`,
  alliedware: `ntp server 192.0.2.10 prefer
clock timezone TRT plus 3`,
  reyee: `ntp server 192.0.2.10
clock timezone TRT 3 0`,
  f5: `modify sys ntp servers add { 192.0.2.10 }
modify sys ntp timezone Europe/Istanbul
save sys config`,
  omniswitch: `ntp server 192.0.2.10 prefer
ntp client enable
system timezone +3:00
write memory`
};

window.copyNtpConfig = function(vendor, btn) {
  var cmd = window.NTP_CONFIGS[vendor];
  var ipEl = document.getElementById('ntp-server-ip'), ntpIp = ipEl ? JSON.parse(ipEl.textContent) : null;
  if (cmd && ntpIp) cmd = cmd.split('192.0.2.10').join(ntpIp);
  if (cmd && window.copyWithFeedback) {
    window.copyWithFeedback(cmd, btn, 'Kopyalama başarılı');
  }
};
