# Mimari

Bu belge EMREDIUS'un bileşenlerini, veri akışlarını ve veri modelini teknik düzeyde anlatır. Kurulum ve çalıştırma için [README](../README.md), menü → URL indeksi için [MODULES.md](MODULES.md).

## 1. Bileşenler ve süreçler

Sistem tek sunucuda (AlmaLinux) birkaç bağımsız systemd süreci olarak çalışır. Süreçler birbirini çağırmaz; ortak durum iki veritabanındadır: FreeRADIUS'un **MariaDB** şeması ve NMS için **SQLite (WAL)**.

```mermaid
flowchart LR
    ADM["Yönetici (tarayıcı)"]
    DEV["Ağ cihazları<br/>(switch, AP, firewall)"]

    subgraph HOST["AlmaLinux sunucu"]
        direction TB
        NGX["nginx<br/>TLS 443"]
        PANEL["emredius-panel<br/>gunicorn gthread, 1 worker x 16 thread<br/>127.0.0.1:5000"]
        RAD["FreeRADIUS<br/>UDP 1812 / 1813"]
        NMSD["emredius-nms<br/>python -m nms.runner<br/>TACACS+ TCP 49 + SNMP poller"]
        SYSLOG["emredius-syslog<br/>python -m nms.syslogd<br/>UDP 514"]
        TIMERS["systemd timer'lar<br/>5651 arşivi, OUI, yedek doğrulama"]
        MDB[("MariaDB<br/>radcheck, radacct, nas ...")]
        SQL[("SQLite WAL<br/>enterprise_nms.db")]
    end

    ADM -- "HTTPS" --> NGX --> PANEL
    DEV -- "802.1X / MAB" --> RAD
    DEV -- "AAA" --> NMSD
    NMSD -- "SNMP sorgu 161" --> DEV
    DEV -- "syslog" --> SYSLOG
    DEV -- "NetFlow / IPFIX / sFlow<br/>UDP 2055, 4739, 6343" --> PANEL

    RAD <--> MDB
    PANEL <--> MDB
    PANEL <--> SQL
    NMSD <--> SQL
    SYSLOG --> SQL
    TIMERS --> MDB
```

| Süreç | Giriş noktası | Dinlediği port | Yazdığı depo |
|---|---|---|---|
| Panel | `wsgi:app` (`gunicorn -c gunicorn.conf.py`) | 127.0.0.1:5000 (nginx arkasında); akış toplayıcı thread'i UDP 2055, 4739, 6343 | MariaDB, SQLite |
| NMS | `nms.runner` (`DaemonSupervisor`) | TACACS+ TCP 49, SNMP poller | SQLite |
| Syslog | `nms.syslogd` | UDP 514 | SQLite (`syslog_msgs`) |
| Zamanlayıcılar | `scripts/maintenance.py archive5651`, `scripts/update_oui.py`, `scripts/backup_verify.sh` | - | dosya arşivi, MariaDB |

Birim dosyaları `deploy/systemd/` altındadır.

### Neden bu tasarım?

- **Tek gunicorn worker, çok thread.** Giriş denemesi sayaçları, ayar önbelleği ve arka plan işleri süreç başına tutulur. Tek süreç bunları tutarlı kılar; trafik düşük ve G/Ç ağırlıklı olduğu için thread yeterlidir (`gunicorn.conf.py`).
- **FreeRADIUS şemasına dokunmadan yönetim.** Panel, FreeRADIUS'un kendi SQL şemasını (`radcheck`, `radreply`, `radusergroup`, `radacct`, `nas`, ...) okur/yazar. RADIUS tarafı kendi sürecinde ve kendi performansıyla çalışır; panel çökse bile kimlik doğrulama sürer. DB parolasının tek kaynağı FreeRADIUS'un `sql` modülü yapılandırmasıdır (`emredius/config.py`).
- **NMS için SQLite WAL.** Telemetri, envanter, alarm ve syslog tek dosyada; çok süreçli okuma kilitlenmez. TACACS+ sırları ve SNMP community'leri bu dosyada olduğu için `nms/data/` ve `*.db` `.gitignore`'dadır.
- **Menü = blueprint + servis + şablon + test.** İş mantığı `services/`, HTTP katmanı `blueprints/`, görünüm `templates/` altındadır; her menünün kendi test dosyası vardır (`scripts/new_menu.py` iskelet üretir).

## 2. Panel katmanları

```mermaid
flowchart TB
    REQ["HTTP isteği"] --> SEC["core.security<br/>güvenlik başlıkları, oturum doğrulama"]
    SEC --> CSRF["core.csrf<br/>CSRF jetonu"]
    CSRF --> RBAC["core.rbac<br/>require_page / api_auth_required"]
    RBAC --> BP["blueprints/&lt;menü&gt;/routes.py"]
    BP --> SVC["services/&lt;menü&gt;.py"]
    SVC --> MDB[("MariaDB")]
    SVC --> SQL[("SQLite NMS")]
    SVC --> SYSD["systemctl, firewall-cmd, SSH, SNMP<br/>core.system.run_cmd"]
    BP --> TPL["templates/&lt;menü&gt;/ (Jinja)"]
```

- **Roller** (`core/auth.py`): `superadmin`, `network_admin`, `helpdesk`, `auditor` (salt okunur). Sayfa yetkileri düzenlenebilir yetki matrisindedir (`/permissions`).
- **Kimlik:** web hesapları (hash'li), Linux sistem hesapları (`/etc/shadow`) ve iki adımlı doğrulama (`/login-2fa`). IP başına kaba kuvvet kilidi vardır.
- **Çok kiracılık:** envanter, akış, MAC tarama gibi NMS tabloları `tenant_id` taşır (`core/tenant.py`).
- **Güvenli sistem çağrıları:** sunucuyu değiştiren komutlar `core.system.run_cmd` üzerinden geçer; `SYSTEM_DRY_RUN=1` ile staging'de engellenir.

## 3. Ana akışlar

### 3.1 RADIUS kimlik doğrulama ve oturum

```mermaid
sequenceDiagram
    participant D as Ağ cihazı (NAS)
    participant R as FreeRADIUS
    participant M as MariaDB
    participant P as Panel
    D->>R: Access-Request (802.1X / MAB)
    R->>M: radcheck, radusergroup, radgroupreply sorgusu
    M-->>R: öznitelikler
    R-->>D: Access-Accept / Reject
    D->>R: Accounting Start / Interim / Stop
    R->>M: radacct yazar
    P->>M: oturumları okur (Oturumlar, Dashboard)
    P->>M: kullanıcı ve grup yönetimi yazar
```

### 3.2 TACACS+ yönetici erişimi (RFC 8907)

```mermaid
sequenceDiagram
    participant D as Cihaz
    participant T as nms.tacacs
    participant S as SQLite
    D->>T: Authentication START (ASCII, PAP veya CHAP)
    T->>S: tacacs_clients (NAS IP / CIDR için gizli anahtar)
    T->>S: users, groups (priv_lvl 0-15)
    T-->>D: PASS / FAIL
    D->>T: Authorization REQUEST (cmd + argümanlar)
    T->>S: tacacs_rules (sıralı regex allow/deny)
    T-->>D: PASS_ADD / FAIL
    D->>T: Accounting START / STOP
    T->>S: tacacs_accounting (komut denetim günlüğü)
```

### 3.3 SNMP keşif ve izleme

CIDR keşfi (`nms/snmp/discovery.py`) cihazlara sırayla v2c/v3 kimlik bilgisi dener, `sysObjectID` ile üreticiyi tanır ve arayüzleri tarar. Panel tarafındaki uç (`nms/web/routes_snmp.py`): 1024 adrese kadar istek içinde senkron, daha büyük aralıklar (süper yönetici için sınırsız) arka plan işi olarak çalışır.

```mermaid
sequenceDiagram
    participant UI as Tarayıcı (snmp.js)
    participant API as POST /api/snmp/discovery/scan
    participant J as Arka plan thread
    participant F as Geçici iş dosyası
    UI->>API: cidr, community, port
    alt 1024 adres ve altı
        API-->>UI: 200 + bulunan cihazlar
    else daha büyük aralık
        API->>J: 4096'lık parçalarla tarama başlat
        API-->>UI: 202 + job_id
        loop 3 sn'de bir
            J->>F: ilerleme (done / total / bulunan)
            UI->>F: GET /api/snmp/discovery/scan/job_id
        end
        UI->>F: DELETE (durdur isteği)
        J->>F: sonuç (done veya error)
    end
```

İş durumu geçici bir JSON dosyasında tutulur; bu sayede durum sorgusunu hangi süreç/thread karşılarsa karşılasın aynı sonucu görür.

```mermaid
stateDiagram-v2
    [*] --> running
    running --> running: parça tamamlandı
    running --> done: tüm parçalar bitti
    running --> done: durdurma isteği (kısmi sonuç)
    running --> error: istisna
    done --> [*]
    error --> [*]
```

Sürekli izleme `nms/snmp/poller.py` içindedir: arayüz sayaçlarından bps/pps/hata hızı (`snmp_telemetry`), CPU/bellek/sıcaklık (`snmp_health`) ve eşik kuralları (`nms/snmp/alarms.py`, `alarms` tablosu) üretir.

### 3.4 Akış ve syslog toplama

- **NetFlow v5/v9, IPFIX, sFlow:** panel sürecindeki toplayıcı (`services/flows.py`) UDP 2055, 4739 ve 6343'ü dinler, paketleri dakika bazında `flow_rollup` tablosunda toplar. Kaynak IP izin listesi `services/flow_acl.py` ve Sertleştirme menüsündedir.
- **Syslog:** `nms.syslogd` UDP 514'ü dinler, mesajları `syslog_msgs` tablosuna yazar; gönderici izin listesi `syslog_cfg` anahtarındadır.
- `nms/netflow/` ayrı bir toplayıcı sürecidir; panelin toplayıcısı tek toplayıcı olduğu için kurulu servisi yoktur ve portlar çakışacağından birlikte çalıştırılmamalıdır.

## 4. Veri modeli

### 4.1 NMS (SQLite, `nms/common/db.py`)

```mermaid
erDiagram
    groups ||--o{ users : "group_id"
    groups ||--o{ tacacs_rules : "group_id"
    snmp_devices ||--o{ snmp_interfaces : "device_id"
    snmp_devices ||--o{ snmp_telemetry : "device_id"
    snmp_devices ||--o{ snmp_health : "device_id"
    snmp_devices ||--o{ alarms : "device_id"

    groups {
        int id PK
        int priv_lvl
        text description
    }
    users {
        int id PK
        int priv_lvl
        int group_id FK
    }
    tacacs_rules {
        int id PK
        int group_id FK
        int priority
        text pattern
    }
    tacacs_clients {
        int id PK
        text description
    }
    tacacs_accounting {
        int id PK
        int priv_lvl
        text cmd
    }
    snmp_devices {
        int id PK
        int port
        text sys_descr
    }
    snmp_interfaces {
        int id PK
        int device_id FK
        int if_index
        int if_oper_status
    }
    snmp_telemetry {
        int id PK
        int device_id FK
        int if_index
        real in_bps
        real out_bps
    }
    snmp_health {
        int id PK
        int device_id FK
        real cpu_percent
        real memory_percent
    }
    alarms {
        int id PK
        int device_id FK
        text message
    }
```

Menü başına eklenen tablolar (`inv_*`, `topo_links`, `eq_*`, `flow_rollup`, `syslog_msgs`, `alm_*`, `ipam_*`, `cfg_*`, `ms_*`, `mxa_*`) aynı SQLite dosyasındadır ve `tenant_id` taşır. Şema, ilgili servis modülünün başındaki `CREATE TABLE IF NOT EXISTS` ifadelerinde tanımlıdır.

### 4.2 RADIUS (MariaDB, FreeRADIUS standart şeması)

```mermaid
erDiagram
    radcheck }o--|| radusergroup : "username"
    radusergroup }o--|| radgroupreply : "groupname"
    radusergroup }o--|| radgroupcheck : "groupname"
    radcheck ||--o{ radacct : "username"
    nas ||--o{ radacct : "nasipaddress"

    radcheck {
        text username
        text attribute
        text value
    }
    radusergroup {
        text username
        text groupname
    }
    radacct {
        int radacctid PK
        text username
        text nasipaddress
        datetime acctstarttime
        datetime acctstoptime
    }
    nas {
        int id PK
        text nasname
    }
```

Şemanın sahibi FreeRADIUS'tur. Bu diyagram yalnızca panelin kullandığı tabloları ve ilişkileri gösterir; panel ayrıca `radreply` ve `radpostauth` tablolarını da kullanır.

## 5. Güvenlik katmanları

| Katman | Uygulama |
|---|---|
| Taşıma | nginx TLS; panel yalnızca 127.0.0.1'e bağlı |
| Oturum | HttpOnly, Secure, SameSite=Lax çerez; 30 dk ömür; `SECRET_KEY` dosyası 0600 |
| İstek | CSRF jetonu, güvenlik başlıkları (HSTS, CSP bölümleri, Permissions-Policy) |
| Yetki | rol + sayfa matrisi, REST için `X-API-Key` veya `Bearer` |
| Denetim | yönetici işlemleri denetim kaydına yazılır; günlük imzalı 5651 arşivi |
| Ağ | firewalld: UDP 514, 6343, 2055, 4739 yalnız RFC1918 kaynaklara açık |
| SELinux | dosya etiketleri `restorecon` ile düzeltilir; yönerge ve yedek betiği `deploy/selinux/` |

Ayrıntılı bulgu listesi: [GUVENLIK_TARAMA.md](GUVENLIK_TARAMA.md).
