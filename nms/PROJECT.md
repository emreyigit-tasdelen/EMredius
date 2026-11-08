# Project: Enterprise TACACS+ AAA and Multi-vendor SNMP NMS

## Architecture
- **Language & Runtime**: Python 3.12, SQLite 3.49 (WAL Mode), pure async networking with `cryptography 48.0.0`.
- **Daemons / Services**:
  1. `tacacs_daemon` (TCP Port 49): RFC 8907 AAA Server handling Authentication, Privilege Levels (0-15), Regex Command Authorization, and Real-time Command Accounting.
  2. `snmp_daemon` (UDP Port 161/162): Universal SNMPv2c / SNMPv3 USM Poller, CIDR Auto-Discovery, Multi-Vendor Telemetry Math, and Stateful Alarm Engine with Telegram/Slack webhooks.
  3. `web_app` (HTTP Port 5000): Unified Web Interface with FreeRADIUS Foundation + `[TACACS+ Yönetimi]` + `[SNMP NMS / Ağ İzleme]`, 6-Language Engine (TR, EN, ZH, RU, ES, FR), Chart.js live telemetry graphs, Dark/Light mode, RBAC.
- **Database Architecture**: SQLite in WAL mode (`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;`) for lock-free multi-process concurrency across daemons and web API.

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | TACACS+ TCP 49 Server Socket | Async TCP server socket binding port 49 | M1 | RFC 8907 §3.4 |
| 2 | TACACS+ 12-Byte Header Codec | Header pack/unpack (ver, type, seq, flags, session_id, len) | M1 | RFC 8907 §4.1 |
| 3 | TACACS+ Single Connection Mode | Multiplexing sessions over single TCP connection | M1 | RFC 8907 §4.3 |
| 4 | TACACS+ MD5 Obfuscation Pad | Symmetric MD5 pseudo-pad XOR encryption/decryption | M1 | RFC 8907 §4.5 |
| 5 | Authentication START Handler | Action LOGIN/ENABLE, authen_types (ASCII, PAP, CHAP) | M1 | RFC 8907 §5.1 |
| 6 | Authentication CONTINUE Handler | User message response, abort flag handling | M1 | RFC 8907 §5.2 |
| 7 | Authentication REPLY Generator | Status PASS, FAIL, GETDATA, GETUSER, GETPASS | M1 | RFC 8907 §5.3 |
| 8 | Authentication ASCII Flow | Interactive console/SSH prompt challenge flow | M1 | RFC 8907 §5.1 |
| 9 | Authentication PAP Flow | Inband password verification | M1 | RFC 8907 §5.1 |
| 10 | Authentication CHAP Flow | MD5 challenge-response verification | M1 | RFC 8907 §5.1 |
| 11 | Authentication ENABLE Flow | Enable secret privilege escalation verification | M1 | RFC 8907 §5.1 |
| 12 | Privilege Level 0-15 Management | User and group privilege level resolution | M1 | RFC 8907 §9 |
| 13 | Authorization REQUEST Codec | Parse authen_method, priv_lvl, user, port, AV args | M1 | RFC 8907 §6.1 |
| 14 | Command Reconstruction | Concatenate `cmd` and positional `cmd-arg`s | M1 | RFC 8907 §8.2 |
| 15 | Regex Command Authorization Policy | Allow/Deny regex rule evaluation with ordered matching | M1 | R1, AC |
| 16 | AV-Pair Parsing | Mandatory (`=`) vs Optional (`*`) attribute separation | M1 | RFC 8907 §8.1 |
| 17 | Multi-Vendor AV-Pair Dispatch | Cisco, Huawei, Juniper, Fortinet, Aruba AV profiles | M1 | R1 |
| 18 | Accounting REQUEST Codec | Flags START (2), STOP (4), WATCHDOG (8), AV extraction | M1 | RFC 8907 §7.1 |
| 19 | Real-Time Accounting Logger | Immediate commit of command audit log into SQLite WAL | M1 | R1, AC |
| 20 | Multi-Client Secret Lookup | Resolve shared secret and profile by NAS IP / CIDR | M1 | RFC 8907 §4.5 |
| 21 | SNMPv2c Protocol Engine | Community-based Get, GetNext, GetBulk, Set (UDP 161) | M2 | RFC 1905 |
| 22 | SNMPv3 USM Protocol Engine | noAuthNoPriv, authNoPriv, authPriv security levels | M2 | RFC 3414 |
| 23 | SNMPv3 HMAC Authentication | MD5, SHA1, SHA224, SHA256 HMAC digest verification | M2 | RFC 3414, 7860 |
| 24 | SNMPv3 Privacy Encryption | DES, AES128, AES192, AES256 CFB mode encryption | M2 | RFC 3826 |
| 25 | SNMPv3 EngineID & Time Sync | Dynamic EngineID discovery & time-window tracking | M2 | RFC 3414 §3 |
| 26 | RFC 1213 MIB-II Collector | Polling sysDescr, sysObjectID, sysUpTime, sysName | M2 | RFC 1213 |
| 27 | RFC 2863 IF-MIB Collector | ifTable & ifXTable 32-bit and 64-bit HC counters | M2 | RFC 2863 |
| 28 | Cisco Enterprise Collector | IOS/IOS-XE/NX-OS CPU, RAM, Temp OID collection | M2 | Cisco MIBs |
| 29 | MikroTik Enterprise Collector | RouterOS v6/v7 CPU, RAM, Temp OID collection | M2 | MikroTik MIB |
| 30 | Huawei Enterprise Collector | VRP hwEntity CPU, RAM, Temp OID collection | M2 | Huawei MIB |
| 31 | Juniper Enterprise Collector | JunOS jnxOperating CPU, RAM, Temp OID collection | M2 | Juniper MIB |
| 32 | Fortinet Enterprise Collector | FortiGate fgSys CPU, RAM, Session count collection | M2 | Fortinet MIB |
| 33 | HP / Aruba Enterprise Collector | Comware & ArubaOS CPU, RAM OID collection | M2 | Aruba MIB |
| 34 | Auto-Discovery CIDR Scanner | Async IP range scan with UDP port check & credential test | M2 | R2 |
| 35 | Vendor Fingerprinting | sysObjectID regex mapping to vendor and model profile | M2 | R2 |
| 36 | Telemetry Math Engine | Delta rates: bps, pps, errors, discards, wrap handling | M2 | R2, AC |
| 37 | Time-Series Metrics Persistence | SQLite WAL storage of periodic interface and health stats | M2 | R2 |
| 38 | Stateful Alarm Engine | Link-down, CPU/RAM threshold, device unreachable alerts | M2 | R2, AC |
| 39 | Alarm Hysteresis & Flap Damping | 10% deadband and flapping suppression to stop alert spam | M2 | R2 |
| 40 | Telegram Webhook Dispatcher | Asynchronous Telegram Bot API alert notifications | M2 | R2 |
| 41 | Slack Webhook Dispatcher | Asynchronous Slack incoming webhook alert notifications | M2 | R2 |
| 42 | Web Application Core | Modular Flask app, session security, database connection | M3 | R3, AC |
| 43 | FreeRADIUS Foundation Module | Radcheck, radreply, nas, radacct management | M3 | R3, AC |
| 44 | TACACS+ Management Web Tab | Manage users, privs (0-15), groups, devices, regex rules | M3 | R3, AC |
| 45 | Live Command Audit Table | Searchable, filterable real-time log with CSV/JSON export | M3 | R3, AC |
| 46 | SNMP NMS Web Tab | Device inventory, live topology/status map | M3 | R3, AC |
| 47 | Chart.js Live Traffic Graphs | Real-time time-series bandwidth (in/out bps, packets) | M3 | R3, AC |
| 48 | Device Health Widgets | Gauge/progress indicators for CPU, RAM, Temp, Uptime | M3 | R3 |
| 49 | Alarm Management View | Active/resolved alarm listing, acknowledge, webhook config | M3 | R3, AC |
| 50 | 6-Language Dynamic Engine | TR, EN, ZH, RU, ES, FR dynamic translations without reload | M3 | R3 |
| 51 | Dark / Light Theme Engine | CSS custom property theme switcher with localStorage save | M3 | R3 |
| 52 | Role-Based Access Control | Admin, Operator, Viewer roles with UI and API protection | M3 | R3 |
| 53 | Daemon Process Management | Start/stop/status controls and heartbeat monitoring | M3 | R3, AC |
| 54 | E2E Test Infra & Simulators | RFC 8907 test client & multi-vendor SNMP mock responders | M0_E2E | AC |
| 55 | Acceptance Criteria Verification | 100% pass of all 8 acceptance criteria + adversarial tests | M4 | AC |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M0_E2E | E2E Test Suite Track | Test runners, mock simulators, Tiers 1-4 test cases (TEST_READY.md) | none | IN_PROGRESS |
| M1 | Core TACACS+ RFC 8907 Engine | TCP 49 async daemon, codec, MD5 pad, Auth, Author, Acct, regex engine | none | DONE |
| M2 | Multi-Vendor SNMPv2c/v3 Engine | SNMPv2c/v3 engine, 6-vendor OIDs, auto-discovery, telemetry math, alarms | none | DONE |
| M3 | Unified Web Panel & 6-Language UI | Flask web panel, TACACS+ tab, SNMP tab, 6 languages, Chart.js, RBAC | M1, M2 | IN_PROGRESS |
| M4 | Final Milestone & Hardening | 100% E2E test pass, Tier 5 adversarial hardening, Forensic Audit | M0_E2E, M1, M2, M3 | PLANNED |

## Interface Contracts

### 1. Database Contract (SQLite WAL mode: `data/enterprise_nms.db`)
- `users` (id, username, password_hash, enable_password_hash, chap_secret, priv_lvl, group_id, enabled, created_at, updated_at)
- `groups` (id, name, priv_lvl, description)
- `tacacs_clients` (id, ip_cidr, shared_secret, vendor, name)
- `tacacs_rules` (id, group_id, priority, pattern, action ['permit'/'deny'], description)
- `tacacs_accounting` (id, timestamp, device_ip, client_ip, username, priv_lvl, cmd, status ['PERMITTED'/'DENIED'])
- `snmp_devices` (id, ip, port, version ['v2c'/'v3'], community, v3_user, v3_auth_proto, v3_auth_key, v3_priv_proto, v3_priv_key, vendor, sys_name, sys_descr, status, last_seen)
- `snmp_interfaces` (id, device_id, if_index, if_descr, if_name, if_type, if_speed, if_admin_status, if_oper_status, if_mac)
- `snmp_telemetry` (id, timestamp, device_id, if_index, in_bps, out_bps, in_pps, out_pps, in_errors, out_errors)
- `snmp_health` (id, timestamp, device_id, cpu_percent, memory_percent, temperature_c, uptime_seconds)
- `alarms` (id, timestamp, device_id, if_index, alarm_type, severity ['INFO'/'WARNING'/'CRITICAL'], message, resolved, resolved_at)
- `daemon_status` (daemon_name PRIMARY KEY, last_heartbeat, pid, status, metrics_json)

### 2. Daemon IPC Contract
- All daemons record heartbeat timestamp every 5 seconds to `daemon_status`.
- TACACS+ daemon listens on `0.0.0.0:49` TCP.
- SNMP poller listens on UDP `0.0.0.0:162` (for traps) and queries agents on UDP `161`.
- Web application reads SQLite WAL without write locking (`PRAGMA busy_timeout=5000`).

### 3. Web API REST Contract
- `/api/tacacs/rules` [GET, POST, DELETE]
- `/api/tacacs/accounting` [GET] (query params: `limit`, `username`, `device_ip`, `status`, `search`)
- `/api/snmp/devices` [GET, POST, DELETE]
- `/api/snmp/discovery/scan` [POST] (payload: `{"cidr": "192.168.1.0/24", "community": "public", ...}`)
- `/api/snmp/telemetry/<device_id>/<if_index>` [GET] (time-series points for Chart.js)
- `/api/snmp/health/<device_id>` [GET]
- `/api/alarms` [GET, POST] (ack, filter active/resolved)
- `/api/i18n/<lang>` [GET] (loads translation bundle for TR, EN, ZH, RU, ES, FR)

## Code Layout
```
enterprise_tacacs_nms/
├── data/
│   └── enterprise_nms.db            # SQLite WAL database
├── src/
│   ├── common/
│   │   ├── __init__.py
│   │   ├── db.py                    # Schema migration, connection pooling & WAL pragmas
│   │   └── models.py                # Database models & dataclasses
│   ├── tacacs/
│   │   ├── __init__.py
│   │   ├── codec.py                 # RFC 8907 header/body packet serialization & parsing
│   │   ├── crypto.py                # MD5 pad obfuscation & XOR encryption
│   │   ├── authen.py                # Authentication state machine (ASCII, PAP, CHAP, ENABLE)
│   │   ├── author.py                # Authorization state machine & regex policy engine
│   │   ├── acct.py                  # Accounting processor & real-time DB logging
│   │   └── server.py                # Asyncio TCP 49 daemon entry point
│   ├── snmp/
│   │   ├── __init__.py
│   │   ├── engine.py                # Dual SNMPv2c / SNMPv3 client implementation
│   │   ├── mibs.py                  # Standard MIB-II, IF-MIB & 6 vendor OID catalogs
│   │   ├── discovery.py             # CIDR network scanner & vendor fingerprinting
│   │   ├── poller.py                # Background telemetry & health polling daemon
│   │   ├── telemetry.py             # Delta calculation, wrap handling & stats
│   │   ├── alarms.py                # Stateful alarm engine with hysteresis & flap damping
│   │   └── webhooks.py              # Telegram & Slack webhook dispatchers
│   └── web/
│       ├── __init__.py
│       ├── app.py                   # Flask entry point & blueprint registration
│       ├── auth.py                  # RBAC session management & decorators
│       ├── routes_tacacs.py         # TACACS+ management API & views
│       ├── routes_snmp.py           # SNMP NMS API & views
│       ├── routes_radius.py         # FreeRADIUS foundation views
│       ├── static/
│       │   ├── css/app.css          # Responsive dark/light styles
│       │   └── js/
│       │       ├── app.js           # UI controls & theme switcher
│       │       ├── i18n.js          # 6-language client-side switcher
│       │       └── charts.js        # Chart.js bandwidth telemetry rendering
│       ├── templates/
│       │   ├── base.html            # Unified layout with dark/light & lang selector
│       │   ├── tacacs.html          # TACACS+ Management Tab & Audit Table
│       │   ├── snmp.html            # SNMP NMS Tab & Charts
│       │   └── radius.html          # FreeRADIUS Foundation Tab
│       └── locales/
│           ├── tr.json              # Turkish translations
│           ├── en.json              # English translations
│           ├── zh.json              # Chinese translations
│           ├── ru.json              # Russian translations
│           ├── es.json              # Spanish translations
│           └── fr.json              # French translations
├── tests/
│   ├── test_tacacs_rfc8907.py       # TACACS+ unit & codec tests
│   ├── test_snmp_multivendor.py     # SNMP v2c/v3 & vendor MIB tests
│   ├── test_web_i18n_rbac.py        # Web routes, 6-language engine & RBAC tests
│   ├── e2e/
│   │   ├── mock_tacacs_client.py    # Simulated network device TACACS+ client
│   │   ├── mock_snmp_agent.py       # Simulated multi-vendor SNMP agent (Cisco, MikroTik, etc.)
│   │   ├── test_tier1_features.py   # Tier 1 Feature Coverage E2E tests
│   │   ├── test_tier2_boundaries.py # Tier 2 Boundary & Corner Cases E2E tests
│   │   ├── test_tier3_combined.py   # Tier 3 Cross-feature Combinations E2E tests
│   │   └── test_tier4_scenarios.py  # Tier 4 Real-world Application Scenarios E2E tests
└── run_all.py                       # Single unified service launcher for daemons + web
```
