# Modüller (otomatik: python scripts/new_menu.py --index)

| menü | URL'ler | servis | şablon | test |
|---|---|---|---|---|
| admins | /admin/add-system, /admin/add-unified, /admin/add-web, /admin/audit/export.csv +14 | services/admins.py | templates/admins/ | tests/test_admins.py |
| alarms | /alarms, /alarms/<event_id>/ack, /alarms/<event_id>/resolve, /alarms/data +4 | services/alarms.py | templates/alarms/ | tests/test_alarms.py |
| anomalies | /anomalies, /anomalies/data, /anomalies/rules | services/anomalies.py | templates/anomalies/ | - |
| api | /api/docs, /api/openapi.json, /api/v1/alarms, /api/v1/apn +18 | - | templates/api/ | tests/test_api.py |
| apn | /apn, /apn/<kind>/<int:rec_id>/delete, /apn/<kind>/<int:rec_id>/edit, /apn/<kind>/<int:rec_id>/update +1 | services/apn.py | templates/apn/ | tests/test_apn.py |
| approvals | /approvals, /approvals/<int:rec_id>/approve, /approvals/<int:rec_id>/delete, /approvals/<int:rec_id>/reject +1 | services/approvals.py | templates/approvals/ | tests/test_approvals.py |
| audit | /accounting, /audit, /audit/archive/<filename>, /audit/archive/verify +1 | - | templates/audit/ | tests/test_audit.py |
| auth | /api/session/heartbeat, /login, /login-2fa, /login/2fa +1 | - | templates/auth/ | - |
| authlog | /authlog, /authlog/data, /authlog/export.csv | services/authlog.py | templates/authlog/ | - |
| availability | /availability, /availability/data | services/availability.py | templates/availability/ | - |
| backups | /backup, /backup/create, /backup/create-source-bundle, /backup/delete/<path:filename> +5 | services/backups.py | templates/backups/ | tests/test_backups.py |
| batch | /batch-users, /voucher/delete/<code>, /voucher/generate, /vouchers +3 | - | templates/batch/ | tests/test_batch.py |
| boards | /boards, /boards/<int:board_id>/data, /boards/<int:board_id>/delete, /boards/<int:board_id>/export.json +3 | services/boards.py | templates/boards/ | tests/test_boards.py |
| certs | /certs, /certs/check, /certs/data, /certs/settings | services/certs.py | templates/certs/ | - |
| cfgaudit | /configs/audit, /configs/audit/changes, /configs/audit/diff/<ip>, /configs/audit/report.<fmt> | services/cfgaudit.py | templates/cfgaudit/ | tests/test_cfgaudit.py |
| cli | /api/cli/autocomplete, /api/cli/execute, /cli, /terminal | services/cli.py | templates/cli/ | tests/test_cli.py |
| configs | /configs, /configs/<ip>/backup, /configs/<ip>/diff, /configs/<ip>/upload +10 | services/configs.py | templates/configs/ | tests/test_configs.py |
| correlation | /correlation, /correlation/data | services/correlation.py | templates/correlation/ | - |
| dashboard | /, /api/dashboard/stats | services/dashboard.py | templates/dashboard/ | tests/test_dashboard.py |
| equipment | /equipment, /equipment/data/<kind>, /equipment/discover, /equipment/export/<kind>.<fmt> | services/equipment.py | templates/equipment/ | tests/test_equipment.py |
| erasures | /erasures, /erasures/run | services/erasures.py | templates/erasures/ | tests/test_erasures.py |
| flows | /flows, /flows/data, /flows/export.<fmt> | services/flows.py | templates/flows/ | tests/test_flows.py |
| groups | /group/add, /group/delete/<path:groupname>, /groups, /profiles | services/groups.py | templates/groups/ | tests/test_groups.py |
| hardening | /hardening, /hardening/netflow-sources, /hardening/policy | services/hardening.py | templates/hardening/ | tests/test_hardening.py |
| health | /health, /health/data/<kind>, /health/export/<kind>.<fmt>, /health/radiolink/data +2 | services/health.py | templates/health/ | tests/test_health.py |
| integrations | /integrations, /integrations/test, /integrations/webhook, /integrations/webhook-test | services/integrations.py | templates/integrations/ | - |
| inventory | /inventory, /inventory/data, /inventory/export.<fmt>, /inventory/range/<int:range_id>/delete +2 | services/inventory.py | templates/inventory/ | tests/test_inventory.py |
| ipam | /ipam, /ipam/addr/<int:aid>/delete, /ipam/addr/add, /ipam/data +4 | services/ipam.py | templates/ipam/ | tests/test_ipam.py |
| ippools | /ippools, /ippools/<name>/assignments, /ippools/add, /ippools/assign +2 | services/ippools.py | templates/ippools/ | tests/test_ippools.py |
| ipscan | /ip-scan, /ip-scan/history/<scan_id>/delete, /ip-scan/job/<job_id>, /ip-scan/job/<job_id>/cancel +2 | services/ipscan.py | templates/ipscan/ | tests/test_ipscan.py |
| logs | /api/logs/stream, /logs | - | templates/logs/ | tests/test_logs.py |
| loops | /loops, /loops/data, /loops/export/<kind>.<fmt> | services/loops.py | templates/loops/ | tests/test_loops.py |
| macalarm | /macalarms, /macalarms/data, /macalarms/rule/<rtype>, /macalarms/run | services/macalarm.py | templates/macalarm/ | tests/test_macalarm.py |
| machist | /machist, /machist/data, /machist/export.csv | services/machist.py | templates/machist/ | tests/test_machist.py |
| macs | /mac-auth, /mac/add, /mac/delete/<mac>, /macs | services/macs.py | templates/macs/ | tests/test_macs.py |
| macscan | /macscan, /macscan/data, /macscan/export.<fmt>, /macscan/scan | services/macscan.py | templates/macscan/ | tests/test_macscan.py |
| nacmarks | /blacklist, /enforcement, /enforcement/data, /quarantine | services/nacmarks.py | templates/nacmarks/ | - |
| nas | /nas, /nas/add, /nas/delete/<int:nas_id> | services/nas.py | templates/nas/ | tests/test_nas.py |
| notifications | /api/notifications, /api/notifications/read, /notifications | services/notifications.py | templates/notifications/ | tests/test_notifications.py |
| ntp | /api/ntp/restart, /api/ntp/status, /api/ntp/sync, /ntp +1 | - | templates/ntp/ | tests/test_ntp.py |
| permissions | /permissions, /permissions/export.json, /permissions/save | - | templates/permissions/ | - |
| portscan | /portscan, /portscan/job/<job_id>, /portscan/job/<job_id>/cancel, /portscan/job/<job_id>/delete +1 | services/portscan.py | templates/portscan/ | tests/test_portscan.py |
| radtest | /test | services/radtest.py | templates/radtest/ | tests/test_radtest.py |
| reports | /reports, /reports/download/<int:run_id>, /reports/generate, /reports/schedule/<int:sid>/<action> +1 | services/reports.py | templates/reports/ | tests/test_reports.py |
| security | /api/security/2fa/reset/<path:username>, /api/security/password/reset, /api/security/password/reset/<path:username>, /api/system/telemetry +5 | - | templates/security/ | tests/test_security.py |
| services | /api/server/reboot, /api/service/restart/<srv_key>, /api/service/status/<srv_key>, /api/service/test-ping/<srv_key> +3 | - | templates/services/ | tests/test_services.py |
| sessions | /session/disconnect/<int:radacctid>, /sessions, /sessions/clean-ghosts | services/sessions.py | templates/sessions/ | tests/test_sessions.py |
| settings | /api/settings/dns, /api/settings/firewall/reload, /api/settings/ssh/reload, /api/settings/timezone +1 | - | templates/settings/ | tests/test_settings.py |
| siem | /siem, /siem/settings, /siem/test | services/siem.py | templates/siem/ | - |
| snmp_page | /snmp, /snmp/topology.json, /snmp/topology/stream | - | - | - |
| svchealth | /svchealth, /svchealth/check, /svchealth/data, /svchealth/settings +1 | services/svchealth.py | templates/svchealth/ | tests/test_svchealth.py |
| syslog | /syslog, /syslog/data, /syslog/export.csv, /syslog/settings | services/syslog.py | templates/syslog/ | tests/test_syslog.py |
| tacacs_page | /tacacs | - | - | - |
| tenants | /tenants, /tenants/<int:tid>/delete, /tenants/<int:tid>/rename, /tenants/add +4 | - | templates/tenants/ | tests/test_tenants.py |
| topology | /topology, /topology/data, /topology/discover, /topology/export.<fmt> +1 | services/topology.py | templates/topology/ | tests/test_topology.py |
| users | /user/add, /user/delete/<path:username>, /user/disable/<path:username>, /user/edit +6 | - | templates/users/ | tests/test_users.py |
| watch | /watch, /watch/<int:target_id>/delete, /watch/add, /watch/check +3 | services/watch.py | templates/watch/ | tests/test_watch.py |
