# Kurulum

Bu belge EMREDIUS'u AlmaLinux 8/9 üzerinde kurmak için referans adımları özetler. Komutlar `root` ile çalıştırılır; yolları kendi ortamınıza göre uyarlayın. Üretime almadan önce bir test sunucusunda deneyin.

## 1. Önkoşullar

- AlmaLinux 8/9, Python 3.12, nginx, MariaDB, FreeRADIUS (`freeradius`, `freeradius-mysql`, `freeradius-utils`), firewalld, SELinux (enforcing).
- FreeRADIUS'un SQL modülü (`/etc/raddb/mods-enabled/sql`) MariaDB'deki `radius` şemasına bağlı olmalıdır. Panel bu şemayı yönetir ve veritabanı parolasını FreeRADIUS yapılandırmasından okur (parola panel ortam dosyasına yazılmaz).

## 2. Kod ve sanal ortam

```bash
install -d -m 755 /opt/emredius /etc/emredius /var/lib/emredius
# depoyu /opt/emredius altına kopyalayın (git clone veya arşiv)
cd /opt/emredius
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## 3. Yapılandırma

```bash
cp deploy/emredius.env.example /etc/emredius/emredius.env
cp deploy/my.cnf.example       /etc/emredius/my.cnf      # yedekleme için mysqldump istemci ayarı
chmod 600 /etc/emredius/emredius.env /etc/emredius/my.cnf
```

Değişkenlerin tamamı için [README](../README.tr.md) içindeki yapılandırma tablosuna bakın. Oturum anahtarı (`SECRET_KEY`) yoksa ilk açılışta `/etc/emredius/secret_key` dosyasına 0600 izniyle üretilir.

## 4. Servisler

```bash
cp deploy/systemd/*.service deploy/systemd/*.socket deploy/systemd/*.timer /etc/systemd/system/
rm -f /etc/systemd/system/emredius-staging.service   # test sunucusu birimi, üretimde gerekmez
systemctl daemon-reload
systemctl enable --now emredius-panel.socket emredius-panel.service emredius-nms emredius-syslog
systemctl enable --now emredius-5651.timer emredius-oui.timer emredius-backup-verify.timer
```

Akış toplayıcı (NetFlow/IPFIX/sFlow) panel sürecinin içinde çalışır; ayrı `emredius-netflow.service` birimi yalnızca bağımsız toplayıcı isteyenler içindir.

## 5. nginx ve güvenlik duvarı

- nginx, TLS (443) sonlandırır ve `127.0.0.1:5000` adresine proxy eder. Sertifikayı kendi CA'nızdan veya kurumsal PKI'dan alın.
- Syslog (UDP 514), sFlow (6343), NetFlow (2055) ve IPFIX (4739) portlarını yalnızca ağ cihazlarınızın bulunduğu özel ağ bloklarına (RFC 1918) açın:

```bash
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.0.0.0/8" port port="514" protocol="udp" accept'
firewall-cmd --reload
```

- Yeni dosya ve dizinlerde SELinux etiketlerini düzeltin: `restorecon -R /opt/emredius /etc/emredius`. Ayrıntı için `deploy/selinux/README.md`.

## 6. Doğrulama

```bash
.venv/bin/python scripts/healthcheck_setup.py     # tek seferlik: sağlık kontrolü hesaplarını üretir
.venv/bin/python scripts/healthcheck.py           # panel, giriş, RADIUS testi
.venv/bin/python scripts/smoke.py                 # tüm menülerde rota taraması
.venv/bin/python -m pytest -q tests
```

## 7. Yedekleme ve bakım

- `scripts/backup.sh` ve `radius-backup.service`: veritabanı ve yapılandırma yedeği; `emredius-backup-verify.timer` yedeği geri yükleyerek doğrular.
- `emredius-5651.timer`: günlük imzalı 5651 kayıt arşivi (saat NTP ile senkron değilse ertelenir).
- `scripts/rotate_db_password.py`: MariaDB parolasını döndürür, FreeRADIUS yapılandırmasını günceller, başarısızlıkta geri alır.
