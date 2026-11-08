# Güvenlik Notları

Bu belge EMREDIUS'un uyguladığı güvenlik denetimlerini ve statik analiz sonuçlarının özetini içerir. Bir güvenlik açığı bildirmek için kök dizindeki [SECURITY.md](../SECURITY.md) dosyasına bakın.

## Uygulanan denetimler

| Alan | Denetim |
|---|---|
| Oturum | HttpOnly, Secure, SameSite=Lax çerez; 30 dakika ömür; iki adımlı doğrulama |
| CSRF | Tüm değiştirici isteklerde jeton zorunlu (yalnızca giriş ve API anahtarlı `/api/v1` muaf) |
| Yetkilendirme | Global `security_gate`; her route rol/yetki matrisinden geçer; anonim erişim reddi testlidir |
| Giriş koruması | Hesap bazlı kalıcı kilit, IP başına bellek içi sayaç; ters vekilde istek sınırı önerilir |
| Başlıklar | HSTS, Permissions-Policy, `frame-ancestors`, `base-uri`, `form-action`, `object-src`; `script-src` için Report-Only gözlem modu |
| SQL | Her yerde parametreli sorgu; dinamik kısımlar yalnızca sabit sütun listeleri |
| Girdi/çıktı | Jinja otomatik kaçış; JS bağlamı için `esc_js`; yönlendirmeler yalnızca aynı host |
| Alt süreçler | Liste argümanlı sabit komutlar; tek istisna yalnızca süper yöneticiye açık, denetim kaydına yazılan CLI aracı |
| Sırlar | Parolalar ve anahtarlar depoda tutulmaz; ortam dosyaları ve yedekler 0600 |
| Satır içi betik | Olay işleyiciler `data-on-*` ile `csp-actions.js` üzerinden delege edilir (CSP'ye hazırlık) |

## Statik analiz özeti (bandit, pip-audit, gitleaks)

| Önem | Konu | Sonuç |
|---|---|---|
| Orta | `shell=True` (CLI aracı) | Bilinçli özellik; yalnız süper yönetici, denetim kaydı var |
| Orta | f-string SQL (B608) | İncelendi: sabit sütun listesi, parametreli WHERE; yanlış pozitif |
| Orta | `urlopen` şema denetimi (B310) | İncelendi: sabit https adresleri; yanlış pozitif |
| Düşük | Markup (B704) | Sunucu üretimli etiket, değerler kaçışlı; yanlış pozitif |
| Düşük | `try/except/pass` (B110) | Güvenlikle ilgili olanlar günlüğe yazar; kalanı kaynak kapatma gibi zararsız |
| Bilgi | `radtest` varsayılan `testing123` | RADIUS test aracı için örnek değer |
| Bilgi | `settings.py` SHA-256 sabiti | Eski varsayılan jetonun özeti (jeton değil); eşleşirse jeton reddedilip yenisi üretilir |
| Bilgi | gitleaks | Depoda gerçek sır yok; kalan uyarılar yanlış pozitif (özet sabiti, ayar adı, test anahtarı, üçüncü taraf kütüphane) |

Bağımlılıklar `requirements.txt` ile sabitlenir ve düzenli olarak `pip-audit` ile taranır.

## Bilinen sınırlar

- Panel tek gunicorn süreciyle çalışacak şekilde tasarlanmıştır; IP başına giriş sayacı süreç belleğindedir.
- Stil kısıtı (`style-src`) satır içi stiller nedeniyle gevşektir; zorunlu `script-src` için kalan satır içi betik bloklarının taşınması gerekir.
- MariaDB'nin yalnızca loopback adresini dinlemesi (`bind-address=127.0.0.1`) ve systemd sertleştirmesi (`ProtectSystem`, `RestrictAddressFamilies`) kurulum önerisidir.
