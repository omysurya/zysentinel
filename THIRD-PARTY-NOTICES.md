# Third-Party Notices / Pemberitahuan Pihak Ketiga

ZySentinel memakai, mengunduh saat instalasi, atau memanggil komponen pihak ketiga berikut. Komponen ini tetap berada di bawah
lisensi aslinya masing-masing. Hak cipta ZySentinel sendiri: lihat `LICENSE` (Apache License 2.0, edisi Free) atau `LICENSE.pro`
(EULA, edisi Pro/Max).

ZySentinel uses, downloads at install time, or invokes the third-party components below. Each remains under its own license.

## Diunduh atau disusun saat instalasi (tidak dibundel di paket)

| Komponen | Pemakaian | Lisensi | Sumber |
| --- | --- | --- | --- |
| OWASP CoreRuleSet (CRS) | ruleset dasar WAF (diunduh dari release resmi, SHA-256 diverifikasi) | Apache License 2.0 | https://github.com/coreruleset/coreruleset |
| Coraza (`libcoraza`) | engine WAF untuk nginx (di-compile dari source) | Apache License 2.0 | https://github.com/corazawaf/libcoraza |
| Coraza nginx connector | modul dinamis nginx (di-compile dari source) | Apache License 2.0 | https://github.com/corazawaf/coraza-nginx |
| nginx source | header untuk compile modul dinamis yang cocok dengan nginx terpasang | BSD 2-Clause | https://nginx.org |
| `maxminddb` (Python) | pembaca database GeoIP | Apache License 2.0 | https://github.com/maxmind/MaxMind-DB-Reader-python |

## Dipakai dari sistem atau control panel (tidak dibundel)

| Komponen | Pemakaian | Lisensi |
| --- | --- | --- |
| ModSecurity v2 | engine WAF untuk Apache dan OpenLiteSpeed | Apache License 2.0 |
| ClamAV (`clamd`, `clamscan`, `freshclam`) | antivirus, dipanggil sebagai program terpisah | GNU GPL v2 |
| rkhunter | pemeriksa rootkit, dipanggil sebagai program terpisah | GNU GPL v2 |
| Apache ECharts | grafik dashboard (dimuat dari aaPanel) | Apache License 2.0 |
| ipset, iptables/nftables | firewall kernel, dipanggil sebagai program terpisah | GNU GPL v2 |
| Python `cryptography` | verifikasi signature Ed25519 dan dekripsi modul | Apache License 2.0 / BSD |

## Data pihak ketiga

- **GeoLite2** (database negara/kota yang disediakan aaPanel): *This product includes GeoLite2 data created by MaxMind, available
  from https://www.maxmind.com.* Data GeoLite2 tunduk pada GeoLite2 End User License Agreement MaxMind.
- **Spamhaus DROP/EDROP**: daftar jaringan yang diunduh langsung oleh server pengguna dari https://www.spamhaus.org/drop/ dan
  tunduk pada ketentuan pemakaian Spamhaus.
- **OSV.dev**: data advisori kerentanan dependensi aplikasi diambil dari API https://osv.dev; setiap advisori tetap berada di
  bawah lisensi sumber aslinya.
- **Rentang IP Cloudflare**: daftar publik dari https://www.cloudflare.com/ips/.

## Aset UI standalone (paket rilis Pro)

Aset berikut dilayani lokal oleh `sentinel-ui` (tanpa CDN saat berjalan); versi dan hash dikunci di `payload/ui/assets/assets.sha256`.

| Komponen | Versi | Lisensi |
| --- | --- | --- |
| jQuery | 3.7.1 | MIT |
| layer (pop-up) | 3.5.1 | MIT |
| layui (hanya font ikon + CSS ikon) | 2.9.16 | MIT |
| Apache ECharts | 5.5.1 | Apache License 2.0 |
| Peta dunia GeoJSON (`world.json`, dari paket ECharts 4.9.0; data Natural Earth) | 4.9.0 | Apache License 2.0 (data: domain publik) |

## Data GeoIP server tanpa aaPanel (paket rilis Pro)

Di server tanpa aaPanel, `sentinel-geo.py` mengunduh data GeoIP dari **DB-IP Lite** (https://db-ip.com/db/lite.php, lisensi CC BY 4.0):
"IP Geolocation by DB-IP". Data tidak disertakan dalam paket; diunduh saat pemasangan/pembaruan dan disimpan di `/www/server/sentinel/data/geo/`.

## Biner terkompilasi statis (paket rilis Pro)

Biner C yang terkompilasi statis di paket rilis Pro menautkan library berikut:

| Library | Lisensi | Catatan |
| --- | --- | --- |
| OpenSSL `libcrypto` 3.x | Apache License 2.0 | https://www.openssl.org |
| SQLite | Public domain | https://www.sqlite.org |
| GNU C Library (glibc) | GNU LGPL v2.1 atau lebih baru | Penautan statis. Sesuai LGPL v2.1 bagian 6, setiap release Pro menyertakan aset `zysentinel-pro-vX.Y.Z-relink.tar.gz` (object file program + `relink.sh` + versi toolchain) untuk menautkan ulang dengan glibc lain. |

Teks lengkap lisensi: Apache License 2.0 di `LICENSE` (edisi Free) atau `licenses/Apache-2.0.txt` (paket Pro); GNU LGPL v2.1 di
`licenses/LGPL-2.1.txt` (paket Pro dan relink kit); MIT di `licenses/MIT-jquery.txt` (jQuery; layer memakai teks MIT yang sama
dengan pemberitahuan hak cipta di kepala `layer.js`). Teks lisensi komponen yang tidak dibundel tersedia di sumber masing-masing.
