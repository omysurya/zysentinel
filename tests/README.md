# Uji plugin ZySentinel

| Folder/berkas | Isi | Cara jalan |
| --- | --- | --- |
| `test_docker_full.py`, `run_docker_tests.sh` | suite fungsional di container Debian/Alma | lihat skrip |
| `crud_test.py` | validasi masukan CRUD firewall/WAF/EDR/antivirus (738 pemeriksaan) | `python3 crud_test.py /path/sentinel_main.py ringkas` di mesin uji |
| `test_security_regression.py` | injeksi perintah, notify.conf, ReDoS, review_decide, pembaruan | `python3 test_security_regression.py` |
| `ui/` | uji UI jsdom (`ui_test.js`, `t_*.js`, `fullpage.js`) | `cd ui && npm install && node t_err.js ../../index.html` |
| `waf/` | analisis serangan dari log dan uji ruleset (replay, false positive, regresi) | lihat `waf/README.md` |
| `lifecycle/` | uji pasang/reinstall/uninstall/pasang ulang di container uji | `bash lifecycle/lifecycle_test.sh sentinel.zip` |
| `prod/` | uji firewall/WAF di host produksi (netns, dead-man) | lihat `prod/README.md` |
| `atk_types_test.py` | endpoint `get_attack_types` (klasifikasi log audit WAF untuk diagram donat) dan `get_attack_map` (total peta = total donat) | `python3 atk_types_test.py /path/sentinel_main.py` |
| `fw_counters_test.py` | penguraian penghitung paket firewall (`get_fw` mengirim objek, bukan teks mentah) | `python3 fw_counters_test.py /path/sentinel_main.py` |
| `ui/t_fwhits.js`, `ui/t_fwtab.js` | render tabel Packet Counters dan seluruh tab Firewall dengan data nyata (cari `undefined`) | `node ui/t_fwhits.js ../index.html` |
| `ui/t_upload.js` | tab Realtime Upload Protection: judul, umpan balik Refresh, badge dan kotak info (data nyata `get_upload_scan_status`) | `node ui/t_upload.js ../index.html status.json` |
| `upload_realtime_test.py` | uji end-to-end Realtime Upload Protection di sandbox (nginx+Coraza+PHP+salinan pemindai+clamd tiruan): upload tetap 200, karantina, latensi, daemon mati/kill -9, inotify dimulai ulang/buta, clamd lambat/mati/pulih, webshell/polyglot, penyerang mengejar berkas (gerbang fanotify), biaya gerbang (60 pemeriksaan, ±6 menit) | `python3 upload_realtime_test.py ../payload/sentinel-upload-scan.py` (root) |
| `upload_heuristic_test.py` | heuristik webshell/backdoor/polyglot, positif palsu pada data acak, penguraian jawaban clamd (offline) | `python3 upload_heuristic_test.py ../payload/sentinel-upload-scan.py` |
| `selfheal_test.py` | logika sentinel-selfheal.py dengan systemctl dan jam tiruan: backoff, batas 12/24 jam, menyerah, unit macet, operator stop, dry-run (offline, 25 pemeriksaan) | `python3 selfheal_test.py ../payload/sentinel-selfheal.py` |
| `selfheal_systemd_test.py` | uji NYATA dengan systemd (unit uji zys-test-*): crash-loop berhenti, selfheal memulihkan, kill -9/SIGTERM, stop operator, unit macet; verifikasi direktif unit payload | `python3 selfheal_systemd_test.py ../payload/sentinel-selfheal.py ../payload/systemd` (root) |
| `sweeper_test.py` | Sweeper (orkestrator + mesin C/Python) di sandbox: karantina, paritas, abaikan/sah, TOCTOU, symlink, inkremental, batal, kalibrasi, build, karantina bersama | `python3 -B sweeper_test.py ../payload` |
| `sweeper_api_test.py` | API panel Sweeper (validasi, pemindaian di latar, temuan, aksi, konfigurasi) | `python3 -B sweeper_api_test.py ../payload` |
| `sweeper_corpus_test.py` | akurasi pada korpus nyata (opsional): 0 webshell pada berkas sah, recall pada korpus webshell, paritas C = Python | `python3 sweeper_corpus_test.py ../payload --legit /www/wwwroot --shell <korpus> --parity 150` |
| `ui/t_sweeper.js` | UI sub-tab Sweeper (jsdom): tabel, aksi, pengaturan, polling, XSS, dua bahasa | `node ui/t_sweeper.js ../index.html` |
| `learn_test.py` | fitur belajar dari Blokir/Izinkan di Event Feed: API di sandbox + guardd NYATA di netns (ban/review/izinkan/pencabutan) | `python3 -B learn_test.py ../payload` |
| `guardd_audit_test.py` | regresi audit guardd di netns: UA alat, CIDR allowlist, normalisasi path, baris > 4 KB, throttle->ban, flood, WordPress, review | `python3 -B guardd_audit_test.py ../payload` |
| `waf/body_limit_test.py` | Coraza NYATA (nginx sementara di netns): batas argumen multipart, badan tanpa Content-Type, log audit tanpa header/Cookie | `python3 -B waf/body_limit_test.py ../payload [base.conf.in pembanding]` |
| `prod/fw_netns_test.py` | PERILAKU PAKET sentinel-fw.sh + sentinel-ports.py di dua netns (lama vs baru): review+ban, throttle per IP, QUIC, privat palsu, panic, atomik, Docker. Firewall host tidak tersentuh | `python3 -B prod/fw_netns_test.py ../payload/sentinel-fw.sh ../payload/sentinel-ports.py` |
| `integ_test.sh` | integritas berkas web (anti-tamper) di mount namespace privat: baseline otomatis, .user.ini/.htaccess/.phar, path berspasi, cache dikecualikan, notifikasi hanya perubahan baru | `bash integ_test.sh ../payload/sentinel-av.sh` |
| `ui/t_mode.js` | status mode blokir: lencana Mode, catatan dinamis, kartu Mode Blokir/Layanan Daemon di atas Settings | `node ui/t_mode.js ../index.html` |
| `ui/t_geo.js` | tab Origin: tabel #tbGeo terisi dari get_geo_stat (regresi "loading" selamanya), kartu Country Block tetap dimuat | `node ui/t_geo.js ../index.html` |
| `crud_aksi_test.py` | API CRUD kolom Action: update_port_rule (baseline hanya keterangan, rollback saat kernel menolak), learned_add/learned_update/revoke; sandbox, kernel tidak tersentuh | `python3 -B crud_aksi_test.py ../sentinel_main.py` |
| `ui/t_crud.js` | UI kolom Action: Ubah/Hapus aturan port (inbound/outbound/baseline), ubah durasi Blocked IPs, tambah/ubah Learned Rules | `node ui/t_crud.js ../index.html` |
| `defcon_test.py` | level DEFCON get_elite_posture: kill/alert 15 menit terakhir, alert WHITELISTED diabaikan, indikator (sandbox __PATH) | `python3 -B defcon_test.py ../sentinel_main.py` |
| `ui/t_defcon.js` | kartu DEFCON setelah Memory (pengganti banner), dialog indikator, Refresh berprogres | `node ui/t_defcon.js ../index.html` |
| `ui/t_peta.js` | peta asal serangan dengan echarts dan world.json ASLI milik panel (SVG di jsdom), tanpa get_sysinfo | `node ui/t_peta.js ../index.html /www/server/panel/BTPanel/static/js/echarts.min.js /www/server/panel/BTPanel/static/vite/data/world.json` |
| `proc_guard_test.py` | process guard: whitelist berbasis perintah (bagian A), pemantauan exec seketika lewat proc connector dengan uid uji 65534 (bagian A2). Bagian B (proses nyata sebagai www) HANYA di mesin uji: `ZYS_PROC_LIVE=1` | `python3 -B proc_guard_test.py ../payload/sentinel-proc.py` |
| `ui/t_learned.js`, `ui/t_telemetry.js` | UI tab Learned Rules + tata letak Event Feed; nama halaman telemetri = IP publik | `node ui/t_learned.js ../index.html` |

**Jangan jalankan di host produksi:** `crud_test.py` (memanggil API sungguhan; 21 Okt 2026 menyalakan geo-ban CN) dan bagian B `proc_guard_test.py` (guard produksi membunuh proses uji dan mengirim notifikasi).
