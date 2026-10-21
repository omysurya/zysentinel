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
| `atk_types_test.py` | endpoint `get_attack_types` (klasifikasi log audit WAF untuk diagram donat) | `python3 atk_types_test.py /path/sentinel_main.py` |
| `fw_counters_test.py` | penguraian penghitung paket firewall (`get_fw` mengirim objek, bukan teks mentah) | `python3 fw_counters_test.py /path/sentinel_main.py` |
| `ui/t_fwhits.js`, `ui/t_fwtab.js` | render tabel Packet Counters dan seluruh tab Firewall dengan data nyata (cari `undefined`) | `node ui/t_fwhits.js ../index.html` |
| `ui/t_upload.js` | tab Realtime Upload Protection: judul, umpan balik Refresh, badge dan kotak info (data nyata `get_upload_scan_status`) | `node ui/t_upload.js ../index.html status.json` |
| `upload_realtime_test.py` | uji end-to-end Realtime Upload Protection di sandbox (nginx+Coraza+PHP+salinan pemindai+clamd tiruan): upload tetap 200, karantina, latensi, daemon mati/kill -9, inotify dimulai ulang/buta, clamd lambat/mati/pulih, webshell/polyglot, penyerang mengejar berkas (gerbang fanotify), biaya gerbang (60 pemeriksaan, ±6 menit) | `python3 upload_realtime_test.py ../payload/sentinel-upload-scan.py` (root) |
| `upload_heuristic_test.py` | heuristik webshell/backdoor/polyglot, positif palsu pada data acak, penguraian jawaban clamd (offline) | `python3 upload_heuristic_test.py ../payload/sentinel-upload-scan.py` |
| `selfheal_test.py` | logika sentinel-selfheal.py dengan systemctl dan jam tiruan: backoff, batas 12/24 jam, menyerah, unit macet, operator stop, dry-run (offline, 25 pemeriksaan) | `python3 selfheal_test.py ../payload/sentinel-selfheal.py` |
| `selfheal_systemd_test.py` | uji NYATA dengan systemd (unit uji zys-test-*): crash-loop berhenti, selfheal memulihkan, kill -9/SIGTERM, stop operator, unit macet; verifikasi direktif unit payload | `python3 selfheal_systemd_test.py ../payload/sentinel-selfheal.py ../payload/systemd` (root) |
