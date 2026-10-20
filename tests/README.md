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
