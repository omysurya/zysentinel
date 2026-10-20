# Uji pada host produksi (hanya setelah izin pemilik server)

Semua skrip memakai jaringan tiruan (netns + veth, sumber 198.51.100.2 = TEST-NET-2) sebagai
"internet": port yang dibuka/dijatuhkan terlihat seperti dari luar, bukan dari loopback.

    ./probe_prod.sh sebelum          # baseline port TCP (setelah pasang: bandingkan dengan diff)
    DOMAINS="a.com b.com" ./sitehealth.sh sebelum   # kode HTTP tiap situs nyata via loopback
    ./probe_fine.sh 60               # pantau 80/443/SSH tiap 0,4 dtk selama 60 dtk (jalankan sambil install)
    python3 waf_prod_test.py         # skenario WAF pada vhost uji loopback (lihat docstring di skrip)
    python3 waf_scen_prod.py         # daftar IP/URL, mode, modul, bot_level, batas body lewat API plugin
    python3 fw_scen_prod.py          # ban/unban, pagar anti-blokir diri, allow, aturan port, baseline

Sebelum mengubah firewall produksi pasang pengaman rollback:

    systemd-run --on-active=600 --unit=zys-deadman /www/server/sentinel/bin/sentinel-fw.sh remove
    # ... uji ... lalu batalkan:  systemctl stop zys-deadman.timer

Catatan: serangan simulasi dari 127.0.0.1 memicu auto-ban WAF aaPanel (free_waf) untuk 127.0.0.1;
itu hanya memengaruhi permintaan uji dari loopback.
