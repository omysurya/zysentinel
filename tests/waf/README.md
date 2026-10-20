# Uji dan analisis WAF (ruleset ZySentinel)

Analisis serangan dari log (jalankan di server yang punya log; hasil di `ZY_ATK_DIR`, bawaan /tmp/zys-atk/):

    mkdir -p /tmp/zys-atk
    python3 collect.py        # kumpulkan permintaan dari semua error log dan access log vhost
    python3 classify.py       # kelompokkan per jenis serangan; tampilkan yang dijawab 2xx di origin
    python3 cand.py           # uji pola aturan kandidat terhadap SELURUH log (hit, IP, status origin)
    python3 replay_all.py [main.conf] [hasil.json]    # putar ulang serangan/probe ke nginx terisolasi
    python3 legit_replay.py <main.conf> <hasil.json>  # putar ulang permintaan SAH (2xx) -> hitung false positive

`replay_all.py` dan `legit_replay.py` memakai modul Coraza dari cache plugin dan menulis log audit sesuai
isi `main.conf`; arahkan `SENTINEL_WAF_AUDIT` ke berkas sementara bila memakai ruleset kandidat agar
log audit produksi tidak tercemar.

Uji regresi ruleset (butuh nginx+Coraza atau Apache+ModSecurity, jalankan di container uji):

    ENGINE=nginx python3 zyrules_test.py <zyrules> <crs> <nginx> <modul.so> <libdir>   # 227 pemeriksaan
    ENGINE=nginx python3 zygen_test.py <zyrules> <sentinel-zyrules.py> <crs> <nginx> <modul.so> <libdir>
    ENGINE=nginx python3 probe_test.py <zyrules> <sentinel-zyrules.py> <crs> <nginx> <modul.so> <libdir>
