# Uji UI panel (jsdom)

Memuat `index.html` asli utuh dengan backend tiruan.

    cd tests/ui && npm install          # jsdom + jquery
    node t_open.js ../../index.html     # permintaan saat dialog dibuka
    node t_tabs.js ../../index.html     # permintaan per tab dan sub-tab
    node t_err.js  ../../index.html     # galat jaringan/timeout/500/non-JSON, spanduk, PANIC
    node t_xss.js  ../../index.html     # data berbahaya di-escape; antrean review
    AUTOYES=1 ./t_clickall.sh           # klik semua tombol, konfirmasi dijawab "ya"

Fixture data nyata (opsional) lewat `FIX=/path/fixtures.json`; tanpa itu
dipakai balasan tiruan serba-bisa. Jangan commit fixture dari produksi.
