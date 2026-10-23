# Berkontribusi ke ZySentinel (edisi Free)

Repositori ini (`https://github.com/omysurya/zysentinel`) adalah **edisi Free** ZySentinel: terbuka, boleh di-fork, di-clone, dan diajukan pull request.

## Cara kerja repositori ini

- Kode di sini **dihasilkan** dari sumber tunggal pengembang pada setiap rilis `vX.Y.Z`. Pull request yang diterima dibawa ke sumber
  tersebut oleh pengelola, lalu muncul kembali di sini pada rilis berikutnya bersama nama Anda sebagai penulis commit.
- Fitur berbayar (paket Pro/Max) **tidak** diimplementasikan di repositori ini. Menu fitur itu tetap tampil di panel dengan lencana
  Pro/Max dan dialog Upgrade, sama persis dengan perilaku build Pro tanpa lisensi.
- Setiap push dan pull request diperiksa otomatis oleh `.github/workflows/i1-check.yml` (`python3 .github/i1_check.py .`).
  Pull request yang menambahkan implementasi atau infrastruktur fitur berbayar akan ditolak pemeriksaan ini.
- `.github/i1_check.py` dan `sentinel_license.py` dibangkitkan otomatis; perubahan pada keduanya tidak dapat diterima.
- Rilis berlabel `pro-vX.Y.Z` (pre-release) hanya berisi paket terkompilasi edisi Pro untuk pelanggan; kode sumbernya tidak ada di sini.

## Sebelum mengajukan pull request

```bash
python3 .github/i1_check.py .          # harus LULUS
python3 -m py_compile sentinel_main.py
bash -n install.sh
```

- Satu perubahan logis per pull request; jelaskan "mengapa" di deskripsi.
- Jangan menguji di server produksi; gunakan VM atau container uji.
- Laporkan celah keamanan secara pribadi lewat fitur **Feedback & Report Bugs** di panel plugin, bukan lewat issue publik.

## Contributing (English summary)

This public repository is the **Free edition**, generated from the maintainers' single source at every `vX.Y.Z` release.
Accepted pull requests are imported into that source and reappear here in the next release with your authorship preserved.
Paid (Pro/Max) features are not implemented here; every push and pull request runs `python3 .github/i1_check.py .`,
which rejects paid-feature code. Do not edit the generated files `.github/i1_check.py` and `sentinel_license.py`.
`pro-vX.Y.Z` pre-releases contain compiled Pro packages only. Report security issues privately via the plugin's Feedback feature.
