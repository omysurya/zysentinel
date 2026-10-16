#!/bin/bash
# ------------------------------------------------------------------
# Pengirim notifikasi Sentinel.
#
# Isi: membaca baris di tabel notif yang belum terkirim, mengirim
# satu per satu lewat HTTP, lalu menandai hasilnya.
#
# Dipisahkan dari daemon dengan sengaja. Kalau HTTP dikirim dari
# daemon, satu endpoint yang tidak menjawab akan menahan pemrosesan
# log selama beberapa detik. Daemon membaca log tiap dua detik,
# jadi satu alamat nakal sudah cukup untuk membuat Sentinel berhenti
# melihat serangan. Dengan pemisahan ini, jaringan hanya menyentuh
# skrip ini.
#
# Sifat penting:
#   - Kegagalan tidak menghapus baris. Notifikasi dicoba lagi pada
#     siklus berikutnya, dengan batas percobaan supaya antrean tidak
#     tumbuh tanpa akhir kalau alamatnya memang salah terus.
#   - Satu baris gagal tidak menghentikan baris lain. Pengiriman
#     dilanjutkan ke baris berikutnya.
#   - Tidak ada token yang ditulis ke log. Kalau notify_token diisi,
#     ia dikirim sebagai header dan tidak pernah dicetak.
# ------------------------------------------------------------------
set -u

BASE=/www/server/sentinel
ETC="$BASE/etc"
DB="$BASE/data/guardd.db"
LOG="$BASE/log/notify.log"
JENIS="${1:-all}"

# Batas percobaan. Melewati batas berarti alamatnya salah, bukan
# jaringan yang sesaat. Baris yang sudah giveup masih ada di tabel
# supaya operator bisa melihatnya, tapi tidak dicoba lagi.
MAKS_COBA="${SENTINEL_NOTIF_MAX:-5}"
BATAS_ANTRI="${SENTINEL_NOTIF_BATCH:-20}"
TIMEOUT="${SENTINEL_NOTIF_TIMEOUT:-8}"

say() { echo "$(date '+%Y-%m-%d %H:%M:%S') notif: $*" >> "$LOG" 2>/dev/null; }

[ -f "$ETC/notify.conf" ] || exit 0
# shellcheck disable=SC1091
. "$ETC/notify.conf" 2>/dev/null

URL="${NOTIFY_URL:-}"
TOKEN="${NOTIFY_TOKEN:-}"
KIND="${NOTIFY_KIND:-semua}"

[ -n "$URL" ] || exit 0
[ -f "$DB" ] || exit 0
command -v sqlite3 >/dev/null 2>&1 || { say "sqlite3 tidak ada"; exit 0; }
command -v curl >/dev/null 2>&1 || { say "curl tidak ada"; exit 0; }

jenis_clause() {
	case "$1" in
		ban)      printf " AND jenis='ban'" ;;
		throttle) printf " AND jenis='throttle'" ;;
		*)        printf "" ;;
	esac
}

# sqlite3 CLI tidak punya mode JSON yang bisa diandalkan untuk nilai
# berisi kutip. Baris diambil dengan pemisah tab, dan isi notifikasi
# disanitasi lebih dulu supaya tidak mungkin berisi tab atau baris baru.
ambil() {
	sqlite3 -separator $'\t' "$DB" \
	  "SELECT id, ts, ip, jenis, isi FROM notif
	    WHERE terkirim=0 AND coba < $MAKS_COBA$(jenis_clause "$KIND")
	    ORDER BY id ASC LIMIT $BATAS_ANTRI;" 2>/dev/null
}

kirim() {
	local id="$1" ts="$2" ip="$3" jenis="$4" isi="$5" tmp

	# Bentuk payload JSON. Nilai disanitasi lebih dulu supaya tidak
	# dapat merusak struktur JSON.
	isi="${isi//\\/\\\\}"
	isi="${isi//\"/\\\"}"
	isi="${isi//$'\t'/ }"
	isi="${isi//$'\n'/ }"

	tmp="$(mktemp)"
	printf '{"sumber":"sentinel","waktu":%s,"ip":%s,"jenis":"%s","pesan":"%s"}' \
	  "$ts" "$ip" "$jenis" "$isi" > "$tmp"

	local kode
	if [ -n "$TOKEN" ]; then
		kode="$(curl -sS -o /dev/null -w '%{http_code}' \
		  --max-time "$TIMEOUT" -X POST "$URL" \
		  -H 'Content-Type: application/json' \
		  -H "Authorization: Bearer $TOKEN" \
		  --data-binary "@$tmp" 2>/dev/null)"
	else
		kode="$(curl -sS -o /dev/null -w '%{http_code}' \
		  --max-time "$TIMEOUT" -X POST "$URL" \
		  -H 'Content-Type: application/json' \
		  --data-binary "@$tmp" 2>/dev/null)"
	fi
	rm -f "$tmp"

	# 2xx berarti berhasil. 3xx dan 4xx juga dianggap selesai karena
	# mengulangnya tidak akan berubah, sedangkan 5xx dan jaringan mati
	# layak dicoba lagi.
	case "$kode" in
		2*)
			sqlite3 "$DB" "UPDATE notif SET terkirim=1, coba=coba+1,
			  galat=NULL WHERE id=$id;" 2>/dev/null
			say "terkirim id=$id jenis=$jenis kode=$kode"
			;;
		3*|4*)
			sqlite3 "$DB" "UPDATE notif SET terkirim=1, coba=coba+1,
			  galat='http $kode' WHERE id=$id;" 2>/dev/null
			say "ditandai selesai id=$id kode=$kode"
			;;
		000|"")
			sqlite3 "$DB" "UPDATE notif SET coba=coba+1,
			  galat='tidak ada jawaban' WHERE id=$id;" 2>/dev/null
			;;
		*)
			sqlite3 "$DB" "UPDATE notif SET coba=coba+1,
			  galat='http $kode' WHERE id=$id;" 2>/dev/null
			say "gagal id=$id kode=$kode"
			;;
	esac
}

BARIS="$(ambil)"
[ -n "$BARIS" ] || exit 0

JML=0
while IFS=$'\t' read -r id ts ip jenis isi; do
	[ -n "$id" ] || continue
	kirim "$id" "$ts" "$ip" "$jenis" "$isi"
	JML=$((JML + 1))
	# Batas kedua selain batas di SQL. Kalau barisnyalah yang rusak
	# dan loop tidak pernah berhenti, pengIRM ini yang menghentikannya.
	[ "$JML" -ge "$BATAS_ANTRI" ] && break
done <<< "$BARIS"

# Beri tahu daemon bahwa ada antrean, supaya status.json bisa
# menampilkan jumlah notifikasi yang belum terkirim.
SISA="$(sqlite3 "$DB" "SELECT COUNT(*) FROM notif WHERE terkirim=0;" 2>/dev/null)"
[ -n "$SISA" ] && printf '%s' "$SISA" > "$BASE/run/notif_pending" 2>/dev/null
exit 0