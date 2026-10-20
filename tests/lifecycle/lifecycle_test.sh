#!/bin/bash
# lifecycle_test.sh <sentinel.zip>
# Uji siklus hidup di mesin UJI (container dengan aaPanel + NET_ADMIN), BUKAN produksi:
#   1. pasang dari zip  2. reinstall dua kali (idempoten)  3. uninstall tanpa TTY seperti aaPanel
#   4. pasang ulang dari zip. Di tiap tahap: snapshot (snap.sh) dan perbandingan berkas/aturan pihak lain.
set -u
ZIP="${1:?pakai: lifecycle_test.sh /path/sentinel.zip}"; D=/root/snap; PL=/www/server/panel/plugin
cd "$(dirname "$0")"
pasang() { rm -rf $PL/sentinel; unzip -q "$ZIP" -d $PL/; bash $PL/sentinel/install.sh install </dev/null >/root/lc_$1.log 2>&1; echo "install($1) rc=$?"; }
pasang awal;      bash ./snap.sh S0
for i in 1 2; do bash $PL/sentinel/install.sh install </dev/null >/root/lc_re$i.log 2>&1; echo "reinstall#$i rc=$?"; bash ./snap.sh R$i; done
echo "idempotensi R1->R2:"; diff <(sed -n '/--iptables$/,$p' $D/R1.sentinel) <(sed -n '/--iptables$/,$p' $D/R2.sentinel) && echo "  identik"
bash $PL/sentinel/install.sh uninstall </dev/null >/root/lc_un.log 2>&1; echo "uninstall rc=$?"; bash ./snap.sh U1
echo "berkas/aturan pihak lain S0->U1:"; diff $D/S0.unrelated $D/U1.unrelated && echo "  tidak berubah"
echo "sisa Sentinel setelah uninstall:"; sed -n '/--procs/,$p' $D/U1.sentinel | grep -v '^--' | head
pasang ulang;     bash ./snap.sh S1
echo "berkas/aturan pihak lain S0->S1:"; diff $D/S0.unrelated $D/S1.unrelated && echo "  tidak berubah"
echo "world-writable:"; sed -n '/--worldwritable/,/--cfg/p' $D/S1.sentinel
