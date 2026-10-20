#!/bin/bash
# probe_prod.sh <label>: probe TCP dari "internet" tiruan (netns + veth, sumber 198.51.100.2 = TEST-NET-2)
# ke alamat host 198.51.100.1. Tidak menyentuh aturan apa pun; antarmuka sementara dihapus di akhir.
L=${1:-x}; OUT=/root/zyprobe-$L.txt; [ -d /root ] || OUT=/tmp/zyprobe-$L.txt
PORTS="22 53 80 443 888 2019 2244 3000 3306 6379 8000 15960 18080 18999 21115 21116 21117 21118 21119 45876"
cleanup() { ip netns del zyprobe 2>/dev/null; ip link del vethzp0 2>/dev/null; }
trap cleanup EXIT; cleanup
ip netns add zyprobe && ip link add vethzp0 type veth peer name vethzp1 && ip link set vethzp1 netns zyprobe || { echo "gagal membuat netns"; exit 1; }
ip addr add 198.51.100.1/24 dev vethzp0 && ip link set vethzp0 up
ip netns exec zyprobe ip addr add 198.51.100.2/24 dev vethzp1
ip netns exec zyprobe ip link set vethzp1 up; ip netns exec zyprobe ip link set lo up
: > $OUT
for p in $PORTS; do
  r=$(ip netns exec zyprobe timeout 4 bash -c "exec 3<>/dev/tcp/198.51.100.1/$p" 2>&1; echo "rc=$?")
  case "$r" in *rc=0) st=TERBUKA ;; *refused*) st=DITOLAK-SERVICE ;; *rc=124) st=DROP/TIMEOUT ;; *) st="lain:$r" ;; esac
  printf '%s %s\n' "$p" "$st" >> $OUT
done
cat $OUT | tr '\n' ';'; echo
