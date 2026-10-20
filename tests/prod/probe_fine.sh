#!/bin/bash
# probe_fine.sh <detik>: setiap 0.4 dtk uji 80, 443, 2244 dari 198.51.100.2; cetak hanya perubahan status
ip netns del zyprobe 2>/dev/null; ip link del vethzp0 2>/dev/null
ip netns add zyprobe && ip link add vethzp0 type veth peer name vethzp1 && ip link set vethzp1 netns zyprobe || exit 1
ip addr add 198.51.100.1/24 dev vethzp0; ip link set vethzp0 up
ip netns exec zyprobe ip addr add 198.51.100.2/24 dev vethzp1; ip netns exec zyprobe ip link set vethzp1 up
END=$(( $(date +%s) + $1 )); prev=""
while [ $(date +%s) -lt $END ]; do
  cur=""
  for p in 80 443 2244; do
    if ip netns exec zyprobe timeout 1 bash -c "exec 3<>/dev/tcp/198.51.100.1/$p" 2>/dev/null; then cur="$cur $p=ok"; else cur="$cur $p=DROP"; fi
  done
  [ "$cur" != "$prev" ] && echo "$(date +%T.%N | cut -c1-12)$cur"; prev="$cur"
done
ip netns del zyprobe 2>/dev/null; ip link del vethzp0 2>/dev/null
