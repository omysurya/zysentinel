#!/bin/bash
# snap.sh <nama>: rekam keadaan ke /root/snap/<nama>.{unrelated,sentinel}
N=$1; D=/root/snap; mkdir -p $D
{
  sha256sum /www/server/nginx/conf/nginx.conf 2>/dev/null
  find /www/server/panel/vhost -type f ! -name '*.bak.*' ! -path '*/extension/*/sentinel-waf.conf' ! -name 'sentinel_waf.conf' -exec sha256sum {} + 2>/dev/null | sort -k2
  find /www/server/panel/config -type f 2>/dev/null -exec stat -c '%n %U:%G %a' {} + | sort
  find /www/server/panel/plugin -mindepth 1 -maxdepth 1 ! -name sentinel -exec stat -c '%n %U:%G %a' {} + | sort
  find /www/server/panel/plugin -mindepth 2 -maxdepth 2 ! -path '*/sentinel/*' -exec stat -c '%n %U:%G %a' {} + 2>/dev/null | sort | head -300
  iptables-save 2>/dev/null | grep -v -i sentinel | grep -vE '^#|^:|^\*|COMMIT' | sort
  ipset list -n 2>/dev/null | grep -v '^sentinel' | sort
  ls /etc/systemd/system 2>/dev/null | grep -v '^sentinel' | sort
  ls /etc/ld.so.conf.d /etc/logrotate.d 2>/dev/null | grep -vi 'sentinel\|zysentinel' | sort
  crontab -l 2>/dev/null | sort
} > $D/$N.unrelated
{
  echo "--procs"; ps -eo user,args | grep -E "[g]uardd|[s]entinel-(proc|upload)|[s]entinel-notify" | sed 's/ \+/ /g' | sort
  echo "--iptables"; iptables-save 2>/dev/null | grep -i sentinel | sort
  echo "--iptables-dups"; iptables-save 2>/dev/null | grep -i sentinel | sort | uniq -d
  echo "--ipset"; ipset list -n 2>/dev/null | grep '^sentinel' | sort
  echo "--tree"; [ -d /www/server/sentinel ] && find /www/server/sentinel -printf '%m %u:%g %y %p\n' 2>/dev/null | grep -v -E '/(log|data|db|av/(last|baseline)|run|backup|tmp|src)/.+' | sort || echo none
  echo "--worldwritable"; find /www/server/sentinel /www/server/panel/plugin/sentinel -perm -o+w ! -type l 2>/dev/null | grep -v '\.git/' | sort
  echo "--cfg"; for f in etc/guardd.conf etc/allowlist.txt etc/notify.conf etc/waf.conf etc/proc_whitelist.json etc/ports.json; do [ -f /www/server/sentinel/$f ] && sha256sum /www/server/sentinel/$f; done
  echo "--units"; ls /etc/systemd/system 2>/dev/null | grep -i sentinel | sort
  echo "--misc"; ls /etc/ld.so.conf.d /etc/logrotate.d 2>/dev/null | grep -i 'sentinel' | sort; ls /www/server/panel/vhost/nginx/extension/*/sentinel-waf.conf 2>/dev/null
} > $D/$N.sentinel
echo "snap $N: $(wc -l < $D/$N.unrelated) unrelated, $(wc -l < $D/$N.sentinel) sentinel"
