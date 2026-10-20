#!/bin/bash
# sitehealth.sh <label>: kode HTTP tiap domain yang DNS-nya ke server ini (https dan http, via loopback)
OUT=/root/sitehealth-$1.txt; : > $OUT
for d in ${DOMAINS:?isi DOMAINS="a.com b.com"}; do
  s=$(curl -sk -m 8 -o /dev/null -w '%{http_code}' --resolve $d:443:127.0.0.1 https://$d/)
  h=$(curl -s -m 8 -o /dev/null -w '%{http_code}' --resolve $d:80:127.0.0.1 http://$d/)
  echo "$d https=$s http=$h" >> $OUT
done
cat $OUT
