#!/bin/bash
# Jalankan t_click.js untuk tiap tab/sub-tab (proses baru tiap kali agar keadaan bersih)
F=${1:-/www/server/panel/plugin/sentinel/index.html}
cd "$(dirname "$0")"
for spec in "0 -1" "0 0" "0 1" "0 2" "0 3" "0 4" "0 5" "0 6" "0 7" "0 8" "0 9" "0 10" "1 -1" "1 0" "1 2" "1 4" "1 6" "1 7" "2 -1" "3 -1" "3 1" "3 2" "4 0" "4 1" "4 2" "4 3"; do
  set -- $spec
  node t_click.js "$F" $1 $2 2>&1 | tail -1
done
