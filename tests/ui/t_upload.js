// Uji tab Realtime Upload Protection: judul, umpan balik tombol Refresh, badge dan kotak info layanan.
// Kode snUploadScanMuat diambil langsung dari index.html. Data nyata: JSON keluaran get_upload_scan_status.
// Pakai: node t_upload.js <index.html> <status.json>
const fs = require('fs');
const { JSDOM } = require('jsdom');
const html = fs.readFileSync(process.argv[2], 'utf8');
const nyata = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
const script = html.match(/<script[^>]*>([\s\S]*?)<\/script>/)[1];
const kode = (() => { const i = script.indexOf('function snUploadStatsRows'), j = script.indexOf('function snUploadVhostToggle'); return script.slice(i, j); })();
const bagian = html.slice(html.indexOf('id="w-upload"'), html.indexOf('<!-- ============================= FIREWALL'));
let gagal = 0;
const cek = (n, k, i) => { console.log((k ? '  LULUS ' : '  GAGAL ') + n + (k ? '' : '  -> ' + i)); if (!k) gagal++; };

cek('judul bagian = "Realtime Upload Protection"', /<h3><span>Realtime Upload Protection<\/span>/.test(bagian), bagian.slice(0, 200));
cek('tidak ada lagi "Imunify360 Style" di judul/halaman tab', !/Upload Scanner Service \(Imunify360 Style\)/.test(html));

function jalan(lang, data, manual) {
  const w = new JSDOM('<body>' + bagian.replace(/^[^>]*>/, '<div>') + '</body>', { runScripts: 'outside-only' }).window;
  w.$ = require('jquery')(w); w.SN_LANG = lang;
  w.__spin = 0; w.__stop = 0; w.__toast = []; w.__btnAjax = null;
  w.snSpinBtn = (b) => { if (!b) return () => {}; w.__spin++; return () => { w.__stop++; }; };
  w.snEsc = (t) => String(t).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  w.snJsAttr = (t) => w.snEsc(String(t).replace(/\\/g, '\\\\').replace(/'/g, "\\'"));
  w.layer = { msg: (m) => w.__toast.push(m) };
  w.snAjax = (m, d, cb, p, btn) => { w.__btnAjax = btn; cb(data); };
  w.eval(kode);
  const tombol = w.document.getElementById('btnUsvcRefresh');
  w.snUploadScanMuat(manual ? tombol : undefined, manual);
  return w;
}
let w = jalan('id', nyata, true);
const d = w.document;
cek('tombol Refresh: spinner menyala lalu berhenti', w.__spin === 1 && w.__stop === 1, w.__spin + '/' + w.__stop);
cek('tombol dikirim ke snAjax (efek loading)', w.__btnAjax && w.__btnAjax.id === 'btnUsvcRefresh');
cek('tombol punya ikon refresh', !!d.querySelector('#btnUsvcRefresh .layui-icon-refresh'));
cek('label "Diperbarui HH:MM:SS" muncul', /^Diperbarui \d/.test(d.getElementById('usvcTime').textContent), d.getElementById('usvcTime').textContent);
cek('toast "Status diperbarui" pada klik manual', w.__toast.length === 1 && w.__toast[0] === 'Status diperbarui', w.__toast);
cek('badge BERJALAN (service_running=true)', d.getElementById('usvcBadge').textContent === 'BERJALAN' && /sn-ok/.test(d.getElementById('usvcBadge').className), d.getElementById('usvcBadge').textContent);
const info = d.getElementById('usvcInfo').textContent;
cek('kotak info terisi: PID, clamd siap, RAM, vhost', /PID \d+/.test(info) && /siap/.test(info) && /MB/.test(info) && /\d+ \/ \d+/.test(info), info);
cek('tidak ada "undefined"/NaN di info', !/undefined|NaN/.test(d.getElementById('usvcInfo').innerHTML));
cek('tabel vhost: ' + nyata.vhosts.length + ' baris', d.querySelectorAll('#tbUploadVhosts tr').length === nyata.vhosts.length, d.querySelectorAll('#tbUploadVhosts tr').length);
cek('tombol layanan = Restart (layanan berjalan)', /onclick/.test(d.getElementById('btnUsvcToggle').outerHTML) && d.getElementById('btnUsvcToggle').getAttribute('onclick') === "snUploadScanServiceToggle('restart')");
w = jalan('id', nyata, false);
cek('muat otomatis (bukan klik): tanpa toast dan tanpa spinner, label tetap terisi', w.__toast.length === 0 && w.__spin === 0 && /Diperbarui/.test(w.document.getElementById('usvcTime').textContent));
w = jalan('en', nyata, true);
cek('bahasa Inggris: RUNNING, Updated, Status refreshed', w.document.getElementById('usvcBadge').textContent === 'RUNNING' && /^Updated/.test(w.document.getElementById('usvcTime').textContent) && w.__toast[0] === 'Status refreshed');
const denganStat = JSON.parse(JSON.stringify(nyata));
denganStat.stats = { scanned: '203', infected: '103', lat_avg_ms: '55.0', lat_p95_ms: '144.8', lat_max_ms: '164.6', queue: '0', held_now: '0', gate_on: '1', gate_wait: '30', gate_deny: '30', sweep_enq: '2', catchup_enq: '5' };
w = jalan('id', denganStat, true);
const infoS = w.document.getElementById('usvcInfo').textContent;
cek('statistik mesin tampil: latensi, dipindai/terinfeksi, antrean, gerbang, sapuan', /55 \/ 144\.8 \/ 164\.6 ms/.test(infoS) && /203 \/ 103/.test(infoS) && /aktif \(30 menunggu, 30 ditolak\)/.test(infoS) && /2 \/ 5/.test(infoS), infoS);
cek('tanpa stats (daemon lama): kotak info tetap utuh dan tanpa baris statistik', !/Latensi putusan/.test(d.getElementById('usvcInfo').textContent));
w = jalan('en', denganStat, true);
cek('statistik dalam bahasa Inggris', /Verdict latency avg \/ p95 \/ max/.test(w.document.getElementById('usvcInfo').textContent) && /Execution gate/.test(w.document.getElementById('usvcInfo').textContent));
const mati = JSON.parse(JSON.stringify(nyata)); mati.service_running = false; mati.systemd_active = false; mati.clamd_ready = false; mati.available_ram_mb = 50;
w = jalan('id', mati, true);
cek('layanan mati: badge BERHENTI dan tombol Jalankan', w.document.getElementById('usvcBadge').textContent === 'BERHENTI' && w.document.getElementById('btnUsvcToggle').getAttribute('onclick') === "snUploadScanServiceToggle('start')");
cek('RAM di bawah sekring diberi peringatan', /di bawah batas sekring/.test(w.document.getElementById('usvcInfo').textContent));
const jahat = JSON.parse(JSON.stringify(nyata)); jahat.vhosts = [{ vhost: "x'><img src=x onerror=alert(1)>", root: '<script>1</script>', server: 'nginx', enabled: true, quarantined_count: 0 }];
w = jalan('id', jahat, true);
cek('XSS pada nama vhost/root di-escape', !w.document.querySelector('#tbUploadVhosts img') && !w.document.querySelector('#tbUploadVhosts script'));
w = jalan('id', null, true);
cek('respons null: spinner berhenti, tidak melempar', w.__stop === 1 && w.__toast.length === 0);
console.log('\nRINGKAS: ' + gagal + ' gagal'); process.exit(gagal ? 1 : 0);
