// Uji UI sub-tab Sweeper (tab Antivirus): kode diambil langsung dari index.html, backend (snAjax) ditiru.
// Pakai: node t_sweeper.js <index.html>
const fs = require('fs');
const { JSDOM } = require('jsdom');
const html = fs.readFileSync(process.argv[2], 'utf8');
const script = html.match(/<script[^>]*>([\s\S]*?)<\/script>/)[1];
const i = script.indexOf('/* ---------- Sweeper (pemindai webshell'), j = script.indexOf('function snAvRestore(id, path){');
if (i < 0 || j < 0) { console.error('blok Sweeper tidak ditemukan'); process.exit(2); }
const kode = script.slice(i, j);
const markup = html.slice(html.indexOf('<!-- Subpage: Sweeper'), html.indexOf('<!-- Subpage 4: Realtime Console Tab -->'));
let gagal = 0;
const cek = (n, k, x) => { console.log((k ? '  LULUS ' : '  GAGAL ') + n + (k ? '' : '  -> ' + x)); if (!k) gagal++; };

const STATUS = (o) => Object.assign({
  engine: { kind: 'c', version: 'sentinel-sweeper 1.0', gcc: true, c_available: true },
  config: { auto_quarantine: true, quarantine_min_score: 90, report_min_score: 50, custom_paths: ['/www/x'], exclude: ['/.git/'], skip_vhosts: [], throttle_ms: 2, nice: 10, max_size_mb: 2, incremental: true, engine: 'auto', entropy: { mean: 4.664, sd: 0.325 } },
  running: false, job: { state: 'done', progress: {} }, schedule: true, allow_count: 2,
  last: { finished: 1792546000, engine: 'c', summary: { scanned: 17903, flagged: 3, quarantined: 2, seconds: 6, cpu_seconds: 4.0, max_rss_kb: 17536 } },
  roots: [{ vhost: 'a', path: '/www/wwwroot/a' }, { vhost: 'b', path: '/www/wwwroot/b' }], counts: { webshell: 1, suspicious: 2, quarantined: 5 },
}, o || {});
const ROWS = [
  { path: '/www/wwwroot/a/up/s.php', vhost: 'a', verdict: 'webshell', score: 98, rules: [['eval-input', 98, 'eval']], entropy: 5.1234, size: 2048, status: 'open' },
  { path: '/www/wwwroot/a/inc.php', vhost: 'a', verdict: 'suspicious', score: 85, rules: [['include-input', 85, 'include'], ['tidak-dikenal', 20, '']], entropy: 4.5, size: 100, status: 'open' },
  { path: '/www/wwwroot/a/q.php', vhost: 'a', verdict: 'webshell', score: 97, rules: [['varcall-input', 97, 'f']], entropy: 4.9, size: 50, status: 'quarantined' },
  { path: '/www/wwwroot/a/i.php', vhost: 'a', verdict: 'suspicious', score: 70, rules: [], entropy: 4.1, size: 10, status: 'ignored' },
  { path: '/www/wwwroot/a/<img src=x onerror=alert(1)>.php', vhost: '<b>', verdict: 'webshell', score: 99, rules: [['<script>', 99, '"><x>']], entropy: 6, size: 1, status: 'open' },
];

function jalan(lang, handlers) {
  const dom = new JSDOM('<body><div id="top-antivirus" class="on"><div class="sn-tabs"><span></span><span></span><span></span></div><b id="avSweepCount"></b><select id="swFilter"><option value="open" selected>o</option><option value="webshell">w</option></select><div id="avQuarDummy"></div>' + markup.replace(/<!--[\s\S]*?-->/g, '') + '</div></body>', { runScripts: 'dangerously' });
  const w = dom.window;
  w.$ = require('jquery')(w); w.SN_LANG = lang; w.SN_AV_TAB = 'sweeper';
  w.__calls = []; w.__toast = []; w.__confirm = []; w.__prompt = null; w.__opened = null;
  w.snSpinBtn = () => () => {};
  w.snEsc = (t) => String(t === undefined || t === null ? '' : t).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  w.ukuranAngka = (n) => n + ' B'; w.kelasSkor = () => 'x';
  w.kosong = (sel, n, t) => w.$(sel).html('<tr><td colspan="' + n + '" class="sn-empty">' + t + '</td></tr>');
  w.snProgress = () => 1; w.snAvQuarMuat = () => w.__calls.push(['snAvQuarMuat']); w.snAvSub = (n) => w.__calls.push(['snAvSub', n]);
  w.layer = { msg: (m) => w.__toast.push(m), close: () => 0, confirm: (m, o, yes) => { w.__confirm.push(m); yes(1); }, prompt: (o, yes) => { w.__prompt = o; w.__yesPrompt = yes; },
              open: (o) => { w.__opened = o; w.$('body').append('<div id="layerBox">' + o.content + '</div>'); } };
  w.snAjax = (m, d, cb) => { w.__calls.push([m, d]); const h = handlers[m]; cb(typeof h === 'function' ? h(d) : h); };
  w.eval(kode);
  return w;
}

// --- render status
let w = jalan('id', { get_sweeper_status: STATUS(), get_sweeper_findings: ROWS, sweeper_action: 'dikarantina' });
w.snSwMuat(null, true);
let d = w.document;
cek('badge mesin C native (hijau)', /C native/.test(d.getElementById('swEngineBadge').textContent) && /sn-ok/.test(d.getElementById('swEngineBadge').className), d.getElementById('swEngineBadge').textContent);
cek('cacah di label sub-tab = webshell + mencurigakan terbuka (3)', d.getElementById('avSweepCount').textContent === '3', d.getElementById('avSweepCount').textContent);
const info = d.getElementById('swInfo').textContent;
cek('info: folder, pemindaian terakhir, berkas dipindai/ditandai, durasi/CPU/memori', /2 \(vhost/.test(info) && /17903 \/ 3/.test(info) && /6 s \/ 4 s \/ 17 MB/.test(info) && /2 \/ 5/.test(info), info);
cek('info: karantina otomatis aktif skor 90+, jadwal harian, 2 hash sah', /aktif \(skor 90\+\)/.test(info) && /harian/.test(info) && /Hash sah2/.test(info), info);
cek('tidak ada undefined/NaN di info', !/undefined|NaN/.test(d.getElementById('swInfo').innerHTML));
cek('tombol pindai aktif dan tombol hentikan tersembunyi saat tidak berjalan', d.getElementById('swBtnAbort').style.display === 'none' && d.getElementById('btnSwAll').style.pointerEvents !== 'none');
cek('klik manual memberi toast "Status diperbarui"', w.__toast.indexOf('Status diperbarui') >= 0, w.__toast);
// --- tabel
const trs = d.querySelectorAll('#tbSweep tr');
cek('tabel temuan: 5 baris', trs.length === 5, trs.length);
cek('level: WEBSHELL / MENCURIGAKAN / DIKARANTINA / DIABAIKAN', /WEBSHELL/.test(trs[0].textContent) && /MENCURIGAKAN/.test(trs[1].textContent) && /DIKARANTINA/.test(trs[2].textContent) && /DIABAIKAN/.test(trs[3].textContent));
cek('indikator tampil dengan bobot dan penjelasan Indonesia', /eval-input 98/.test(trs[0].textContent) && /menjalankan data dari request/.test(trs[0].innerHTML), trs[0].innerHTML.slice(0, 300));
cek('indikator tak dikenal tetap tampil (id apa adanya)', /tidak-dikenal 20/.test(trs[1].textContent));
cek('berkas terbuka: tombol Karantina, Tandai sah, Abaikan', trs[0].querySelectorAll('.sn-btn').length === 3);
cek('berkas dikarantina: tombol Lihat Karantina; diabaikan: Buka kembali', /Lihat Karantina/.test(trs[2].textContent) && /Buka kembali/.test(trs[3].textContent));
cek('XSS pada path/indikator di-escape (tidak ada elemen img/script/b)', !d.querySelector('#tbSweep img') && !d.querySelector('#tbSweep script') && !d.querySelector('#tbSweep b'), d.getElementById('tbSweep').innerHTML.slice(-400));
cek('path tersimpan utuh di atribut data-p (aman untuk aksi)', trs[4].querySelector('[data-p]').getAttribute('data-p') === ROWS[4].path);
// --- aksi
trs[0].querySelectorAll('.sn-btn')[0].click();
let aksi = w.__calls.filter(c => c[0] === 'sweeper_action');
cek('Karantina: konfirmasi lalu sweeper_action {act:quarantine, path}', w.__confirm.length === 1 && aksi.length === 1 && aksi[0][1].act === 'quarantine' && aksi[0][1].path === ROWS[0].path, JSON.stringify(aksi));
cek('setelah karantina: segarkan karantina AV', w.__calls.some(c => c[0] === 'snAvQuarMuat'));
trs[0].querySelectorAll('.sn-btn')[2].click();
aksi = w.__calls.filter(c => c[0] === 'sweeper_action');
cek('Abaikan: tanpa konfirmasi, act=ignore', aksi[aksi.length - 1][1].act === 'ignore' && w.__confirm.length === 1);
// --- filter
d.getElementById('swFilter').value = 'webshell'; w.snSwFindings();
cek('filter dikirim ke backend', w.__calls.filter(c => c[0] === 'get_sweeper_findings').pop()[1].filter === 'webshell');
// --- kosong / galat
w = jalan('id', { get_sweeper_findings: [] }); w.snSwFindings();
cek('daftar kosong: pesan tidak ada temuan', /Tidak ada temuan/.test(w.document.getElementById('tbSweep').textContent));
w = jalan('id', { get_sweeper_findings: null }); w.snSwFindings();
cek('galat backend: pesan gagal memuat, tidak melempar', /Gagal memuat/.test(w.document.getElementById('tbSweep').textContent));
// --- berjalan
w = jalan('id', { get_sweeper_status: STATUS({ running: true, job: { state: 'running', progress: { scanned: 1200, flagged: 1, path: '/www/wwwroot/a/x.php' } } }), get_sweeper_findings: [], get_sweeper_job: { running: true, job: { progress: { scanned: 2000, flagged: 2, path: '/p' } } } });
w.snSwRender(STATUS({ running: true, job: { state: 'running', progress: { scanned: 1200, flagged: 1, path: '/www/wwwroot/a/x.php' } } }));
d = w.document;
cek('saat berjalan: progres tampil, tombol hentikan muncul, tombol pindai dinonaktifkan', d.getElementById('swProg').style.display !== 'none' && d.getElementById('swBtnAbort').style.display !== 'none' && d.getElementById('btnSwAll').style.pointerEvents === 'none' && /1200 berkas dipindai, 1 ditandai/.test(d.getElementById('swProgTxt').textContent), d.getElementById('swProgTxt').textContent);
// --- mulai
w = jalan('id', { get_sweeper_status: STATUS(), get_sweeper_findings: [], sweeper_start: { started: true, running: true }, get_sweeper_job: { running: false, job: { summary: { scanned: 10, webshell: 1, quarantined: 1 } } } });
w.snSwStart('vhosts', 'auto');
const st = w.__calls.find(c => c[0] === 'sweeper_start');
cek('mulai semua vhost (auto): konfirmasi dulu, lalu sweeper_start {scope:vhosts, mode:auto}', w.__confirm.length === 1 && /webshell/.test(w.__confirm[0]) && st && st[1].scope === 'vhosts' && st[1].mode === 'auto', JSON.stringify(st));
w.snSwStart('vhosts', 'report');
cek('mode laporan: tanpa konfirmasi', w.__confirm.length === 1 && w.__calls.filter(c => c[0] === 'sweeper_start').pop()[1].mode === 'report');
w.snSwStart('path', 'auto', '/www/wwwroot/a');
cek('scan folder: path ikut dikirim', w.__calls.filter(c => c[0] === 'sweeper_start').pop()[1].path === '/www/wwwroot/a');
w.snSwStartPath();
cek('Scan Folder membuka prompt path', !!w.__prompt);
cek('dialog Folder to scan memakai label tombol eksplisit (bukan bawaan layer)', !!w.__prompt && Array.isArray(w.__prompt.btn) && w.__prompt.btn.length === 2 && /^[\x20-\x7e]+$/.test(w.__prompt.btn.join('')), JSON.stringify(w.__prompt && w.__prompt.btn));
// --- pengaturan
w = jalan('en', { get_sweeper_status: STATUS(), get_sweeper_allow: [{ sha256: 'a'.repeat(64), catatan: 'uji' }], set_sweeper_config: { ok: 1 }, sweeper_schedule: { enabled: false } });
w.snSwConfig();
d = w.document;
cek('modal pengaturan terisi dari konfigurasi', d.getElementById('swCfgPaths').value === '/www/x' && d.getElementById('swCfgExcl').value === '/.git/' && d.getElementById('swCfgAuto').checked && d.getElementById('swCfgQmin').value === '90');
cek('daftar hash sah tampil dengan tombol hapus', /aaaaaaaaaaaaaaaa/.test(d.getElementById('swAllowBox').textContent) && d.querySelector('[data-h]').getAttribute('data-h') === 'a'.repeat(64));
d.getElementById('swCfgPaths').value = '/a\n\n  /b  \n'; d.getElementById('swCfgAuto').checked = false; d.getElementById('swCfgThr').value = '7'; d.getElementById('swCfgSched').checked = false;
w.__opened.yes(5);
const sc = w.__calls.find(c => c[0] === 'set_sweeper_config');
const cfg = JSON.parse(sc[1].config);
cek('simpan: baris kosong dibuang, spasi dipangkas, angka jadi integer, boolean benar', JSON.stringify(cfg.custom_paths) === '["/a","/b"]' && cfg.auto_quarantine === false && cfg.throttle_ms === 7 && cfg.quarantine_min_score === 90 && cfg.engine === 'auto', sc[1].config);
cek('simpan juga mengatur jadwal (off)', w.__calls.find(c => c[0] === 'sweeper_schedule')[1].mode === 'off');
d.querySelector('[data-h]').click();
cek('hapus hash sah memanggil sweeper_allow_remove', w.__calls.find(c => c[0] === 'sweeper_allow_remove')[1].sha256 === 'a'.repeat(64));
d.getElementById('swCfgCal').value = '/www/wwwroot/bersih'; w.snSwCalibrate();
cek('kalibrasi mengirim path', w.__calls.find(c => c[0] === 'sweeper_calibrate')[1].path === '/www/wwwroot/bersih');
// --- Inggris dan mesin Python
w = jalan('en', { get_sweeper_status: STATUS({ engine: { kind: 'python', c_available: false, gcc: false } }), get_sweeper_findings: ROWS });
w.snSwMuat(null, false);
cek('bahasa Inggris dan mesin Python: badge kuning "Python (slow)"', /Python \(slow\)/.test(w.document.getElementById('swEngineBadge').textContent) && /sn-warn/.test(w.document.getElementById('swEngineBadge').className) && /WEBSHELL/.test(w.document.querySelector('#tbSweep tr').textContent) && /runs data taken from the request/.test(w.document.querySelector('#tbSweep tr').innerHTML));
// --- kelengkapan i18n
const kunci0 = ['av_sub_sweeper', 'tip_av_sweeper', 'sw_desc', 'btn_sw_scan_all', 'btn_sw_report', 'btn_sw_path', 'btn_sw_abort', 'btn_sw_settings', 'sw_flt_open', 'sw_th_level', 'sw_note'];
console.log('\nRINGKAS: ' + gagal + ' gagal'); process.exit(gagal ? 1 : 0);
