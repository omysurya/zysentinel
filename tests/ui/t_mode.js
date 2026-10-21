// Uji status mode blokir: lencana Mode, catatan #stNote yang berubah sesuai enforce, status di kartu
// Settings, rincian per lapisan, dan pembacaan ulang status setelah tombol enforce. Kode dari index.html.
// Pakai: node t_mode.js <index.html>
const fs = require('fs');
const { JSDOM } = require('jsdom');
const html = fs.readFileSync(process.argv[2], 'utf8');
const script = html.match(/<script[^>]*>([\s\S]*?)<\/script>/)[1];
const potong = (a, b) => { const i = script.indexOf(a), j = script.indexOf(b, i + 1); if (i < 0 || j < 0) throw new Error('tidak ketemu ' + a); return script.slice(i, j); };
const kode = potong('function snUpdateBadgesAndNotes(m){', '\n}\n') + '\n}\n' + potong('/* ---------- mode blokir per lapisan ---------- */', 'function snSvc(aksi, btn){');
let gagal = 0;
const cek = (n, k, x) => { console.log((k ? '  LULUS ' : '  GAGAL ') + n + (k ? '' : '  -> ' + x)); if (!k) gagal++; };
const L = (g, f, w, p, u) => [
  { kode: 'guardd', aktif: true, blokir: g, ket: 'enforce=' + (g ? 1 : 0) }, { kode: 'firewall', aktif: true, blokir: f, ket: 'x' },
  { kode: 'waf', aktif: true, blokir: w, ket: 'coraza, mode=block' }, { kode: 'proc', aktif: true, blokir: p, ket: 'mode=enforce' },
  { kode: 'upload', aktif: u !== null, blokir: !!u, ket: '3 vhost' }];
const M = (enf, pos) => ({ guardd_service: 'active', fw_service: 'active', status: { enforce: enf, pid: 1 }, posture: pos, fw_backend: 'iptables-nft', waf_engine: 'coraza' });
function jalan(lang) {
  const dom = new JSDOM('<body><span id="bMode"></span><span id="bGuard"></span><span id="bFw"></span><span id="bBackend"></span><span id="bWaf"></span><div id="stNote" style="display:none"></div><div id="modeNow" style="display:none"></div><div id="cardBlockMode"></div><span id="badgeEnforce"></span><div id="tileMonitor" class="sn-tile"></div><div id="tileBlock" class="sn-tile"></div></body>', { runScripts: 'outside-only' });
  const w = dom.window; w.$ = require('jquery')(w); w.SN_LANG = lang; w.__calls = []; w.__opened = null; w.__timers = [];
  w.snEsc = (t) => String(t == null ? '' : t).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  w.layer = { msg: () => 0, open: (o) => { w.__opened = o; } };
  w.snProgress = () => 1; w.snConf = () => w.__calls.push('snConf'); w.snStatus = () => w.__calls.push('snStatus');
  w.snAjax = (m, d, cb) => { w.__calls.push(m + ':' + JSON.stringify(d)); cb('enforce diubah menjadi 1, daemon direstart'); };
  w.setTimeout = (f, t) => { w.__timers.push(t); };
  w.eval(kode);
  return w;
}
let w = jalan('id'); const d = () => w.document, note = () => d().getElementById('stNote'), mode = () => d().getElementById('bMode');
w.snUpdateBadgesAndNotes(M(0, { ringkas: 'parsial', lapisan: L(false, true, true, true, true), enforce_jalan: 0, enforce_setel: 0, menunggu: false }));
cek('enforce=0: catatan "Monitor mode" tampil', /Monitor/i.test(note().textContent) && note().style.display !== 'none', note().textContent.slice(0, 60));
cek('enforce=0 + lapisan lain blokir: lencana "Parsial" (kuning)', /Parsial/.test(mode().textContent) && /sn-warn/.test(mode().className), mode().textContent);
cek('kartu Settings: "MONITOR SAJA (enforce = 0)"', /MONITOR SAJA \(enforce = 0\)/.test(d().getElementById('modeNow').textContent));
w.snUpdateBadgesAndNotes(M(0, { ringkas: 'parsial', lapisan: L(false, true, true, true, true), enforce_jalan: 0, enforce_setel: 1, menunggu: true }));
cek('baru disetel, daemon restart: catatan "Menerapkan" dan lencana "Menerapkan..."', /Menerapkan perubahan/.test(note().textContent) && /Menerapkan/.test(mode().textContent), note().textContent.slice(0, 60));
w.snUpdateBadgesAndNotes(M(1, { ringkas: 'blokir', lapisan: L(true, true, true, true, true), enforce_jalan: 1, enforce_setel: 1, menunggu: false }));
cek('enforce=1 semua lapisan: catatan "Mode blokir penuh aktif" TAMPIL (dulu disembunyikan)', /Mode blokir penuh aktif/.test(note().textContent) && note().style.display !== 'none', note().textContent.slice(0, 60));
cek('lencana "Blokir Penuh" (hijau)', /Blokir Penuh/.test(mode().textContent) && /sn-ok/.test(mode().className), mode().className);
cek('kartu Settings: "MEMBLOKIR (enforce = 1)"', /MEMBLOKIR \(enforce = 1\)/.test(d().getElementById('modeNow').textContent));
cek('enforce=1: kartu "Enable Blocking" aktif, "Monitor Only" tidak; lencana kartu MEMBLOKIR', /\bon\b/.test(d().getElementById('tileBlock').className) && !/\bon\b/.test(d().getElementById('tileMonitor').className) && d().getElementById('badgeEnforce').textContent === 'MEMBLOKIR');
w.snUpdateBadgesAndNotes(M(1, { ringkas: 'parsial', lapisan: L(true, true, false, true, null), enforce_jalan: 1, enforce_setel: 1, menunggu: false }));
cek('enforce=1 tetapi WAF deteksi dan upload mati: catatan menyebut lapisan itu', /WAF/.test(note().textContent) && /Upload Protection/.test(note().textContent), note().textContent);
w.snUpdateBadgesAndNotes(M(0, { ringkas: 'parsial', lapisan: L(false, true, true, true, true), enforce_jalan: 0, enforce_setel: 0, menunggu: false }));
cek('kembali ke enforce=0 sesudah blokir: catatan monitor MUNCUL lagi (dulu tetap tersembunyi)', /Monitor/i.test(note().textContent) && note().style.display !== 'none');
w.snUpdateBadgesAndNotes(M(0, { ringkas: 'monitor', lapisan: L(false, false, false, false, null), enforce_jalan: 0, enforce_setel: 0, menunggu: false }));
cek('enforce=0: kartu "Monitor Only" aktif kembali', /\bon\b/.test(d().getElementById('tileMonitor').className) && !/\bon\b/.test(d().getElementById('tileBlock').className));
cek('tidak ada lapisan memblokir: lencana "Monitor Saja" (merah)', /Monitor Saja/.test(mode().textContent) && /sn-bad/.test(mode().className));
w.snModeDetail();
cek('klik lencana: rincian 5 lapisan dengan status', w.__opened && (w.__opened.content.match(/<tr>/g) || []).length === 6 && /MATI/.test(w.__opened.content) && /Settings/.test(w.__opened.content), w.__opened && w.__opened.content.slice(0, 200));
w.snSetConf('enforce', '1', null);
cek('tombol Enable Blocking: set_conf enforce=1, lalu status dibaca ulang 3x (2,5 / 6 / 12 dtk)', w.__calls.some((c) => /set_conf:.*"key":"enforce".*"value":"1"/.test(c)) && JSON.stringify(w.__timers) === '[2500,6000,12000]', JSON.stringify(w.__timers));
w = jalan('en');
w.snUpdateBadgesAndNotes(M(1, { ringkas: 'blokir', lapisan: L(true, true, true, true, true), enforce_jalan: 1, enforce_setel: 1, menunggu: false }));
cek('bahasa Inggris: "Full blocking mode active" dan "Mode: Full Blocking"', /Full blocking mode active/.test(note().textContent) && /Full Blocking/.test(mode().textContent));
w.snUpdateBadgesAndNotes({ guardd_service: 'inactive', fw_service: 'active', status: { enforce: 1 }, posture: null });
cek('guardd mati: catatan "not running" tampil', /not running/.test(note().textContent) && note().style.display !== 'none');
cek('tidak ada undefined/NaN', !/undefined|NaN/.test(d().body.innerHTML));
// tata letak: kedua kartu paling atas di Settings (sebelum catatan kalibrasi ambang)
const atur = html.slice(html.indexOf('id="c-atur"'));
const iBlok = atur.indexOf('id="cardBlockMode"'), iSvc = atur.indexOf('id="cardDaemonSvc"'), iKal = atur.indexOf('note_threshold_calib');
cek('kartu Mode Blokir dan Layanan Daemon berada PALING ATAS tab Settings', iBlok > 0 && iSvc > iBlok && iKal > iSvc, [iBlok, iSvc, iKal]);
cek('tombol kartu: Monitor/Blocking memanggil snSetConf enforce 0/1; Start/Stop/Restart/Reload memanggil snSvc', /id="tileMonitor"[^>]*snSetConf\('enforce','0'/.test(html) && /id="tileBlock"[^>]*snSetConf\('enforce','1'/.test(html) && ['start','stop','restart','reload'].every((a) => new RegExp('class="[^"]*sn-tile[^"]*" onclick="snSvc\\(\'' + a + '\'\\)"').test(html)));
cek('tidak ada duplikat id panel lama', ['btnSvcStart','badgeGuarddSvc','modeNow','tileBlock'].every((x) => html.split('id="' + x + '"').length === 2));
console.log('\nRINGKAS: ' + gagal + ' gagal'); process.exit(gagal ? 1 : 0);
