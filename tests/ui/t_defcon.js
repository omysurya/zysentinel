// Uji kartu DEFCON (pengganti banner): posisi setelah Memory, warna per level, dialog indikator, refresh berprogres.
// Pakai: node t_defcon.js <index.html>
const fs = require('fs');
const { JSDOM } = require('jsdom');
const html = fs.readFileSync(process.argv[2], 'utf8');
const script = html.match(/<script[^>]*>([\s\S]*?)<\/script>/)[1];
const potong = (a, b) => { const i = script.indexOf(a), j = script.indexOf(b, i + 1); if (i < 0 || j < 0) throw new Error(a); return script.slice(i, j); };
const kode = potong('/* ---------- kartu statistik defender elit ---------- */', '/* ---------- panel sistem ---------- */')
  + potong('function snDefconTeks(p){', 'function snEliteLoad(') + potong('/* ---------- dialog DEFCON', 'function snToggleEgress(');
let gagal = 0;
const cek = (n, k, x) => { console.log((k ? '  LULUS ' : '  GAGAL ') + n + (k ? '' : '  -> ' + x)); if (!k) gagal++; };
const IND = (o) => [{ kode: 'panic', nilai: 0, baik: true, level: 1 }, { kode: 'kill_15m', nilai: o.kill || 0, baik: !o.kill, level: 2 },
  { kode: 'alert_15m', nilai: 0, baik: true, level: 2 }, { kode: 'persistensi', nilai: 0, baik: true, level: 2 },
  { kode: 'egress', nilai: 1, baik: true, level: 4 }, { kode: 'proc_guard', nilai: 1, baik: true, level: 4 }, { kode: 'intel', nilai: 1686, baik: true, level: 4 }];
const POST = (lv, o) => ({ defcon: lv, defcon_title: 't', defcon_desc: 'd', indikator: IND(o || {}), diukur: 1792560000, panic_on: false,
  egress_guard: { active: true }, proc_guard: { active: true, mode: 'enforce', kills: 0 }, threat_intel: { count: 1686 }, sys_persistence: { status: 'clean', changes: 0 } });
function jalan(lang, respon) {
  const w = new JSDOM('<body><div id="snStats"></div><span id="tgEgress"></span><span id="tgProc"></span><span id="tgIntel"></span><span id="tgFim"></span><span id="btnPanicToggle"></span></body>', { runScripts: 'dangerously' }).window;
  w.$ = require('jquery')(w); w.SN_LANG = lang; w.__open = null; w.__calls = [];
  w.snEsc = (t) => String(t == null ? '' : t).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  w.waktu = (t) => 'W' + t; w.snUpdateBadgesAndNotes = () => w.__calls.push('badges');
  w.layer = { open: (o) => { w.__open = o; w.$('body').append('<div id="lay">' + o.content + '</div>'); o.success && o.success(); }, msg: () => 0 };
  w.snAjax = (m, d, cb) => { w.__calls.push(m); cb(respon[m]); };
  w.eval('var SN_ELITE_DATA = null;' + kode);
  w.SN_STATUS_DATA = { status: { bans_active: 2, total_req: 10, lines: 5 }, rss_mb: 4.3 };
  return w;
}
let w = jalan('id', { get_elite_posture: POST(2, { kill: 1 }), get_status: { status: { bans_active: 3 }, rss_mb: 4.4 } });
w.SN_ELITE_DATA = POST(3); w.snUpdateDefconBanner(w.SN_ELITE_DATA);
let st = w.document.querySelectorAll('#snStats .sn-stat');
const label = (e) => e.querySelector('.k').textContent;
cek('kartu DEFCON tepat SESUDAH kartu Memory (terakhir)', label(st[st.length - 2]) === 'Memori' && label(st[st.length - 1]) === 'DEFCON', [...st].map(label).join(','));
const kartu = w.document.getElementById('snDefconCard');
cek('kartu menampilkan "DEFCON 3" hijau dan bisa diklik', /DEFCON 3/.test(kartu.textContent) && /16, ?185, ?129|#10b981/i.test(kartu.querySelector('.v').getAttribute('style')) && kartu.getAttribute('onclick') === 'snDefconDetail()', kartu.outerHTML.slice(0, 300));
cek('tooltip kartu: judul level + "klik untuk rincian"', /PERTAHANAN PENUH AKTIF/.test(kartu.getAttribute('title')) && /klik untuk rincian/.test(kartu.getAttribute('title')));
cek('banner DEFCON lama sudah dihapus dari HTML', !/id="snDefconBanner"/.test(html) && !/snDefconRefreshManual/.test(script));
kartu.click();
const lay = () => w.document.getElementById('lay');
cek('klik kartu: dialog "Postur Keamanan (DEFCON)" dengan tombol Refresh/Tutup', /Postur Keamanan/.test(w.__open.title) && JSON.stringify(w.__open.btn) === '["Refresh","Tutup"]');
cek('tinggi dialog menyesuaikan isi: area[1] kosong (bukan "auto" yang mengunci tinggi ~100 px)', Array.isArray(w.__open.area) && w.__open.area[1] === '' && w.__open.area[0] === '720px', JSON.stringify(w.__open.area));
cek('isi sudah ada di content SAAT dialog dibuka (layer menghitung tinggi dari sini), bukan diisi sesudahnya', /DEFCON 3/.test(w.__open.content) && (w.__open.content.match(/<tr>/g) || []).length === 8 && !w.__open.success, w.__open.content.length);
cek('batas tinggi: maxHeight 90% jendela agar tidak melebihi layar', Number(w.__open.maxHeight) > 0);
cek('dialog: level, judul, deskripsi, dan 7 indikator yang diukur', /DEFCON 3/.test(lay().textContent) && /Seluruh layer pertahanan/.test(lay().textContent) && lay().querySelectorAll('tbody tr').length === 7, lay().textContent.slice(0, 200));
cek('indikator: nilai Threat Intel 1686, Egress "Aktif", semua OK, efek level ditampilkan', /1686/.test(lay().textContent) && /Aktif/.test(lay().textContent) && lay().querySelectorAll('.sn-badge.sn-ok').length === 7 && /DEFCON 4/.test(lay().textContent));
cek('urutan penentuan level dijelaskan', /Urutan penentuan/.test(lay().textContent));
w.__open.yes();
const prog = w.document.getElementById('dfcProg').textContent;
cek('Refresh: progres 2 langkah dengan centang dan durasi', /1\/2 Postur pertahanan/.test(prog) && /2\/2 Status layanan/.test(prog) && /Selesai dalam \d+ ms, 2\/2 OK/.test(prog), prog);
cek('Refresh memanggil get_elite_posture lalu get_status', w.__calls.indexOf('get_elite_posture') >= 0 && w.__calls.indexOf('get_status') > w.__calls.indexOf('get_elite_posture'));
cek('sesudah Refresh: dialog dan kartu menampilkan level baru (DEFCON 2, oranye) dan indikator bermasalah', /DEFCON 2/.test(lay().textContent) && lay().querySelectorAll('.sn-badge.sn-bad').length === 1 && /DEFCON 2/.test(w.document.getElementById('snDefconCard').textContent));
w = jalan('en', { get_elite_posture: null, get_status: { status: {}, rss_mb: 1 } });
w.SN_ELITE_DATA = POST(4); w.snUpdateDefconBanner(w.SN_ELITE_DATA); w.snDefconDetail(); w.__open.yes();
const prog2 = w.document.getElementById('dfcProg').textContent;
cek('Refresh gagal sebagian: langkah gagal ditandai, ringkasan 1/2 OK (en)', /Done in \d+ ms, 1\/2 OK/.test(prog2) && /✘/.test(prog2), prog2);
w = jalan('id', {}); w.snStats({}, null);
cek('sebelum postur dimuat: kartu "DEFCON ..." tanpa galat', /\.\.\./.test(w.document.getElementById('snDefconCard').textContent));
w.snDefconDetail();
cek('dialog sebelum postur dimuat: pesan "Tekan Refresh"', /Tekan Refresh/.test(w.document.getElementById('lay').textContent));
console.log('\nRINGKAS: ' + gagal + ' gagal'); process.exit(gagal ? 1 : 0);
