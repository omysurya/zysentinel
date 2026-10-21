// Uji UI "Learned Rules" dan aksi Blokir/Izinkan di Event Feed: kode diambil langsung dari index.html, backend (snAjax) ditiru.
// Pakai: node t_learned.js <index.html>
const fs = require('fs');
const { JSDOM } = require('jsdom');
const html = fs.readFileSync(process.argv[2], 'utf8');
const script = html.match(/<script[^>]*>([\s\S]*?)<\/script>/)[1];
const i = script.indexOf('function snFeed(){'), j = script.indexOf('/* ---------- IP timeline ---------- */');
if (i < 0 || j < 0) { console.error('blok Event Feed/Learned tidak ditemukan'); process.exit(2); }
const kode = script.slice(i, j);
let gagal = 0;
const cek = (n, k, x) => { console.log((k ? '  LULUS ' : '  GAGAL ') + n + (k ? '' : '  -> ' + x)); if (!k) gagal++; };

const EVENTS = [
  { ts: 1792549000, ip: '198.51.100.1', kind: 'scanner', score: 90, level: 1, host: 'a.test', path: '/probe.php', ua: 'EvilScan/1.0' },
  { ts: 1792549100, ip: '198.51.100.2', kind: 'flood', score: 80, level: 1, host: 'a.test', path: '/', ua: 'x' },
];
const LRN = (o) => Object.assign({ enabled: true, enforce: 1, max: 500, lessons: [
  { id: 'a1b2c3d4', aksi: 'B', kind: 'scanner', path: '/probe.php', ua: 'evilscan', host: 'a.test', sources: ['198.51.100.1', '198.51.100.9'], created: 1792549000, hits: 3, last_hit: 1792549500 },
  { id: 'feed0001', aksi: 'A', kind: 'bad-ua', path: '', ua: 'grokbot', host: 'a.test', sources: ['198.51.100.5'], created: 1792549001, hits: 0, last_hit: 0 },
  { id: 'baadf00d', aksi: 'B', kind: 'scanner', path: '/<img src=x onerror=alert(1)>', ua: '"><script>', host: '<b>', sources: ['<i>'], created: 1792549002, hits: 0, last_hit: 0 },
] }, o || {});

function jalan(lang, handlers) {
  const dom = new JSDOM('<body><table><tbody id="tbFeed"></tbody></table><div id="lrnInfo" style="display:none"></div><span id="lrnToggleTxt"></span><table><tbody id="tbLearned"></tbody></table></body>', { runScripts: 'dangerously' });
  const w = dom.window;
  w.$ = require('jquery')(w); w.SN_LANG = lang;
  w.__calls = []; w.__toast = []; w.__confirm = [];
  w.snSpinBtn = () => () => {};
  w.snEsc = (t) => String(t === undefined || t === null ? '' : t).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  w.kelasLevel = () => 'lv1'; w.teksLevel = () => 'WATCH'; w.kelasSkor = () => 'sc1'; w.waktu = (t) => 'T' + t;
  w.kosong = (sel, n, t) => w.$(sel).html('<tr><td colspan="' + n + '" class="sn-empty">' + t + '</td></tr>');
  w.snBans = () => w.__calls.push(['snBans']); w.snAllowMuat = () => w.__calls.push(['snAllowMuat']);
  w.layer = { msg: (m) => w.__toast.push(m), close: () => 0, confirm: (m, o, yes) => { w.__confirm.push([m, o]); yes(1); } };
  w.snAjax = (m, d, cb) => { w.__calls.push([m, d]); const h = handlers[m]; cb(typeof h === 'function' ? h(d) : h); };
  w.eval(kode);
  return w;
}
const panggil = (w, m) => w.__calls.filter((c) => c[0] === m);

// --- Event Feed: tombol membawa ts kejadian
let w = jalan('id', { get_events: EVENTS, get_learned: LRN(), ban_ip: 'diblokir | Dipelajari: x', allow_ip: 'diizinkan', learned_revoke: 'ok', learned_toggle: 'ok' });
w.snFeed();
let d = w.document;
const btns = d.querySelectorAll('#tbFeed tr:first-child .sn-btn');
cek('baris feed: tombol Izinkan dan Blokir memuat ip dan ts kejadian', btns.length === 2 && /snFeedAllow\('198.51.100.1',1792549000\)/.test(btns[0].getAttribute('onclick')) && /snFeedBan\('198.51.100.1',1792549000\)/.test(btns[1].getAttribute('onclick')), btns.length && btns[0].getAttribute('onclick'));
btns[1].click();
let c = panggil(w, 'ban_ip')[0];
cek('Blokir mengirim ip dan ev_ts ke ban_ip', c && c[1].ip === '198.51.100.1' && String(c[1].ev_ts) === '1792549000' && c[1].secs === '', c);
cek('dialog Blokir menjelaskan pembelajaran (id)', /dipelajari/i.test(w.__confirm[0][0]) && /Aturan Dipelajari/.test(w.__confirm[0][0]), w.__confirm[0][0]);
cek('tombol dialog Blokir berlabel Indonesia, bukan bawaan layer', JSON.stringify(w.__confirm[0][1].btn) === '["Blokir","Batal"]', w.__confirm[0][1].btn);
cek('hasil Blokir (termasuk kalimat pelajaran) ditampilkan', w.__toast.some((t) => /Dipelajari: x/.test(t)), w.__toast);
cek('setelah Blokir: feed, tabel Blocked IPs, dan tab Learned disegarkan', panggil(w, 'get_events').length >= 2 && panggil(w, 'snBans').length === 1 && panggil(w, 'get_learned').length === 1, w.__calls.map((x) => x[0]));
btns[0].click();
c = panggil(w, 'allow_ip')[0];
cek('Izinkan mengirim ip dan ev_ts ke allow_ip', c && c[1].ip === '198.51.100.1' && String(c[1].ev_ts) === '1792549000', c);
cek('dialog Izinkan menjelaskan pembelajaran dan tombol berlabel eksplisit', /dikenali/.test(w.__confirm[1][0]) && JSON.stringify(w.__confirm[1][1].btn) === '["Izinkan","Batal"]', w.__confirm[1]);
w = jalan('en', { get_events: EVENTS });
w.snFeed(); w.document.querySelectorAll('#tbFeed tr:first-child .sn-btn')[1].click();
cek('dialog Blokir bahasa Inggris dan label Block/Cancel', /learned/i.test(w.__confirm[0][0]) && JSON.stringify(w.__confirm[0][1].btn) === '["Block","Cancel"]', w.__confirm[0]);

// --- tata letak tabel Event Feed (jsdom tidak punya layout; yang dicek struktur yang menjamin tidak overflow)
{
  const tb = html.match(/<table class="sn-tb sn-feedtb">[\s\S]*?<\/table>/)[0];
  const cols = (tb.match(/<col\b/g) || []).length, ths = (tb.match(/<th\b/g) || []).length;
  cek('Event Feed: tabel berlayout tetap dalam pembungkus yang dapat menggulir', /<div class="sn-feedwrap">\s*<table class="sn-tb sn-feedtb">/.test(html) && /table\.sn-tb\.sn-feedtb\{table-layout:fixed/.test(html) && /\.sn-feedwrap\{[^}]*overflow-x:auto/.test(html));
  cek('Event Feed: jumlah <col> = jumlah <th> = 9, kolom Action selebar 175px', cols === 9 && ths === 9 && /<col style="width:175px">\s*<\/colgroup>/.test(tb), [cols, ths]);
  cek('Event Feed: hanya URI dan User Agent yang fleksibel (dua <col> tanpa lebar)', (tb.match(/<col>/g) || []).length === 2, tb.match(/<col>/g));
  const wf = jalan('id', { get_events: EVENTS }); wf.snFeed();
  const row = wf.document.querySelector('#tbFeed tr:first-child');
  const act = row.cells[8];
  cek('baris feed: 9 sel, sel Action adalah td biasa (bukan td flex) berisi div pembungkus tombol', row.cells.length === 9 && act.tagName === 'TD' && act.className === 'sn-act' && act.firstElementChild.tagName === 'DIV' && act.querySelectorAll('.sn-btn').length === 2, [row.cells.length, act.outerHTML.slice(0, 80)]);
  cek('tombol di kolom Action tidak dibungkus baris (flex-wrap:nowrap)', /nowrap/.test(act.firstElementChild.getAttribute('style')));
  cek('baris tanpa IP tetap 9 sel', (() => { const x = jalan('id', { get_events: [{ ts: 1, ip: '', kind: 'x', score: 1, level: 0, host: 'h', path: '/p', ua: 'u' }] }); x.snFeed(); return x.document.querySelector('#tbFeed tr').cells.length === 9; })());
}

// --- tab Learned
w = jalan('id', { get_learned: LRN(), learned_revoke: 'Pelajaran a1b2c3d4 dicabut', learned_toggle: 'Pembelajaran dijeda' });
w.snLearned(null, true); d = w.document;
let trs = d.querySelectorAll('#tbLearned tr');
cek('3 pelajaran ditampilkan', trs.length === 3, trs.length);
cek('baris blokir: badge Blokir (merah), pola URI+UA, sumber +1, 3 kali diterapkan', /Blokir/.test(trs[0].textContent) && /lv3/.test(trs[0].innerHTML) && /URI \/probe.php/.test(trs[0].textContent) && /UA evilscan/.test(trs[0].textContent) && /198.51.100.1 \+1/.test(trs[0].textContent) && /3/.test(trs[0].cells[5].textContent), trs[0].textContent);
cek('baris izinkan: badge Izinkan, hanya UA, hitungan "-"', /Izinkan/.test(trs[1].textContent) && !/URI/.test(trs[1].textContent) && /UA grokbot/.test(trs[1].textContent) && trs[1].cells[5].textContent === '-', trs[1].textContent);
cek('XSS: data berbahaya di-escape, tidak ada elemen img/script tersisip', d.querySelectorAll('#tbLearned img, #tbLearned script, #tbLearned i').length === 0 && /&lt;img/.test(trs[2].innerHTML), trs[2].innerHTML);
cek('tidak ada undefined/NaN', !/undefined|NaN/.test(d.getElementById('tbLearned').innerHTML));
cek('mode enforce=1: tidak ada kotak info', d.getElementById('lrnInfo').style.display === 'none');
cek('tombol jeda berlabel "Jeda pembelajaran"', d.getElementById('lrnToggleTxt').textContent === 'Jeda pembelajaran', d.getElementById('lrnToggleTxt').textContent);
trs[0].querySelector('.sn-btn.dgr').click();
c = panggil(w, 'learned_revoke')[0];
cek('Cabut mengirim id yang sudah dibersihkan, dengan dialog berlabel Cabut/Batal', c && c[1].id === 'a1b2c3d4' && JSON.stringify(w.__confirm[0][1].btn) === '["Cabut","Batal"]', c);
cek('setelah Cabut: tabel dimuat ulang', panggil(w, 'get_learned').length >= 2);
w.snLearnedToggle();
c = panggil(w, 'learned_toggle')[0];
cek('toggle saat nyala mengirim enabled=0', c && String(c[1].enabled) === '0', c);
let r = trs[2].querySelector('.sn-btn.dgr').getAttribute('onclick');
cek('id berbahaya tidak lolos ke onclick', /snLearnedRevoke\('baadf00d'\)/.test(r), r);

w = jalan('id', { get_learned: LRN({ enforce: 0 }) }); w.snLearned(null, true);
cek('enforce=0: kotak info menyebut Review Queue', w.document.getElementById('lrnInfo').style.display !== 'none' && /Review Queue/.test(w.document.getElementById('lrnInfo').textContent), w.document.getElementById('lrnInfo').textContent);
w = jalan('id', { get_learned: LRN({ enabled: false }) }); w.snLearned(null, true);
cek('dijeda: info jeda dan tombol "Lanjutkan pembelajaran"', /dijeda/.test(w.document.getElementById('lrnInfo').textContent) && w.document.getElementById('lrnToggleTxt').textContent === 'Lanjutkan pembelajaran', w.document.getElementById('lrnInfo').textContent);
w.snLearnedToggle();
cek('toggle saat dijeda mengirim enabled=1', String(panggil(w, 'learned_toggle')[0][1].enabled) === '1');
w = jalan('en', { get_learned: LRN() }); w.snLearned(null, true);
cek('bahasa Inggris: badge Block/Allow dan tombol Revoke', /Block/.test(w.document.querySelector('#tbLearned tr').textContent) && /Allow/.test(w.document.querySelectorAll('#tbLearned tr')[1].textContent) && /Revoke/.test(w.document.querySelector('#tbLearned .sn-btn.dgr').textContent));
w = jalan('en', { get_learned: LRN({ lessons: [] }) }); w.snLearned(null, true);
cek('kosong: pesan petunjuk (en)', /Nothing learned yet/.test(w.document.getElementById('tbLearned').textContent));

// --- i18n dan markup
const kunci = ['sub_learned', 'tip_sub_learned', 'tip_lrn_toggle', 'tip_refresh_lrn', 'lrn_desc', 'lrn_th_rule', 'lrn_th_pattern', 'lrn_th_source', 'lrn_th_hits'];
const en = script.slice(script.indexOf('en: {', script.indexOf('var SN_I18N')), script.indexOf('id: {', script.indexOf('var SN_I18N')));
const idb = script.slice(script.indexOf('id: {', script.indexOf('var SN_I18N')));
cek('semua kunci i18n ada di en dan id', kunci.every((k) => new RegExp('\\b' + k + ':').test(en) && new RegExp('\\b' + k + ':').test(idb)), kunci.filter((k) => !new RegExp('\\b' + k + ':').test(en) || !new RegExp('\\b' + k + ':').test(idb)));
cek('markup: tab dan subpage Learned terpasang, handler SN_SUB terdaftar', /snSub\('learned',this\)/.test(html) && /id="sub-learned"/.test(html) && /learned: snLearned/.test(script));
cek('tab Learned bukan span bersarang (tidak ada padding ganda)', !/snSub\('learned',this\)[^>]*><span/.test(html));
console.log('\nRINGKAS: ' + gagal + ' gagal');
process.exit(gagal ? 1 : 0);
