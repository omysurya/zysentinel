// Uji render tabel Packet Counters: kode snRenderFwHits diambil langsung dari index.html.
const fs = require('fs');
const { JSDOM } = require('jsdom');
const html = fs.readFileSync(process.argv[2], 'utf8');
const script = html.match(/<script[^>]*>([\s\S]*?)<\/script>/)[1];
const potong = (a, b) => { const i = script.indexOf(a), j = script.indexOf(b, i); if (i < 0 || j < 0) { console.error('blok tidak ditemukan: ' + a); process.exit(2); } return script.slice(i, j); };
const kode = potong('function ukuranAngka', 'function waktu(') + '\n' + potong('function snRenderFwHits', '/* ---------- render kernel sets');
let gagal = 0;
const cek = (n, k, i) => { console.log((k ? '  LULUS ' : '  GAGAL ') + n + (k ? '' : '  -> ' + i)); if (!k) gagal++; };
function jalan(lang, hits) {
  const w = new JSDOM('<body><div id="fwHitBox"></div><span id="fwHitTime"></span></body>', { runScripts: 'outside-only' }).window;
  w.$ = require('jquery')(w); w.SN_LANG = lang;
  w.snEsc = (t) => String(t).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  w.eval(kode); w.snRenderFwHits(hits);
  return w.document.getElementById('fwHitBox');
}
const data = [
  { target: 'DROP', rule: 'intel-drop', detail: 'match-set sentinel_intel src', pkts: 12, bytes: 560 },
  { target: 'RETURN', rule: 'review', detail: 'match-set sentinel_review src', pkts: 0, bytes: 0 },
  { target: 'DROP', rule: 'syn-guard', detail: '', pkts: 1234567, bytes: 98765432 },
];
let b = jalan('id', data), baris = b.querySelectorAll('tbody tr');
cek('3 baris untuk 3 butir', baris.length === 3, baris.length);
cek('tidak ada kata "undefined" di tabel', !/undefined/.test(b.innerHTML), b.innerHTML.match(/.{30}undefined.{30}/));
cek('kolom target terisi', baris[0].children[0].textContent === 'DROP' && baris[1].children[0].textContent === 'RETURN');
cek('kolom aturan terisi dan detail tampil', /intel-drop/.test(baris[0].children[1].textContent) && /sentinel_intel/.test(baris[0].children[1].textContent), baris[0].children[1].textContent);
cek('paket dan bytes: angka nyata', baris[0].children[2].textContent === '12' && baris[0].children[3].textContent === '560.0 B'.replace('.0', '') , baris[0].children[2].textContent + ' / ' + baris[0].children[3].textContent);
cek('nol tampil "0" dan "0 B"', baris[1].children[2].textContent === '0' && baris[1].children[3].textContent === '0 B');
cek('byte besar diformat (94.2 MB)', baris[2].children[3].textContent === '94.2 MB', baris[2].children[3].textContent);
cek('judul kolom Indonesia', /Aturan Pertahanan/.test(b.innerHTML) && /Paket/.test(b.innerHTML));
b = jalan('en', data); cek('judul kolom Inggris', /Defense Rule/.test(b.innerHTML) && /Packets/.test(b.innerHTML));
b = jalan('id', ['DROP 0 0 match-set x /* sentinel:x */', null, 7, {}]);
cek('butir bukan objek / tanpa target dilewati: tak ada baris "undefined", tampil pesan kosong', !/undefined/.test(b.innerHTML) && !b.querySelector('tbody') && /belum tersedia/.test(b.textContent), b.innerHTML.slice(0, 200));
b = jalan('id', []); cek('daftar kosong: pesan, bukan tabel kosong', !b.querySelector('table') && b.textContent.length > 10);
b = jalan('id', [{ target: 'DROP', rule: '<img src=x onerror=alert(1)>', detail: '"><script>', pkts: 1, bytes: 1 }]);
cek('XSS pada nama aturan di-escape', !b.querySelector('img') && !b.querySelector('script'), b.innerHTML.slice(0, 200));
console.log('\nRINGKAS: ' + gagal + ' gagal'); process.exit(gagal ? 1 : 0);
