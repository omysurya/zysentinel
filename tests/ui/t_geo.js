// Uji tab Origin: tabel #tbGeo diisi dari get_geo_stat (dulu selalu "loading" karena fungsinya tertimpa),
// kartu Country Block tetap dimuat. Kode dari index.html, backend ditiru. Pakai: node t_geo.js <index.html>
const fs = require('fs');
const { JSDOM } = require('jsdom');
const html = fs.readFileSync(process.argv[2], 'utf8');
const script = html.match(/<script[^>]*>([\s\S]*?)<\/script>/)[1];
const potong = (a, b) => { const i = script.indexOf(a), j = script.indexOf(b, i + 1); return script.slice(i, j); };
const kode = potong('/* ---------- asal negara penyerang (tab Origin)', '/* ---------- blokir per negara') + potong('function snBendera(kode){', 'function snPetaSerangan(');
let gagal = 0;
const cek = (n, k, x) => { console.log((k ? '  LULUS ' : '  GAGAL ') + n + (k ? '' : '  -> ' + x)); if (!k) gagal++; };
const STAT = { negara: [{ kode: 'US', nama: 'United States', ip: 45, n: 2379, puncak: 100 }, { kode: 'SG', nama: 'Singapore', ip: 7, n: 1061, puncak: 63 },
  { kode: 'TW', nama: 'Taiwan,China', ip: 2, n: 141, puncak: 62 }, { kode: '??', nama: 'Tidak diketahui', ip: 1, n: 3, puncak: 5 },
  { kode: 'XX"><img src=x onerror=alert(1)>', nama: '<script>alert(1)</script>', ip: 1, n: 1, puncak: 1 }], tak_tahu: 1, geo_tersedia: true, total_ip: 56 };
const BAN = { mode: 'off', blok: 0, aturan: 0, negara_daftar: [] };
function jalan(lang, stat) {
  const w = new JSDOM('<body><select id="selGeoJam"><option value="168" selected>7</option></select><div id="geoNote" style="display:none"></div><table><tbody id="tbGeo"><tr><td>loading</td></tr></tbody></table><span id="geoBanBadge"></span><div id="geoBanStatus"></div><select id="geoBanNegara"><option>x</option></select></body>', { runScripts: 'outside-only' }).window;
  w.$ = require('jquery')(w); w.SN_LANG = lang; w.__calls = [];
  w.snEsc = (t) => String(t == null ? '' : t).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  w.kelasSkor = () => 'sc1'; w.snGeoBanKotak = () => w.__calls.push('snGeoBanKotak');
  w.kosong = (sel, n, t) => w.$(sel).html('<tr><td colspan="' + n + '" class="sn-empty">' + t + '</td></tr>');
  w.snAjax = (m, d, cb) => { w.__calls.push([m, d]); cb(m === 'get_geo_stat' ? stat : (m === 'get_geo_ban' ? BAN : [])); };
  w.eval(kode);
  return w;
}
let w = jalan('id', STAT); w.snGeoMuat();
const tb = w.document.getElementById('tbGeo'), trs = tb.querySelectorAll('tr');
cek('get_geo_stat dipanggil dengan rentang dari pilihan (168 jam)', w.__calls.some((c) => c[0] === 'get_geo_stat' && c[1].hours === '168'));
cek('tabel TIDAK lagi "loading": 5 baris negara', !/loading/.test(tb.textContent) && trs.length === 5, tb.textContent.slice(0, 80));
cek('baris AS: bendera, kode, nama, 45 IP, 2379 kejadian, puncak 100, batang 100%', /🇺🇸 US/.test(trs[0].cells[0].textContent) && trs[0].cells[1].textContent === 'United States' && trs[0].cells[2].textContent === '45' && trs[0].cells[3].textContent === '2379' && trs[0].cells[4].textContent === '100' && /width:100%/.test(trs[0].innerHTML), trs[0].textContent);
cek('Taiwan (tak punya poligon peta) tetap ada di tabel', /Taiwan/.test(trs[2].textContent));
cek('"??" ditampilkan "Tidak diketahui" tanpa tombol Blokir', /Tidak diketahui/.test(trs[3].textContent) && !trs[3].querySelector('.sn-btn'));
cek('tombol Blokir memanggil snGeoBanCepat dengan kode negara', /snGeoBanCepat\('US'\)/.test(trs[0].querySelector('.sn-btn').getAttribute('onclick')) && trs[0].querySelector('.sn-btn').textContent === 'Blokir');
cek('XSS: kode/nama berbahaya di-escape dan tidak diberi tombol', !tb.querySelector('img, script') && !trs[4].querySelector('.sn-btn'), trs[4].innerHTML);
cek('catatan sumber GeoLite2 dan jumlah IP tampil', /56 IP penyerang/.test(w.document.getElementById('geoNote').textContent) && w.document.getElementById('geoNote').style.display !== 'none');
cek('kartu Country Block tetap dimuat sesudah tabel (get_geo_ban)', w.__calls.some((c) => c[0] === 'get_geo_ban') && w.__calls.indexOf('snGeoBanKotak') > 0);
w = jalan('en', { negara: [], tak_tahu: 0, geo_tersedia: true, total_ip: 0 }); w.snGeoMuat();
cek('kosong (en): pesan "No attackers recorded"', /No attackers recorded/.test(w.document.getElementById('tbGeo').textContent));
w = jalan('en', { negara: [], tak_tahu: 0, geo_tersedia: false, total_ip: 0 }); w.snGeoMuat();
cek('GeoIP tidak ada: catatan menjelaskan', /GeoIP database/.test(w.document.getElementById('geoNote').textContent));
w = jalan('id', null); w.snGeoMuat();
cek('respons gagal: pesan galat, bukan "loading" selamanya', /Gagal memuat statistik negara/.test(w.document.getElementById('tbGeo').textContent));
cek('hanya satu fungsi snGeoMuat (tidak tertimpa lagi)', (script.match(/function snGeoMuat\(/g) || []).length === 1);
cek('header tabel diterjemahkan (kunci geo_th_* di en dan id)', (script.match(/geo_th_country:/g) || []).length === 2 && /data-i18n="geo_th_country"/.test(html));
console.log('\nRINGKAS: ' + gagal + ' gagal'); process.exit(gagal ? 1 : 0);
