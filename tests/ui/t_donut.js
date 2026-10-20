// Uji diagram donat "Jenis Serangan": kode diambil langsung dari index.html, echarts dan snAjax ditiru.
const fs = require('fs');
const { JSDOM } = require('jsdom');
const html = fs.readFileSync(process.argv[2], 'utf8');
const script = html.match(/<script[^>]*>([\s\S]*?)<\/script>/)[1];
const potong = (a, b) => { const i = script.indexOf(a), j = script.indexOf(b, i); if (i < 0 || j < 0) { console.error('blok tidak ditemukan: ' + a); process.exit(2); } return script.slice(i, j); };
const kode = potong('var SN_I18N = {', 'function snSetLang') + '\n' + potong('/* ---------- diagram donat jenis serangan', '/* ---------- blocked IPs');
let gagal = 0;
const cek = (n, k, i) => { console.log((k ? '  LULUS ' : '  GAGAL ') + n + (k ? '' : '  -> ' + i)); if (!k) gagal++; };

function jalan(lang, data) {
  const dom = new JSDOM('<body><div id="donutKosong" style="display:none"></div><div id="donutJenis"></div></body>', { runScripts: 'outside-only' });
  const w = dom.window;
  w.$ = require('jquery')(w);
  w.SN_LANG = lang; w.__opt = []; w.__init = 0;
  w.echarts = { init: () => { w.__init++; return { setOption: (o, r) => w.__opt.push([o, r]), resize() {} }; } };
  w.snAjax = (m, d, cb) => { w.__m = m; w.__d = d; cb(data); };
  w.eval(kode);
  w.snJenisSerangan(24);
  return w;
}
const data = { total: 5582, jenis: [{ key: 'ddos', n: 5394 }, { key: 'scanner', n: 120 }, { key: 'sqli', n: 40 }, { key: 'bruteforce', n: 4 }, { key: 'aneh', n: 1 }] };
let w = jalan('id', data);
cek('memanggil get_attack_types dengan jam', w.__m === 'get_attack_types' && w.__d.hours === 24, w.__m);
const o = w.__opt[0][0], s = o.series[0];
cek('donat: radius dalam dan luar', s.type === 'pie' && Array.isArray(s.radius), JSON.stringify(s.radius));
cek('jumlah irisan = jumlah jenis', s.data.length === 5, s.data.length);
cek('nama Indonesia dan nilai benar', s.data[0].name === 'DDoS / Flood' && s.data[0].value === 5394 && s.data[3].name === 'Brute Force', JSON.stringify(s.data[0]));
cek('jenis tak dikenal tetap tampil (nama = kunci, warna cadangan)', s.data[4].name === 'aneh' && s.data[4].itemStyle.color === '#64748b', JSON.stringify(s.data[4]));
cek('total di tengah', o.title.text === '5582' && o.title.subtext === 'serangan', JSON.stringify(o.title));
cek('setOption memakai notMerge=true', w.__opt[0][1] === true, w.__opt[0][1]);
cek('panel kosong disembunyikan', w.document.getElementById('donutKosong').style.display === 'none' && w.document.getElementById('donutJenis').style.display === 'block');
w = jalan('en', data);
cek('nama Inggris', w.__opt[0][0].series[0].data[1].name === 'Scanner / Probe' && w.__opt[0][0].title.subtext === 'attacks', w.__opt[0][0].title.subtext);
w = jalan('id', { total: 0, jenis: [] });
cek('data kosong: pesan tampil, diagram tersembunyi, echarts tak dibuat', w.document.getElementById('donutKosong').style.display !== 'none' && w.document.getElementById('donutJenis').style.display === 'none' && w.__init === 0);
w = jalan('id', null);
cek('respons galat (null) tidak melempar', w.__opt.length === 0);
const warna = Object.keys(w.SN_ATK_WARNA), unik = new Set(Object.values(w.SN_ATK_WARNA));
cek('warna tiap jenis unik', unik.size === warna.length, warna.length + '/' + unik.size);
const kunci = ['ddos','scanner','sqli','xss','rce','traversal','bruteforce','bot','protocol','campuran','lainnya'];
cek('semua jenis punya warna dan nama di kedua bahasa', kunci.every(k => w.SN_ATK_WARNA[k] && w.SN_I18N.id['atk_' + k] && w.SN_I18N.en['atk_' + k]));
console.log('\nRINGKAS: ' + gagal + ' gagal'); process.exit(gagal ? 1 : 0);
