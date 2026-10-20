// Render opsi donat dengan echarts asli milik panel (renderer SVG di jsdom): opsi dari index.html harus valid.
// Pakai: node t_donut_svg.js <index.html> <echarts.min.js>
const fs = require('fs');
const { JSDOM } = require('jsdom');
const html = fs.readFileSync(process.argv[2], 'utf8');
const script = html.match(/<script[^>]*>([\s\S]*?)<\/script>/)[1];
const potong = (a, b) => { const i = script.indexOf(a), j = script.indexOf(b, i); return script.slice(i, j); };
const kode = potong('var SN_I18N = {', 'function snSetLang') + '\n' + potong('/* ---------- diagram donat jenis serangan', '/* ---------- blocked IPs');
const w = new JSDOM('<body><div id="donutKosong"></div><div id="donutJenis"></div></body>', { runScripts: 'outside-only', pretendToBeVisual: true }).window;
w.$ = require('jquery')(w); w.SN_LANG = 'id';
// jsdom tanpa paket canvas: ukuran teks ditiru agar tata letak echarts jalan
w.HTMLCanvasElement.prototype.getContext = () => ({ font: '', measureText: (t) => ({ width: 7 * String(t).length }) });
w.eval(fs.readFileSync(process.argv[3], 'utf8'));
const asli = w.echarts.init;
let galat = null;
w.echarts.init = (el) => asli.call(w.echarts, el, null, { renderer: 'svg', width: 320, height: 300 });
const origErr = w.console.error; w.console.error = (...a) => { galat = a.join(' '); };
w.snAjax = (m, d, cb) => cb({ total: 5582, jenis: [{ key: 'ddos', n: 5394 }, { key: 'scanner', n: 120 }, { key: 'sqli', n: 40 }, { key: 'xss', n: 20 }, { key: 'bruteforce', n: 4 }] });
w.eval(kode); w.snJenisSerangan(24);
const svg = w.document.getElementById('donutJenis').innerHTML;
const n = (svg.match(/<path/g) || []).length;
const cek = (nama, k, i) => console.log('  ' + (k ? 'LULUS ' : 'GAGAL ') + nama + (k ? '' : '  -> ' + i));
cek('tidak ada galat echarts', !galat, galat);
cek('SVG terbentuk dengan >= 5 path irisan (' + n + ')', n >= 5, svg.slice(0, 200));
cek('total 5582 dan keterangan tampil', svg.includes('5582') && svg.includes('serangan'), '');
cek('legenda memuat nama jenis', svg.includes('DDoS / Flood') && svg.includes('Brute Force'), '');
process.exit(galat || n < 5 ? 1 : 0);
