// Peta asal serangan dengan echarts ASLI dan world.json ASLI milik panel (renderer SVG di jsdom).
// Pakai: node t_peta.js <index.html> <echarts.min.js> <world.json>
const fs = require('fs');
const { JSDOM } = require('jsdom');
const html = fs.readFileSync(process.argv[2], 'utf8');
const script = html.match(/<script[^>]*>([\s\S]*?)<\/script>/)[1];
const potong = (a, b) => { const i = script.indexOf(a), j = script.indexOf(b, i); return script.slice(i, j); };
const kode = potong('/* ---------- peta asal serangan', '/* ---------- blocked IPs');
const dunia = JSON.parse(fs.readFileSync(process.argv[4], 'utf8'));
let gagal = 0;
const cek = (n, k, i) => { console.log('  ' + (k ? 'LULUS ' : 'GAGAL ') + n + (k ? '' : '  -> ' + i)); if (!k) gagal++; };
const DATA = { jam: 24, total: 1229, tak_tahu: 3, geo_tersedia: true, negara: [
  { kode: 'US', nama: 'United States', n: 770, ip: 43 }, { kode: 'ID', nama: 'Indonesia', n: 154, ip: 14 },
  { kode: 'DE', nama: 'Germany', n: 82, ip: 5 }, { kode: 'TW', nama: 'Taiwan,China', n: 50, ip: 2 },
  { kode: 'GB', nama: 'United Kingdom', n: 49, ip: 5 }, { kode: 'AU', nama: 'Australia', n: 37, ip: 2 }, { kode: 'XX', nama: '<img src=x onerror=alert(1)>', n: 1, ip: 1 }] };
function jalan(lang, duniaOk, data) {
  const w = new JSDOM('<body><div id="petaKosong" style="display:none"></div><div id="petaSerangan"></div><div id="petaTop"></div></body>', { runScripts: 'outside-only', pretendToBeVisual: true }).window;
  w.$ = require('jquery')(w); w.SN_LANG = lang; w.__url = null; w.__panggil = [];
  w.HTMLCanvasElement.prototype.getContext = () => ({ font: '', measureText: (t) => ({ width: 7 * String(t).length }) });
  w.eval(fs.readFileSync(process.argv[3], 'utf8'));
  const asli = w.echarts.init; w.__galat = null;
  w.echarts.init = (el) => asli.call(w.echarts, el, null, { renderer: 'svg', width: 420, height: 250 });
  w.console.error = (...a) => { w.__galat = a.join(' '); };
  w.$.ajax = (o) => { w.__url = o.url; if (duniaOk) o.success(dunia); else o.error({}); o.complete(); };
  w.snEsc = (t) => String(t == null ? '' : t).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  w.snAjax = (m, d, cb) => { w.__panggil.push([m, d]); cb(data); };
  w.eval(kode);
  return w;
}
let w = jalan('id', true, DATA);
w.snPetaSerangan(24);
const svg = w.document.getElementById('petaSerangan').innerHTML;
const n = (svg.match(/<path/g) || []).length;
cek('memanggil get_attack_map dengan rentang jam yang sama dengan donut', w.__panggil[0][0] === 'get_attack_map' && w.__panggil[0][1].hours === 24);
cek('world.json diambil dari panel sendiri (/static/vite/data/world.json), bukan internet', w.__url === '/static/vite/data/world.json', w.__url);
cek('tidak ada galat echarts', !w.__galat, w.__galat);
cek('peta dunia tergambar (>= 150 negara sebagai path SVG: ' + n + ')', n >= 150, svg.slice(0, 200));
cek('negara dengan serangan terbanyak diwarnai merah (skala visualMap)', /fill="(rgba?\(239,68,68(,1)?\)|#ef4444)"/i.test(svg), (svg.match(/fill="[^"]+"/g) || []).slice(0, 8));
const opt = w.SN_PETA.getOption();
const tip = opt.tooltip[0].formatter({ name: 'United States', data: { value: 770, ip: 43, kode: 'US' } });
cek('tooltip: bendera, nama, jumlah serangan, jumlah IP, persen dari total donut', /🇺🇸/.test(tip) && /770 serangan/.test(tip) && /43 IP/.test(tip) && /62\.7%/.test(tip), tip);
cek('tooltip negara tanpa serangan hanya nama', opt.tooltip[0].formatter({ name: 'Peru' }) === 'Peru');
const top = w.document.getElementById('petaTop').innerHTML;
cek('daftar 5 negara teratas di bawah peta (termasuk Taiwan yang tak punya poligon)', (top.match(/<span/g) || []).length === 6 && /🇮🇩 Indonesia <b>154<\/b>/.test(top) && /Taiwan/.test(top), top);
cek('asal tidak diketahui ditampilkan', /Asal tidak diketahui <b>3<\/b>/.test(top));
w.snPetaSerangan(24); cek('pemuatan ulang: world.json tidak diunduh lagi, peta tetap', (w.document.getElementById('petaSerangan').innerHTML.match(/<path/g) || []).length >= 150);
w = jalan('id', true, { jam: 24, total: 7, tak_tahu: 0, negara: [{ kode: 'ZZ', nama: '<img src=x onerror=alert(1)>', n: 7, ip: 1 }] });
w.snPetaSerangan(24);
cek('XSS: nama negara berbahaya di-escape', !w.document.querySelector('#petaTop img') && /&lt;img/.test(w.document.getElementById('petaTop').innerHTML));
w = jalan('en', true, { jam: 24, total: 0, tak_tahu: 0, negara: [] });
w.snPetaSerangan(24);
cek('tanpa data: pesan kosong tampil, peta disembunyikan', w.document.getElementById('petaKosong').style.display !== 'none' && w.document.getElementById('petaSerangan').style.display === 'none');
w = jalan('en', false, DATA);
w.snPetaSerangan(24);
cek('world.json gagal dimuat: pesan jelas, daftar negara tetap tampil', /World map file is not available/.test(w.document.getElementById('petaKosong').textContent) && /United States/.test(w.document.getElementById('petaTop').textContent));
const atas = html.slice(html.indexOf('id="donutJenis"'), html.indexOf('class="sn-tabs"', html.indexOf('id="donutJenis"')));
cek('kartu System Information diganti peta (tidak ada #snSys, ada #petaSerangan)', !/id="snSys"/.test(html) && /id="petaSerangan"/.test(atas));
cek('tidak ada pemanggilan get_sysinfo / snSysMuat di UI', !/get_sysinfo|snSysMuat/.test(script));
cek('peta dimuat bersama donut di snGrafik', /snJenisSerangan\(jam\);\s*snPetaSerangan\(jam\);/.test(script));
console.log('\nRINGKAS: ' + gagal + ' gagal'); process.exit(gagal ? 1 : 0);
