// Uji nama halaman telemetri = IP publik server (bukan teks tetap). Kode diambil dari index.html, backend ditiru.
// Pakai: node t_telemetry.js <index.html>
const fs = require('fs');
const { JSDOM } = require('jsdom');
const html = fs.readFileSync(process.argv[2], 'utf8');
const script = html.match(/<script[^>]*>([\s\S]*?)<\/script>/)[1];
const i = script.indexOf('var SN_TELEMETRY_ENABLED'), j = script.indexOf('/* Sanitizer HTML entity');
const kode = script.slice(i, j);
let gagal = 0;
const cek = (n, k, x) => { console.log((k ? '  LULUS ' : '  GAGAL ') + n + (k ? '' : '  -> ' + x)); if (!k) gagal++; };
function jalan(resp, host) {
  const dom = new JSDOM('<body></body>', { runScripts: 'outside-only', url: 'https://' + host + ':15960/' });
  const w = dom.window;
  w.SN_LANG = 'en'; w.setTimeout = (f) => f(); w.$ = () => ({ attr() { return this; }, text() { return this; }, html() { return this; } });
  w.snAjax = (m, d, cb) => cb(resp);
  w.eval(kode);
  w.snInitTelemetry();
  return w;
}
const cfg = (w) => Array.from(w.dataLayer).find((a) => a[0] === 'config');
let w = jalan({ enabled: true, server_ip: '103.127.99.26' }, 'panel.contoh.id');
cek('page_title = IP publik dari server, bukan nama halaman tetap', cfg(w) && cfg(w)[2].page_title === '103.127.99.26', cfg(w));
cek('tidak ada lagi teks "ZySentinel Dashboard" di konfigurasi telemetri', !JSON.stringify(Array.from(w.dataLayer)).includes('ZySentinel Dashboard'));
w = jalan({ enabled: true }, 'panel.contoh.id');
cek('tanpa server_ip: jatuh ke hostname', cfg(w)[2].page_title === 'panel.contoh.id', cfg(w));
w = jalan({ enabled: true, server_ip: '<script>x</script>' }, '1.2.3.4');
cek('server_ip yang bukan IPv4 ditolak (jatuh ke hostname)', cfg(w)[2].page_title === '1.2.3.4', cfg(w));
w = jalan({ enabled: false, server_ip: '103.127.99.26' }, 'x');
cek('telemetri nonaktif: tidak ada yang dikirim', !w.dataLayer || w.dataLayer.length === 0);
console.log('\nRINGKAS: ' + gagal + ' gagal'); process.exit(gagal ? 1 : 0);
