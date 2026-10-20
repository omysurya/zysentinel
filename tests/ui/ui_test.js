// Uji logika UI progres Coraza dengan jsdom + jQuery asli dan backend tiruan.
// Kode UI yang diuji diambil langsung dari index.html (bukan salinan).
const fs = require('fs');
const { JSDOM } = require('jsdom');
const html = fs.readFileSync(process.argv[2], 'utf8');
const script = html.match(/<script[^>]*>([\s\S]*?)<\/script>/)[1];
const i = script.indexOf('/* ---------- Modal progres Coraza ----------');
const j = script.indexOf('/* ---------- tab WAF: ZySentinel Rules ---------- */');
if (i < 0 || j < 0) { console.error('blok UI tidak ditemukan'); process.exit(2); }
const k2a = script.indexOf('/* ---------- tab WAF: ZySentinel Rules ---------- */');
const k2b = script.indexOf('/* ---------- WAF: Real-Time Upload Protection');
if (k2a < 0 || k2b < 0) { console.error('blok ZySentinel tidak ditemukan'); process.exit(2); }
const kode = script.slice(i, j) + '\n' + script.slice(k2a, k2b);

let gagal = 0;
function cek(nama, kondisi, info) {
  console.log((kondisi ? '  LULUS ' : '  GAGAL ') + nama + (kondisi ? '' : '  -> ' + info));
  if (!kondisi) gagal++;
}

async function skenario(nama, { lang, eng, skrip, aksi }) {
  console.log('\n== ' + nama);
  const dom = new JSDOM('<body></body>', { runScripts: 'outside-only' });
  const w = dom.window;
  w.$ = require('jquery')(w);
  w.SN_LANG = lang; w.SN_ENG = eng;
  w.__panggil = [];
  const nyata = w.setTimeout.bind(w);
  w.setTimeout = (f) => nyata(f, 2);
  let n = 0;
  w.layer = {
    open: (o) => { const id = ++n; const d = w.document.createElement('div'); d.id = 'layer' + id; d.innerHTML = o.content; w.document.body.appendChild(d); w.__panggil.push('open:' + o.title); return id; },
    close: (id) => { const d = w.document.getElementById('layer' + id); if (d) d.remove(); },
    confirm: (msg, o, yes) => { w.__panggil.push('confirm'); yes(0); },
    msg: () => 0, alert: () => 0,
  };
  w.snEngineMuat = () => w.__panggil.push('snEngineMuat');
  w.snEsc = (t) => String(t).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  w.kosong = (sel, n, teks) => { w.$(sel).html('<tr><td colspan="' + n + '" class="sn-empty">' + teks + '</td></tr>'); };
  w.snWafLencana = () => {};
  w.snCorazaPasang = () => w.__panggil.push('snCorazaPasang');
  const antrean = {};
  for (const k of Object.keys(skrip)) antrean[k] = skrip[k].slice();
  w.snAjax = (method, data, cb) => {
    w.__panggil.push('ajax:' + method + (data && data.job ? '(' + data.job + ')' : ''));
    const kunci = method === 'get_coraza_job' ? 'job_' + data.job : method;
    const q = antrean[kunci];
    if (!q) { throw new Error('tidak ada skrip untuk ' + kunci); }
    const nilai = q.length > 1 ? q.shift() : q[0];
    nyata(() => cb(nilai), 1);
  };
  w.eval(kode);
  aksi(w);
  // tunggu sampai tombol Tutup muncul (alur selesai) atau 8 detik
  const t0 = Date.now();
  while (Date.now() - t0 < 8000) {
    await new Promise(r => nyata(r, 20));
    const foot = w.document.getElementById('snCzFoot');
    if (foot && foot.style.display !== 'none' && foot.innerHTML.trim()) break;
  }
  return w;
}

const baris = (w, n) => {
  const e = w.document.getElementById('snCzS' + n);
  return e ? { ic: e.querySelector('.ic').textContent, ket: e.querySelector('.ket').textContent } : null;
};
const IKON = { wait: '○', run: '⏳', ok: '✔', fail: '✖', skip: '↷', warn: '⚠' };

(async () => {
  const dl = (t, run, rc, log, etap) => ({ job: 'download', running: run, rc, tahap: t, total: 4, etap: etap || '', log: log || '' });
  const bd = (t, run, rc, log, etap) => ({ job: 'build', running: run, rc, tahap: t, total: 8, etap: etap || '', log: log || '' });
  const zi = (run, rc, log) => ({ job: 'zyinstall', running: run, rc, tahap: 0, total: 0, etap: '', log: log || '' });
  const ENGSIAP = (modul, konektor) => ({ nginx_connector: konektor, apache: 'tidak-terpasang', openlitespeed: 'tidak-terpasang', zyrules: true, coraza: { modul } });

  // 1. Siapkan Coraza: aset kosong, modul belum ada -> unduh, compile, pasang ruleset, modul belum dimuat
  let w = await skenario('Siapkan Coraza: aset kosong -> unduh, compile, pasang ruleset, modul belum dimuat', {
    lang: 'id', eng: { coraza: { aset: false, aturan: 0, modul: 'tidak-ada' } },
    skrip: {
      coraza_download: [{ started: true, running: true }],
      job_download: [dl(1, true, null, '[sentinel-waf] [1/4] mencari versi', 'mencari versi CRS'), dl(2, true, null, '', 'mengunduh arsip CRS'), dl(4, false, 0, '[sentinel-waf] aset Coraza siap', 'x')],
      build_coraza: [{ started: true, running: true, job: 'build' }],
      job_build: [bd(2, true, null, 'a', 'memeriksa cache'), bd(5, true, null, 'b', 'compile libcoraza 1.8.0'), bd(8, false, 0, 'selesai: modul Coraza', 'x')],
      install_zyrules: [{ started: true, running: true, job: 'zyinstall' }],
      job_zyinstall: [zi(true, null, 'ruleset'), zi(false, 0, 'ruleset ZySentinel terpasang')],
      get_waf_engine: [ENGSIAP('tersimpan', 'none')],
    },
    aksi: (w) => w.snCorazaPilihAlur(),
  });
  let st = [0, 1, 2, 3, 4].map(n => baris(w, n));
  cek('baris 0 (periksa) selesai', st[0].ic === IKON.ok, JSON.stringify(st[0]));
  cek('baris 1 (unduh aset) selesai', st[1].ic === IKON.ok, JSON.stringify(st[1]));
  cek('baris 2 (compile konektor) selesai', st[2].ic === IKON.ok, JSON.stringify(st[2]));
  cek('baris 3 (pasang ruleset) selesai', st[3].ic === IKON.ok, JSON.stringify(st[3]));
  cek('baris 4 (modul) PERINGATAN, bukan sukses palsu', st[4].ic === IKON.warn && /belum dimuat/.test(st[4].ket), JSON.stringify(st[4]));
  cek('stat menyatakan modul BELUM dimuat', /BELUM dimuat/.test(w.document.getElementById('snCzStat').textContent), w.document.getElementById('snCzStat').textContent);
  cek('bar 100%', w.document.getElementById('snCzBar').style.width === '100%', w.document.getElementById('snCzBar').style.width);
  cek('tombol "Pasang ke nginx..." tersedia', /Pasang ke nginx/.test(w.document.getElementById('snCzFoot').innerHTML), w.document.getElementById('snCzFoot').innerHTML);
  cek('urutan: download -> compile -> pasang ruleset', (() => { const p = w.__panggil.filter(x => /^ajax:(coraza_download|build_coraza|install_zyrules)/.test(x)); return p.join() === 'ajax:coraza_download,ajax:build_coraza,ajax:install_zyrules'; })(), w.__panggil.join());
  cek('TIDAK memanggil set_waf_engine (pilihan engine sudah dihapus)', !w.__panggil.some(x => /set_waf_engine/.test(x)), w.__panggil.join());

  // 2. Aset ada + modul tersimpan: unduh dan compile dilewati
  w = await skenario('Siapkan Coraza: aset ada + modul sudah dibangun -> unduh dan compile dilewati', {
    lang: 'en', eng: { coraza: { aset: true, aturan: 30, versi: 'v4.30.0', modul: 'tersimpan' } },
    skrip: { install_zyrules: [{ started: true, running: true, job: 'zyinstall' }], job_zyinstall: [zi(false, 0, 'ok')], get_waf_engine: [ENGSIAP('tersimpan', 'none')] },
    aksi: (w) => w.snCorazaPilihAlur(),
  });
  st = [0, 1, 2, 3, 4].map(n => baris(w, n));
  cek('baris 1 dan 2 dilewati (skip)', st[1].ic === IKON.skip && st[2].ic === IKON.skip, JSON.stringify([st[1], st[2]]));
  cek('tidak memanggil download/build', !w.__panggil.some(x => /coraza_download|build_coraza/.test(x)), w.__panggil.join());
  cek('teks bahasa Inggris', /NOT loaded/.test(w.document.getElementById('snCzStat').textContent), w.document.getElementById('snCzStat').textContent);

  // 3. Compile gagal: ruleset TIDAK dipasang
  w = await skenario('Siapkan Coraza: compile gagal -> ruleset tidak dipasang', {
    lang: 'id', eng: { coraza: { aset: true, aturan: 30, modul: 'tidak-ada' } },
    skrip: { build_coraza: [{ started: true, running: true, job: 'build' }], job_build: [bd(5, true, null, 'x', 'compile libcoraza'), bd(5, false, 1, 'GALAT: compile libcoraza gagal', 'compile libcoraza')] },
    aksi: (w) => w.snCorazaPilihAlur(),
  });
  st = [0, 1, 2, 3, 4].map(n => baris(w, n));
  cek('baris 2 GAGAL', st[2].ic === IKON.fail, JSON.stringify(st[2]));
  cek('install_zyrules TIDAK dipanggil', !w.__panggil.some(x => /install_zyrules/.test(x)), w.__panggil.join());
  cek('log kegagalan tampil', /GALAT/.test(w.document.getElementById('snCzLog').textContent), w.document.getElementById('snCzLog').textContent);

  // 4. Modul sudah dimuat di nginx: akhir OK
  w = await skenario('Siapkan Coraza: modul sudah dimuat -> semua OK', {
    lang: 'id', eng: { coraza: { aset: true, aturan: 30, modul: 'dimuat' } },
    skrip: { install_zyrules: [{ started: true, running: true, job: 'zyinstall' }], job_zyinstall: [zi(false, 0, 'ok')], get_waf_engine: [ENGSIAP('dimuat', 'coraza')] },
    aksi: (w) => w.snCorazaPilihAlur(),
  });
  st = [3, 4].map(n => baris(w, n));
  cek('baris 4 OK', st[1].ic === IKON.ok, JSON.stringify(st[1]));

  // 5. Compile Konektor: pemetaan tahap n/8 ke baris
  w = await skenario('Compile Konektor: pemetaan tahap n/8 ke baris', {
    lang: 'id', eng: {},
    skrip: { build_coraza: [{ started: true, running: true, job: 'build' }], job_build: [bd(5, true, null, 'm', 'compile libcoraza'), bd(8, false, 0, '[sentinel-waf] selesai', 'simpan')] },
    aksi: (w) => { w.__tengah = null; const asli = w.snCzTickDetail; w.snCzTickDetail = (ui, off, s) => { asli(ui, off, s); if (s.running && s.tahap === 5) w.__tengah = [0,1,2,3,4,5,6,7].map(n => w.document.getElementById('snCzS' + n).querySelector('.ic').textContent); }; w.snCorazaBuild(); },
  });
  cek('di tahap 5: baris 0-3 selesai, 4 berjalan, 5-7 menunggu', JSON.stringify(w.__tengah) === JSON.stringify([IKON.ok, IKON.ok, IKON.ok, IKON.ok, IKON.run, IKON.wait, IKON.wait, IKON.wait]), JSON.stringify(w.__tengah));

  // 6. Tab ZySentinel Rules
  async function zy(nama, lang, resp) {
    console.log('\n== ' + nama);
    const dom = new JSDOM('<body><div id="zyLegacy"></div><span id="zyBadge"></span><div id="zyInfo"></div><table><tbody id="tbZyModul"></tbody></table><table><tbody id="tbZySet"></tbody></table><table><tbody id="tbZyList"></tbody></table><table><tbody id="tbZyLog"></tbody></table><div id="zyListTabs"><span class="on">a</span><span>b</span></div><input id="zyListVal"></body>', { runScripts: 'outside-only' });
    const w = dom.window;
    w.$ = require('jquery')(w); w.SN_LANG = lang; w.__panggil = [];
    w.snEsc = (t) => String(t).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    w.kosong = (sel, n, teks) => { w.$(sel).html('<tr><td colspan="' + n + '" class="sn-empty">' + teks + '</td></tr>'); };
    w.snProgress = () => 1; w.snCzModal = () => ({}); w.snCzRun = () => {};
    w.layer = { msg: (m) => w.__panggil.push('msg:' + m), confirm: (m, o, y) => { w.__panggil.push('confirm'); y(0); }, close: () => 0 };
    w.snAjax = (method, data, cb) => { w.__panggil.push(method + (data && data.name ? ':' + data.name + '=' + data.state : '') + (data && data.key ? ':' + data.key + '=' + data.value : '')); setTimeout(() => cb(resp[method] !== undefined ? resp[method] : {}), 1); };
    w.eval(kode);
    w.snZyMuat();
    await new Promise(r => setTimeout(r, 80));
    return w;
  }
  const ZYST = { terpasang: true, tersusun: true, mode: 'block', engine: { nginx: 'coraza', apache: 'modsecurity', openlitespeed: 'tidak-terpasang', owasp: 'ada' }, legacy: { legacy: 'ya' },
    pengaturan: { bot_level: 2, strict: 0, fallback: 1, paranoia: 1, threshold: 5 }, audit_log: '/www/wwwlogs/zysentinel_waf_audit.log', main: '/x/main.conf',
    modul: { sensitive_files: { aktif: true }, webshell: { aktif: true }, spam: { aktif: true }, scanner: { aktif: false }, bot: { aktif: true }, lfi_args: { aktif: true } } };
  w = await zy('Tab ZySentinel Rules (ID)', 'id', { get_zyrules: ZYST, get_waf_lists: { ip_black: ['203.0.113.9', '198.51.100.0/24'], ip_white: [], url_black: ['^/x/'], url_white: [] },
    get_waf_logs: { ada: true, kejadian: [{ waktu: '2026/10/20 02:23:00', ip: '127.0.0.1', metode: 'GET', uri: '/.env', status: 403, rule_id: '8000102', pesan: 'ZySentinel: akses berkas lingkungan', zysentinel: true }, { waktu: 't', ip: '<img>', metode: 'GET', uri: '/<script>', status: 403, rule_id: '942100', pesan: 'SQLi', zysentinel: false }] } });
  cek('lencana: memblokir', /memblokir/.test(w.document.getElementById('zyBadge').textContent), w.document.getElementById('zyBadge').textContent);
  cek('6 modul tampil, scanner off', w.$('#tbZyModul tr').length === 6 && /off/.test(w.$('#tbZyModul tr').eq(3).text()), w.$('#tbZyModul').text());
  cek('tombol modul scanner memanggil On', /snZyModul\('scanner','on'\)/.test(w.$('#tbZyModul').html()), w.$('#tbZyModul').html().slice(0, 100));
  cek('pengaturan bot_level bernilai 2 terpilih', w.$('#tbZySet select').eq(0).val() === '2', w.$('#tbZySet select').eq(0).val());
  cek('info menyebut Apache ModSecurity dan Coraza', /ModSecurity/.test(w.$('#zyInfo').text()) && /Coraza/.test(w.$('#zyInfo').text()), w.$('#zyInfo').text());
  cek('banner migrasi Lua tampil', w.$('#zyLegacy').is(':visible') || w.$('#zyLegacy').css('display') !== 'none', w.$('#zyLegacy').html().slice(0, 80));
  cek('daftar ip_black menampilkan 2 entri', w.$('#tbZyList tr').length === 2, w.$('#tbZyList').text());
  cek('log: 2 kejadian, badge ZY untuk aturan ZySentinel', w.$('#tbZyLog tr').length === 2 && /ZY/.test(w.$('#tbZyLog tr').eq(0).text()), w.$('#tbZyLog').text());
  cek('log: HTML di URI di-escape (tidak ada tag mentah)', w.$('#tbZyLog img, #tbZyLog script').length === 0, w.$('#tbZyLog').html().slice(0, 200));
  w.snZyModul('scanner', 'on'); w.snZySetting('bot_level', '3');
  await new Promise(r => setTimeout(r, 20));
  cek('klik modul dan pengaturan memanggil endpoint yang benar', w.__panggil.includes('set_zy_module:scanner=on') && w.__panggil.includes('set_zy_setting:bot_level=3'), w.__panggil.join());
  w = await zy('Tab ZySentinel: engine belum ada, tanpa Lua (EN)', 'en', { get_zyrules: Object.assign({}, ZYST, { terpasang: false, tersusun: false, legacy: { legacy: 'tidak' }, engine: { nginx: 'none', apache: 'tidak-terpasang', openlitespeed: 'tidak-terpasang', owasp: 'hilang' } }), get_waf_lists: { ip_black: [] }, get_waf_logs: { ada: false, kejadian: [] } });
  cek('lencana: not installed', /not installed/.test(w.document.getElementById('zyBadge').textContent), w.document.getElementById('zyBadge').textContent);
  cek('banner migrasi disembunyikan', w.$('#zyLegacy').css('display') === 'none', w.$('#zyLegacy').css('display'));
  cek('log kosong menjelaskan log belum dibuat', /not created/.test(w.$('#tbZyLog').text()), w.$('#tbZyLog').text());

  console.log('\n' + (gagal ? gagal + ' PEMERIKSAAN GAGAL' : 'SEMUA PEMERIKSAAN LULUS'));
  process.exit(gagal ? 1 : 0);
})();
