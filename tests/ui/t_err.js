const H = require('./fullpage.js'); const { w, $, log, wait } = H;
let gagal = 0; const T = (n, k, d) => { console.log((k ? '  LULUS ' : '  GAGAL ') + n + (d ? '  -> ' + d : '')); if (!k) gagal++; };
const lastLayer = () => log.layer.filter(x => !/^close/.test(x));
(async () => {
  await wait(1500);
  w.SN_LANG = 'id';
  for (const [mode, kata] of [['neterr', 'tidak terjangkau'], ['timeout', 'tidak menjawab'], ['http500', 'Galat di server'], ['html', 'tidak valid']]) {
    H.setResponder(() => mode); H.reset();
    let hasil = 'belum';
    w.snAjax('ban_ip', { ip: '1.2.3.4' }, r => { hasil = r; }, null, $('#snModal .sn-btn')[0]);
    await wait(100);
    const dlg = log.layer.filter(x => x.startsWith('alert:'));
    T('aksi pengguna + ' + mode + ' -> dialog berisi "' + kata + '"', hasil === null && dlg.length === 1 && dlg[0].includes(kata), dlg[0] || JSON.stringify(log.layer));
    T('  callback tetap dipanggil dengan null (tombol tidak macet)', hasil === null);
  }
  // penolakan server
  H.setResponder(() => ({ status: false, msg: 'IP tidak valid: 999.1.1.1' })); H.reset();
  let r2 = 'belum'; w.snAjax('ban_ip', { ip: '999.1.1.1' }, r => { r2 = r; }, null, $('#snModal .sn-btn')[0]); await wait(100);
  T('penolakan server (status:false) -> dialog dengan alasan', log.layer.some(x => x.startsWith('alert:') && x.includes('IP tidak valid')), log.layer.join(' | '));
  // senyap: tidak ada dialog; spanduk muncul pada kegagalan ke-2
  H.setResponder(() => 'neterr'); H.reset(); w.SN_FAIL_STREAK = 0; $('#snConnBanner').remove();
  for (let i = 0; i < 3; i++) { w.snAjax('get_status', {}, () => { }, null, null, true); await wait(50); }
  T('penyegaran senyap gagal x3 -> tidak ada dialog', !log.layer.some(x => x.startsWith('alert:')));
  T('penyegaran senyap gagal x3 -> spanduk koneksi tampil', $('#snConnBanner').length === 1, $('#snConnBanner').text().slice(0, 80));
  H.setResponder(() => ({ status: true, msg: {} })); w.snAjax('get_status', {}, () => { }, null, null, true); await wait(50);
  T('permintaan berikutnya berhasil -> spanduk hilang', $('#snConnBanner').length === 0);
  // galat saat menggambar
  H.setResponder(() => ({ status: true, msg: {} })); H.reset();
  w.snAjax('ban_ip', {}, () => { throw new Error('render rusak'); }, null, $('#snModal .sn-btn')[0]); await wait(100);
  T('callback melempar galat -> dialog "Gagal menampilkan hasil"', log.layer.some(x => x.startsWith('alert:') && x.includes('Gagal menampilkan')), log.layer.join('|'));
  // gabung permintaan get_ kembar
  H.setResponder(() => ({ status: true, msg: {} })); H.reset(); let n = 0;
  w.snAjax('get_waf', {}, () => n++); w.snAjax('get_waf', {}, () => n++); await wait(100);
  T('dua get_waf bersamaan -> 1 permintaan, 2 callback', log.ajax.filter(m => m === 'get_waf').length === 1 && n === 2, 'ajax=' + log.ajax.length + ' cb=' + n);
  // aksi tulis tidak digabung
  H.reset(); w.snAjax('ban_ip', { ip: '1.1.1.1' }, () => { }); w.snAjax('ban_ip', { ip: '1.1.1.1' }, () => { }); await wait(100);
  T('dua ban_ip -> 2 permintaan (tulis tidak digabung)', log.ajax.length === 2);
  // PANIC
  H.setResponder(m => m === 'get_panic' ? { status: true, msg: { aktif: false, ports: '80,443' } } : { status: true, msg: 'ok' }); H.reset();
  $('#btnPanicToggle')[0].click(); await wait(200);
  T('tombol PANIC (nonaktif) -> dialog konfirmasi ketik PANIC', log.layer.some(x => x.startsWith('open:') && x.includes('Panik')), log.layer.join('|'));
  H.setResponder(m => m === 'get_panic' ? { status: true, msg: { aktif: true } } : { status: true, msg: 'ok' }); H.reset();
  $('.layui-layer').remove(); $('#btnPanicToggle')[0].click(); await wait(200);
  T('tombol PANIC (aktif) -> konfirmasi matikan', log.layer.some(x => x.startsWith('confirm:') && x.includes('Matikan')), log.layer.join('|'));
  console.log(gagal ? '\nADA YANG GAGAL: ' + gagal : '\nSEMUA PEMERIKSAAN LULUS'); process.exit(gagal ? 1 : 0);
})();
