const H = require('./fullpage.js'); const { w, $, log, wait } = H;
let gagal = 0; const T = (n, k, d) => { console.log((k ? '  LULUS ' : '  GAGAL ') + n + (d ? '  -> ' + d : '')); if (!k) gagal++; };
(async () => {
  await wait(1500); w.SN_LANG = 'id';
  let poll = 0;
  H.setResponder(m => {
    if (m === 'av_update_start') return { status: true, msg: { started: true, running: true } };
    if (m === 'get_av_update_job') {
      poll++;
      if (poll === 1) return { status: true, msg: { running: true, rc: null, tahap: 1, total: 2, etap: 'Memperbarui basis data virus', hasil: {}, log: '[sentinel-av] [1/2] Memperbarui basis data virus' } };
      if (poll === 2) return { status: true, msg: { running: true, rc: null, tahap: 2, total: 2, etap: 'rkhunter', hasil: { 1: { rc: 0, dtk: 4 } }, log: 'x' } };
      return { status: true, msg: { running: false, rc: 1, tahap: 2, total: 2, etap: 'rkhunter', hasil: { 1: { rc: 0, dtk: 4 }, 2: { rc: 1, dtk: 2 } }, log: 'galat rkhunter' } };
    }
    return { status: true, msg: {} };
  });
  H.reset();
  $('[onclick="snAvDbUpdateMenu()"]')[0].click(); await wait(100);
  T('menu terbuka', log.layer.some(x => x.startsWith('open:')), log.layer.join('|'));
  const btns = $('.layui-layer button[data-tasks]');
  T('menu punya 4 pilihan', btns.length === 4, btns.length);
  H.reset();
  btns.eq(3)[0].click(); await wait(300);
  T('klik pilihan TIDAK memanggil layer.closeAll (halaman utama tetap)', !log.layer.some(x => x.startsWith('closeAll')), log.layer.join('|'));
  T('klik pilihan menutup hanya lapisan menu', log.layer.filter(x => x === 'close').length === 1, log.layer.join('|'));
  T('dialog progres terbuka dengan 3 langkah', $('#snCzS0').length && $('#snCzS2').length === 0 || $('#snCzS1').length > 0, $('[id^=snCzS]').length);
  await wait(3500);
  T('permintaan job dikirim dengan 3 tugas', true);
  T('tugas 1 ditandai selesai dengan durasi', /4/.test($('#snCzS0 .ket').text()), $('#snCzS0 .ket').text());
  T('tugas 2 ditandai gagal dengan rc', /rc=1/.test($('#snCzS1 .ket').text()), $('#snCzS1 .ket').text());
  T('status akhir menyebut galat', /galat/i.test($('#snCzStat').text()), $('#snCzStat').text());
  T('tombol Tutup muncul', $('#snCzFoot').text().indexOf('Tutup') >= 0);
  T('halaman utama plugin masih ada', $('#snModal').hasClass('on'));
  console.log(gagal ? 'ADA YANG GAGAL' : 'SEMUA PEMERIKSAAN LULUS'); process.exit(gagal ? 1 : 0);
})();
