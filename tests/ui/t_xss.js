const H = require('./fullpage.js'); const { w, $, log, wait } = H;
let gagal = 0; const T = (n, k) => { console.log((k ? '  LULUS ' : '  GAGAL ') + n); if (!k) gagal++; };
(async () => {
  await wait(1500); w.__xss = 0;
  const bad = '<img src=x onerror="window.__xss=1">';
  const badq = "');window.__xss=1;//";
  H.setResponder(m => {
    if (m === 'get_vhost_quarantine') return { status: true, msg: [{ time_str: bad, signature: bad, dest_file: bad, size_str: bad, uploader_ip: bad, vhost: badq, meta_file: badq }] };
    if (m === 'get_vhost_stat') return { status: true, msg: { vhost: [{ host: bad, req: 1, bytes: 1 }, { host: badq, req: 1, bytes: 1 }], baris: [] } };
    if (m === 'get_review') return { status: true, msg: { antrian: [{ ip: '1.2.3.4', status: 'tunggu', skor: 100, umur: 10, alasan: bad, kode: 'ID', negara: 'x' }], hitungan: { tunggu: 1 } } };
    return { status: true, msg: [] };
  });
  w.snUploadQuarantineModal(badq); await wait(200);
  T('modal karantina: tidak ada elemen img injeksi', $('.layui-layer img[src="x"]').length === 0);
  const btn = $('.layui-layer .sn-btn.ok')[0]; if (btn) { btn.click(); await wait(100); }
  T('modal karantina: onclick tidak lolos dari string JS', w.__xss === 0);
  w.snRevMuat('tunggu'); await wait(200);
  T('antrean review tampil 1 baris (bug m[i] teratasi)', $('#tbRev tr').length === 1 && $('#revKet').text().indexOf('1') !== -1, $('#revKet').text());
  T('antrean review: alasan di-escape', $('#tbRev img').length === 0);
  w.snVhostMuat(); await wait(200);
  T('vhost: host di-escape', $('#tbVhost img, #top-dash img[src="x"]').length === 0);
  console.log(gagal ? 'ADA YANG GAGAL' : 'SEMUA PEMERIKSAAN LULUS'); process.exit(gagal ? 1 : 0);
})();
