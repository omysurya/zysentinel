// Uji kolom Action CRUD: Port Control (Inbound/Outbound), Blocked IPs, Learned Rules. Kode dari index.html,
// backend ditiru. Pakai: node t_crud.js <index.html>
const fs = require('fs');
const { JSDOM } = require('jsdom');
const html = fs.readFileSync(process.argv[2], 'utf8');
const script = html.match(/<script[^>]*>([\s\S]*?)<\/script>/)[1];
const potong = (a, b) => { const i = script.indexOf(a), j = script.indexOf(b, i + 1); if (i < 0 || j < 0) throw new Error(a); return script.slice(i, j); };
const kode = potong('function snPortRender(direction){', 'function snPortToggle(ruleId){') + potong('function snPortDelete(ruleId, port){', 'function snPortToggleGlobal(){')
  + potong('function snPortCari(id){', 'function snFw(aksi){') + potong('/* ---------- blocked IPs ---------- */', '/* ---------- monitored sites ---------- */')
  + potong('/* ---------- aturan yang dipelajari dari keputusan operator ---------- */', '/* ---------- IP timeline ---------- */');
let gagal = 0;
const cek = (n, k, x) => { console.log((k ? '  LULUS ' : '  GAGAL ') + n + (k ? '' : '  -> ' + x)); if (!k) gagal++; };
const PORT = { config: { detected_ssh_port: 2244, detected_panel_port: 15960, inbound: [
  { id: 'in-ssh', port: '2244', protocol: 'tcp', action: 'ACCEPT', source: '0.0.0.0/0', remark: 'SSH', system: true, enabled: true },
  { id: 'in-170000-ab12', port: '8080', protocol: 'tcp', action: 'ACCEPT', source: '10.0.0.0/8', remark: 'API', system: false, enabled: true }],
  outbound: [{ id: 'out-170000-cd34', port: '25', protocol: 'tcp', action: 'DROP', dest: '0.0.0.0/0', remark: 'SMTP', system: false, enabled: true }] } };
function jalan(lang) {
  const w = new JSDOM('<body><table><tbody id="tbPortRules"></tbody></table><table><tbody id="tbBans"></tbody></table><div id="lrnInfo"></div><span id="lrnToggleTxt"></span><table><tbody id="tbLearned"></tbody></table></body>', { runScripts: 'dangerously' }).window;
  w.$ = require('jquery')(w); w.SN_LANG = lang; w.SN_PORT_DATA = PORT; w.SN_PORT_CUR_TAB = 'inbound';
  w.__calls = []; w.__msg = []; w.__open = null; w.__prompt = null;
  w.snEsc = (t) => String(t == null ? '' : t).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  w.kosong = (s, n, t) => w.$(s).html('<tr><td>' + t + '</td></tr>'); w.kelasSkor = () => 'x'; w.waktu = (t) => 'T' + t;
  w.snSpinBtn = () => () => {}; w.snProgress = () => 1; w.snPortLoad = () => w.__calls.push(['snPortLoad']); w.snFwMuat = () => 0;
  w.layer = { msg: (m) => w.__msg.push(m), close: () => 0, confirm: (m, o, yes) => yes(1),
    open: (o) => { w.__open = o; w.$('body').append('<div id="lay">' + o.content + '</div>'); if (o.success) o.success(); },
    prompt: (o, yes) => { w.__prompt = o; w.__yesPrompt = yes; } };
  w.snAjax = (m, d, cb) => { w.__calls.push([m, d]); cb(m === 'get_bans' ? { aktif: [{ ip: '203.0.113.9', kind: 'scanner', score: 160, offenses: 1, sisa: 1800, reason: 'x' }], set_ban: [] }
    : m === 'get_learned' ? { enabled: true, enforce: 1, lessons: [{ id: 'a1b2c3d4', aksi: 'B', kind: 'scanner', path: '/probe.php', ua: 'evilscan', sources: ['1.2.3.4'], created: 1, hits: 0 }] } : 'ok'); };
  w.eval(kode);
  return w;
}
const kirim = (w) => w.__calls.filter((c) => /update_port_rule|add_port_rule|ban_ip|learned_add|learned_update/.test(c[0])).pop();
// ---- Port Control
let w = jalan('id'); const $ = w.$;
w.snPortRender('inbound');
let trs = w.document.querySelectorAll('#tbPortRules tr');
cek('setiap aturan punya tombol Ubah dan Hapus di kolom Action', [...trs].every((tr) => tr.cells[8].querySelectorAll('.sn-btn').length === 2 && /Ubah/.test(tr.cells[8].textContent) && /Hapus/.test(tr.cells[8].textContent)), trs[0].cells[8].innerHTML);
cek('baseline: Hapus nonaktif dengan penjelasan (tidak memanggil apa pun)', !trs[0].cells[8].querySelectorAll('.sn-btn')[1].getAttribute('onclick') && /baseline/.test(trs[0].cells[8].querySelectorAll('.sn-btn')[1].getAttribute('title')));
cek('aturan kustom: Hapus memanggil snPortDelete', /snPortDelete\('in-170000-ab12'/.test(trs[1].cells[8].querySelectorAll('.sn-btn')[1].getAttribute('onclick')));
trs[1].cells[8].querySelector('.sn-btn').click();
cek('Ubah aturan kustom: modal terisi data lama (port, sumber, keterangan), arah dikunci', w.$('#modPortNum').val() === '8080' && w.$('#modPortNet').val() === '10.0.0.0/8' && w.$('#modPortRemark').val() === 'API' && w.$('#modPortDir').prop('disabled') && /Ubah Aturan/.test(w.__open.title));
w.$('#modPortNum').val('8081'); w.__open.yes(1);
let c = kirim(w);
cek('Simpan: update_port_rule dengan id, arah, port baru, sumber', c && c[0] === 'update_port_rule' && c[1].id === 'in-170000-ab12' && c[1].direction === 'inbound' && c[1].port === '8081' && c[1].source === '10.0.0.0/8', JSON.stringify(c));
w.$('#lay').remove(); trs[0].cells[8].querySelector('.sn-btn').click();
cek('Ubah baseline: port/protokol/aksi/alamat terkunci, hanya keterangan bisa diubah, ada penjelasan', w.$('#modPortNum').prop('disabled') && w.$('#modPortNet').prop('disabled') && w.$('#modPortAction').prop('disabled') && !w.$('#modPortRemark').prop('disabled') && /Aturan baseline/.test(w.$('#lay').text()));
w.$('#lay').remove(); w.snPortRender('outbound'); w.document.querySelector('#tbPortRules .sn-btn').click(); w.__open.yes(1); c = kirim(w);
cek('Ubah outbound: kolom dest dikirim', c[0] === 'update_port_rule' && c[1].dest === '0.0.0.0/0' && c[1].direction === 'outbound', JSON.stringify(c));
w.$('#lay').remove(); w.snPortRuleModal(); w.$('#modPortNum').val('9000'); w.__open.yes(1); c = kirim(w);
cek('+ Tambah tetap memanggil add_port_rule', c[0] === 'add_port_rule' && c[1].port === '9000' && !c[1].id, JSON.stringify(c));
w.$('#lay').remove(); w.snPortRuleModal('tidak-ada');
cek('Ubah id yang hilang: pesan, tanpa modal', /tidak ditemukan/.test(w.__msg.pop()));
// ---- Blocked IPs
w.snBans(); const tb = w.document.querySelector('#tbBans tr');
cek('Blocked IPs: tombol Ubah (durasi) dan Buka Blokir', tb.cells[6].querySelectorAll('.sn-btn').length === 2 && /Ubah/.test(tb.cells[6].textContent) && /Buka Blokir/.test(tb.cells[6].textContent));
tb.cells[6].querySelector('.sn-btn').click();
cek('Ubah durasi: prompt berisi sisa waktu sekarang (1800) dengan tombol berlabel', w.__prompt.value === '1800' && JSON.stringify(w.__prompt.btn) === '["Simpan","Batal"]');
w.__yesPrompt('59', 1); cek('durasi < 60 ditolak', /minimal 60/.test(w.__msg.pop()));
w.__yesPrompt('7200', 1); c = kirim(w);
cek('durasi valid: ban_ip dengan secs baru', c[0] === 'ban_ip' && c[1].ip === '203.0.113.9' && c[1].secs === '7200', JSON.stringify(c));
// ---- Learned
w.snLearned(null, true); const lr = w.document.querySelector('#tbLearned tr');
cek('Learned: tombol Ubah dan Cabut', /Ubah/.test(lr.lastChild.textContent) && /Cabut/.test(lr.lastChild.textContent));
lr.lastChild.querySelector('.sn-btn').click();
cek('Ubah: modal terisi (aturan, kategori, path, UA)', w.$('#lrnAksi').val() === 'B' && w.$('#lrnKind').val() === 'scanner' && w.$('#lrnPath').val() === '/probe.php' && w.$('#lrnUa').val() === 'evilscan');
w.$('#lrnPath').val('/backdoor.php'); w.__open.yes(1); c = kirim(w);
cek('Simpan ubah: learned_update dengan id dan pola baru', c[0] === 'learned_update' && c[1].id === 'a1b2c3d4' && c[1].path === '/backdoor.php' && c[1].aksi_l === 'B', JSON.stringify(c));
w.$('#lay').remove(); w.snLearnedModal(); w.$('#lrnAksi').val('A'); w.$('#lrnUa').val('FriendlyCrawler/1.0'); w.__open.yes(1); c = kirim(w);
cek('+ Tambah: learned_add tanpa id', c[0] === 'learned_add' && !c[1].id && c[1].aksi_l === 'A' && c[1].ua === 'FriendlyCrawler/1.0', JSON.stringify(c));
w.$('#lay').remove(); w.snLearnedModal(); w.__open.yes(1);
cek('tambah tanpa path dan UA ditolak di UI', /Isi path/.test(w.__msg.pop()));
cek('tombol "+ Tambah Aturan" ada di toolbar Learned', /onclick="snLearnedModal\(\)"/.test(html));
w = jalan('en'); w.snPortRender('inbound');
cek('bahasa Inggris: Edit / Delete', /Edit/.test(w.document.querySelector('#tbPortRules tr').cells[8].textContent) && /Delete/.test(w.document.querySelector('#tbPortRules tr').cells[8].textContent));
console.log('\nRINGKAS: ' + gagal + ' gagal'); process.exit(gagal ? 1 : 0);
