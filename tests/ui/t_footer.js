// Uji footer hak cipta: teks, tautan ZySens ke https://zysens.com (tab baru, rel aman), tidak ada "-" yatim.
// Pakai: node t_footer.js <index.html>
const fs = require('fs');
const { JSDOM } = require('jsdom');
const html = fs.readFileSync(process.argv[2], 'utf8');
const foot = html.match(/<div class="sn-mfoot">[\s\S]*?<\/div>/)[0];
const d = new JSDOM(foot).window.document;
let gagal = 0;
const cek = (n, k, x) => { console.log((k ? '  LULUS ' : '  GAGAL ') + n + (k ? '' : '  -> ' + x)); if (!k) gagal++; };
const kiri = d.querySelector('.sn-mfoot').firstElementChild;
cek('pojok kiri bawah berisi "Copyright © 2026 ZySens Labs"', kiri.textContent.trim() === 'Copyright © 2026 ZySens Labs', kiri.textContent);
const a = kiri.querySelector('a');
cek('hanya kata "ZySens" yang menjadi tautan ke https://zysens.com', a && a.textContent === 'ZySens' && a.getAttribute('href') === 'https://zysens.com', a && a.outerHTML);
cek('tautan dibuka di tab baru dengan rel noopener noreferrer', a.getAttribute('target') === '_blank' && /noopener/.test(a.getAttribute('rel')) && /noreferrer/.test(a.getAttribute('rel')));
cek('tidak ada lagi elemen #stUmur yang selalu "-"', !/id="stUmur"/.test(html));
cek('Server IP tetap di pojok kanan', /id="stIP"/.test(foot) && foot.indexOf('stCopy') < foot.indexOf('stIP'));
console.log('\nRINGKAS: ' + gagal + ' gagal'); process.exit(gagal ? 1 : 0);
