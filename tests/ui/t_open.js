const H = require('./fullpage.js'); const { w, $, log, wait } = H;
(async () => {
  await wait(1800);
  const open = log.ajax.slice();
  const cnt = {}; open.forEach(m => cnt[m] = (cnt[m] || 0) + 1);
  console.log('Permintaan saat dialog dibuka (' + open.length + '):', JSON.stringify(cnt));
  console.log('Galat JS:', log.errors.length, log.errors.slice(0, 5));
  const tabs = $('.sn-mtabs span');
  console.log('Tab teratas:', tabs.map((i, e) => $(e).text().trim() + '=' + ($(e).attr('onclick') || '')).get().join(' | '));
  process.exit(0);
})();
