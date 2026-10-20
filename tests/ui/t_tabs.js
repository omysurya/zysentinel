const H = require('./fullpage.js'); const { w, $, log, wait } = H;
function cnt(a){ const c={}; a.forEach(m=>c[m]=(c[m]||0)+1); return JSON.stringify(c); }
(async () => {
  await wait(1800); H.reset();
  const top = $('.sn-mtabs span').toArray();
  for (const t of top) {
    H.reset(); t.click(); await wait(700);
    const nm = $(t).text().trim();
    console.log('\n== TAB ' + nm + ': ' + log.ajax.length + ' permintaan ' + cnt(log.ajax) + (log.errors.length ? '  GALAT:' + JSON.stringify(log.errors.slice(0,3)) : ''));
    const page = $('.sn-page.on');
    const subs = page.find('.sn-tabs span').toArray();
    for (const s of subs) {
      H.reset(); s.click(); await wait(600);
      console.log('   - sub ' + $(s).text().trim().slice(0,28) + ': ' + log.ajax.length + ' ' + cnt(log.ajax) + (log.errors.length ? '  GALAT:' + JSON.stringify(log.errors.slice(0,3)) : ''));
    }
  }
  process.exit(0);
})();
