// node t_click.js <html> <indexTab> <indexSub|-1>   -> klik semua elemen ber-onclick di tab/sub itu
const H = require('./fullpage.js'); const { w, $, log, wait } = H;
const ti = +process.argv[3], si = +process.argv[4];
const AY = process.env.AUTOYES === '1';
const SKIP = /snTutup|snBack|location\.|snTop\(|snSub\(|snSub2\(|snWafTab\(|snAvTab\(|snPortTab\(/;
(async () => {
  await wait(1500);
  const top = $('.sn-mtabs span').toArray()[ti]; top.click(); await wait(500);
  const page = $('.sn-page.on');
  if (si >= 0) { const s = page.find('.sn-tabs span').toArray()[si]; if (s) { s.click(); await wait(500); } }
  const scope = (si >= 0) ? page.find('.sn-subpage.on').add(page.find('.sn-subpage.on')) : page;
  let els = (si >= 0 && page.find('.sn-subpage.on').length ? page.find('.sn-subpage.on') : page).find('[onclick]').toArray();
  const out = []; const seen = {};
  for (const el of els) {
    const oc = el.getAttribute('onclick'); if (SKIP.test(oc)) continue;
    const fn = oc.replace(/\(.*$/, ''); seen[fn] = (seen[fn] || 0) + 1; if (seen[fn] > 2) continue;
    const snap = () => $('#snModal').html().length + '|' + $('#snModal .on').length;
    H.reset(); const before = snap();
    let thrown = null; try { el.click(); } catch (e) { thrown = e.message; }
    await wait(AY ? 600 : 250);
    const eff = log.ajax.length + log.layer.length + (snap() !== before ? 1 : 0);
    out.push({ oc: oc.slice(0, 60), txt: $(el).text().trim().slice(0, 22), ajax: log.ajax.slice(), layer: log.layer.slice(0, 2), err: log.errors.concat(thrown ? [thrown] : []).slice(0, 2), eff });
    // tutup dialog sisa
    $('.layui-layer').remove();
  }
  console.log(JSON.stringify({ tab: $(top).text().trim(), sub: si, n: out.length, mati: out.filter(o => !o.eff), galat: out.filter(o => o.err.length), semua: out }));
  process.exit(0);
})();
