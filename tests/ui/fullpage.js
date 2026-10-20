// Muat index.html asli utuh di jsdom dengan backend tiruan; catat permintaan dan jejak umpan balik.
const fs = require('fs'); const { JSDOM, VirtualConsole } = require('jsdom');
const FILE = process.argv[2]; const MODE = process.argv[3] || 'audit'; // audit | open | errors
const html = fs.readFileSync(FILE, 'utf8');
const jq = fs.readFileSync(require.resolve('jquery/dist/jquery.js'), 'utf8');
const log = { ajax: [], layer: [], errors: [] };
const vc = new VirtualConsole();
vc.on('jsdomError', e => log.errors.push('jsdomError: ' + (e.detail && e.detail.message || e.message)));
vc.on('error', m => log.errors.push('console.error: ' + String(m).slice(0, 160)));
function U(){ const f=function(){}; return new Proxy(f,{
  get(t,k){ if(k===Symbol.toPrimitive) return ()=>0; if(k==='length') return 0; if(k==='toString'||k==='toJSON'||k==='valueOf') return ()=>'';
    if(['forEach','map','filter','sort','slice','concat','reduce','some','every','find','indexOf','join'].includes(k)) return ()=>[];
    if(k===Symbol.iterator) return function*(){}; if(typeof k==='symbol') return undefined; return U(); },
  apply(){ return U(); }, has(){ return false; }, ownKeys(){ return []; }, getOwnPropertyDescriptor(){ return undefined; } }); }
const FIX = (() => { try { return JSON.parse(fs.readFileSync(process.env.FIX || '../audit/fixtures.json', 'utf8')); } catch (e) { return {}; } })();
let responder = (method, data) => (FIX[method] ? JSON.parse(JSON.stringify(FIX[method])) : { status: true, msg: method.startsWith('get_') ? U() : '' + method + ' ok' });
const AUTOYES = process.env.AUTOYES === '1';
const script = (html.match(/<script[^>]*>([\s\S]*?)<\/script>/) || [])[1];
const markup = html.replace(/<script[^>]*>[\s\S]*?<\/script>/, '');
const dom = new JSDOM('<!doctype html><html><body><div id="request_token_head" token="t"></div>' + markup + '</body></html>', {
  url: 'http://localhost/', runScripts: 'dangerously', pretendToBeVisual: true, virtualConsole: vc,
  beforeParse(w) {
    let n = 100;
    const rec = (k) => function (...a) { log.layer.push(k + ':' + (typeof a[0] === 'string' ? a[0].replace(/<[^>]+>/g, '').slice(0, 70) : typeof a[0])); return ++n; };
    const body = () => w.document.body;
    const openL = function (o) { const i = ++n; log.layer.push('open:' + (o && o.title || '')); const d = w.document.createElement('div'); d.className = 'layui-layer'; d.id = 'layui-layer' + i; d.innerHTML = (o && typeof o.content === 'string') ? o.content : ''; body().appendChild(d); if (o && o.success) { try { o.success($(d), i); } catch (e) {} } if (AUTOYES && o && o.yes) { setTimeout(() => { try { o.yes(i, $(d)); } catch (e) { log.errors.push('yes: ' + e.message); } }, 20); } return i; };
    const confirmL = function (m, o, yes) { log.layer.push('confirm:' + String(m).replace(/<[^>]+>/g, '').slice(0, 60)); if (typeof o === 'function') { yes = o; } if (AUTOYES && yes) { setTimeout(() => { try { yes(++n); } catch (e) { log.errors.push('confirm-yes: ' + e.message); } }, 20); } return ++n; };
    w.layer = { msg: rec('msg'), alert: rec('alert'), confirm: confirmL, open: openL, close: function (i) { log.layer.push('close'); const e = w.document.getElementById('layui-layer' + i); if (e) e.remove(); }, closeAll: rec('closeAll'), load: rec('load'), tips: rec('tips'), prompt: rec('prompt'), tab: rec('tab'), photos: rec('photos') };
    w.getCookie = () => 't';
    w.addEventListener('error', e => log.errors.push('JS: ' + e.message + ' @' + (e.lineno || '?')));
    w.__setResponder = f => { responder = f; };
    w.$ajaxHook = true;
  }
});
const w = dom.window;
w.eval(jq);
const $ = w.$;
const realAjax = $.ajax;
$.ajax = function (o) {
  const m = (o.data && o.data.method) || (o.url.match(/[?&]s=([\w]+)/) || [])[1];
  log.ajax.push(m);
  const r = responder(m, o.data);
  const d = $.Deferred();
  setTimeout(() => {
    try{
    if (r === 'neterr') { o.error && o.error({ status: 0, statusText: 'error' }, 'error', ''); }
    else if (r === 'timeout') { o.error && o.error({ status: 0, statusText: 'timeout' }, 'timeout', 'timeout'); }
    else if (r === 'http500') { o.error && o.error({ status: 500, responseText: 'Traceback (most recent call last): boom' }, 'error', 'Internal Server Error'); }
    else if (r === 'html') { o.success && o.success('<html>login</html>'); }
    else { try{ o.success && o.success(r); }catch(e){ log.errors.push('callback '+m+': '+e.message); } }
    }catch(e){ log.errors.push('callback '+m+': '+e.message); }
    d.resolve();
  }, 0);
  return d.promise();
};
w.eval(script);
const wait = ms => new Promise(r => setTimeout(r, ms));
module.exports = { w, $, log, wait, setResponder: f => { responder = f; }, reset: () => { log.ajax.length = 0; log.layer.length = 0; log.errors.length = 0; }, dom };
