// Render seluruh tab Firewall (urutan INPUT, set kernel, Packet Counters, aturan chain) dengan keluaran get_fw NYATA
// dan hitung 'undefined'/NaN. Buat JSON dulu: python3 -c "...get_fw(...)['msg']" > get_fw.json (lihat tests/README.md).
// Pakai: node t_fwtab.js <index.html> <get_fw.json>
const fs=require('fs');const {JSDOM}=require('jsdom');
const html=fs.readFileSync(process.argv[2],'utf8');
const script=html.match(/<script[^>]*>([\s\S]*?)<\/script>/)[1];
const cut=(a,b)=>{const i=script.indexOf(a),j=script.indexOf(b,i);if(i<0||j<0)throw new Error(a);return script.slice(i,j)};
const kode=cut('function ukuranAngka','function waktu(')+cut('function snParseIptablesRule','function snRenderFwHits')+cut('function snRenderFwHits','/* ---------- realtime polling')+cut('function snFwMuat','/* ---------- Port Access Control');
const w=new JSDOM('<body><div id="fwUrutanBox"></div><div id="fwSetBox"></div><div id="fwHitBox"></div><span id="fwHitTime"></span><table><tbody id="tbChainRules"></tbody></table></body>',{runScripts:'outside-only'}).window;
w.$=require('jquery')(w);w.SN_LANG='id';
w.snEsc=t=>String(t).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
w.kosong=(s,n,t)=>w.$(s).html('<tr><td>'+t+'</td></tr>');w.snSpinBtn=()=>()=>{};
w.snAjax=(m,d,cb)=>cb(JSON.parse(fs.readFileSync(process.argv[3],'utf8')));
w.eval(kode);w.snFwMuat();
for(const id of ['fwUrutanBox','fwSetBox','fwHitBox','tbChainRules']){const h=w.document.getElementById(id).innerHTML;console.log(id,'panjang',h.length,'undefined:',(h.match(/undefined|NaN|\[object/g)||[]).length)}
console.log('baris counters',w.document.querySelectorAll('#fwHitBox tbody tr').length,'baris chain',w.document.querySelectorAll('#tbChainRules tr').length);
