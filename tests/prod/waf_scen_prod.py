import sys, time, http.client
sys.path.insert(0,'/www/server/panel'); sys.path.insert(0,'/www/server/panel/class'); sys.path.insert(0,'/www/server/panel/plugin/sentinel')
import sentinel_main
class G(dict):
    def get(self,k,d=None): return dict.get(self,k,d)
sm=sentinel_main.sentinel_main()
H='zys-wafuji.local'; P=18555
UA='Mozilla/5.0 (X11; Linux x86_64) Chrome/124.0 Safari/537.36'
def req(path,headers=None):
    h={'Host':H,'User-Agent':UA}; h.update(headers or {})
    c=http.client.HTTPConnection('127.0.0.1',P,timeout=10)
    try:
        c.request('GET',path,headers=h); r=c.getresponse(); b=r.read(); return r.status,b
    except Exception as e: return 'EXC',b''
G_=[]
def cek(n,ok,i=''):
    print('  %s %s%s'%('LULUS' if ok else 'GAGAL',n,'' if ok else '  -> '+str(i)[:140]))
    if not ok: G_.append(n)
def api(m,**k):
    r=getattr(sm,m)(G(k)); 
    if not r['status']: print('    (api %s: %s)'%(m,str(r['msg'])[:110]))
    return r
SQLI='/?id=1%20UNION%20SELECT%201,2,3--'
print('## S1 url_black ^/private/')
api('waf_list_add',list='url_black',value='^/private/')
for p in ['/private/x','//private/x','/./private/x','/%70rivate/x']: s,_=req(p); cek('diblokir '+p, s==403, s)
s,_=req('/'); cek('situs normal tetap 200', s==200, s)
api('waf_list_del',list='url_black',value='^/private/')
s,_=req('/private/x'); cek('setelah dihapus /private/x 200', s==200, s)
print('## S2 url_white ^/api/webhook/')
api('waf_list_add',list='url_white',value='^/api/webhook/')
s,_=req('/api/webhook/x?id=1%20UNION%20SELECT%201,2,3--'); cek('SQLi di path putih lolos (desain)', s==200, s)
s,b=req('/api/webhook/../../.env'); cek('traversal ke .env lewat path putih TETAP diblokir', s!=200 or b!=b'secret\n', s)
s,_=req('/api/webhook/..%2f..%2f.env'); cek('traversal terenkode TETAP diblokir', s!=200, s)
s,_=req(SQLI); cek('SQLi di luar path putih diblokir', s==403, s)
api('waf_list_del',list='url_white',value='^/api/webhook/')
print('## S3 ip_white 127.0.0.1')
api('waf_list_add',list='ip_white',value='127.0.0.1')
s,_=req(SQLI); cek('IP putih: SQLi lolos (WAF mati untuk IP itu)', s==200, s)
api('waf_list_del',list='ip_white',value='127.0.0.1')
s,_=req(SQLI); cek('setelah dihapus SQLi diblokir lagi', s==403, s)
print('## S4 ip_black 127.0.0.1 (pagar anti-blokir diri sendiri)')
r=api('waf_list_add',list='ip_black',value='127.0.0.1'); print('    hasil API:',r['status'],str(r['msg'])[:100])
s,_=req('/'); print('    permintaan sah dari 127.0.0.1 ->',s)
api('waf_list_del',list='ip_black',value='127.0.0.1')
s,_=req('/'); cek('situs kembali 200 setelah ip_black dihapus', s==200, s)
print('## S5 mode monitor / disable / block')
api('set_waf_mode',mode='monitor'); s,_=req(SQLI); cek('monitor: SQLi tidak diblokir', s==200, s)
api('set_waf_mode',mode='disable'); s,_=req(SQLI); cek('disable: SQLi tidak diblokir', s==200, s)
api('set_waf_mode',mode='block'); s,_=req(SQLI); cek('block: SQLi diblokir', s==403, s)
print('## S6 modul scanner off/on')
s,_=req('/',{'Acunetix-Aspect':'1'}); cek('modul on: header scanner 403', s==403, s)
api('set_zy_module',name='scanner',state='off'); s,_=req('/',{'Acunetix-Aspect':'1'}); cek('modul off: header scanner lolos', s==200, s)
s,_=req(SQLI); cek('modul off tidak mematikan CRS (SQLi 403)', s==403, s)
api('set_zy_module',name='scanner',state='on'); s,_=req('/',{'Acunetix-Aspect':'1'}); cek('modul on lagi: 403', s==403, s)
print('## S7 bot_level')
s,_=req('/',{'User-Agent':'AhrefsBot/7.0'}); print('    bot_level 1 AhrefsBot ->',s)
api('set_zy_setting',key='bot_level',value='2'); s,_=req('/',{'User-Agent':'AhrefsBot/7.0'}); cek('bot_level 2: AhrefsBot 403', s==403, s)
api('set_zy_setting',key='bot_level',value='1'); s,_=req('/',{'User-Agent':'AhrefsBot/7.0'}); cek('bot_level 1 kembali: AhrefsBot lolos', s==200, s)
print('## S8 batas body (pengaturan)')
import http.client as hc
def post(n):
    c=hc.HTTPConnection('127.0.0.1',P,timeout=60); t=time.time()
    c.request('POST','/',body=b'a='+b'A'*n,headers={'Host':H,'User-Agent':UA,'Content-Type':'application/x-www-form-urlencoded'}); r=c.getresponse(); r.read(); return r.status,time.time()-t
s,d=post(200000); cek('200KB ditolak 413 cepat (batas 128KB)', s==413 and d<2, (s,d))
api('set_zy_setting',key='body_nofiles_kb',value='256'); s,d=post(200000); print('    batas 256KB: 200KB -> %s %.1fs'%(s,d)); cek('batas dinaikkan: 200KB tidak lagi 413', s!=413, s)
api('set_zy_setting',key='body_nofiles_kb',value='128'); s,d=post(200000); cek('batas dikembalikan: 413', s==413, s)
print('RINGKAS: %d gagal'%len(G_)); print(G_)
