import http.client, json, time, os, re, sys
H='zys-wafuji.local'; P=18555
UA={'User-Agent':'Mozilla/5.0 (X11; Linux x86_64) Chrome/124.0 Safari/537.36'}
def req(path, headers=None, method='GET', body=None):
    h=dict(UA); h['Host']=H; h.update(headers or {})
    c=http.client.HTTPConnection('127.0.0.1',P,timeout=10)
    try:
        c.request(method,path,body=body,headers=h); r=c.getresponse(); b=r.read(); return r.status,b
    except Exception as e: return 'EXC',str(e).encode()
    finally: c.close()
AUD='/www/wwwlogs/zysentinel_waf_audit.jsonl'
def naud(): 
    try: return sum(1 for _ in open(AUD,errors='replace'))
    except: return 0
a0=naud(); G=[]; 
def cek(nama, ok, info=''):
    print('  %s %s%s'%('LULUS' if ok else 'GAGAL',nama,'' if ok else '  -> '+str(info)[:160])); 
    if not ok: G.append(nama)
print('## Permintaan sah (harus 200)')
for p in ['/','/index.html','/?q=hello+world','/?id=42','/?s=select+a+shirt','/?name=O%27Brien','/?q=union+station','/api/webhook/x']:
    s,_=req(p); cek('sah '+p, s in (200,), s)
print('## Berkas sensitif (harus ditolak)')
for p in ['/.env','//.env','/./.env','/a/../.env','/%2eenv','/.%65nv','/.env?x=1','/backup.sql','/%62ackup.sql','/.git/config','/wp-config.php.bak','/.htpasswd','/api_key.txt']:
    s,b=req(p); cek('tolak '+p, s in (403,400,404) and b!=b'secret\n', s)
print('## Serangan aplikasi (harus 403)')
for n,p in [('SQLi union','/?id=1%20UNION%20SELECT%201,2,3--'),('SQLi boolean',"/?id=1'%20OR%20'1'='1"),('SQLi sleep','/?id=1;SELECT%20SLEEP(5)--'),('XSS script','/?x=<script>alert(1)</script>'),('XSS img','/?x=%3Cimg%20src=x%20onerror=alert(1)%3E'),('traversal','/?f=../../../../etc/passwd'),('traversal enc','/?f=..%252f..%252fetc/passwd'),('RCE','/?c=;cat%20/etc/passwd'),('RCE $()','/?c=$(id)'),('LFI php','/?f=php://filter/convert.base64-encode/resource=index.php'),('log4shell','/?x=%24%7Bjndi:ldap://x/a%7D'),('SSRF meta','/?u=http://169.254.169.254/latest/meta-data/')]:
    s,_=req(p); cek(n, s==403, s)
print('## Scanner dan bot')
for ua in ['sqlmap/1.7','Nikto/2.1.6','Acunetix','masscan/1.3','python-requests/2.31','curl/8.0','MJ12bot/1.4','AhrefsBot/7.0']:
    s,_=req('/',{'User-Agent':ua}); print('  info UA %-22s -> %s'%(ua,s))
s,_=req('/',{'User-Agent':'sqlmap/1.7'}); cek('sqlmap diblokir', s==403, s)
s,_=req('/',{'User-Agent':'Nikto/2.1.6'}); cek('Nikto diblokir', s==403, s)
print('## Header, cookie, body, argumen besar')
s,_=req('/',{'X-Forwarded-For':"1.1.1.1' OR '1'='1"}); cek('SQLi di X-Forwarded-For', s==403, s)
s,_=req('/',{'Cookie':"a=1' UNION SELECT 1,2,3--"}); cek('SQLi di cookie', s==403, s)
s,_=req('/',{'Content-Type':'application/json'},'POST','{"id":"1 UNION SELECT 1,2,3--"}'); cek('SQLi di body JSON', s==403, s)
pad='&'.join('p%d=1'%i for i in range(3100)); s,_=req('/?'+pad+'&id=1%20UNION%20SELECT%201,2,3--'); cek('3100 argumen + SQLi', s in (400,403), s)
s,_=req('/',{'Content-Type':'application/x-www-form-urlencoded'},'POST','pad='+'A'*2000000+'&id=1'); print('  info POST 2MB tanpa serangan ->',s)
print('## Blocker page')
s,b=req('/.env'); t=b.decode('utf8','replace'); cek('halaman blocker tampil (403 + HTML)', s==403 and ('ZySentinel' in t or 'blocked' in t.lower() or 'Request ID' in t or 'IP' in t), (s,t[:80]))
print('## Log audit bertambah: %d baris'%(naud()-a0))
print('RINGKAS: %d gagal'%len(G)); print(G)
