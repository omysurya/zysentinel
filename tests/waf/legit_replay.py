import os,sys,json,subprocess,shutil,time,http.client,tempfile,collections,urllib.parse,re
import concurrent.futures as cf
D=os.environ.get('ZY_ATK_DIR', '/tmp/zys-atk/') + ''
MAIN=sys.argv[1]; OUT=sys.argv[2]
R=json.load(open(D+'reqs_cls.json'))
keys={}
for r in R:
    if r['src']!='access' or r['ip'].startswith('127.') or r['ip']=='103.127.99.26': continue
    if not (r['status'] in (200,206,304,101) or (r['status'] in (302,303,307) and 'login' in r['uri'])): continue
    if r['method'] not in ('GET','HEAD'): continue
    k=(r['site'],r['uri'],r['ua'])
    if k not in keys: keys[k]=dict(site=r['site'],uri=r['uri'],ua=r['ua'] or 'Mozilla/5.0 Chrome/124',status=r['status'])
items=list(keys.values()); print('permintaan sah unik:',len(items))
T=tempfile.mkdtemp(prefix='lgr.'); os.chmod(T,0o777)
C='/www/server/panel/plugin/sentinel/coraza-cache'; K=os.listdir(C+'/modules')[0]; L=os.listdir(C+'/libcoraza')[0]
for d in ('lib','tmp','html'): os.makedirs(T+'/'+d)
open(T+'/html/index.html','w').write('ok')
shutil.copy(C+'/modules/'+K+'/ngx_http_coraza_module.so',T); shutil.copy(C+'/libcoraza/'+L+'/lib/libcoraza.so',T+'/lib')
port=34599
conf='load_module %s/ngx_http_coraza_module.so;\nuser www;\nworking_directory /;\nworker_processes 3;\npid %s/n.pid;\nerror_log %s/e.log notice;\nevents{worker_connections 256;}\nhttp{access_log off;client_body_temp_path %s/tmp/b;proxy_temp_path %s/tmp/p;fastcgi_temp_path %s/tmp/f;uwsgi_temp_path %s/tmp/u;scgi_temp_path %s/tmp/s;\nserver{listen 127.0.0.1:%d;root %s/html;coraza on;coraza_rules_file %s;location / {} error_page 404 =200 /index.html;}}\n'%((T,)*8+(port,T,MAIN))
open(T+'/nginx.conf','w').write(conf); subprocess.run('chmod -R a+rwX '+T,shell=True)
env=dict(os.environ,LD_LIBRARY_PATH=T+'/lib')
subprocess.run(['/www/server/nginx/sbin/nginx','-p',T,'-c',T+'/nginx.conf','-e',T+'/s.log'],env=env); time.sleep(2)
def one(it):
    try:
        c=http.client.HTTPConnection('127.0.0.1',port,timeout=20)
        c.request('GET',it['uri'],headers={'Host':it['site'],'User-Agent':it['ua'][:300]}); rr=c.getresponse(); rr.read(); s=rr.status; c.close(); return s
    except Exception: return 0
t0=time.time()
with cf.ThreadPoolExecutor(max_workers=6) as ex: res=list(ex.map(one,items))
for it,s in zip(items,res): it['replay']=s
try: os.kill(int(open(T+'/n.pid').read()),15)
except Exception: pass
print('selesai %.0f dtk; kode:'%(time.time()-t0),dict(collections.Counter(res)))
json.dump(items,open(OUT,'w'))
