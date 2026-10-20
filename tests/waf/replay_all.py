# Putar ulang permintaan berpola serangan/probe ke nginx terisolasi dengan ruleset PRODUKSI (atau ruleset kandidat bila argumen).
import os,sys,json,subprocess,shutil,time,http.client,tempfile,collections,glob
D=os.environ.get('ZY_ATK_DIR', '/tmp/zys-atk/') + ''
MAIN=sys.argv[1] if len(sys.argv)>1 else '/www/server/sentinel/waf/zyrules/gen/main.conf'
OUT=sys.argv[2] if len(sys.argv)>2 else D+'replay_prod.json'
R=json.load(open(D+'reqs_cls.json'))
keys={}; 
for r in R:
    ip=r['ip']
    if ip.startswith('127.') or ip=='103.127.99.26': continue
    if r['cats'] or r['kind'] in ('404-file','php-stderr','dir-index','perm-denied'):
        k=(r['uri'],r['ua'])
        if k not in keys: keys[k]=dict(uri=r['uri'],ua=r['ua'] or 'Mozilla/5.0 (X11; Linux x86_64) Chrome/124.0 Safari/537.36',site=r['site'],cats=r['cats'],kind=r['kind'],src=r['src'],status=r['status'])
items=list(keys.values()); print('unik:',len(items))
T=tempfile.mkdtemp(prefix='rpa.'); os.chmod(T,0o777)
C='/www/server/panel/plugin/sentinel/coraza-cache'; K=os.listdir(C+'/modules')[0]; L=os.listdir(C+'/libcoraza')[0]
for d in ('lib','tmp','html'): os.makedirs(T+'/'+d)
open(T+'/html/index.html','w').write('ok')
shutil.copy(C+'/modules/'+K+'/ngx_http_coraza_module.so',T); shutil.copy(C+'/libcoraza/'+L+'/lib/libcoraza.so',T+'/lib')
port=34588
conf='load_module %s/ngx_http_coraza_module.so;\nuser www;\nworking_directory /;\nworker_processes 3;\npid %s/n.pid;\nerror_log %s/e.log notice;\nevents{worker_connections 256;}\nhttp{access_log off;client_body_temp_path %s/tmp/b;proxy_temp_path %s/tmp/p;fastcgi_temp_path %s/tmp/f;uwsgi_temp_path %s/tmp/u;scgi_temp_path %s/tmp/s;\nserver{listen 127.0.0.1:%d;root %s/html;coraza on;coraza_rules_file %s;location / {} error_page 404 =200 /index.html;}}\n'%((T,)*8+(port,T,MAIN))
open(T+'/nginx.conf','w').write(conf); subprocess.run('chmod -R a+rwX '+T,shell=True)
env=dict(os.environ,LD_LIBRARY_PATH=T+'/lib')
r=subprocess.run(['/www/server/nginx/sbin/nginx','-p',T,'-c',T+'/nginx.conf','-e',T+'/s.log'],env=env,capture_output=True,text=True); print('start rc',r.returncode,r.stderr[:300])
time.sleep(2)
import concurrent.futures as cf
def one(it):
    try:
        c=http.client.HTTPConnection('127.0.0.1',port,timeout=20)
        c.request('GET',it['uri'],headers={'Host':it['site'],'User-Agent':it['ua'][:300]}); rr=c.getresponse(); rr.read(); s=rr.status; c.close(); return s
    except Exception as e: return 0
t0=time.time()
with cf.ThreadPoolExecutor(max_workers=6) as ex: res=list(ex.map(one,items))
for it,s in zip(items,res): it['replay']=s
try: os.kill(int(open(T+'/n.pid').read()),15)
except Exception: pass
print('selesai %.0f dtk; kode:'%(time.time()-t0),dict(collections.Counter(res)))
json.dump(items,open(OUT,'w'))
