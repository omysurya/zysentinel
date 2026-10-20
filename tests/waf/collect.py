# Kumpulkan permintaan dari semua log vhost (error log + access log) untuk analisis serangan.
import re,os,glob,json,collections,urllib.parse
W='/www/wwwlogs'
OUT=os.environ.get('ZY_ATK_DIR', '/tmp/zys-atk/') + 'reqs.json'
acc=re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d{3}) (\S+) "([^"]*)" "([^"]*)"')
err=re.compile(r'^(\d{4}/\d\d/\d\d \d\d:\d\d:\d\d) \[(\w+)\] \d+#\d+: \*\d+ (.*?), client: ([0-9a-fA-F:.]+), server: ([^,]*), request: "(\S+) (\S+) [^"]*"(?:, upstream: "[^"]*")?(?:, host: "([^"]*)")?(?:, referrer: "([^"]*)")?')
R=[]
seen=set()
for f in sorted(glob.glob(W+'/*.log')):
    b=os.path.basename(f)
    if b.startswith(('tcp-','nginx_','access.log')) or 'free_waf' in b: continue
    isErr=b.endswith('.error.log'); site=b[:-10] if isErr else b[:-4]
    n=0
    with open(f,errors='replace') as fh:
        for l in fh:
            if isErr:
                m=err.match(l)
                if not m: continue
                ts,lvl,msg,ip,srv,meth,uri,host,ref=m.groups()
                kind='error'
                if 'access forbidden by rule' in msg: kind='nginx-deny'
                elif 'open()' in msg and 'No such file' in msg: kind='404-file'
                elif 'limiting requests' in msg: kind='limit_req'
                elif 'limiting connections' in msg: kind='limit_conn'
                elif 'FastCGI sent in stderr' in msg: kind='php-stderr'
                elif 'directory index' in msg: kind='dir-index'
                elif 'is forbidden' in msg or 'Permission denied' in msg: kind='perm-denied'
                elif 'upstream' in msg or 'connect()' in msg: kind='upstream'
                R.append(dict(src='error',kind=kind,site=site,ip=ip,ts=ts,method=meth,uri=uri,ua='',status=0,msg=msg[:160]))
            else:
                m=acc.match(l)
                if not m: continue
                ip,ts,meth,uri,st,sz,ref,ua=m.groups()
                R.append(dict(src='access',kind='access',site=site,ip=ip,ts=ts,method=meth,uri=uri,ua=ua,status=int(st),msg=''))
print('total entri:',len(R))
c=collections.Counter((r['src'],r['kind']) for r in R); print(dict(c))
json.dump(R,open(OUT,'w'))
