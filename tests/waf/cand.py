import os
# Uji kandidat aturan terhadap SEMUA permintaan di log: hit, IP unik, dan status di origin (2xx = potensi pengguna sah).
import json,re,urllib.parse,collections,sys
D=os.environ.get('ZY_ATK_DIR', '/tmp/zys-atk/') + ''
R=json.load(open(D+'reqs_cls.json'))
def norm(u):
    p=urllib.parse.unquote(urllib.parse.unquote(u.split('?')[0]))
    p=p.replace('\\','/'); 
    while '//' in p: p=p.replace('//','/')
    p=re.sub(r'/\./','/',p)
    return p.lower()
def args(u): return urllib.parse.unquote(u.split('?',1)[1]).lower() if '?' in u else ''
CAND={
 'cms-wp': r'(?:^|/)(?:wp-login\.php|wp-signup\.php|wp-trackback\.php|wp-cron\.php|xmlrpc\.php|wp-activate\.php|wp-mail\.php|wp-load\.php|wp-blog-header\.php|wp-settings\.php|wp-links-opml\.php|wp-admin(?:/|$)|wp-includes(?:/|$)|wp-content/(?:plugins|themes|mu-plugins|uploads|upgrade|debug\.log)|wp-json(?:/|$)|wlwmanifest\.xml|wp-config)',
 'cms-other': r'(?:^|/)(?:administrator/(?:index\.php)?$|typo3(?:/|$)|magento_version|core/install\.php|joomla(?:/|$)|drupal(?:/|$)|sites/default/files|components/com_|misc/drupal\.js)',
 'dbadmin': r'(?:^|/)(?:adminer(?:[-_.][a-z0-9._-]*)?(?:\.php|\.zip|\.tar\.gz|\.tgz)?$|phpmyadmin[0-9._-]*(?:/|$)|pma(?:/|$)|myadmin(?:/|$)|mysqladmin(?:/|$)|dbadmin(?:/|$)|pgadmin[0-9]*(?:/|$)|phppgadmin(?:/|$)|sqlitemanager(?:/|$)|websql(?:/|$))',
 'phpinfo-like': r'(?:^|/)(?:phpinfo|php_?info|pinfo|pi|info|test|debug|i|phpversion|infophp|php-info|phpinfo[0-9]+|test[0-9]|t|temp|tmp|1|a|x|cmd|shell)\.php$',
 'framework-debug': r'(?:^|/)(?:_ignition(?:/|$)|telescope(?:/|$)|horizon(?:/|$)|_debugbar(?:/|$)|_profiler(?:/|$)|_wdt(?:/|$)|app_dev\.php|debug/(?:default/view|vars|pprof)|actuator(?:/|$)|jolokia(?:/|$)|heapdump$|threaddump$|trace\.axd|elmah\.axd|h2-console|console/login|index\.php/_(?:environment|profiler)|_environment$)',
 'infra-app': r'(?:^|/)(?:geoserver(?:/|$)|solr/(?:admin|select)|jenkins(?:/|$)|hudson(?:/|$)|manager/html|jmx-console|web-console|invoker/|axis2|druid/|nacos/|zabbix(?:/|$)|kibana(?:/|$)|_cat/|_cluster/|_nodes(?:/|$)|_plugin/|api/v1/pods|containers/json|solr(?:/|$)|ghost/api|sonarqube|confluence(?:/|$)|jira(?:/|$)|bitbucket(?:/|$)|gitlab(?:/|$)|owa/|ecp/|autodiscover/|ews/|remote/login|dana-na/|global-protect/|\+cscoe\+|sslvpn|vpn/index\.html|mgmt/(?:tm|shared)/|tmui/)',
 'device-cve': r'(?:^|/)(?:cgi-bin/|hnap1|sdk/weblanguage|onvif/|isapi/|goform/|boaform/|gponform|cstecgi\.cgi|setup\.cgi|apply\.cgi|login\.cgi|syscmd|command\.php|web_shell_cmd|device\.rsp|tmunblock\.cgi)|;stok=|login\.action$|\.action$|/s/[0-9a-f]{8,}/_/;/|meta-inf/maven|api/jsonws|/\.;/|/\.\.;/|;/',
 'archive-guess': r'^/(?:[0-9]{1,4}|(?:[a-z0-9-]+\.)+[a-z]{2,6}|www|web|html|site|public|public_html|htdocs|wwwroot|httpdocs|backup|backups|bak|old|new|dump|db|database|data|src|source|app|application|archive|archives|files|release|dist|build|latest|prod|production|dev|test|staging|admin|api|config|conf|log|logs|temp|tmp|bundle|project|website|webroot|sql|mysql)[0-9_-]*\.(?:zip|rar|7z|tar|tar\.gz|tgz|tar\.bz2|tar\.xz|gz|bz2|xz|sql|sql\.gz|txt\.gz)$',
 'secrets-more': r'(?:^|/)(?:serverless\.ya?ml|settings\.py|local_settings\.py|parameters\.ya?ml|secrets?\.ya?ml|secrets?\.json|application\.(?:properties|ya?ml)|credentials(?:\.(?:json|xml|txt|ya?ml))?|[a-z0-9_-]*service[-_]?account[a-z0-9_-]*\.json|firebase[a-z0-9_-]*\.json|gcp[a-z0-9_-]*\.json|rclone\.conf|netlify\.toml|nuget\.config|[a-z0-9_*-]*\.auto\.tfvars|id_(?:rsa|dsa|ecdsa|ed25519)|\.my\.cnf|\.npmrc|\.pgpass)$',
 'dotpath': r'(?:^|/)\.[^/.][^/]*',
 'laravel-leak': r'(?:^|/)(?:storage/(?:logs|framework|app)/|bootstrap/cache/|vendor/(?:composer|autoload\.php|bin/|phpunit|symfony|laravel|guzzlehttp)|artisan$|composer\.(?:json|lock)$)',
 'wellknown-exec': r'/\.well-known/.*\.(?:php[0-9]?|phtml|phar|jsp|asp|aspx|cgi|pl|sh)(?:/|$)',
}
RX={k:re.compile(v) for k,v in CAND.items()}
st=collections.defaultdict(lambda: collections.Counter()); ips=collections.defaultdict(set); ex=collections.defaultdict(collections.Counter)
OWN=('127.','103.127.99.26')
for r in R:
    if r['src']!='access' or r['ip'].startswith(OWN): continue
    p=norm(r['uri']); a=args(r['uri'])
    for k,rx in RX.items():
        if k=='dotpath':
            if rx.search(p) and not re.match(r'^/\.well-known(/|$)',p):
                st[k][r['status']]+=1; ips[k].add(r['ip']); ex[k][p[:70]]+=1
        elif rx.search(p) or (k=='cms-wp' and 'rest_route=' in a) or (k=='cms-other' and 'option=com_' in a):
            st[k][r['status']]+=1; ips[k].add(r['ip']); ex[k][p[:70]]+=1
for k in CAND:
    s=st[k]; tot=sum(s.values()); ok=sum(v for c,v in s.items() if 200<=c<300); red=sum(v for c,v in s.items() if 300<=c<400)
    print('\n## %-15s hit=%5d IP=%3d  2xx=%d 3xx=%d | status=%s'%(k,tot,len(ips[k]),ok,red,dict(s.most_common(5))))
    if ok:
        for e,v in ex[k].most_common(6): print('     contoh:',v,e)
