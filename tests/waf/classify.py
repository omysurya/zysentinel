import os
import re,json,collections,urllib.parse,sys
D=os.environ.get('ZY_ATK_DIR', '/tmp/zys-atk/') + ''
R=json.load(open(D+'reqs.json'))
def dec(u):
    for _ in range(3):
        v=urllib.parse.unquote_plus(u)
        if v==u: break
        u=v
    return u
CAT=[
 ('secret-env-dotfile', r'(?i)(^|/)\.(env|environment|npmrc|pgpass|my\.cnf|netrc|pypirc|dockercfg|git-credentials|bash_history|zsh_history|mysql_history|viminfo|boto|s3cfg|htpasswd|htaccess|user\.ini|DS_Store|aws|ssh|gnupg|kube|docker|config/(hub|gh)|terraform|vscode|idea|claude|cursor|windsurf|aider|continue|gemini|codex|mcp)\b|(^|/)\.env[._~-]?\w*'),
 ('vcs-leak', r'(?i)/\.(git|svn|hg|bzr|cvs)(/|$)|/CVS/Entries|/\.gitignore|/\.gitlab-ci'),
 ('cloud-or-ci-creds', r'(?i)(credentials|secrets?|secret[_-]?keys?|api[_-]?keys?|service[_-]?account|firebase.*adminsdk|id_(rsa|dsa|ecdsa|ed25519)|\.pem$|\.key$|\.p12$|\.pfx$|\.jks$|\.kdbx$|rclone\.conf|\.tfstate|\.tfvars|terraform\.|serverless\.ya?ml|netlify\.toml|vercel\.json|nuget\.config|\.npmrc|docker-compose|dockerfile|jenkinsfile|\.travis|ansible|vagrantfile|appsettings|web\.config|wp-config|config\.(php|json|ya?ml|ini|inc|bak|old|txt)|settings\.py|database\.ya?ml|parameters\.ya?ml)'),
 ('backup-dump', r'(?i)\.(sql|sqlite3?|db|dump|bak|backup|old|orig|save|swp|swo|zip|rar|7z|tar|tgz|gz|bz2)(\?|$)|(^|/)(backup|backups|dump|database|db|site|www|wwwroot|public_html|web|html|full|export|data)[_.-]?[a-z0-9._-]*\.(zip|rar|7z|tar|gz|sql)|~$'),
 ('lfi-traversal-ssrf', r'(?i)(\.\./|\.\.\\|%2e%2e|/proc/(self|\d+)/|/etc/(passwd|shadow|hosts|issue)|c:\\windows|win\.ini|boot\.ini|php://|file://|data://|expect://|phar://|zip://|gopher://|dict://|ldap://|169\.254\.169\.254|metadata\.google|allowOutsideWorkspace|/@fs/|__vite|fileView|/api/fs/read)'),
 ('rce-cmd-injection', r'(?i)(;|\||`|\$\()\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|python|perl|php|powershell|cmd)\b|(\bcmd=|\bexec=|\bcommand=|\bshell=)|/bin/(ba)?sh|\$\{jndi:|\$\{\$\{|%24%7bjndi|\bsystem\(|\bpassthru\(|\bshell_exec\(|\beval\(|base64_decode\(|allow_url_include|auto_prepend_file|php\?-d|\+-d\+'),
 ('sqli', r'(?i)(\bunion\b.{0,20}\bselect\b|\bselect\b.{0,40}\bfrom\b|\bsleep\s*\(|benchmark\s*\(|waitfor\s+delay|information_schema|\bor\b\s+\d+=\d+|\band\b\s+\d+=\d+|\'\s*(or|and)\s*\'|--\s*$|/\*\*/|extractvalue\(|updatexml\(|load_file\(|into\s+outfile|\bdrop\s+table\b|\bxp_cmdshell\b|0x[0-9a-f]{8,})'),
 ('xss', r'(?i)(<script|%3cscript|javascript:|onerror\s*=|onload\s*=|<svg|<img[^>]+src|alert\(|document\.cookie|<iframe|prompt\(|%3csvg)'),
 ('webshell-or-upload-exec', r'(?i)(/(uploads?|upload|files|images?|img|assets|static|tmp|temp|cache|storage|public|data|wp-content/(uploads|plugins|themes))/[^?]*\.(php[0-9]?|phtml|phar|jsp|jspx|asp|aspx|cgi|pl|py|sh)\b|/(shell|cmd|c99|r57|wso|b374k|alfa|indoxploit|webshell|backdoor|bypass|upload|filemanager|fm|x|1|a|test|info|up|mini|wp-xml|xmrlpc|admin|index2|about|ajax|cache|conf|config|db|default|file|gel|lock|radio|simple|sym|vuln)\.php|eval-stdin\.php|\.(php|phtml)\.(jpg|png|gif|txt|bak)|defunct\.dat|gsocket|chk_404_)'),
 ('cms-wordpress-probe', r'(?i)(wp-login|wp-admin|xmlrpc\.php|wp-includes|wp-content|wp-json|wp-cron|wp-config|wp-trackback|readme\.html|license\.txt|wlwmanifest|/wordpress/|/wp/|/blog/wp)'),
 ('framework-debug-or-cve', r'(?i)(phpunit|/vendor/|think(php)?|invokefunction|_ignition|telescope|horizon|_profiler|_debugbar|actuator|jolokia|heapdump|/env$|/trace$|trace\.axd|elmah|server-status|server-info|phpinfo|info\.php|test\.php|pi\.php|adminer|phpmyadmin|pma/|myadmin|/solr/|/jenkins|/script$|/manager/html|/console|/druid/|/nacos|/swagger|/api-docs|/v2/api-docs|/graphql|/debug|/_next/|__nextjs|/@vite|/sitecore|/owa/|/ecp/|/autodiscover|/remote/login|/vpn/|/mgmt/tm|/cgi-bin/|/hudson|/jmx|/geoserver|/confluence|/jira|META-INF|pom\.properties|/s/[0-9a-f]{8,}|/rest/api|/_ignition/execute-solution|/api/v1/pods|/containers/json|/debug/pprof|/metrics$|/status$|/\.well-known/(?!acme))'),
 ('router-iot-cve', r'(?i)(boaform|gponform|hnap1|setup\.cgi|/cgi-bin/luci|/goform/|/apply\.cgi|/login\.cgi|/syscmd|/command\.php|/shell\?|/GponForm|/tmUnblock|mini_httpd|/ISAPI/|/onvif|/SDK/webLanguage|/Login\.htm|/web_shell_cmd|/device\.rsp)'),
 ('cve-path-misc', r'(?i)(/\.\.;/|;jsessionid|/%2e/|/\.%2e/|%00|/\*/|/\.;/|/admin/\.\.|/index\.php/\w+/\.\./|/containers/|/api/jsonws|/_cat/|/_cluster|/_search|/_nodes|/\?-s|/\?-d|/pearcmd|/cgi/|struts|\.action\b|\.do\?|ognl|/console/login|/mgmt|/api/v1/query|/ws/v1)'),
 ('ai-agent-or-devserver', r'(?i)(allowOutsideWorkspace|/api/fs/|__vite_rsc|/@fs/|/@vite/|\.claude|\.cursor|\.windsurf|CLAUDE\.md|AGENTS\.md|mcp\.json|/mcp$|/\.well-known/mcp|\.aider|\.continue|copilot-instructions|/api/system/fileView|openclaw|/sse$|/rpc$)'),
]
UAS=re.compile(r'(?i)(sqlmap|nikto|nmap|masscan|zgrab|l9scan|nuclei|acunetix|nessus|openvas|wpscan|dirbuster|gobuster|feroxbuster|ffuf|wfuzz|burp|hydra|havij|netsparker|appscan|arachni|skipfish|whatweb|httpx|projectdiscovery|jaeles|xray|zmap|censys|shodan|internetmeasurement|netcraft|expanse|leakix|paloalto|binaryedge|bytespider|petalbot|ahrefsbot|semrush|mj12bot|dotbot|dataforseo|blexbot|serpstat|seekport|amazonbot|gptbot|claudebot|ccbot|perplexity|kimi|qwenbot|chatglm|cohere-ai|meta-externalagent|meta-externalfetcher|diffbot|python-requests|python-urllib|go-http-client|libwww|curl/|wget/|java/|okhttp|scrapy|aiohttp|httpclient|node-fetch|axios|^-$|^$)')
def classify(r):
    u=dec(r['uri']); cats=[]
    for n,p in CAT:
        if re.search(p,u): cats.append(n)
    return cats
tot=collections.Counter(); ips=collections.defaultdict(set); sites=collections.defaultdict(collections.Counter); stat=collections.defaultdict(collections.Counter); ex=collections.defaultdict(collections.Counter)
uaC=collections.Counter(); uaIP=collections.defaultdict(set)
N_att=0
for r in R:
    cats=classify(r)
    r['cats']=cats
    if r['ua'] and UAS.search(r['ua']): 
        k=UAS.search(r['ua']).group(1).lower(); uaC[k]+=1; uaIP[k].add(r['ip'])
    for c in cats:
        tot[c]+=1; ips[c].add(r['ip']); sites[c][r['site']]+=1
        key=r['status'] if r['src']=='access' else 'err:'+r['kind']
        stat[c][key]+=1; ex[c][urllib.parse.unquote(r['uri'])[:90]]+=1
    if cats: N_att+=1
json.dump(R,open(D+'reqs_cls.json','w'))
print('permintaan terklasifikasi serangan: %d dari %d (%.1f%%)'%(N_att,len(R),100*N_att/len(R)))
for c,n in tot.most_common():
    s=stat[c]; ok=sum(v for k,v in s.items() if isinstance(k,int) and 200<=k<300)
    print('\n## %s: %d permintaan, %d IP, situs: %s'%(c,n,len(ips[c]),dict(sites[c].most_common(4))))
    print('   status: %s | 2xx di origin: %d'%(dict(s.most_common(6)),ok))
    print('   contoh:',[e for e,_ in ex[c].most_common(4)])
print('\n## User-Agent alat/scraper terdeteksi:')
for k,v in uaC.most_common(25): print('  %-22s %6d permintaan, %d IP'%(k,v,len(uaIP[k])))
