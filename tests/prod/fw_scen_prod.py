import sys, subprocess, time, os
sys.path.insert(0,'/www/server/panel'); sys.path.insert(0,'/www/server/panel/class'); sys.path.insert(0,'/www/server/panel/plugin/sentinel')
import sentinel_main
class G(dict):
    def get(self,k,d=None): return dict.get(self,k,d)
sm=sentinel_main.sentinel_main()
def sh(c,t=30): return subprocess.run(c,shell=True,capture_output=True,text=True,timeout=t)
def setup():
    sh('ip netns del zyprobe; ip link del vethzp0')
    sh('ip netns add zyprobe && ip link add vethzp0 type veth peer name vethzp1 && ip link set vethzp1 netns zyprobe && ip addr add 198.51.100.1/24 dev vethzp0 && ip link set vethzp0 up && ip netns exec zyprobe ip addr add 198.51.100.2/24 dev vethzp1 && ip netns exec zyprobe ip link set vethzp1 up')
def teardown(): sh('ip netns del zyprobe; ip link del vethzp0')
def porta(p):
    r=sh('ip netns exec zyprobe timeout 3 bash -c "exec 3<>/dev/tcp/198.51.100.1/%d" 2>&1; echo rc=$?'%p)
    return 'buka' if r.stdout.strip().endswith('rc=0') else ('ditolak-service' if 'refused' in r.stdout else 'DROP')
G_=[]
def cek(n,ok,i=''):
    print('  %s %s%s'%('LULUS' if ok else 'GAGAL',n,'' if ok else '  -> '+str(i)[:150]))
    if not ok: G_.append(n)
def api(m,**k):
    r=getattr(sm,m)(G(k)); return r
setup()
try:
    print('## F1 ban/unban IP uji (198.51.100.2) lewat API panel')
    kritis={80:'buka',443:'buka',2244:'buka',15960:'buka'}
    for p,e in kritis.items(): cek('sebelum ban: port %d %s'%(p,e), porta(p)==e, porta(p))
    r=api('ban_ip',ip='198.51.100.2',secs='120'); print('    ban_ip:',r['status'],str(r['msg'])[:90])
    time.sleep(1)
    cek('sesudah ban: port 80 DROP untuk IP yang diban', porta(80)=='DROP', porta(80))
    cek('sesudah ban: port 2244 DROP untuk IP yang diban', porta(2244)=='DROP')
    r=api('unban_ip',ip='198.51.100.2'); print('    unban_ip:',r['status'],str(r['msg'])[:90])
    time.sleep(1)
    for p,e in kritis.items(): cek('sesudah unban: port %d kembali %s'%(p,e), porta(p)==e, porta(p))
    print('## F2 pagar anti-blokir diri sendiri')
    for ip in ['127.0.0.1','103.127.99.26','10.11.13.1','0.0.0.0','255.255.255.255','8.8.8.8/33','1.2.3.4;id']:
        r=api('ban_ip',ip=ip); cek('ban_ip %s ditolak'%ip, r['status'] is False, r['msg'])
    print('## F3 allow_ip: IP putih tidak bisa di-ban')
    r=api('allow_ip',ip='198.51.100.2'); print('    allow_ip:',r['status'],str(r['msg'])[:80])
    r=api('ban_ip',ip='198.51.100.2'); print('    ban_ip setelah allow:',r['status'],str(r['msg'])[:100]); time.sleep(1)
    cek('IP putih tetap bisa akses port 80 walau coba di-ban', porta(80)=='buka', porta(80))
    api('unban_ip',ip='198.51.100.2'); r=api('del_allow',ip='198.51.100.2'); print('    del_allow:',r['status'],str(r['msg'])[:80])
    print('## F4 aturan port: buka 18777/tcp lalu tutup')
    srv=subprocess.Popen(['python3','-m','http.server','18777','--bind','0.0.0.0','--directory','/tmp'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); time.sleep(1)
    cek('sebelum aturan: 18777 DROP', porta(18777)=='DROP', porta(18777))
    r=api('add_port_rule',direction='inbound',protocol='tcp',port='18777',rule_action='ACCEPT',source='198.51.100.0/24',remark='uji-zys'); print('    add_port_rule:',r['status'],str(r['msg'])[:80])
    rid=None
    cfg=api('get_port_firewall')['msg']
    for x in cfg.get('inbound',[]):
        if x.get('remark')=='uji-zys': rid=x['id']
    time.sleep(1.5)
    cek('sesudah aturan: 18777 terbuka dari sumber yang diizinkan', porta(18777)=='buka', porta(18777))
    for p,e in kritis.items(): cek('port kritis %d tetap %s saat aturan ditambah'%(p,e), porta(p)==e)
    if rid: r=api('del_port_rule',id=rid); print('    del_port_rule:',r['status'],str(r['msg'])[:80])
    time.sleep(1.5)
    cek('sesudah dihapus: 18777 DROP lagi', porta(18777)=='DROP', porta(18777))
    srv.terminate()
    print('## F5 aturan baseline (SSH/panel) tidak bisa dihapus/dimatikan')
    for x in cfg.get('inbound',[]):
        if x.get('id') in ('in-ssh','in-panel','in-http','in-https'):
            r=api('del_port_rule',id=x['id']); cek('hapus %s ditolak'%x['id'], r['status'] is False, r['msg'])
            r=api('toggle_port_rule',id=x['id']); cek('matikan %s ditolak'%x['id'], r['status'] is False, r['msg'])
    for p,e in kritis.items(): cek('akhir: port %d %s'%(p,e), porta(p)==e)
finally:
    teardown()
print('RINGKAS: %d gagal'%len(G_)); print(G_)
