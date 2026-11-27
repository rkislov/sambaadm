#!/usr/bin/env python3
"""Run in a disposable ALT container after native-ad.py. No credentials in argv."""
import ipaddress,json,os,pathlib,pwd,socket,struct,subprocess,time,uuid
p=json.loads(pathlib.Path('/etc/kea/sambaadm-gss-profile.json').read_text())
address=os.environ['GSS_DNS_IP'];port=int(os.environ.get('GSS_DNS_PORT','1053'))
owner=pwd.getpwnam('_kea');directory=pathlib.Path('/tmp/gss-d2-'+uuid.uuid4().hex);directory.mkdir(mode=0o750);os.chown(directory,owner.pw_uid,owner.pw_gid)
forward='sambaadm.test.';reverse='0.0.10.in-addr.arpa.'
server={'ip-address':address,'port':port}
service={'ip-address':'127.0.0.1','port':15999,'ncr-protocol':'UDP','ncr-format':'JSON','loggers':[{'name':'kea-dhcp-ddns','severity':'DEBUG','debuglevel':99,'output-options':[{'output':'stdout'}]}],'forward-ddns':{'ddns-domains':[{'name':forward,'dns-servers':[server]}]},'reverse-ddns':{'ddns-domains':[{'name':z,'dns-servers':[server]} for z in p['zones'] if z.endswith(('.in-addr.arpa.','.ip6.arpa.'))]},'hooks-libraries':[{'library':'/usr/lib64/kea/hooks/libddns_gss_tsig.so','parameters':{'credentials-cache':'FILE:/run/kea/sambaadm-ddns/ccache','client-principal':p['principal'],'servers':[{'id':'ad','ip-address':address,'port':port,'server-principal':p['serverPrincipal'],'fallback':False}]}}]}
config=directory/'d2.json';config.write_text(json.dumps({'DhcpDdns':service}));os.chmod(config,0o640);os.chown(config,owner.pw_uid,owner.pw_gid)
env=dict(os.environ,KRB5_CONFIG='/etc/kea/sambaadm-krb5.conf',KRB5CCNAME='FILE:/run/kea/sambaadm-ddns/ccache',KEA_PIDFILE_DIR=str(directory),KEA_LOCKFILE_DIR=str(directory))
log=open(directory/'d2.log','w+')
process=subprocess.Popen(['runuser','-u','_kea','--','kea-dhcp-ddns','-d','-c',str(config)],env=env,stdout=log,stderr=log)
name='d2-'+uuid.uuid4().hex[:12]+'.'+forward

def query(name,kind):return subprocess.check_output(['dig','+short','@'+address,'-p',str(port),name,kind],text=True).strip()
def wait(check,request):
    for _ in range(100):
        if check():return
        if process.poll() is not None:raise RuntimeError('D2 exited')
        if _%5==0:sock.sendto(struct.pack('!H',len(json.dumps(request).encode()))+json.dumps(request).encode(),('127.0.0.1',15999))
        time.sleep(.2)
    raise RuntimeError('DNS result timed out')
succeeded=False
try:
    time.sleep(3)
    sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    for ip,kind in [('10.0.0.'+os.environ.get('GSS_TEST_OCTET','243'),'A'),('2001:db8::f2','AAAA')]:
        hostname=name if kind=='A' else 'v6-'+name
        ptr=ipaddress.ip_address(ip).reverse_pointer+'.'
        request={'change-type':0,'forward-change':True,'reverse-change':True,'fqdn':hostname,'ip-address':ip,'dhcid':'000101'+'ab'*32,'lease-expires-on':'20300101000000','lease-length':3600,'conflict-resolution-mode':'no-check-without-dhcid'}
        sock.sendto(struct.pack('!H',len(json.dumps(request).encode()))+json.dumps(request).encode(),('127.0.0.1',15999))
        wait(lambda: query(hostname,kind)==ip and query(ptr,'PTR')==hostname,request)
        request['change-type']=1;sock.sendto(struct.pack('!H',len(json.dumps(request).encode()))+json.dumps(request).encode(),('127.0.0.1',15999))
        wait(lambda: not query(hostname,kind) and not query(ptr,'PTR'),request)
    succeeded=True
    print('PASS real D2 GSS hook signed A/AAAA/PTR creation and deletion')
finally:
    process.terminate()
    try:process.wait(timeout=5)
    except subprocess.TimeoutExpired:process.kill();process.wait()
    log.seek(0)
    if not succeeded:print(log.read()[-14000:])
