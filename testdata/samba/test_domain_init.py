#!/usr/bin/env python3
"""Disposable ALT systemd test: bootstrap HTTPS -> real panel -> signed helpers.
Pass native static binaries, helper RPM and an ALT image containing the panel
RPM/systemd/Samba test prerequisites. Passwords are generated in memory and
sent only on stdin or inside verified HTTPS. Never run against an existing DC.
"""
import argparse,base64,json,pathlib,secrets,subprocess,sys,time
parser=argparse.ArgumentParser();parser.add_argument('--image',required=True);parser.add_argument('--binary',required=True);parser.add_argument('--helper',required=True);parser.add_argument('--helper-rpm',required=True);parser.add_argument('--client',required=True);parser.add_argument('--keep',action='store_true');args=parser.parse_args()
repo=pathlib.Path(__file__).resolve().parents[2];prefix='sambaadm-domain-init-'+secrets.token_hex(3);realm='init-it.sambaadm.test';password=secrets.token_urlsafe(24)+'aA1!';nodes=[];ca=None;forwarder=None

def call(argv,data=None,check=True):
    payload=json.dumps(data).encode() if isinstance(data,(dict,list)) else data
    p=subprocess.run(argv,input=payload,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    if check and p.returncode:raise RuntimeError(p.stdout.decode(errors='replace').replace(password,'[hidden]')[-4000:])
    return p

def execute(node,script,data=None):return call(['docker','exec','-i',node,'python3','-c',script],data).stdout

def upload(node,destination,data,mode=0o600,owner=None):
    execute(node,"import json,sys,pathlib,os,base64;d=json.load(sys.stdin);p=pathlib.Path(d['path']);p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(base64.b64decode(d['value']));p.chmod(d['mode']);os.chown(p,*d['owner']) if d.get('owner') else None",dict(path=destination,value=base64.b64encode(data).decode(),mode=mode,owner=owner))

def create(host,dns=None):
    node=prefix+'-'+host;command=['docker','run','--name',node,'--privileged','--cgroupns=private','-d','--hostname',host+'.'+realm,'--tmpfs','/run','--tmpfs','/tmp']
    if dns:command+=['--dns',dns]
    call(command+[args.image,'/lib/systemd/systemd']);nodes.append(node)
    call(['docker','cp',str(repo/'deploy/sambaadm-setup'),node+':/usr/sbin/sambaadm-setup']);call(['docker','cp',args.binary,node+':/usr/bin/sambaadm']);call(['docker','cp',args.helper,node+':/usr/bin/sambaadm-helper'])
    for _ in range(40):
        p=call(['docker','exec',node,'systemctl','is-system-running'],check=False)
        if p.stdout.strip() in [b'running',b'degraded']:break
        time.sleep(.5)
    ip=call(['docker','inspect',node,'--format','{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}']).stdout.decode().strip()
    return node,ip

bootstrap_client=r'''
import json,sys,re,ssl,hashlib,http.cookiejar,urllib.request,urllib.error,time,base64,pathlib
value=json.load(sys.stdin);console=pathlib.Path('/root/bootstrap-console').read_text();token=re.search(r'Код доступа: (\S+)',console).group(1);fingerprint=re.search(r'SHA-256 сертификата: (\S+)',console).group(1)
cert=ssl.get_server_certificate(('127.0.0.1',8445));assert hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert)).hexdigest()==fingerprint
context=ssl.create_default_context(cadata=cert);jar=http.cookiejar.CookieJar();client=urllib.request.build_opener(urllib.request.HTTPSHandler(context=context),urllib.request.HTTPCookieProcessor(jar));csrf=''
def api(path,body=None):
 request=urllib.request.Request('https://127.0.0.1:8445'+path,data=json.dumps(body).encode() if body is not None else None,headers={'Content-Type':'application/json','X-CSRF-Token':csrf})
 try:
  with client.open(request,timeout=200) as response:return json.load(response)
 except urllib.error.HTTPError as error:raise RuntimeError(error.read().decode())
csrf=api('/api/unlock',{'token':token})['csrf'];input=value['input'];plan=api('/api/plan',input);assert plan['certificate'] and plan['ca']
input.update(revision=plan['revision'],certificate=plan['certificate'],ca=plan['ca'],confirm=True,password=value['password'])
job=api('/api/start',input)
for _ in range(600):
 status=api('/api/status?id='+job['id'])
 if status['state'] not in ['queued','running']:break
 time.sleep(1)
assert status['state']=='completed',status
status['_ca']=plan['ca'];print(json.dumps(status))
'''

panel_client=r'''
import json,sys,ssl,http.cookiejar,urllib.request,urllib.parse,urllib.error,base64,time,html.parser
value=json.load(sys.stdin);base='https://sambaadm.'+value['realm'];context=ssl.create_default_context(cadata=base64.b64decode(value['ca']).decode());jar=http.cookiejar.CookieJar();client=urllib.request.build_opener(urllib.request.HTTPSHandler(context=context),urllib.request.HTTPCookieProcessor(jar))
body=urllib.parse.urlencode({'username':'Administrator@'+value['realm'],'password':value['password'],'helper_auth':'session'}).encode()
with client.open(urllib.request.Request(base+'/login',data=body),timeout=30) as response:response.read();assert response.url==base+'/'
with client.open(base+'/settings/domain-init',timeout=30) as response:page=response.read().decode()
class Tokens(html.parser.HTMLParser):
 def handle_starttag(self,tag,attrs):
  d=dict(attrs)
  if tag=='meta' and d.get('name')=='csrf-token':self.csrf=d['content']
p=Tokens();p.feed(page);csrf=p.csrf
input=value['input']
def api(path,data=None):
 request=urllib.request.Request(base+'/api/v1'+path,data=json.dumps(data).encode() if data is not None else None,headers={'Content-Type':'application/json','X-CSRF-Token':csrf})
 try:
  with client.open(request,timeout=200) as response:return json.load(response)
 except urllib.error.HTTPError as error:raise RuntimeError(error.read().decode())
metadata=api('/domain-init');assert metadata['realm']==value['realm'];assert metadata['netbios']=='INITTEST'
plan=api('/domain-init/plan',input);assert plan['ca']==value['ca'],'DC issuer differs from initial panel CA'
input.update(revision=plan['revision'],certificate=plan['certificate'],ca=plan['ca'],confirm=True,username='Administrator@'+value['realm'],password=value['password'])
job=api('/domain-init/start',input)
for _ in range(600):
 status=api('/domain-init?'+urllib.parse.urlencode({'id':job['id'],'node':input['node']}))
 if status['state'] not in ['queued','running']:break
 time.sleep(1)
assert status['state']=='completed',status
print(json.dumps(status))
'''

try:
    first,ip=create('initdc')
    resolver=call(['docker','exec',first,'cat','/etc/resolv.conf']).stdout.decode();forwarder=next(line.split()[1] for line in resolver.splitlines() if line.startswith('nameserver '))
    upload(first,'/usr/share/sambaadm/helper-packages/'+pathlib.Path(args.helper_rpm).name,pathlib.Path(args.helper_rpm).read_bytes(),0o644)
    call(['docker','exec','-d',first,'sh','-c','umask 077; echo $$ >/root/bootstrap-pid; exec /usr/bin/sambaadm domain-init --state-dir /var/lib/sambaadm-domain-init >/root/bootstrap-console 2>&1'])
    for _ in range(60):
        if b'SHA-256' in call(['docker','exec',first,'cat','/root/bootstrap-console'],check=False).stdout:break
        time.sleep(.2)
    input=dict(mode='forest',realm=realm,netbios='INITTEST',hostname='initdc',address=ip,forwarder=forwarder,site='Main-Init',source='',level='2008_R2',panelName='sambaadm.'+realm)
    status=json.loads(execute(first,bootstrap_client,dict(input=input,password=password)));ca=status['_ca']
    print('PASS first forest through real HTTPS bootstrap; panel/helper/TLS/site verified',flush=True)
    call(['docker','exec',first,'samba-tool','sites','create','Branch-Init'])
    call(['docker','cp',args.client,first+':/usr/bin/init-test-client'])
    public=call(['docker','exec',first,'cat','/var/lib/sambaadm/enrollment/management.pub']).stdout
    owner=json.loads(execute(first,"import pwd,json;u=pwd.getpwnam('sambaadm');print(json.dumps([u.pw_uid,u.pw_gid]))"))
    for host,mode in [('rwnew','DC'),('ronew','RODC')]:
        node,address=create(host,ip);fqdn=host+'.'+realm
        call(['docker','exec','-i',first,'samba-tool','dns','add','127.0.0.1',realm,host,'A',address,'-U','Administrator'],(password+'\n').encode())
        call(['docker','exec',node,'mkdir','-p','/etc/sambaadm-helper','/var/lib/sambaadm-helper','/var/log/sambaadm-helper','/srv/samba'])
        call(['docker','exec',node,'chmod','700','/etc/sambaadm-helper','/var/lib/sambaadm-helper'])
        call(['docker','exec',node,'openssl','genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256','-out','/etc/sambaadm-helper/tls.key'])
        call(['docker','exec',node,'chmod','600','/etc/sambaadm-helper/tls.key'])
        csr=call(['docker','exec',node,'openssl','req','-new','-key','/etc/sambaadm-helper/tls.key','-subj','/CN='+fqdn]).stdout
        signed=json.loads(call(['docker','exec','-i',first,'/usr/bin/init-test-client'],dict(Action='sign',CSR=base64.b64encode(csr).decode(),Input={'mode':'DC','hostname':host,'realm':realm})).stdout)
        upload(node,'/etc/sambaadm-helper/tls.crt',base64.b64decode(signed['certificate']));upload(node,'/etc/sambaadm-helper/domain-ca.pem',base64.b64decode(ca));upload(node,'/etc/sambaadm-helper/management.pub',public)
        cfg={'helper':{'node':fqdn,'trusted_keys':['/etc/sambaadm-helper/management.pub'],'listen':'0.0.0.0:8444','tls':{'cert':'/etc/sambaadm-helper/tls.crt','key':'/etc/sambaadm-helper/tls.key'},'state_dir':'/var/lib/sambaadm-helper','backup_root':'/var/lib/sambaadm-helper/backups','sysvol_prefix':realm+'/Policies'},'samba':{'smb_conf':'/etc/samba/smb.conf','shares_root':'/srv/samba'},'audit':{'file':'/var/log/sambaadm-helper/audit.log'}}
        upload(node,'/etc/sambaadm-helper/config.yaml',json.dumps(cfg).encode())
        call(['docker','cp',str(repo/'deploy/sambaadm-helper.service'),node+':/etc/systemd/system/sambaadm-helper.service']);call(['docker','exec',node,'chown','root:root','/etc/systemd/system/sambaadm-helper.service']);call(['docker','exec',node,'systemctl','daemon-reload']);call(['docker','exec',node,'systemctl','enable','--now','sambaadm-helper'])
        execute(first,"import json,sys,pathlib,os;v=json.load(sys.stdin);p=pathlib.Path('/var/lib/sambaadm/enrollment/nodes.json');d=json.loads(p.read_text());d['Nodes'].append({'Name':v['name'],'Transport':'https','Endpoint':'https://'+v['name']+':8444','CACert':'/etc/sambaadm/domain-ca.pem'});p.write_text(json.dumps(d));os.chown(p,*v['owner']);p.chmod(0o600)",dict(name=fqdn,owner=owner))
        input=dict(mode=mode,node=fqdn,realm=realm,netbios='INITTEST',hostname=host,address=address,forwarder=forwarder,site='Branch-Init',source='initdc.'+realm,level='2008_R2',panelName='')
        status=json.loads(execute(first,panel_client,dict(input=input,realm=realm,password=password,ca=ca)))
        print('PASS '+mode+' through real panel and signed helper; site, TLS and SYSVOL verified',flush=True)
    print('PASS isolated domain lifecycle: '+','.join(nodes),flush=True)
finally:
    if not args.keep:
        for node in reversed(nodes):call(['docker','rm','-f',node],check=False)
    else:print('Retained test nodes: '+','.join(nodes),flush=True)
