#!/usr/bin/python3
"""Real Samba/BIND, with a container service adapter in place of systemd."""
import base64,hashlib,json,os,re,pathlib,signal,subprocess,tempfile,time
assert pathlib.Path('/.dockerenv').exists()
base=pathlib.Path('/tmp/dns-backend-real');base.mkdir(mode=0o755)
pathlib.Path('/etc/samba/smb.conf').unlink(missing_ok=True)
subprocess.run(['samba-tool','domain','provision','--use-rfc2307','--realm=SAMBAADM.TEST','--domain=SAMBAADM','--server-role=dc','--dns-backend=SAMBA_INTERNAL','--adminpass=Lab-Only-Adm1n-Pass!','--host-name=dc1','--option=vfs objects = dfs_samba4 acl_xattr xattr_tdb','--option=xattr_tdb:file = /var/lib/samba/private/xattr.tdb','--option=acl_xattr:ignore system acls = yes'],check=True)
smb=pathlib.Path('/etc/samba/smb.conf');original=smb.read_text();bind=base/'named.conf'
key=base64.b64encode(b'test-only-rndc-key-32-bytes-long!!').decode()
control='key "dns-test" { algorithm hmac-sha256; secret "'+key+'"; };\n'
bind.write_text('options { directory "/tmp"; listen-on {127.0.0.1;}; listen-on-v6 {none;}; recursion yes; dnssec-validation no; };\n'+control+'controls { inet 127.0.0.1 port 953 allow {127.0.0.1;} keys {"dns-test";}; };\n');bind.chmod(0o644)
pathlib.Path('/etc/rndc.conf').write_text(control+'options {default-server 127.0.0.1;default-key "dns-test";};\n')
pathlib.Path('/etc/bind/rndc.conf').write_bytes(pathlib.Path('/etc/rndc.conf').read_bytes())
adapter='''#!/usr/bin/python3
import json,os,pathlib,signal,subprocess,sys,time
base=pathlib.Path('/tmp/dns-backend-real');args=sys.argv[1:];unit=args[-1];pidfile=base/(unit+'.pid')
def alive():
 try:return pathlib.Path('/proc/'+pidfile.read_text()+'/stat').read_text().split()[2]!='Z'
 except Exception:return False
def group_alive(group):
 for entry in pathlib.Path('/proc').iterdir():
  if not entry.name.isdigit():continue
  try:
   if os.getpgid(int(entry.name))==group and (entry/'stat').read_text().split()[2]!='Z':return True
  except (ProcessLookupError,FileNotFoundError,PermissionError):pass
 return False
def stop():
 if not pidfile.exists():return
 group=int(pidfile.read_text())
 try:os.killpg(group,signal.SIGTERM)
 except ProcessLookupError:return
 for _ in range(200):
  if not group_alive(group):return
  time.sleep(.05)
 try:os.killpg(group,signal.SIGKILL)
 except ProcessLookupError:return
 for _ in range(100):
  if not group_alive(group):return
  time.sleep(.05)
 raise RuntimeError('service children did not stop: '+unit)
def start():
 if alive():return
 command=['samba','-i','--no-process-group'] if unit=='samba.service' else ['named','-g','-u','bind','-c',str(base/'named.conf')]
 log=(base/(unit+'.log')).open('a');p=subprocess.Popen(command,start_new_session=True,stdout=log,stderr=log);pidfile.write_text(str(p.pid));time.sleep(1)
 if not alive():raise RuntimeError('service failed: '+unit)
if args[0]=='is-active':sys.exit(0 if alive() else 3)
if args[0]=='is-enabled':sys.exit(0)
if args[0]=='stop':stop()
if args[0]=='restart':stop();start()
if args[0]=='start' or args[0]=='enable' and '--now' in args:start()
'''
for name,content in [('systemctl',adapter),('apt-get','#!/bin/sh\nexit 0\n')]:
 p=pathlib.Path('/usr/sbin')/name
 if p.is_symlink():p.unlink()
 p.write_text(content);p.chmod(0o755)
subprocess.run(['/usr/sbin/systemctl','start','samba.service'],check=True)
for _ in range(30):
 if subprocess.run(['dig','+short','@127.0.0.1','sambaadm.test','SOA'],stdout=subprocess.PIPE).stdout.strip():break
 time.sleep(1)
for target in ['BIND9_DLZ','SAMBA_INTERNAL']:
 folder=base/target;folder.mkdir(mode=0o700)
 current=smb.read_bytes();old=bind.read_bytes();services=subprocess.check_output(['testparm','-s','--parameter-name=server services'],stderr=subprocess.DEVNULL,text=True).strip();parts=[v.strip() for v in services.split(',') if v.strip()!='dns']
 if target=='SAMBA_INTERNAL':parts.append('dns')
 text=re.sub(r'(?im)^\s*server services\s*=.*\n','',smb.read_text());text=text.replace('[global]','[global]\n\tserver services = '+', '.join(parts),1)
 request={'id':'b'*32,'actor':'test','stateDir':str(base),'smb':text,'smbHash':hashlib.sha256(current).hexdigest(),'bindHash':hashlib.sha256(old).hexdigest(),'plan':{'target':target,'backend':'SAMBA_INTERNAL' if target=='BIND9_DLZ' else 'BIND9_DLZ','reinstall':False,'smbPath':str(smb),'bindPath':str(bind)}}
 (folder/'request.json').write_text(json.dumps(request))
 subprocess.run(['python3','/src/internal/service/helper_dns_backend.py',str(folder)],check=True)
 st=json.loads((folder/'status.json').read_text())
 if st['state']!='completed':
  print(json.dumps(st,indent=2,ensure_ascii=False))
  for p in base.glob('*.log'):print(p,p.read_text()[-10000:])
  raise AssertionError('real migration failed: '+target)
 print('PASS real Samba/BIND switch:',target,flush=True)
 if target=='BIND9_DLZ':
  subprocess.run(['samba-tool','dns','add','127.0.0.1','sambaadm.test','app','NS','ns.routing.test','-U','Administrator%Lab-Only-Adm1n-Pass!','--use-kerberos=off'],check=True)
  subprocess.run(['/service.test','-test.run','^TestIntegrationDNSForwardingHost$','-test.v'],env={**os.environ,'SAMBAADM_DNS_FORWARD_IT':'1'},check=True)
