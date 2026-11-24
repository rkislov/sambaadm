#!/usr/bin/python3
"""Run only in a disposable container; exercise the fixed worker with fake tools."""
import hashlib,json,os,pathlib,subprocess,tempfile
assert pathlib.Path('/.dockerenv').exists() and os.geteuid()==0
repo=pathlib.Path('/src')
fake='''#!/usr/bin/python3
import json,os,pathlib,sys
name=pathlib.Path(sys.argv[0]).name; args=sys.argv[1:]; base=pathlib.Path(os.environ['DNS_TEST_DIR']); log=base/'commands';log.open('a').write(name+' '+' '.join(args)+'\\n')
if name=='systemctl':
 if args[0] in ('is-active','is-enabled'):sys.exit(0 if args[-1]=='samba.service' else 1)
 if args[0]=='restart' and os.environ.get('DNS_TEST_FAIL')=='1' and not (base/'failed').exists():(base/'failed').write_text('1');sys.exit(1)
elif name=='testparm': print('EXAMPLE.TEST' if any('realm' in a for a in args) else 's3fs, rpc, dns')
elif name=='named':print('BIND 9.18.0')
elif name=='dig':print('ns.example.test. host.example.test. 1 2 3 4 5' if args[-1]=='SOA' else '0 100 389 dc.example.test.')
'''
for name in ['systemctl','testparm','dig','apt-get','named-checkconf','samba_upgradedns','named']:
 path=pathlib.Path('/usr/sbin')/name
 if path.is_symlink():path.unlink()
 path.write_text(fake);path.chmod(0o755)
import grp
try:grp.getgrnam('bind')
except KeyError:subprocess.run(['groupadd','bind'],check=True)
dl=pathlib.Path('/var/lib/samba/bind-dns');dl.mkdir(parents=True,exist_ok=True);(dl/'dns.keytab').write_text('test key');module=pathlib.Path('/tmp/dlz_bind9_18.so');module.write_text('fixture')
(dl/'named.conf').write_text('dlz "AD DNS Zone" {\n # database "dlopen /tmp/dlz_bind9_18.so";\n};\n')
for target,fail,stale in [('BIND9_DLZ',False,False),('SAMBA_INTERNAL',False,False),('BIND9_DLZ',True,False),('BIND9_DLZ',False,True)]:
 with tempfile.TemporaryDirectory() as folder:
  base=pathlib.Path(folder);smb=base/'smb.conf';bind=base/'named.conf';smb.write_text('[global]\nserver services = s3fs, rpc, dns\n');bind.write_text('// manual BIND settings\n');smb.chmod(0o640);bind.chmod(0o640);old=smb.read_bytes();before=bind.read_bytes();job=base/'job';job.mkdir(mode=0o700)
  request={'id':'a'*32,'actor':'test','stateDir':folder,'smb':'[global]\nserver services = s3fs, rpc'+(', dns' if target=='SAMBA_INTERNAL' else '')+'\n','smbHash':hashlib.sha256(old if not stale else b'stale').hexdigest(),'bindHash':hashlib.sha256(before).hexdigest(),'plan':{'target':target,'backend':'SAMBA_INTERNAL' if target=='BIND9_DLZ' else 'BIND9_DLZ','reinstall':False,'smbPath':str(smb),'bindPath':str(bind)}}
  (job/'request.json').write_text(json.dumps(request));env={**os.environ,'DNS_TEST_DIR':folder,'DNS_TEST_FAIL':'1' if fail else '0'}
  subprocess.run(['/usr/bin/python3',str(repo/'internal/service/helper_dns_backend.py'),str(job)],env=env,check=True)
  st=json.loads((job/'status.json').read_text());commands=(base/'commands').read_text()
  if fail or stale:
   assert st['state']=='failed',st
   assert smb.read_bytes()==old and bind.read_bytes()==before,st
   if stale:assert 'samba_upgradedns' not in commands,commands
   else:assert commands.count('samba_upgradedns')==2,commands
  else:
   assert st['state']=='completed',st
   assert '--dns-backend='+target in commands
   assert smb.read_text()==request['smb']
  assert smb.stat().st_mode&0o777==0o640
  print('PASS backend worker:',target,'rollback' if fail else 'stale rejection' if stale else 'success')
