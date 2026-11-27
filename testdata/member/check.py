"""Runs only in a disposable member container created by run.sh."""
import importlib.util, os, pathlib, subprocess, time, json
assert pathlib.Path('/.dockerenv').exists()
spec=importlib.util.spec_from_file_location('member','/tmp/member.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
profile=os.environ['PROFILE'];name='fsss' if profile=='sssd' else 'fswb'
v=dict(mode='member',identityProvider=profile,realm='sambaadm.test',netbios='SAMBAADM',hostname=name,address=os.environ['ADDRESS'],forwarder=os.environ['DNS'],source='dc1.sambaadm.test',panelName='sambaadm.sambaadm.test',username='Administrator@sambaadm.test',password='Lab-Only-Adm1n-Pass!')
def run(args,timeout=30):
 p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=timeout)
 if p.returncode:raise RuntimeError(str(args)+': '+p.stdout[-2000:])
 return p.stdout
w={'run':run,'ENV':{**os.environ,'LC_ALL':'C'}}
m.validate(v);m.inspect_domain(v)
modern=m.modern_keytab(run)
pathlib.Path('/etc/samba/smb.conf').write_text(m.smb_config(v,modern))
pathlib.Path('/etc/krb5.conf').write_text('[libdefaults]\ndefault_realm = SAMBAADM.TEST\ndns_lookup_kdc = true\ndns_lookup_realm = false\nrdns = false\n')
p=pathlib.Path('/etc/nsswitch.conf');p.write_text(m.nss_config(p.read_text(),'sss' if profile=='sssd' else 'winbind'))
if profile=='sssd':
 p=pathlib.Path('/etc/sssd/sssd.conf');p.write_text(m.sssd_config(v,modern));p.chmod(0o600);run(['sssctl','config-check'])
run(['testparm','-s']);m.join(v,w);run(['net','ads','keytab','create','-P'])
pathlib.Path('/run/samba').mkdir(parents=True,exist_ok=True)
if profile=='sssd':run(['sssd','-D'])
run(['winbindd','-D'])
for attempt in range(20):
 try:report=m.verify(v,w);break
 except Exception:
  if attempt==19:raise
  time.sleep(1)
if profile=='sssd':
 before=pathlib.Path('/etc/krb5.keytab').read_bytes()
 run(['net','ads','changetrustpw','-P'] if modern else ['adcli','update','--domain='+v['realm'],'--domain-controller='+v['source'],'--host-keytab=/etc/krb5.keytab','--host-fqdn='+name+'.sambaadm.test','--computer-name='+name.upper(),'--computer-password-lifetime=0','--add-samba-data'])
 for attempt in range(10):
  after=pathlib.Path('/etc/krb5.keytab').read_bytes()
  if before!=after:break
  time.sleep(1)
 assert before!=after,'keytab did not rotate'
 run(['kinit','-k','-t','/etc/krb5.keytab',name.upper()+'$@SAMBAADM.TEST'])
 run(['kdestroy'])
 report['rotatedMachineKeytabVerified']=True
# The occupied computer name must not be reused by the fresh-server workflow.
try:m.inspect_domain(v)
except RuntimeError as e:
 assert 'уже занято' in str(e),str(e)
else:raise AssertionError('installer accepted an existing computer')
root=pathlib.Path('/srv/samba/check');root.mkdir(parents=True,mode=0o750);root.chmod(0o750)
gid=report['gid'];run(['setfacl','-m',f'g:{gid}:rwx,d:g:{gid}:r-x',str(root)])
with pathlib.Path('/etc/samba/smb.conf').open('a') as f:f.write('\n[check]\npath = /srv/samba/check\nread only = no\ninherit acls = no\n')
run(['smbd','-D']);time.sleep(1)
pathlib.Path('/tmp/upload.txt').write_text('real SMB with '+profile+'\n')
args=['smbclient','--client-protection=sign','//'+name+'.sambaadm.test/check','--user=Administrator@sambaadm.test','-c','put /tmp/upload.txt uploaded.txt; mkdir child; get uploaded.txt /tmp/download.txt; ls']
p=subprocess.run(args,input=v['password']+'\n',stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=30)
assert p.returncode==0,p.stdout
assert pathlib.Path('/tmp/download.txt').read_text()==pathlib.Path('/tmp/upload.txt').read_text(),p.stdout
assert root.joinpath('uploaded.txt').stat().st_mode&0o111==0
child_acl=run(['getfacl','-n',str(root/'child')]);assert f'group:{gid}:r-x' in child_acl,child_acl
report.update(smbSignedReadWrite=True,nonExecutableFile=True,inheritedDirectorySearch=True,occupiedNameRejected=True)
print(json.dumps(report,ensure_ascii=False));print(p.stdout);print(child_acl)
run(['rpm','-q','samba','samba-winbind','sssd','sssd-winbind-idmap'])
