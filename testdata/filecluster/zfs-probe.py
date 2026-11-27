"""Destructive only to a fresh, owned file vdev inside a marked disposable guest.

Run as root in testdata/filecluster QEMU guests. Never uses a physical/data disk.
Tests the SAME state/data separation and snapshot format as the helper recipe.
"""
import datetime,json,os,pathlib,pwd,secrets,shutil,subprocess,tempfile
if os.geteuid()!=0 or pathlib.Path('/etc/sambaadm-ha-lab').read_text()!='disposable QEMU lab\n':
 raise SystemExit('Requires an explicitly marked disposable lab guest')
def run(*args):
 result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
 if result.returncode:raise RuntimeError(str(args)+': '+result.stdout)
 return result.stdout.strip()
if not pathlib.Path('/etc/hostid').exists():run('zgenhostid')
run('modprobe','zfs')
print(run('uname','-r'),run('zfs','version'),flush=True)
pool='sambaadm_probe_'+secrets.token_hex(5)
base=pathlib.Path(tempfile.mkdtemp(prefix='sambaadm-zfs-probe-'));os.chmod(base,0o755)
vdev=base/'vdev.img'
with vdev.open('xb') as output:output.truncate(512*1024*1024)
created=False
try:
 run('zpool','create','-m','none','-o','cachefile=none','-o','multihost=on','-O','canmount=off','-O','acltype=posixacl','-O','xattr=sa','-O','snapdir=hidden','-O','sync=standard',pool,str(vdev));created=True
 for name,mode in [('state',0o700),('data',0o770)]:
  run('zfs','create','-o','canmount=on','-o','mountpoint='+str(base/name),pool+'/'+name);os.chmod(base/name,mode)
 data=base/'data';state=base/'state';uid=str(pwd.getpwnam('nobody').pw_uid)
 run('setfacl','-m','u:'+uid+':r-x,d:u::rwx,d:u:'+uid+':r-x,d:g::---,d:m::r-x,d:o::---',str(data))
 nested=data/'nested';nested.mkdir();document=nested/'report.txt';document.write_text('before snapshot\n');(state/'machine-state').write_text('secret-before\n')
 acl=run('getfacl','-cpn',str(nested));assert 'user:'+uid+':r-x' in acl,acl
 assert run('runuser','-u','nobody','--','cat',str(document))=='before snapshot'
 assert not document.stat().st_mode & 0o111,'regular file unexpectedly executable'
 denied=subprocess.run(['runuser','-u','nobody','--','ls',str(state)],capture_output=True)
 assert denied.returncode!=0,'Samba machine state exposed'
 snapshot='sambaadm_'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y.%m.%d-%H.%M.%S')
 label='До изменения документа'
 run('zfs','snapshot','-o','org.sambaadm:label='+label,pool+'/data@'+snapshot)
 document.write_text('after snapshot\n');(state/'machine-state').write_text('secret-current\n')
 old=data/'.zfs/snapshot'/snapshot/'nested/report.txt';assert old.read_text()=='before snapshot\n'
 readonly=subprocess.run(['sh','-c','printf changed > "$1"','probe',str(old)],capture_output=True)
 assert readonly.returncode!=0,'snapshot is writable'
 listed=run('zfs','list','-H','-t','snapshot','-o','name','-r',pool).splitlines()
 assert listed==[pool+'/data@'+snapshot],'snapshot includes private Samba state'
 assert run('zfs','get','-H','-o','value','org.sambaadm:label',pool+'/data@'+snapshot)==label
 # Entered snapshot path creates a ZFS automount. Release it before pool stop.
 run('zpool','export',pool)
 run('zpool','import','-d',str(base),'-o','cachefile=none',pool)
 assert document.read_text()=='after snapshot\n' and old.read_text()=='before snapshot\n'
 assert (state/'machine-state').read_text()=='secret-current\n'
 assert run('zpool','get','-H','-o','value','cachefile',pool)=='none'
 assert run('zpool','get','-H','-o','value','multihost',pool)=='on'
 print(json.dumps({'result':'PASS','kernel':run('uname','-r'),'zfs':run('zfs','version'),'checks':['POSIX ACL','inherited directory x','regular file without x','state private','data-only named read-only snapshot','export/import preserves snapshot and current machine state']},ensure_ascii=False),flush=True)
finally:
 if created:
  # Test owns exactly this random pool. Refuse to conceal a failed cleanup.
  run('zpool','destroy',pool)
 shutil.rmtree(base)
