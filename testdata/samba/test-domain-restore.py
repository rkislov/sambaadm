"""Forest-loss recovery through the supported Samba restore, fully network isolated."""
import base64
import importlib.util
import json
import logging
import os
import pathlib
import ldb
from samba import param
from samba.auth import system_session
from samba.provision import provision
from samba.samdb import SamDB


source=pathlib.Path('/tmp/source')
lp=param.LoadParm()
lp.set('vfs objects','dfs_samba4 acl_xattr xattr_tdb')
lp.set('xattr_tdb:file','/tmp/source/private/xattr.tdb')
lp.set('acl_xattr:ignore system acls','yes')
result=provision(logging.getLogger('test'),system_session(),targetdir=str(source),
                 realm='SAMBAADM.TEST',domain='SAMBAADM',hostname='dc1',hostip='192.0.2.1',
                 serverrole='active directory domain controller',dns_backend='SAMBA_INTERNAL',
                 adminpass='Lab-Only-Adm1n-Pass!',lp=lp,dom_for_fun_level=4,skip_sysvolacl=False)
conf=source/'etc/smb.conf'
lp=param.LoadParm();lp.load(str(conf))
sam=SamDB(session_info=system_session(),lp=lp)
# Native provisioning does not run the normal first-start SPN updater.
# Model an initialized source DC; the restore worker must never repair missing
# service principals just to make its own Kerberos check pass.
dc_account=sam.search(expression='(sAMAccountName=DC1$)',attrs=['servicePrincipalName'])[0]
existing_spns=[str(value) for value in dc_account.get('servicePrincipalName',[])]
required_spns=['ldap/dc1.sambaadm.test','cifs/dc1.sambaadm.test']
missing_spns=[value for value in required_spns if value.lower() not in {v.lower() for v in existing_spns}]
if missing_spns:
    message=ldb.Message();message.dn=dc_account.dn
    message['servicePrincipalName']=ldb.MessageElement(missing_spns,ldb.FLAG_MOD_ADD,'servicePrincipalName')
    sam.modify(message)
guid=bytes(sam.search(base=sam.domain_dn(),scope=ldb.SCOPE_BASE,attrs=['objectGUID'])[0]['objectGUID'][0])
request=dict(id='00000000-0000-0000-0000-000000000001',controller='dc1.sambaadm.test',
             domainGUID=base64.b64encode(guid).decode(),baseDN=str(sam.domain_dn()),planRevision='a'*64)

sam.newuser('recovery-user','Restore-User-Test1!')
user=sam.search(expression='(sAMAccountName=recovery-user)',attrs=['objectGUID','objectSid','unicodePwd'])[0]
original_user={key:bytes(user[key][0]) for key in ['objectGUID','objectSid','unicodePwd']}
original_invocation=str(sam.get_invocation_id())
original_krbtgt=bytes(sam.search(expression='(sAMAccountName=krbtgt)',attrs=['unicodePwd'])[0]['unicodePwd'][0])
second_computer='CN=DC2,OU=Domain Controllers,'+str(sam.domain_dn())
second_server='CN=DC2,CN=Servers,CN=Default-First-Site-Name,CN=Sites,'+str(sam.get_config_basedn())
sam.add({'dn':second_computer,'objectClass':['computer'],'sAMAccountName':'DC2$','userAccountControl':'8194','dNSHostName':'dc2.sambaadm.test'})
sam.add({'dn':second_server,'objectClass':['server'],'serverReference':second_computer,'dNSHostName':'dc2.sambaadm.test'})
sam.add({'dn':'CN=NTDS Settings,'+second_server,'objectClass':['nTDSDSA'],'options':'6','invocationId':b'0123456789abcdef','hasMasterNCs':[str(sam.domain_dn()),str(sam.get_config_basedn()),str(sam.get_schema_basedn())],'msDS-hasMasterNCs':[str(sam.domain_dn()),str(sam.get_config_basedn()),str(sam.get_schema_basedn())]},controls=['relax:0'])
del sam; del result
import sys, subprocess
sys.path.insert(0,'/work')
import helper_domain_backup as worker
sourcejob=pathlib.Path('/tmp/source-job');sourcejob.mkdir(mode=0o700)
request['purpose']='full'
archive=worker.capture(sourcejob,str(conf),request)
job=pathlib.Path('/tmp/recovery-job');job.mkdir(mode=0o700)
restore=dict(id='00000000-0000-0000-0000-000000000003',backupID=request['id'],archive=str(archive),sha256=worker.digest_file(archive),newName='RECOVER',controller='recover.sambaadm.test',address='192.0.2.2')
(job/'request.json').write_text(json.dumps(restore))
import shutil
shutil.copyfile('/work/helper_domain_backup.py',job/'backup_worker.py')
subprocess.run([sys.executable,'/work/helper_domain_restore.py',str(job)],check=True)
status=json.loads((job/'status.json').read_text())
if status['status']!='ready':
    print((job/'worker.log').read_text())
if status['status']!='ready' and (job/'dc/etc/smb.conf').exists():
    print((job/'dc/etc/smb.conf').read_text())
    if (job/'verification.log').exists():
        print((job/'verification.log').read_text())
assert status['status']=='ready'

assert status['activation']=='manual' and status['invocationID']!=original_invocation
assert all(status['liveVerification'][key] for key in ['dcStarted','userLogin','invalidPasswordRejected','sysvolRead','kerberosTGT','kerberosLDAP','kerberosSYSVOL'])
worker.require_stopped()
final_lp=param.LoadParm();final_lp.load(status['config'])
final=SamDB(url=str(job/'dc/private/sam.ldb'),session_info=system_session(),lp=final_lp)
user=final.search(expression='(sAMAccountName=recovery-user)',attrs=['objectGUID','objectSid','unicodePwd'])[0]
for attr,expected in original_user.items():
    assert bytes(user[attr][0])==expected,attr
assert bytes(final.search(expression='(sAMAccountName=krbtgt)',attrs=['unicodePwd'])[0]['unicodePwd'][0])!=original_krbtgt
assert len(final.search(base=final.get_config_basedn(),expression='(objectClass=nTDSDSA)',attrs=[]))==1
assert not final.search(expression='(|(sAMAccountName=DC1$)(sAMAccountName=DC2$))',attrs=[])
assert not final.search(expression='(sAMAccountName=restore-*)',attrs=[]), 'probe user leaked into persistent candidate'
del final
assert worker.digest_file(archive)==restore['sha256']
manifest=worker.verify_archive(archive)
for name,meta in manifest['files'].items():
    if not meta['directory']:
        assert worker.digest_file('/'+name)==meta['sha256'], name
import helper_domain_restore as recovery
for name,checksum in [('RECOVER','0'*64),('DC1',restore['sha256'])]:
    try:
        recovery.check_layout(worker,archive,checksum,name)
    except ValueError:
        pass
    else:
        raise AssertionError('unsafe recovery input accepted')
config_hash=worker.digest_file(pathlib.Path(status['config']))
try:
    with open(os.devnull,'w') as log:
        recovery.recover(worker,job,restore,archive,log)
except ValueError as error:
    assert 'already exists' in str(error)
else:
    raise AssertionError('existing target overwritten')
assert worker.digest_file(pathlib.Path(status['config']))==config_hash
print('PASS: full forest recovery, new DSA/invocation, all FSMO, old DC removal, krbtgt rotation, preserved user SID/GUID/password, and Kerberos/LDAP/SYSVOL verification')
print('PASS: source files and archive unchanged; corrupt checksum, original DC name and existing target rejected')
