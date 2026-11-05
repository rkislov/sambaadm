"""Disposable, network-isolated native backup/restore test; no Samba CLI."""
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

# Make accidental CLI use fail even if a future dependency tries it.
if os.path.exists('/usr/bin/samba-tool'):
    os.rename('/usr/bin/samba-tool','/usr/bin/samba-tool.disabled')
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
# Empty site fixture exercises both ordering and restoration of selected GUIDs.
site='CN=Cleanup-Rehearsal,CN=Sites,'+str(sam.get_config_basedn())
sam.add({'dn':site,'objectClass':['top','site']})
sam.add({'dn':'CN=Servers,'+site,'objectClass':['top','serversContainer']})
sam.add({'dn':'CN=NTDS Site Settings,'+site,'objectClass':['top','nTDSSiteSettings']})
objects=[]
for row in sam.search(base=site,scope=ldb.SCOPE_SUBTREE,attrs=['objectClass','objectGUID','uSNChanged','cn','name']):
    attrs={key:[base64.b64encode(bytes(v)).decode() for v in row[key]] for key in ['objectClass','objectGUID','uSNChanged','cn','name'] if key in row}
    objects.append(dict(dn=str(row.dn),guid=base64.b64encode(bytes(row['objectGUID'][0])).decode(),usn=str(row['uSNChanged'][0]),attributes=attrs,findings=[{'code':'site_without_servers'}] if str(row.dn)==site else []))
computer='CN=Retired-Backup,OU=Domain Controllers,'+str(sam.domain_dn())
server='CN=Retired-Backup,CN=Servers,CN=Default-First-Site-Name,CN=Sites,'+str(sam.get_config_basedn())
sam.add({'dn':computer,'objectClass':['computer'],'sAMAccountName':'Retired-Backup$','userAccountControl':'8194','dNSHostName':'retired-backup.sambaadm.test'})
sam.add({'dn':server,'objectClass':['server'],'serverReference':computer,'dNSHostName':'retired-backup.sambaadm.test'})
for dn,code in [(server,'server_without_ntds'),(computer,'retired_server_computer')]:
    keys=['objectClass','objectGUID','uSNChanged','userAccountControl','dNSHostName','serverReference','sAMAccountName','objectSid']
    row=sam.search(base=dn,scope=ldb.SCOPE_BASE,attrs=keys)[0]
    attrs={key:[base64.b64encode(bytes(v)).decode() for v in row[key]] for key in keys if key in row}
    objects.append(dict(dn=dn,guid=base64.b64encode(bytes(row['objectGUID'][0])).decode(),usn=str(row['uSNChanged'][0]),attributes=attrs,findings=[{'dn':dn,'code':code}]))
# Extended retired metadata, including RID and DFSR descendants.
ntds='CN=NTDS Settings,'+server
sam.add({'dn':ntds,'objectClass':['nTDSDSA'],'options':'6','invocationId':b'0123456789abcdef','hasMasterNCs':[str(sam.domain_dn()),str(sam.get_config_basedn()),str(sam.get_schema_basedn())],'msDS-hasMasterNCs':[str(sam.domain_dn()),str(sam.get_config_basedn()),str(sam.get_schema_basedn())]},controls=['relax:0'])
rid='CN=RID Set,'+computer
local='CN=DFSR-LocalSettings,'+computer
subscriber='CN=Domain System Volume,'+local
subscription='CN=SYSVOL Subscription,'+subscriber
global_dn='CN=Cleanup-DFSR-Global,CN=System,'+str(sam.domain_dn())
group='CN=CleanupRG,'+global_dn
topology='CN=Topology,'+group
member='CN=Retired-Backup,'+topology
sam.add({'dn':global_dn,'objectClass':['msDFSR-GlobalSettings']})
sam.add({'dn':group,'objectClass':['msDFSR-ReplicationGroup'],'msDFSR-ReplicationGroupType':'1'})
sam.add({'dn':topology,'objectClass':['msDFSR-Topology']})
sam.add({'dn':member,'objectClass':['msDFSR-Member'],'msDFSR-ComputerReference':computer})
group_guid=bytes(sam.search(base=group,scope=ldb.SCOPE_BASE,attrs=['objectGUID'])[0]['objectGUID'][0])
for dn,klass in [(rid,'rIDSet'),(local,'msDFSR-LocalSettings'),(subscriber,'msDFSR-Subscriber'),(subscription,'msDFSR-Subscription')]:
    record={'dn':dn,'objectClass':[klass]}
    if klass=='rIDSet': record.update(rIDAllocationPool='21474836484500',rIDPreviousAllocationPool='21474836484500',rIDNextRID='4500',rIDUsedPool='0')
    if klass=='msDFSR-Subscriber': record.update({'msDFSR-MemberReference':member,'msDFSR-ReplicationGroupGuid':group_guid})
    if klass=='msDFSR-Subscription': record.update({'msDFSR-ContentSetGuid':b'0123456789abcdef','msDFSR-ReplicationGroupGuid':group_guid})
    sam.add(record,controls=['relax:0'])
for dn in [ntds,rid,local,subscriber,subscription,member]:
    keys=['objectClass','objectGUID','uSNChanged','options','cn','name']
    row=sam.search(base=dn,scope=ldb.SCOPE_BASE,attrs=keys)[0]
    attrs={key:[base64.b64encode(bytes(v)).decode() for v in row[key]] for key in keys if key in row}
    objects.append(dict(dn=dn,guid=base64.b64encode(bytes(row['objectGUID'][0])).decode(),usn=str(row['uSNChanged'][0]),attributes=attrs,findings=[{'dn':dn,'code':'retired_dfsr_member' if dn==member else 'retired_dc_child'}]))
partition=sam.search(base='CN=Partitions,'+str(sam.get_config_basedn()),expression='(&(objectClass=crossRef)(nCName=DC=DomainDnsZones,'+str(sam.domain_dn())+'))',attrs=['objectGUID'])[0]
change=ldb.Message();change.dn=partition.dn;change['msDS-NC-Replica-Locations']=ldb.MessageElement([ntds],ldb.FLAG_MOD_ADD,'msDS-NC-Replica-Locations');sam.modify(change)
keys=['objectClass','objectGUID','uSNChanged','msDS-NC-Replica-Locations']
row=sam.search(base=partition.dn,scope=ldb.SCOPE_BASE,attrs=keys)[0]
attrs={key:[base64.b64encode(bytes(v)).decode() for v in row[key]] for key in keys if key in row}
objects.append(dict(dn=str(row.dn),guid=base64.b64encode(bytes(row['objectGUID'][0])).decode(),usn=str(row['uSNChanged'][0]),attributes=attrs,findings=[{'dn':str(row.dn),'code':'retired_replica_link'}],remove={'msDS-NC-Replica-Locations':[base64.b64encode(ntds.encode()).decode()]}))
from samba.dcerpc import dnsp
from samba.ndr import ndr_pack
records=[]
for host in ['retired-backup.sambaadm.test','dc1.sambaadm.test']:
    record=dnsp.DnssrvRpcRecord();record.wType=33;record.rank=240;record.dwTtlSeconds=900
    srv=dnsp.srv();srv.wPort=389;srv.wPriority=0;srv.wWeight=100;srv.nameTarget=host
    record.data=srv;records.append(ndr_pack(record))
node='DC=_cleanup._tcp,DC=sambaadm.test,CN=MicrosoftDNS,DC=DomainDnsZones,'+str(sam.domain_dn())
sam.add({'dn':node,'objectClass':['dnsNode'],'dnsRecord':records,'dNSTombstoned':'FALSE'})
keys=['objectClass','objectGUID','uSNChanged','dnsRecord','dNSTombstoned']
row=sam.search(base=node,scope=ldb.SCOPE_BASE,attrs=keys)[0]
attrs={key:[base64.b64encode(bytes(v)).decode() for v in row[key]] for key in keys if key in row}
objects.append(dict(dn=node,guid=base64.b64encode(bytes(row['objectGUID'][0])).decode(),usn=str(row['uSNChanged'][0]),attributes=attrs,findings=[{'dn':node,'code':'retired_dns_records'}],remove={'dnsRecord':[base64.b64encode(records[0]).decode()]}))
request['plan']={'revision':request['planRevision'],'objects':objects}
del sam;del result
(source/'private/backup-hardlink-a').write_text('hardlink fixture')
os.link(source/'private/backup-hardlink-a',source/'private/backup-hardlink-b')
job=pathlib.Path('/tmp/backup-job');job.mkdir(mode=0o700)
(job/'request.json').write_text(json.dumps(request))
spec=importlib.util.spec_from_file_location('worker','/work/helper_domain_backup.py');worker=importlib.util.module_from_spec(spec);spec.loader.exec_module(worker)
native_check=worker.check_database
def guarded_check(database,expected_deleted_links=None):
    if expected_deleted_links:
        for rejected in [None,{(dn,attr,b'wrong-guid') for dn,attr,guid in expected_deleted_links}]:
            try:
                native_check(database,rejected)
            except ValueError:
                pass
            else:
                raise AssertionError('Unplanned link tombstone was accepted')
    return native_check(database,expected_deleted_links)
worker.check_database=guarded_check
archive=worker.capture(job,str(conf),request)
manifest=worker.verify_archive(archive)
try:
    receipt=worker.rehearse_cleanup(job,archive,request,worker.digest_file(archive))
except Exception:
    if (job/'live.log').exists():
        print((job/'live.log').read_text())
    raise
assert receipt['status']=='verified' and receipt['planRevision']==request['planRevision']
print('PASS: native cleanup rehearsal removes NTDS/RID/DFSR and one shared DNS record, then a second archive restore recovers GUIDs and original records')
try:
    worker.restore_isolated(archive,'/tmp/wrong-checksum','0'*64)
    raise AssertionError('Wrong checksum was accepted')
except ValueError as e:
    assert 'checksum mismatch' in str(e)
assert not pathlib.Path('/tmp/wrong-checksum').exists()
restored=worker.restore_isolated(archive,'/tmp/restored',worker.digest_file(archive))
assert os.stat('/tmp/restored/tmp/source/private/backup-hardlink-a').st_ino==os.stat('/tmp/restored/tmp/source/private/backup-hardlink-b').st_ino
assert restored['domainGUID']==request['domainGUID']
# Verify original configuration and all source data are intact after the rehearsal.
for name,meta in manifest['files'].items():
    if not meta['directory']:
        assert worker.digest_file('/'+name)==meta['sha256'],name
        if not name.endswith('/xattr.tdb'):
            assert worker.digest_file('/tmp/restored/'+name)==meta['sha256'],name
print('PASS: native cold backup, all file checksums, isolated restore and native dbcheck and SYSVOL ACLs; Samba CLI disabled')

import subprocess, time

# The production per-copy path must provide live evidence, not only dbcheck.
assert receipt['kind']=='live-dc-kerberos-ldap-sysvol-cleanup-second-restore-v2'
assert all(receipt['live'][key] for key in ['dcStarted','userLogin','invalidPasswordRejected','sysvolRead','kerberosTGT','kerberosLDAP','kerberosSYSVOL'])
assert receipt['live']['authentication']=='temporary-user-ntlm-and-kerberos'
worker.require_stopped()
print('PASS: per-copy NTLM checks plus fresh Kerberos TGT, LDAP login, CIFS ticket, SMB SYSVOL read and process cleanup')

# Exercise failure on actual SMB content. No source/archived file is changed.
_, local_sam, restored_paths = worker.identity(restored['config'],request)
del local_sam
policy = pathlib.Path(restored_paths.sysvol)/receipt['live']['sysvolPath']
policy.unlink()
try:
    worker.verify_live_restore(restored['config'],request)
    raise AssertionError('missing restored SYSVOL file accepted')
except ValueError as error:
    assert 'verification failed' in str(error)
worker.require_stopped()
print('PASS: missing SYSVOL blocks live verification and stops all DC processes')

# A missing/broken daemon must fail before any success evidence is returned.
original_popen=subprocess.Popen
(pathlib.Path(restored['config']).parent/'live-process.log').unlink()
startup_marker=pathlib.Path('/tmp/live-startup-failed')
def broken_daemon(*args,**kwargs):
    startup_marker.write_text('attempted')
    raise OSError('injected daemon startup failure')
subprocess.Popen=broken_daemon
try:
    try:
        worker.verify_live_restore(restored['config'],request)
        raise AssertionError('daemon startup failure accepted')
    except ValueError as error:
        assert 'verification failed' in str(error)
finally:
    subprocess.Popen=original_popen
worker.require_stopped()
assert startup_marker.read_text()=='attempted'
print('PASS: daemon startup failure blocks verification')

# A hung child and a descendant in a different session must both be killed.
original_probe = worker.live_restore_probe
pidfile = pathlib.Path('/tmp/live-timeout-child.pid')
def hung_probe(config, job, channel):
    os.setsid()
    child=subprocess.Popen(['/bin/sleep','120'],start_new_session=True)
    pidfile.write_text(str(child.pid))
    channel.send('started')
    time.sleep(120)
worker.live_restore_probe=hung_probe
try:
    try:
        worker.verify_live_restore(restored['config'],request,timeout=0.2)
        raise AssertionError('hung probe accepted')
    except ValueError as error:
        assert 'timed out' in str(error)
    assert not pathlib.Path('/proc/'+pidfile.read_text()).exists()
finally:
    worker.live_restore_probe=original_probe
print('PASS: live timeout kills and reaps descendants across process groups')

# Kerberos is independently mandatory even though the same user already
# authenticated and read SYSVOL over NTLM. Removing only the relevant service
# principals must fail at LDAP or SMB, without an NTLM fallback.
import tempfile
for service, expected_stage in [('ldap','kerberos-ldap'),('cifs','kerberos-sysvol'),('cifs','host-alias-success')]:
    with tempfile.TemporaryDirectory(prefix='kerberos-negative-') as temporary:
        os.chmod(temporary,0o711)
        negative=worker.restore_isolated(archive,pathlib.Path(temporary)/'image',worker.digest_file(archive))
        _, negative_sam, _=worker.identity(negative['config'],request)
        account=negative_sam.search(expression='(sAMAccountName=DC1$)',attrs=['servicePrincipalName'])[0]
        remove=[bytes(v) for v in account['servicePrincipalName'] if str(v).lower().startswith((service+'/', 'host/'))]
        assert remove
        change=ldb.Message();change.dn=account.dn
        change['servicePrincipalName']=ldb.MessageElement(remove,ldb.FLAG_MOD_DELETE,'servicePrincipalName')
        negative_sam.modify(change)
        assert not negative_sam.search(expression='(servicePrincipalName='+service+'/dc1.sambaadm.test)',attrs=['name'])
        assert not negative_sam.search(expression='(servicePrincipalName=HOST/dc1.sambaadm.test)',attrs=['name'])
        if service=='cifs' and expected_stage!='host-alias-success':
            # Samba can resolve HOST/DC by computer CN even without HOST SPNs.
            # Remove the standard CIFS->HOST mapping in this disposable negative
            # fixture too, so a legitimate Kerberos alias cannot satisfy it.
            mapping_dn='CN=Directory Service,CN=Windows NT,CN=Services,'+str(negative_sam.get_config_basedn())
            mappings=negative_sam.search(base=mapping_dn,scope=ldb.SCOPE_BASE,attrs=['sPNMappings'])[0]
            values=[]
            for value in mappings['sPNMappings']:
                name, aliases=str(value).split('=',1)
                values.append(name+'='+','.join(alias for alias in aliases.split(',') if alias.lower()!='cifs'))
            change=ldb.Message();change.dn=ldb.Dn(negative_sam,mapping_dn)
            change['sPNMappings']=ldb.MessageElement(values,ldb.FLAG_MOD_REPLACE,'sPNMappings')
            negative_sam.modify(change)
        del negative_sam
        try:
            evidence=worker.verify_live_restore(negative['config'],request)
            if expected_stage!='host-alias-success':
                raise AssertionError('missing '+service+' SPN accepted via fallback')
            assert evidence['kerberosSYSVOL'] and evidence['kerberosLDAP'] and evidence['kerberosTGT']
        except ValueError as error:
            assert expected_stage in str(error),str(error)
        worker.require_stopped()
    if expected_stage=='host-alias-success':
        print('PASS: legitimate CIFS to HOST mapping passes Kerberos verification without explicit CIFS SPN')
    else:
        print('PASS: unavailable '+service+' ticket blocks '+expected_stage+' despite successful NTLM; no fallback')

# The KDC itself must be running; passing NTLM checks cannot substitute for a TGT.
with tempfile.TemporaryDirectory(prefix='kerberos-kdc-') as temporary:
    os.chmod(temporary,0o711)
    negative=worker.restore_isolated(archive,pathlib.Path(temporary)/'image',worker.digest_file(archive))
    def without_kdc(args,**kwargs):
        config_path=pathlib.Path(next(v.split('=',1)[1] for v in args if v.startswith('--configfile=')))
        config_path.write_text(config_path.read_text().replace(' cldap kdc drepl ', ' cldap drepl '))
        return original_popen(args,**kwargs)
    subprocess.Popen=without_kdc
    try:
        try:
            worker.verify_live_restore(negative['config'],request)
            raise AssertionError('stopped KDC accepted')
        except ValueError as error:
            assert 'kerberos-tgt' in str(error),str(error)
    finally:
        subprocess.Popen=original_popen
    worker.require_stopped()
print('PASS: stopped KDC blocks verification despite successful NTLM')

# Failure cannot leave a verified receipt, even after successful offline recovery.
failed_job=pathlib.Path('/tmp/failed-job');failed_job.mkdir(mode=0o700)
original_live=worker.verify_live_restore
def fail_live(*args,**kwargs):
    raise ValueError('injected live failure')
worker.verify_live_restore=fail_live
try:
    try:
        worker.rehearse_cleanup(failed_job,archive,request,worker.digest_file(archive))
        raise AssertionError('failed live check accepted')
    except ValueError as error:
        assert 'injected live failure' in str(error)
    assert not (failed_job/'restore.json').exists()
finally:
    worker.verify_live_restore=original_live
assert worker.digest_file(archive)==receipt['sha256']
print('PASS: failed live check cannot issue a restore receipt; archive remains unchanged')
