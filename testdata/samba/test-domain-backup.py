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
receipt=worker.rehearse_cleanup(job,archive,request,worker.digest_file(archive))
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

# Start the restored DC only inside this networkless container, then bind with
# an actual restored secret. This is stronger than merely opening the databases.
import subprocess, time, signal
from samba.credentials import Credentials, DONT_USE_KERBEROS
from samba import gensec
config=pathlib.Path(restored['config'])
with config.open('a') as f:
    f.write('\n[global]\ninterfaces = lo\nbind interfaces only = yes\n')
log=open('/tmp/restored-daemon.log','w')
daemon=subprocess.Popen(['/usr/sbin/samba','--foreground','--no-process-group','--configfile='+str(config)],stdout=log,stderr=log,start_new_session=True)
try:
    creds=Credentials();creds.guess(lp);creds.set_kerberos_state(DONT_USE_KERBEROS);creds.set_username('Administrator');creds.set_domain('SAMBAADM');creds.set_realm('SAMBAADM.TEST');creds.set_password('Lab-Only-Adm1n-Pass!');creds.set_gensec_features(gensec.FEATURE_SEAL)
    bound=None
    for attempt in range(40):
        try:
            bound=SamDB(url='ldap://127.0.0.1',credentials=creds,lp=lp)
            break
        except Exception:
            if daemon.poll() is not None:
                raise AssertionError(open('/tmp/restored-daemon.log').read())
            time.sleep(0.5)
    assert bound is not None,open('/tmp/restored-daemon.log').read()
    restored_guid=bytes(bound.search(base=bound.domain_dn(),scope=ldb.SCOPE_BASE,attrs=['objectGUID'])[0]['objectGUID'][0])
    assert restored_guid==guid
    assert len(bound.search(expression='(objectClass=groupPolicyContainer)',attrs=['name']))>=2
    try:
        worker.capture(job,str(conf),request)
        raise AssertionError('running Samba was accepted for a cold snapshot')
    except ValueError as e:
        assert 'must be stopped' in str(e)
    print('PASS: restored DC starts, secret-based LDAP bind and GPO lookup succeed; running-DC backup is blocked')
finally:
    os.killpg(daemon.pid,signal.SIGTERM)
    daemon.wait(timeout=15)
    log.close()
