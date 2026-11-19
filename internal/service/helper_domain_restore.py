"""Offline disaster recovery into a new DC using Samba's supported restore tool.

The immutable sambaadm cold archive is staged, converted to a native offline
backup and restored by the installed Samba release. Never activates a service.
"""
import datetime
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')


def save(path, value):
    temp = path.with_name(path.name+'.tmp')
    with temp.open('x') as out:
        json.dump(value, out)
        out.flush()
        os.fsync(out.fileno())
    os.replace(temp, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def run_tool(args, log):
    result = subprocess.run(['/usr/bin/samba-tool']+args, stdin=subprocess.DEVNULL,
                            stdout=log, stderr=subprocess.STDOUT, timeout=600,
                            env={**os.environ, 'SAMBA_SELFTEST': '0'})
    if result.returncode:
        raise ValueError('Native Samba recovery step failed; inspect worker.log')


def check_layout(worker, archive, checksum, new_name):
    worker.require_isolated_network()
    worker.require_stopped()
    if worker.digest_file(archive) != checksum:
        raise ValueError('Archive checksum mismatch')
    manifest = worker.verify_archive(archive)
    if manifest['request'].get('purpose') != 'full':
        raise ValueError('Standalone full backup required')
    if new_name.lower() == manifest['request']['controller'].split('.')[0].lower():
        raise ValueError('Use a new DC name for forest recovery')
    return manifest



def sync_candidate(target):
    import stat
    for folder, dirs, files in os.walk(target, topdown=False):
        for name in files:
            path=pathlib.Path(folder)/name
            mode=path.lstat().st_mode
            if stat.S_ISSOCK(mode):
                continue
            if not stat.S_ISREG(mode):
                raise ValueError('Unsupported recovered file type')
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        fd=os.open(folder,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def recover(worker, directory, request, archive, log):
    import ldb
    import samba
    from samba import param
    from samba.auth import system_session
    from samba.samdb import SamDB
    manifest = check_layout(worker, archive, request['sha256'], request['newName'])
    if request.get('domainGUID') and request['domainGUID'] != manifest['request']['domainGUID']:
        raise ValueError('Recovery plan domain identity differs from archive')
    if request['backupID'] != manifest['request']['id']:
        raise ValueError('Recovery plan backup identity differs from archive')
    recorded_version = manifest.get('sambaVersion')
    if recorded_version and recorded_version != samba.version:
        raise ValueError('Recovery requires the source Samba version: '+recorded_version)
    target = directory/'dc'
    if target.exists() or target.is_symlink():
        raise ValueError('Recovery target already exists; inspect the previous attempt')
    # Native restore implements new DSA/invocation IDs, FSMO/RID recovery,
    # old DC removal, replication-vector handling and krbtgt rotation.
    with tempfile.TemporaryDirectory(prefix='staging-', dir=directory) as temporary:
        temporary = pathlib.Path(temporary)
        staged = worker.restore_isolated(archive, temporary/'source', request['sha256'])
        lp = param.LoadParm();lp.load(staged['config'])
        original = SamDB(session_info=system_session(), lp=lp)
        domains = original.search(base='CN=Partitions,'+str(original.get_config_basedn()),
                                  expression='(&(objectClass=crossRef)(systemFlags:1.2.840.113556.1.4.803:=2))', attrs=['nCName'])
        if len(domains) != 1:
            raise ValueError('Only single-domain forest recovery is supported')
        backend=original.search(base='@PARTITION',scope=ldb.SCOPE_BASE,attrs=['backendStore'])[0]
        if 'backendStore' in backend and str(backend['backendStore'][0]).lower() != 'tdb':
            raise ValueError('Only the TDB backend is supported for recovery')
        old_invocation = str(original.get_invocation_id())
        domain_sid = str(original.get_domain_sid())
        # Prevent a new name from colliding with any former DC/account.
        if original.search(expression='(sAMAccountName='+ldb.binary_encode(request['newName']+'$')+')', attrs=[]):
            raise ValueError('New DC account name already exists in archive')
        del original
        native_config = temporary/'source'/'etc'/'smb.conf'
        native_config.parent.mkdir(mode=0o700,exist_ok=True)
        shutil.copyfile(staged['config'],native_config)
        native = temporary/'native';native.mkdir(mode=0o700)
        run_tool(['domain','backup','offline','--configfile='+str(native_config), '--targetdir='+str(native)],log)
        candidates = list(native.glob('*.tar.bz2'))
        if len(candidates) != 1:
            raise ValueError('Native offline backup did not produce exactly one archive')
        run_tool(['domain','backup','restore','--backup-file='+str(candidates[0]),
                  '--targetdir='+str(target), '--newservername='+request['newName'],
                  '--host-ip='+request['address']], log)
        config = target/'etc/smb.conf'
        # Native restore rewrites provision paths. Reject custom source paths
        # that would leave a dependency on the temporary staging tree.
        text = config.read_text()
        import re
        from samba.ntacls import getntacl, setntacl
        from samba.dcerpc.security import dom_sid
        acl_lp=param.LoadParm();acl_lp.load(str(config))
        for attr in ['xattr_tdb:file','posix:eadb']:
            match=re.search(r'(?im)^\s*'+re.escape(attr)+r'\s*=\s*(.*?)\s*$',text)
            if match:
                acl_lp.set(attr,match.group(1))
        sysvol=pathlib.Path(acl_lp.get('path','sysvol'))
        permissions=manifest['sysvolACL']
        if not permissions:
            raise ValueError('Archive does not contain SYSVOL permissions')
        source_root=min(permissions,key=lambda value:len(pathlib.PurePosixPath(value).parts))
        for attr,dest in [('xattr_tdb:file',target/'private/xattr.tdb'),('posix:eadb',target/'private/eadb.tdb')]:
            if acl_lp.get(attr):
                acl_lp.set(attr,str(dest))
        # The native restorer does not set an ACL on the SYSVOL root itself.
        # Reapply every saved SYSVOL ACL, including that root, to the final
        # VFS store. Domain SID and all user/group SIDs remain unchanged.
        for name,sddl in permissions.items():
            relative=pathlib.PurePosixPath(name).relative_to(source_root)
            path=sysvol/relative
            if not path.exists() or path.is_symlink():
                raise ValueError('Restored SYSVOL path missing or unsafe')
            setntacl(acl_lp,str(path),sddl,domain_sid,system_session())
            if getntacl(acl_lp,str(path),system_session()).as_sddl(dom_sid(domain_sid))!=sddl:
                raise ValueError('SYSVOL permission migration failed')
            metadata=manifest['files'][name]
            os.chown(path,metadata['uid'],metadata['gid'])
            os.chmod(path,metadata['mode'])
        # xattr_tdb is an optional VFS ACL store; recover it under the new private
        # directory rather than retaining a temporary source pathname.
        text = re.sub(r'(?im)^(\s*xattr_tdb:file\s*=).*$',r'\1 '+str(target/'private/xattr.tdb'),text)
        text = re.sub(r'(?im)^(\s*pid directory\s*=).*$',r'\1 '+str(target/'run'),text)
        text = re.sub(r'(?im)^(\s*ncalrpc dir\s*=).*$',r'\1 '+str(target/'run/ncalrpc'),text)
        text = re.sub(r'(?im)^(\s*posix:eadb\s*=).*$',r'\1 '+str(target/'private/eadb.tdb'),text)
        config.write_text(text)
        if str(temporary) in text:
            raise ValueError('Restored configuration retains temporary paths; unsupported custom layout')
    lp = param.LoadParm();lp.load(str(config))
    # LoadParm.set in the staging reader uses process-global command-line
    # overrides. Rebind those overrides to the final tree before opening it.
    for key,value in {'private dir':target/'private','state directory':target/'state',
                      'cache directory':target/'cache','lock directory':target,
                      'pid directory':target/'run','ncalrpc dir':target/'run/ncalrpc',
                      'binddns dir':target/'bind-dns','xattr_tdb:file':target/'private/xattr.tdb'}.items():
        lp.set(key,str(value))
    if lp.get('posix:eadb'):
        lp.set('posix:eadb',str(target/'private/eadb.tdb'))
    lp.dump(False,str(config))
    (target/'private/tls').mkdir(mode=0o700,exist_ok=True)
    # Complete the normal new-DC bootstrap in the persistent candidate, not
    # in the verification image. Without this first-start update the new DC
    # can accept NTLM while lacking LDAP/CIFS Kerberos service principals.
    subprocess.run(['/usr/sbin/samba_spnupdate','--configfile='+str(config)],
                   stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,
                   timeout=60,check=True)
    sam = SamDB(session_info=system_session(), lp=lp)
    domain_guid = __import__('base64').b64encode(bytes(sam.search(base=sam.domain_dn(),scope=ldb.SCOPE_BASE,attrs=['objectGUID'])[0]['objectGUID'][0])).decode()
    if domain_guid != manifest['request']['domainGUID'] or str(sam.get_domain_sid()) != domain_sid:
        raise ValueError('Recovered domain identity mismatch')
    if str(sam.get_invocation_id()) == old_invocation:
        raise ValueError('Recovered DC retained the old invocation ID')
    ntds = sam.search(base=sam.get_config_basedn(),expression='(objectClass=nTDSDSA)',attrs=['objectGUID'])
    if len(ntds) != 1:
        raise ValueError('Old DC metadata remains in recovered forest')
    dsa = ntds[0].dn
    roles = [str(sam.domain_dn()),str(sam.get_schema_basedn()),'CN=Partitions,'+str(sam.get_config_basedn()),
             'CN=RID Manager$,CN=System,'+str(sam.domain_dn()),'CN=Infrastructure,'+str(sam.domain_dn()),
             'CN=Infrastructure,DC=DomainDnsZones,'+str(sam.domain_dn()),'CN=Infrastructure,DC=ForestDnsZones,'+str(sam.domain_dn())]
    for dn in roles:
        record = sam.search(base=dn,scope=ldb.SCOPE_BASE,attrs=['fSMORoleOwner'])[0]
        if ldb.Dn(sam,str(record['fSMORoleOwner'][0])) != dsa:
            raise ValueError('Recovered DC does not own every FSMO role')
    worker.check_database(sam)
    invocation = str(sam.get_invocation_id())
    del sam
    # This probe changes only a throw-away test user, and stops every descendant
    # before handing the persistent recovered tree back to the operator.
    live_request = {**manifest['request'],'controller':request['controller']}
    with tempfile.TemporaryDirectory(prefix='sambaadm-recovered-') as verify_tmp:
        os.chmod(verify_tmp,0o711)
        verify_dir=pathlib.Path(verify_tmp)
        # Capture and reopen the exact recovered candidate, preserving SYSVOL
        # ACLs and remapping all paths with the existing verifier. The probe
        # never creates users or changes permissions in the persistent target.
        verification_archive=worker.capture(verify_dir,str(config),live_request)
        verified=worker.restore_isolated(verification_archive,verify_dir/'image',worker.digest_file(verification_archive))
        verify_lp=param.LoadParm();verify_lp.load(verified['config'])
        image_root=pathlib.Path(verified['config']).parent
        for key,name in [('cache directory','cache'),('lock directory','lock'),('pid directory','run'),('ncalrpc dir','rpc'),('binddns dir','bind-dns')]:
            path=image_root/name;path.mkdir(mode=0o700,exist_ok=True);verify_lp.set(key,str(path))
        verify_lp.dump(False,verified['config'])
        try:
            live=worker.verify_live_restore(verified['config'],live_request)
        finally:
            with (directory/'verification.log').open('x') as diagnostics:
                for name in ['live-process.log','live-samba.log']:
                    path=pathlib.Path(verified['config']).parent/name
                    if path.exists():
                        with path.open(errors='replace') as source:
                            diagnostics.write(source.read(4*1024*1024))
    if worker.digest_file(archive) != request['sha256']:
        raise ValueError('Source archive changed during recovery')
    sync_candidate(target)
    return dict(config=str(config), target=str(target), domainGUID=domain_guid,
                domainSID=domain_sid, invocationID=invocation, liveVerification=live,
                status='ready', activation='manual', finished=now())


def main():
    os.umask(0o077)
    directory = pathlib.Path(sys.argv[1])
    sys.path.insert(0,str(directory))
    import backup_worker as worker
    request = json.loads((directory/'request.json').read_text())
    status = dict(request,status='running',started=now(),activation='manual')
    save(directory/'status.json',status)
    try:
        import contextlib
        with (directory/'worker.log').open('x') as log, contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
            result = recover(worker,directory,request,pathlib.Path(request['archive']),log)
        status.update(result)
    except Exception:
        import traceback
        with (directory/'worker.log').open('a') as log:
            traceback.print_exc(file=log)
        status.update(status='failed',finished=now(),error='Recovery incomplete; inspect private worker.log. Source archive is retained. Do not start the partial target.')
    save(directory/'status.json',status)


if __name__ == '__main__':
    main()
