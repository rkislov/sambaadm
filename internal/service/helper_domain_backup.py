"""Native cold DC snapshot and isolated restore; no command-handler delegation."""
import base64
import datetime
import hashlib
import io
import json
import os
import pathlib
import socket
import stat
import sys
import tarfile
import traceback
import tempfile

LIMIT = 10 * 1024**3
PATH_PARAMETERS = ['private dir','state directory','cache directory','lock directory','pid directory','ncalrpc dir','binddns dir','xattr_tdb:file','posix:eadb']


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')


def save(path, value):
    with open(str(path)+'.tmp', 'x', encoding='utf-8') as f:
        json.dump(value, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(str(path)+'.tmp', path)
    fd = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def require_stopped():
    for process in pathlib.Path('/proc').iterdir():
        if not process.name.isdecimal():
            continue
        try:
            exe = pathlib.Path(os.readlink(process / 'exe')).name
        except FileNotFoundError:
            continue
        if exe in {'samba', 'smbd', 'winbindd', 'samba-dcerpcd', 'samba-bgqd'}:
            raise ValueError('Samba must be stopped for a cold snapshot; helper never stops services')


def identity(conf, job):
    import ldb
    from samba import param
    from samba.auth import system_session
    from samba.samdb import SamDB
    from samba.provision import provision_paths_from_lp
    lp = param.LoadParm()
    lp.load(conf)
    sam = SamDB(session_info=system_session(), lp=lp)
    if sam.am_rodc():
        raise ValueError('Writable DC required')
    domain = sam.search(base=sam.domain_dn(), scope=ldb.SCOPE_BASE, attrs=['objectGUID'])[0]
    if base64.b64encode(bytes(domain['objectGUID'][0])).decode() != job['domainGUID']:
        raise ValueError('Domain identity mismatch')
    if str(sam.domain_dn()).lower() != job['baseDN'].lower():
        raise ValueError('Domain name mismatch')
    root = sam.search(base='', scope=ldb.SCOPE_BASE, attrs=['dsServiceName'])[0]
    ntds = sam.search(base=str(root['dsServiceName'][0]), scope=ldb.SCOPE_BASE, attrs=[])[0]
    server = sam.search(base=ntds.dn.parent(), scope=ldb.SCOPE_BASE, attrs=['dNSHostName'])[0]
    if str(server['dNSHostName'][0]).lower() != job['controller'].lower():
        raise ValueError('Controller identity mismatch')
    paths = provision_paths_from_lp(lp, lp.get('realm'))
    return lp, sam, paths


def check_database(sam, expected_deleted_links=None):
    from samba.dbchecker import dbcheck
    expected=set(expected_deleted_links or [])
    class CleanupChecker(dbcheck):
        expected_count=0
        def err_deleted_dn(self,dn,attrname,val,dsdb_dn,correct_dn,remove_plausible=False):
            # Samba 4.17 dbcheck reports even inactive forward-link tombstones.
            # They must remain for replication. Accept ONLY this plan's deleted
            # links with the deleted bit and exact source/attribute/target GUID.
            flags=dsdb_dn.dn.get_extended_component('RMD_FLAGS')
            guid=dsdb_dn.dn.get_extended_component('GUID')
            key=(str(dn).lower(),attrname.lower(),bytes(guid) if guid else b'')
            if remove_plausible and flags is not None and int(flags)==1 and key in expected:
                self.expected_count+=1
                return
            return super().err_deleted_dn(dn,attrname,val,dsdb_dn,correct_dn,remove_plausible)
    checker=CleanupChecker(sam,quiet=True,fix=False,yes=False)
    errors=checker.check_database(controls=['search_options:1:2'])
    if errors!=checker.expected_count:
        raise ValueError('Database consistency check failed')


def digest_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024*1024), b''):
            h.update(chunk)
    return h.hexdigest()


def inventory(roots):
    found = {}
    total = 0
    inodes = {}
    for root in roots:
        root = pathlib.Path(root)
        if not root.is_absolute() or root.is_symlink():
            raise ValueError('Absolute non-symlink source required')
        for directory, dirs, files in os.walk(root):
            # Samba IPC endpoints are recreated, not recovery data.
            dirs[:] = sorted(d for d in dirs if not d.endswith('.sock'))
            for path in [pathlib.Path(directory)] + [pathlib.Path(directory)/n for n in dirs+sorted(files)]:
                st = path.lstat()
                if stat.S_ISSOCK(st.st_mode):
                    continue
                if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
                    raise ValueError('Unsupported source file type: '+str(path))
                name = str(path).lstrip('/')
                if name in found:
                    continue
                total += st.st_size if path.is_file() else 0
                attrs = {k: base64.b64encode(os.getxattr(path,k)).decode() for k in sorted(os.listxattr(path))}
                found[name] = dict(mode=stat.S_IMODE(st.st_mode), uid=st.st_uid, gid=st.st_gid,
                                   mtime=st.st_mtime_ns, size=st.st_size if path.is_file() else 0,
                                   directory=path.is_dir(), xattrs=attrs,
                                   sha256=digest_file(path) if path.is_file() else '')
                if path.is_file():
                    inode = (st.st_dev,st.st_ino)
                    found[name]['hardlink'] = inodes.get(inode,'')
                    inodes.setdefault(inode,name)
                if len(found)>100000 or total>LIMIT:
                    raise ValueError('Snapshot size or entry limit exceeded')
    return found


def capture(directory, conf, job):
    require_stopped()
    import re
    if re.search(r'^\s*(include|config backend)\s*=', pathlib.Path(conf).read_text(), re.MULTILINE|re.IGNORECASE):
        raise ValueError('External or registry configuration requires a separate supported backup plan')
    lp, sam, paths = identity(conf,job)
    check_database(sam)
    domain_sid = str(sam.get_domain_sid())
    del sam
    roots = sorted(set(os.path.abspath(p) for p in [paths.private_dir, paths.state_dir, paths.sysvol, os.path.dirname(conf)]))
    target = os.path.realpath(directory)
    for source in roots:
        if os.path.commonpath([target,os.path.realpath(source)]) == os.path.realpath(source):
            raise ValueError('Snapshot destination overlaps Samba source')
    before = inventory(roots)
    from samba.ntacls import getntacl
    from samba.auth import system_session
    from samba.dcerpc.security import dom_sid
    acl = {}
    for name in before:
        full = '/'+name
        if os.path.commonpath([full,os.path.abspath(paths.sysvol)]) == os.path.abspath(paths.sysvol):
            acl[name] = getntacl(lp,full,system_session()).as_sddl(dom_sid(domain_sid))
    manifest = dict(format='sambaadm-cold-dc-v1', request=job, config=os.path.abspath(conf),
                    roots=roots, files=before, sysvolACL=acl, pathParameters={key:lp.get(key) for key in PATH_PARAMETERS}, domainSID=domain_sid, restoreMode='isolated-same-dc', created=now())
    archive = directory/'domain.tar.gz'
    with tarfile.open(archive,'x:gz',format=tarfile.PAX_FORMAT) as tar:
        for name, meta in sorted(before.items()):
            if meta['directory']:
                continue
            info = tarfile.TarInfo('files/'+name)
            info.size=meta['size'];info.mode=0o600
            with open('/'+name,'rb') as f:
                tar.addfile(info,f)
        raw=json.dumps(manifest,sort_keys=True).encode()
        info=tarfile.TarInfo('manifest.json');info.size=len(raw);info.mode=0o600
        tar.addfile(info,io.BytesIO(raw))
    os.chmod(archive,0o600)
    require_stopped()
    if before != inventory(roots):
        raise ValueError('Source changed during snapshot')
    with archive.open('rb') as f:
        os.fsync(f.fileno())
    verify_archive(archive)
    return archive


def read_manifest(tar):
    m=tar.getmember('manifest.json')
    if not m.isfile() or m.size>64*1024**2:
        raise ValueError('Invalid manifest')
    manifest=json.load(tar.extractfile(m))
    if manifest['format']!='sambaadm-cold-dc-v1' or len(manifest['files'])>100000:
        raise ValueError('Unsupported archive')
    for name in manifest['files']:
        if name.startswith('/') or '..' in pathlib.PurePosixPath(name).parts or str(pathlib.PurePosixPath(name))!=name:
            raise ValueError('Unsafe member path')
    return manifest


def verify_archive(path):
    if path.stat().st_size>LIMIT or not path.is_file() or path.is_symlink():
        raise ValueError('Invalid archive')
    with tarfile.open(path,'r:gz') as tar:
        manifest=read_manifest(tar)
        seen=set();expanded=0
        for member in tar:
            if member.name in seen or not member.isfile():
                raise ValueError('Duplicate or non-regular member')
            seen.add(member.name)
            if member.name=='manifest.json':
                continue
            if not member.name.startswith('files/'):
                raise ValueError('Unexpected archive member')
            meta=manifest['files'][member.name[6:]]
            if meta['directory'] or member.size!=meta['size']:
                raise ValueError('Member mismatch')
            expanded+=member.size
            if expanded>LIMIT:
                raise ValueError('Expanded archive exceeds limit')
            h=hashlib.sha256();f=tar.extractfile(member)
            for chunk in iter(lambda:f.read(1024*1024),b''):
                h.update(chunk)
            if h.hexdigest()!=meta['sha256']:
                raise ValueError('Member checksum mismatch')
        expected={'manifest.json'}|{'files/'+n for n,m in manifest['files'].items() if not m['directory']}
        if seen!=expected:
            raise ValueError('Missing archive member')
    return manifest


def restore_isolated(archive,target,expected):
    # This is a rehearsal-only recovery path, never a production restore endpoint.
    require_isolated_network()
    require_stopped()
    if digest_file(archive)!=expected:
        raise ValueError('Archive checksum mismatch')
    manifest=verify_archive(archive)
    if manifest['config'].lstrip('/') not in manifest['files']:
        raise ValueError('Configuration is not in the archive')
    target=pathlib.Path(target)
    if not target.is_absolute() or target.exists():
        raise ValueError('New absolute restore directory required')
    target.mkdir(mode=0o700)
    with tarfile.open(archive,'r:gz') as tar:
        for name,meta in sorted(manifest['files'].items()):
            dest=target/name
            if meta['directory']:
                dest.mkdir(parents=True,exist_ok=True,mode=0o700)
            else:
                dest.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
                with dest.open('xb') as f:
                    source=tar.extractfile('files/'+name)
                    for chunk in iter(lambda:source.read(1024*1024),b''):
                        f.write(chunk)
                    f.flush();os.fsync(f.fileno())
        for name,meta in manifest['files'].items():
            link=meta.get('hardlink')
            if link:
                other=manifest['files'].get(link)
                if not other or other['directory'] or other['sha256']!=meta['sha256']:
                    raise ValueError('Invalid hardlink metadata')
                os.unlink(target/name)
                os.link(target/link,target/name)
        for name,meta in sorted(manifest['files'].items(),reverse=True):
            dest=target/name
            os.chown(dest,meta['uid'],meta['gid']);os.chmod(dest,meta['mode'])
            for key,value in meta['xattrs'].items():
                os.setxattr(dest,key,base64.b64decode(value,validate=True))
            os.utime(dest,ns=(meta['mtime'],meta['mtime']))
    # Rewrite paths only in a separate rehearsal configuration. Original stays intact.
    from samba import param
    lp=param.LoadParm();lp.load(str(target/manifest['config'].lstrip('/')))
    for key in PATH_PARAMETERS:
        # LoadParm instances can inherit process-global settings from a prior
        # rehearsal. Use the source values recorded at capture, never those defaults.
        value=manifest['pathParameters'][key]
        if value and os.path.isabs(value):
            mapped=target/value.lstrip('/');mapped.parent.mkdir(parents=True,exist_ok=True)
            if key.endswith('dir') or key.endswith('directory'):
                mapped.mkdir(parents=True,exist_ok=True)
            lp.set(key,str(mapped))
    conf=target/'rehearsal.conf'
    lp.dump(False,str(conf))
    # Service paths cannot be set via global LoadParm.set; edit only exported values.
    text=conf.read_text()
    for source in sorted(manifest['roots'],key=len,reverse=True):
        # Prefix replacement limited to values, avoiding arbitrary config source execution.
        text=text.replace('= '+source,'= '+str(target/source.lstrip('/')))
    conf.write_text(text)
    lp,sam,_=identity(str(conf),manifest['request'])
    from samba.ntacls import setntacl, getntacl
    from samba.auth import system_session
    from samba.dcerpc.security import dom_sid
    for name,sddl in manifest['sysvolACL'].items():
        if name not in manifest['files']:
            raise ValueError('ACL path outside manifest')
        file=str(target/name)
        setntacl(lp,file,sddl,manifest['domainSID'],system_session())
        if getntacl(lp,file,system_session()).as_sddl(dom_sid(manifest['domainSID']))!=sddl:
            raise ValueError('Restored SYSVOL ACL mismatch')
    check_database(sam)
    return dict(status='restored_isolated',domainGUID=manifest['request']['domainGUID'],config=str(conf))


def require_isolated_network():
    import fcntl, struct
    # systemd creates PrivateNetwork=yes; kernels may also expose dormant
    # tunnel templates in an otherwise empty namespace. Reject any active NIC.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        for _, name in socket.if_nameindex():
            flags = struct.unpack('H', fcntl.ioctl(probe.fileno(), 0x8913, struct.pack('256s', name.encode()))[16:18])[0]
            if name != 'lo' and flags & 1:
                raise ValueError('Restore rehearsal requires all non-loopback interfaces down')
            if name == 'lo' and not flags & 1:
                raise ValueError('Isolated loopback must be up')


def live_restore_probe(config, job, result):
    """Runs only in a disposable child process group; no production credentials."""
    import secrets, subprocess, time
    import ldb
    from samba import gensec, param
    from samba.credentials import Credentials, DONT_USE_KERBEROS, MUST_USE_KERBEROS, SPECIFIED
    from samba.samdb import SamDB
    from samba.samba3 import param as s3param
    from samba.samba3 import libsmb_samba_internal as libsmb
    os.setsid()
    result.send('started')
    stage = 'preparation'
    try:
        require_isolated_network()
        require_stopped()
        lp, sam, paths = identity(config, job)
        username = 'restore-' + secrets.token_hex(6)
        password = secrets.token_urlsafe(48) + '!aA1'
        sam.newuser(username, password)
        user = sam.search(expression='(sAMAccountName='+username+')', attrs=['objectGUID'])[0]
        user_guid = bytes(user['objectGUID'][0])
        domain_guid = base64.b64decode(job['domainGUID'])
        # Only the disposable private-tmp image becomes traversable to the
        # ordinary SMB user. The archive/job directory remains mode 0700.
        image_root = pathlib.Path(config).parent
        sysvol = pathlib.Path(paths.sysvol)
        sysvol.relative_to(image_root)
        for ancestor in sysvol.parents:
            if ancestor == image_root.parent:
                break
            os.chmod(ancestor, ancestor.stat().st_mode | 0o111)
        # Only known-safe settings are copied. Never start arbitrary source
        # shares, VFS modules, hooks, DNS scripts or external configuration.
        values = {'server role': 'active directory domain controller',
                  'realm': lp.get('realm'), 'workgroup': lp.get('workgroup'),
                  'netbios name': lp.get('netbios name'),
                  'interfaces': 'lo', 'bind interfaces only': 'yes',
                  'name resolve order': 'host',
                  'server services': 's3fs rpc nbt wrepl ldap cldap kdc drepl winbindd ntp_signd kcc dnsupdate dns',
                  'dns update command': '/bin/true', 'spn update command': '/bin/true',
                  'log file': str(image_root/'live-samba.log'),
                  'ntp signd socket directory': str(image_root/'ntp_signd'),
                  'winbindd socket directory': '/run/samba/winbindd',
                  'usershare path': str(image_root/'usershares'),
                  'usershare max shares': '0'}
        # Preserve authentication restrictions; do not silently enable NTLM
        # in a domain whose restored configuration disallows it.
        for key in ['ntlm auth', 'server signing', 'smb encrypt', 'ldap server require strong auth']:
            value = lp.get(key)
            if value is not None:
                values[key] = value
        for key in PATH_PARAMETERS:
            if lp.get(key):
                mapped = pathlib.Path(lp.get(key))
                mapped.relative_to(image_root)
                values[key] = str(mapped)
        modules = lp.get('vfs objects') or []
        if isinstance(modules, str):
            modules = modules.split()
        if any(m not in {'dfs_samba4', 'acl_xattr', 'xattr_tdb'} for m in modules):
            raise ValueError('Unsupported VFS module for live restore verification')
        if modules:
            values['vfs objects'] = ' '.join(modules)
        values['acl_xattr:ignore system acls'] = lp.get('acl_xattr:ignore system acls') or 'no'
        # libwbclient uses its compiled socket location. /run is a private
        # tmpfs in the helper unit, so this cannot reach the host winbindd.
        pathlib.Path('/run/samba').mkdir(mode=0o755, parents=True, exist_ok=True)
        live_config = pathlib.Path(config).parent/'live.conf'
        lines = ['[global]']
        for key, value in values.items():
            value = str(value)
            if '\n' in value or '\r' in value:
                raise ValueError('Invalid live configuration value')
            lines.append(key+' = '+value)
        lines.extend(['[sysvol]', 'path = '+paths.sysvol, 'read only = yes'])
        live_config.write_text('\n'.join(lines)+'\n')
        realm = lp.get('realm')
        domain = lp.get('workgroup')
        import re
        controller = job['controller'].lower()
        if not re.fullmatch(r'[a-z0-9][a-z0-9.-]*[a-z0-9]', controller) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]', realm):
            raise ValueError('Invalid Kerberos realm or controller name')
        addresses = {item[4][0] for item in socket.getaddrinfo(controller, 389, type=socket.SOCK_STREAM)}
        if addresses != {'127.0.0.1'}:
            raise ValueError('Isolated controller name must resolve only to loopback')
        krb_config = image_root/'krb5-live.conf'
        krb_config.write_text('[libdefaults]\n default_realm = '+realm+'\n'
                             ' dns_lookup_kdc = false\n dns_lookup_realm = false\n'
                             ' dns_canonicalize_hostname = false\n rdns = false\n'
                             '[realms]\n '+realm+' = {\n  kdc = 127.0.0.1\n }\n'
                             '[domain_realm]\n '+controller+' = '+realm+'\n')
        os.environ['KRB5_CONFIG'] = str(krb_config)
        kerberos_cache = 'MEMORY:sambaadm-live-'+secrets.token_hex(16)
        os.environ['KRB5CCNAME'] = kerberos_cache
        del sam, lp
        log = (pathlib.Path(config).parent/'live-process.log').open('x')
        stage = 'startup'
        daemon = subprocess.Popen(['/usr/sbin/samba', '--foreground', '--no-process-group',
                                   '--configfile='+str(live_config)], stdout=log, stderr=log)
        client_lp = s3param.get_context()
        client_lp.load(str(live_config))
        ldap_lp = param.LoadParm()
        ldap_lp.load(str(live_config))
        def credentials(secret, kerberos=False):
            creds = Credentials()
            creds.guess(ldap_lp)
            creds.set_username(username); creds.set_domain(domain); creds.set_realm(realm)
            creds.set_password(secret); creds.set_kerberos_state(MUST_USE_KERBEROS if kerberos else DONT_USE_KERBEROS)
            creds.set_gensec_features(gensec.FEATURE_SEAL)
            return creds
        stage = 'ntlm-ldap'
        creds = credentials(password)
        deadline = time.monotonic()+45
        while True:
            try:
                bound = SamDB(url='ldap://127.0.0.1', credentials=creds, lp=ldap_lp)
                break
            except Exception:
                if daemon.poll() is not None or time.monotonic() >= deadline:
                    raise ValueError('Restored DC did not become ready')
                time.sleep(0.5)
        row = bound.search(base=bound.domain_dn(), scope=ldb.SCOPE_BASE, attrs=['objectGUID'])[0]
        if bytes(row['objectGUID'][0]) != domain_guid:
            raise ValueError('Live domain identity mismatch')
        rows = bound.search(expression='(sAMAccountName='+username+')', attrs=['objectGUID'])
        if len(rows) != 1 or bytes(rows[0]['objectGUID'][0]) != user_guid:
            raise ValueError('Live user identity mismatch')
        stage = 'ntlm-invalid-password'
        try:
            SamDB(url='ldap://127.0.0.1', credentials=credentials(password+'wrong'), lp=ldap_lp)
        except ldb.LdbError as error:
            if error.args[0] != ldb.ERR_INVALID_CREDENTIALS:
                raise
        else:
            raise ValueError('Invalid password was accepted')
        # Default Domain Policy is readable by an ordinary authenticated user.
        # Compare actual SMB bytes with the recovered file, not just a tree connect.
        stage = 'ntlm-sysvol'
        relative = realm.lower()+'/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI'
        expected = (pathlib.Path(paths.sysvol)/relative).read_bytes()
        if not expected or len(expected) > 1024*1024:
            raise ValueError('Invalid default policy GPT.INI')
        connection = libsmb.Conn('127.0.0.1', 'sysvol', client_lp, creds, force_smb1=False)
        if connection.loadfile(relative.replace('/', '\\')) != expected:
            raise ValueError('SYSVOL SMB content mismatch')
        # A fresh in-memory TGT and MUST_USE_KERBEROS forbid a successful NTLM
        # fallback from being mistaken for a working KDC or service principal.
        stage = 'kerberos-tgt'
        kerberos_creds = credentials(password, kerberos=True)
        kerberos_creds.get_named_ccache(ldap_lp, kerberos_cache)
        stage = 'kerberos-ldap'
        kerberos_bound = SamDB(url='ldap://'+controller, credentials=kerberos_creds, lp=ldap_lp)
        kerberos_domain = kerberos_bound.search(base=kerberos_bound.domain_dn(), scope=ldb.SCOPE_BASE, attrs=['objectGUID'])[0]
        kerberos_users = kerberos_bound.search(expression='(sAMAccountName='+username+')', attrs=['objectGUID'])
        if bytes(kerberos_domain['objectGUID'][0]) != domain_guid or len(kerberos_users) != 1 or bytes(kerberos_users[0]['objectGUID'][0]) != user_guid:
            raise ValueError('Kerberos LDAP identity mismatch')
        stage = 'kerberos-sysvol'
        smb_kerberos_creds = credentials('', kerberos=True)
        smb_kerberos_creds.set_named_ccache(kerberos_cache, SPECIFIED, ldap_lp)
        if smb_kerberos_creds.get_kerberos_state() != MUST_USE_KERBEROS:
            raise ValueError('Kerberos requirement was changed')
        # Explicitly request the CIFS service ticket as well as requiring
        # Kerberos in SMB; a different service ticket must not satisfy this check.
        cifs_security = gensec.Security.start_client({'lp_ctx': ldap_lp, 'target_hostname': controller})
        cifs_security.set_credentials(smb_kerberos_creds)
        cifs_security.set_target_hostname(controller)
        cifs_security.set_target_service('cifs')
        cifs_security.start_mech_by_name('gssapi_krb5')
        _, cifs_token = cifs_security.update(b'')
        if not cifs_token:
            raise ValueError('CIFS Kerberos service ticket unavailable')
        del cifs_token
        kerberos_smb = libsmb.Conn(controller, 'sysvol', client_lp, smb_kerberos_creds, force_smb1=False)
        if kerberos_smb.loadfile(relative.replace('/', '\\')) != expected:
            raise ValueError('Kerberos SYSVOL SMB content mismatch')
        if daemon.poll() is not None:
            raise ValueError('Restored DC exited during verification')
        result.send(dict(dcStarted=True, userLogin=True, invalidPasswordRejected=True,
                         sysvolRead=True, authentication='temporary-user-ntlm-and-kerberos',
                         kerberosTGT=True, kerberosLDAP=True, kerberosSYSVOL=True,
                         sysvolPath=relative))
    except BaseException:
        traceback.print_exc()
        result.send(dict(failedStage=stage))
    finally:
        result.close()


def verify_live_restore(config, job, timeout=90):
    import multiprocessing, signal, ctypes, time
    require_isolated_network()
    # Adopt daemon descendants even when Samba creates its own process groups.
    libc = ctypes.CDLL(None, use_errno=True)
    previous = ctypes.c_int()
    if libc.prctl(37, ctypes.byref(previous), 0, 0, 0) != 0 or libc.prctl(36, 1, 0, 0, 0) != 0:
        raise ValueError('Cannot supervise restored DC descendants')
    context = multiprocessing.get_context('fork')
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=live_restore_probe, args=(config, job, sender))
    process.start()
    sender.close()
    try:
        if not receiver.poll(5) or receiver.recv() != 'started':
            raise ValueError('Live restore worker did not start')
        if not receiver.poll(timeout):
            raise ValueError('Live restore verification timed out')
        evidence = receiver.recv()
        if not evidence or evidence.get('failedStage'):
            raise ValueError('Live restore verification failed at '+(evidence or {}).get('failedStage', 'unknown'))
        return evidence
    finally:
        # Walk descendants as well as the process group: smbd may create
        # independent sessions. Subreaping keeps them owned by this worker.
        for attempt in range(100):
            parents = {}
            for entry in pathlib.Path('/proc').iterdir():
                if not entry.name.isdecimal():
                    continue
                try:
                    fields = (entry/'stat').read_text().rsplit(')', 1)[1].split()
                    parents[int(entry.name)] = int(fields[1])
                except FileNotFoundError:
                    continue
            descendants = {os.getpid()}
            while True:
                expanded = descendants | {pid for pid, ppid in parents.items() if ppid in descendants}
                if expanded == descendants:
                    break
                descendants = expanded
            descendants.discard(os.getpid())
            for pid in descendants:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.join(0.05)
            while True:
                try:
                    if os.waitpid(-1, os.WNOHANG)[0] == 0:
                        break
                except ChildProcessError:
                    break
            if not descendants:
                break
            time.sleep(0.05)
        receiver.close()
        libc.prctl(36, previous.value, 0, 0, 0)
        if descendants:
            raise ValueError('Restored DC processes did not stop')


def rehearse_cleanup(directory, archive, job, checksum):
    """Offline database recovery and committed cleanup rehearsal, never live recovery."""
    plan=job.get('plan')
    if not plan or plan['revision']!=job['planRevision']:
        raise ValueError('Cleanup plan is required for restore verification')
    restored=restore_isolated(archive,directory/'rehearsal',checksum)
    import ldb
    lp,sam,_=identity(restored['config'],job)
    objects=plan['objects']
    if not objects or len(objects)>150:
        raise ValueError('Invalid cleanup count')
    sites={o['dn'].lower() for o in objects if b'site' in [base64.b64decode(v).lower() for v in o['attributes']['objectClass']] and o.get('findings')}
    def check_object(o):
        rows=sam.search(base=o['dn'],scope=ldb.SCOPE_BASE,attrs=list(o['attributes']))
        if len(rows)!=1:
            raise ValueError('Selected object missing from backup')
        entry=rows[0]
        for key,values in o['attributes'].items():
            if key in {'uSNChanged','whenChanged'}:
                continue
            actual=sorted(bytes(v) for v in entry.get(key,[]))
            if actual!=sorted(base64.b64decode(v,validate=True) for v in values):
                raise ValueError('Backup object differs from plan: '+o['dn']+' '+key)
        classes={bytes(v).lower() for v in entry['objectClass']}
        parent=str(entry.dn.parent()).lower()
        allowed=bool(o.get('findings')) and bool(classes & {b'site',b'sitelink',b'ntdsconnection'})
        if parent in sites and classes & {b'serverscontainer',b'ntdssitesettings'}:
            allowed=True
        codes={f.get('code') for f in o.get('findings',[]) if f.get('dn','').lower()==o['dn'].lower()}
        if b'server' in classes and codes & {'server_without_ntds','disabled_dc_metadata','server_computer_reference','server_without_computer'}:
            allowed=True
        if b'computer' in classes and codes & {'dc_computer_without_server','retired_server_computer'}:
            flags=int(bytes(entry['userAccountControl'][0]))
            allowed=bool(flags & 2 and flags & (8192|67108864))
        if 'retired_dc_child' in codes and classes & {b'ntdsdsa',b'ntdsconnection',b'ridset',b'msdfsr-localsettings',b'msdfsr-subscriber',b'msdfsr-subscription'}:
            allowed=True
        if 'retired_dc_connection' in codes and b'ntdsconnection' in classes:
            allowed=True
        if 'retired_dfsr_member' in codes and b'msdfsr-member' in classes:
            allowed=True
        if 'retired_dfsr_connection' in codes and b'msdfsr-connection' in classes:
            allowed=True
        if o.get('remove'):
            allowed=True
            for attr,values in o['remove'].items():
                if attr not in {'dnsRecord','msDS-NC-Replica-Locations','msDS-NC-RO-Replica-Locations','interSiteTopologyGenerator'} or not values:
                    raise ValueError('Unsupported cleanup modification')
                if attr=='dnsRecord' and b'dnsnode' not in classes:
                    raise ValueError('DNS modification requires dnsNode')
                if any(base64.b64decode(v) not in [bytes(x) for x in entry.get(attr,[])] for v in values):
                    raise ValueError('Removal value not found in restored database')
        if not o.get('remove'):
            selected={x['dn'].lower() for x in objects if not x.get('remove')}
            for child in sam.search(base=o['dn'],scope=ldb.SCOPE_ONELEVEL,attrs=['objectGUID']):
                if str(child.dn).lower() not in selected:
                    raise ValueError('Unplanned descendant in restored database')
        if not allowed:
            raise ValueError('Unsupported cleanup object')
    for obj in objects:
        check_object(obj)
    expected_deleted_links=set()
    deleted_guids={o['dn'].lower():base64.b64decode(o['guid']) for o in objects if not o.get('remove')}
    for obj in objects:
        for attr,values in obj.get('remove',{}).items():
            if attr in {'msDS-NC-Replica-Locations','msDS-NC-RO-Replica-Locations'}:
                for value in values:
                    target=base64.b64decode(value).decode().lower()
                    if target not in deleted_guids:
                        raise ValueError('Replica link target is not selected for deletion')
                    expected_deleted_links.add((obj['dn'].lower(),attr.lower(),deleted_guids[target]))
    def rank(obj):
        return (0 if obj.get('remove') else 1,-len(ldb.Dn(sam,obj['dn'])))
    ordered=sorted(objects,key=rank)
    # Match LDAP's committed per-operation semantics. Samba finalizes backlink
    # cleanup at transaction commit; an outer uncommitted transaction cannot
    # faithfully verify this plan. Recovery is tested by restoring the immutable
    # archive a second time after the committed cleanup, not by cancelling writes.
    for obj in ordered:
        if obj.get('remove'):
            message=ldb.Message();message.dn=ldb.Dn(sam,obj['dn'])
            for attr,values in obj['remove'].items():
                message[attr]=ldb.MessageElement([base64.b64decode(v) for v in values],ldb.FLAG_MOD_DELETE,attr)
            if 'dnsRecord' in obj['remove'] and len(obj['remove']['dnsRecord'])==len(obj['attributes']['dnsRecord']):
                message['dNSTombstoned']=ldb.MessageElement(['TRUE'],ldb.FLAG_MOD_REPLACE,'dNSTombstoned')
            sam.modify(message)
        else:
            sam.delete(obj['dn'])
    check_database(sam,expected_deleted_links)
    for obj in objects:
        if obj.get('remove'):
            entry=sam.search(base=obj['dn'],scope=ldb.SCOPE_BASE,attrs=list(obj['remove']))[0]
            for attr,values in obj['remove'].items():
                expected=sorted(base64.b64decode(v) for v in obj['attributes'][attr] if v not in values)
                if sorted(bytes(v) for v in entry.get(attr,[]))!=expected:
                    raise ValueError('Unexpected values after rehearsal modification')
            continue
        try:
            sam.search(base=obj['dn'],scope=ldb.SCOPE_BASE,attrs=['objectGUID'])
        except ldb.LdbError as error:
            if error.args[0]!=ldb.ERR_NO_SUCH_OBJECT:
                raise
        else:
            raise ValueError('Rehearsal deletion was not observed')
    del sam
    with tempfile.TemporaryDirectory(prefix='sambaadm-live-') as temporary:
        os.chmod(temporary, 0o711)
        recovered=restore_isolated(archive,pathlib.Path(temporary)/'recovery',checksum)
        lp,sam,_=identity(recovered['config'],job)
        for obj in objects:
            check_object(obj)
        check_database(sam)
        del sam
        try:
            live = verify_live_restore(recovered['config'], job)
        finally:
            # Keep bounded private daemon diagnostics after removing the image.
            with (directory/'live.log').open('x') as log:
                for name in ['live-process.log', 'live-samba.log']:
                    path = pathlib.Path(recovered['config']).parent/name
                    if path.exists():
                        with path.open(errors='replace') as source:
                            log.write(source.read(4*1024*1024))
    if digest_file(archive)!=checksum:
        raise ValueError('Archive changed during live verification')
    receipt=dict(id=job['id'],sha256=checksum,planRevision=job['planRevision'],status='verified',finished=now(),kind='live-dc-kerberos-ldap-sysvol-cleanup-second-restore-v2', live=live)
    save(directory/'restore.json',receipt)
    return receipt


def main():
    os.umask(0o077)
    if sys.argv[1]=='--restore-isolated':
        print(json.dumps(restore_isolated(pathlib.Path(sys.argv[2]),sys.argv[3],sys.argv[4])))
        return
    directory=pathlib.Path(sys.argv[1]);conf=sys.argv[2]
    job=json.loads((directory/'request.json').read_text())
    status=dict(job,status='running',started=now(),restoreVerified=False,format='sambaadm-cold-dc-v1')
    save(directory/'status.json',status)
    try:
        import contextlib
        with (directory/'worker.log').open('x') as log, contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
            archive=capture(directory,conf,job)
            checksum=digest_file(archive)
            rehearse_cleanup(directory,archive,job,checksum)
        status.update(status='backed_up',sha256=digest_file(archive),bytes=archive.stat().st_size,archive=archive.name)
    except Exception:
        with (directory/'worker.log').open('a') as log:
            traceback.print_exc(file=log)
        status.update(status='failed',error='Cold backup or isolated rehearsal failed; inspect the private helper log')
    status['finished']=now();save(directory/'status.json',status)


if __name__=='__main__':
    main()
