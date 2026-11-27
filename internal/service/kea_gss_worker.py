"""Restricted helper worker: native Kea GSS installation and Samba AD provisioning.
Account passwords are accepted/generated in memory, never stored in job input.
"""
import contextlib
import datetime
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import uuid

SOURCE_URL = 'https://downloads.isc.org/isc/kea/3.0.0/kea-3.0.0.tar.xz'
SOURCE_SHA256 = 'bf963d1e10951d8c570c6042afccf27c709d45e03813bd2639d7bb1cfc4fee76'
SOURCES = ['gss_tsig_api.cc', 'gss_tsig_callouts.cc', 'gss_tsig_cfg.cc', 'gss_tsig_context.cc', 'gss_tsig_impl.cc', 'gss_tsig_key.cc', 'gss_tsig_log.cc', 'gss_tsig_messages.cc', 'managed_key.cc', 'tkey_exchange.cc', 'version.cc']
BASE_PACKAGES = ['krb5-kinit', 'krb5-kadmin', 'python3-module-samba', 'bind-utils']
BUILD_PACKAGES = ['kea', 'kea-hooks', 'libkea-devel', 'gcc-c++', 'libkrb5-devel', 'libssl-devel', 'make', 'rpm-build', 'ca-certificates']
REDACT = []
WRITES = {}
ENV = dict(os.environ, PATH='/usr/sbin:/usr/bin:/sbin:/bin', LC_ALL='C')


def run(args, *, data=None, env=None, timeout=40, cwd=None):
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env or ENV, timeout=timeout, cwd=cwd)
    if result.returncode:
        detail = (result.stderr or result.stdout).decode(errors='replace')[-3000:]
        raise RuntimeError(f'{Path(args[0]).name}: {detail}')
    return result.stdout.decode(errors='replace').strip()


def private_directory(path):
    p=Path(path)
    if not p.is_absolute():raise ValueError('absolute state path required')
    p.mkdir(parents=True,mode=0o700,exist_ok=True)
    if p.is_symlink() or not p.is_dir():raise ValueError('invalid state directory')
    os.chmod(p,0o700)
    return p


def atomic(path, data, mode=0o600, owner=None):
    path=Path(path)
    if path.is_symlink():raise ValueError('symlink destination rejected')
    fd,name=tempfile.mkstemp(prefix='.sambaadm-gss-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as f:
            f.write(data if isinstance(data,bytes) else data.encode())
            if owner:os.fchown(f.fileno(),owner.pw_uid,owner.pw_gid)
            os.fchmod(f.fileno(),mode);f.flush();os.fsync(f.fileno())
        os.replace(name,path)
        WRITES[str(path)] = hashlib.sha256(data if isinstance(data,bytes) else data.encode()).hexdigest()
        directory=os.open(path.parent,os.O_RDONLY)
        try:os.fsync(directory)
        finally:os.close(directory)
    finally:
        if os.path.exists(name):os.unlink(name)


def text(value):return value.decode() if isinstance(value,bytes) else str(value)


def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def install_plan():
    try:
        run(['apt-cache','show','kea-gss-tsig']);mode='package';packages=['kea-dhcp-ddns','kea-gss-tsig',*BASE_PACKAGES]
    except RuntimeError:
        version=run(['kea-dhcp-ddns','-v'])
        if version!='2.6.0':raise ValueError('Нет пакета kea-gss-tsig и проверенной сборки для установленной версии Kea; поддерживается backport для 2.6.0 p10')
        mode='build';packages=[*BUILD_PACKAGES,*BASE_PACKAGES]
    simulation=run(['apt-get','-s','install',*packages])
    if any(line.lstrip().startswith('Remv ') for line in simulation.splitlines()):raise ValueError('План зависимостей удаляет пакеты; устраните конфликт вручную')
    try:target=run(['rpm','-q','--qf','%{VERSION}-%{RELEASE}.%{ARCH}','libkea'])
    except RuntimeError:target='not-installed'
    plan={'mode':mode,'packages':packages,'target':target,'simulation':simulation}
    if mode=='build':plan.update(source=SOURCE_URL,sha256=SOURCE_SHA256,license='MPL-2.0',description='Отдельный RPM с открытым GSS hook Kea 3.0.0, собранным против установленной libkea 2.6.0; демон и прочие hooks не заменяются')
    plan['revision']=digest(plan)
    return plan


def install_job(directory):
    import fcntl
    root=private_directory(directory)
    lock=open(root.parents[2]/'operations.lock','a+b')
    fcntl.flock(lock.fileno(),fcntl.LOCK_EX)
    request=json.loads((root/'input.json').read_text())
    def save(state,phase,detail=''):
        atomic(root/'status.json',json.dumps({'id':root.name,'state':state,'phase':phase,'detail':detail,'updated':datetime.datetime.now(datetime.timezone.utc).isoformat()}))
    save('running','Проверка плана установки')
    try:
        plan=install_plan()
        if request.get('revision')!=plan['revision']:raise ValueError('Состав пакетов изменился; повторите предпросмотр')
        save('running','Установка зависимостей')
        log=run(['apt-get','-y','install',*plan['packages']],timeout=900)
        atomic(root/'install.log',log)
        if plan['mode']=='build':
            if run(['kea-dhcp-ddns','-v'])!='2.6.0':raise ValueError('Версия Kea изменилась после установки зависимостей')
            save('running','Загрузка проверенного исходного архива ISC')
            with urllib.request.urlopen(SOURCE_URL,timeout=40) as response:archive=response.read(64*1024*1024+1)
            if len(archive)>64*1024*1024 or hashlib.sha256(archive).hexdigest()!=SOURCE_SHA256:raise ValueError('Контрольная сумма источника ISC не совпала')
            archive_path=root/'kea-3.0.0.tar.xz';atomic(archive_path,archive)
            source=private_directory(root/'source')
            with tarfile.open(archive_path,'r:xz') as tar:
                for member in tar:
                    prefix='kea-3.0.0/src/hooks/d2/gss_tsig/'
                    if member.isfile() and member.name.startswith(prefix):
                        name=member.name[len(prefix):]
                        if '/' not in name and name.endswith(('.h','.cc')):atomic(source/name,tar.extractfile(member).read())
                    elif member.isfile() and member.name=='kea-3.0.0/COPYING':atomic(source/'COPYING',tar.extractfile(member).read())
            save('running','Сборка GSS hook против libkea 2.6.0')
            libraries=['d2srv','dns++','process','http','cfgclient','asiodns','asiolink','hooks','cc','log','exceptions','util','cryptolink','dhcp_ddns','stats']
            compiled=source/'libddns_gss_tsig.so'
            output=run(['g++','-std=c++17','-O2','-fPIC','-shared','-pthread','-I.','-I/usr/include/kea','-Wl,--no-undefined','-o',str(compiled),*SOURCES,*['-lkea-'+lib for lib in libraries],'-lgssapi_krb5','-lkrb5','-lcrypto','-llog4cplus'],cwd=source,timeout=900)
            atomic(root/'build.log',output)
            save('running','Сборка и установка совместимого RPM')
            builder_name='sambaadm-kea-build'
            try:builder=pwd.getpwnam(builder_name)
            except KeyError:
                run(['useradd','--system','--no-create-home','--shell','/sbin/nologin',builder_name]);builder=pwd.getpwnam(builder_name)
            top=Path(tempfile.mkdtemp(prefix='sambaadm-kea-gss-',dir='/var/tmp'))
            os.chown(top,builder.pw_uid,builder.pw_gid)
            build_source=top/'payload';build_source.mkdir(mode=0o700)
            for name in ['libddns_gss_tsig.so','COPYING']:shutil.copyfile(source/name,build_source/name)
            compiled=build_source/'libddns_gss_tsig.so'
            for name in ['BUILD','BUILDROOT','RPMS','SOURCES','SPECS','SRPMS']:private_directory(top/name)
            libdir=run(['rpm','--eval','%{_libdir}'])
            if libdir not in ['/usr/lib64','/usr/lib']:raise ValueError('unsupported library directory')
            evr=run(['rpm','-q','--qf','%{VERSION}-%{RELEASE}','libkea'])
            if not re.fullmatch(r'[0-9a-zA-Z.+_-]+',evr):raise ValueError('invalid libkea EVR')
            manifest={'source':SOURCE_URL,'sha256':SOURCE_SHA256,'target':evr,'license':'MPL-2.0','built':datetime.datetime.now(datetime.timezone.utc).isoformat()}
            atomic(build_source/'source.json',json.dumps(manifest,indent=2))
            spec=f'''Name: kea-gss-tsig-sambaadm
Version: 3.0.0
Release: alt1.kea26
Summary: GSS-TSIG hook built for the installed ALT p10 Kea
License: MPL-2.0
Group: System/Servers
URL: https://www.isc.org/kea/
Requires: libkea = {evr}
Conflicts: kea-gss-tsig
%description
Open ISC GSS-TSIG hook built against ALT libkea 2.6.0. Exact ABI dependency.
The source archive and its hash are recorded in source.json. No daemon replacement.
%prep
%build
%install
mkdir -p %buildroot{libdir}/kea/hooks %buildroot/usr/share/doc/kea-gss-tsig-sambaadm
install -m755 {compiled} %buildroot{libdir}/kea/hooks/libddns_gss_tsig.so
install -m644 {build_source}/COPYING {build_source}/source.json %buildroot/usr/share/doc/kea-gss-tsig-sambaadm/
%files
{libdir}/kea/hooks/libddns_gss_tsig.so
/usr/share/doc/kea-gss-tsig-sambaadm
'''
            spec_path=top/'SPECS/gss.spec';atomic(spec_path,spec)
            for current,dirs,files in os.walk(top):
                os.chown(current,builder.pw_uid,builder.pw_gid)
                for name in files:os.chown(Path(current)/name,builder.pw_uid,builder.pw_gid)
            run(['runuser','-u',builder_name,'--','rpmbuild','-bb','--define','_topdir '+str(top),str(spec_path)],timeout=180)
            rpms=list((top/'RPMS').rglob('kea-gss-tsig-sambaadm-3.0.0-*.rpm'))
            if len(rpms)!=1:raise ValueError('RPM output not found')
            run(['rpm','-Uvh','--replacepkgs','--test',str(rpms[0])]);run(['rpm','-Uvh','--replacepkgs',str(rpms[0])]);shutil.copyfile(rpms[0],root/rpms[0].name);shutil.rmtree(top)
        paths=[Path(d)/'kea/hooks/libddns_gss_tsig.so' for d in ['/usr/lib64','/usr/lib']]
        library=next((p for p in paths if p.is_file()),None)
        if not library:raise ValueError('Установка завершилась без GSS hook')
        save('complete','GSS-TSIG установлен',str(library))
    except Exception as e:
        save('failed','Установка не завершена',str(e)[-5000:])


def connection(value):
    import ldb
    from samba import param
    from samba.auth import system_session
    from samba.credentials import Credentials
    from samba.samdb import SamDB
    node=value['node'];controller=value['gss']['controller'].lower()
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}',controller) or '.' not in controller:raise ValueError('Укажите FQDN контроллера Samba AD')
    lp=param.LoadParm();lp.load_default();lp.set('ldap timeout','15')
    user=value.get('user','');secret=value.get('secret','')
    if user and secret:
        lp.set('tls verify peer','ca_and_name');lp.set('client ldap sasl wrapping','plain')
        if value.get('ca'):lp.set('tls cafile',value['ca'])
        credentials=Credentials();credentials.guess(lp);credentials.parse_string(user);credentials.set_bind_dn(user);credentials.set_password(secret)
        sam=SamDB(url='ldaps://'+controller,session_info=system_session(),credentials=credentials,lp=lp)
    else:
        expected=(lp.get('netbios name')+'.'+lp.get('realm')).lower()
        if lp.get('server role')!='active directory domain controller' or controller!=expected:raise ValueError('Для удалённого DC войдите по паролю с учётной записью, имеющей права управления учётными записями и ACL DNS-зон')
        sam=SamDB(session_info=system_session(),lp=lp)
    if str(sam.domain_dn()).lower()!=value['baseDN'].lower():raise ValueError('Домен DC отличается от настроенного домена helper')
    return sam,lp


def domain_plan(value):
    import ldb
    from samba import sd_utils
    from samba.dcerpc import security
    sam,lp=connection(value)
    base=str(sam.domain_dn());realm='.'.join(part[3:] for part in base.split(',') if part.upper().startswith('DC=')).upper()
    node=value['node'].lower()
    if not node or len(node)>253:raise ValueError('У helper не задано имя узла')
    members=sorted(set(name.lower() for name in value['gss'].get('members',[])))
    if members and (len(members)!=2 or node not in members or any(not re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,252}',name) for name in members)):raise ValueError('HA должна содержать два разных узла, включая текущий helper')
    identity='|'.join(members) if members else node
    account='kea-ddns-'+hashlib.sha256(identity.encode()).hexdigest()[:11]
    principal=account+'@'+realm
    marker='sambaadm:kea-ddns:'+identity
    found=sam.search(base=base,expression='(sAMAccountName='+ldb.binary_encode(account)+')',attrs=['objectGUID','objectSid','description','msDS-KeyVersionNumber','userPrincipalName','uSNChanged'])
    existing=None
    if found:
        if len(found)!=1 or text(found[0].get('description',[''])[0])!=marker:raise ValueError('Имя служебной учётной записи уже занято посторонним объектом')
        entry=found[0]
        existing={'dn':str(entry.dn),'revision':text(entry['uSNChanged'][0]),'guid':text(sam.schema_format_value('objectGUID',entry['objectGUID'][0])),'sid':str(security.dom_sid.from_bytes(entry['objectSid'][0])) if hasattr(security.dom_sid,'from_bytes') else None,'kvno':int(text(entry.get('msDS-KeyVersionNumber',[b'0'])[0]))}
        if not existing['sid']:
            from samba.ndr import ndr_unpack
            existing['sid']=str(ndr_unpack(security.dom_sid,entry['objectSid'][0]))
    names=[value['ddns']['forwardZone'],*value['ddns']['reverseZones']]
    names=list(dict.fromkeys(name.lower().rstrip('.') for name in names))
    if not names or len(names)>513:raise ValueError('invalid zone list')
    root=sam.search(base='',scope=ldb.SCOPE_BASE,attrs=['namingContexts','defaultNamingContext'])[0]
    dns_bases=[]
    for context in root['namingContexts']:
        context=text(context)
        if context.lower().startswith(('dc=domaindnszones,','dc=forestdnszones,')):dns_bases.append('CN=MicrosoftDNS,'+context)
    dns_bases.append('CN=MicrosoftDNS,CN=System,'+base)
    sd=sd_utils.SDUtils(sam);zones=[];missing=[]
    for name in names:
        if not re.fullmatch(r'[a-z0-9_-]+(?:\.[a-z0-9_-]+)+',name):raise ValueError('invalid DNS zone')
        rows=[]
        for search_base in dns_bases:
            try:rows.extend(sam.search(base=search_base,scope=ldb.SCOPE_ONELEVEL,expression='(&(objectClass=dnsZone)(name='+ldb.binary_encode(name)+'))',attrs=['objectGUID']))
            except ldb.LdbError as e:
                if e.args[0]!=ldb.ERR_NO_SUCH_OBJECT:raise
        if not rows:missing.append(name);continue
        if len(rows)!=1:raise ValueError('Неоднозначная DNS-зона '+name)
        row=rows[0];sddl=sd.get_sd_as_sddl(str(row.dn))
        zones.append({'name':name+'.','dn':str(row.dn),'guid':text(sam.schema_format_value('objectGUID',row['objectGUID'][0])),'revision':hashlib.sha256(sddl.encode()).hexdigest()})
    if missing:raise ValueError('Сначала создайте DNS-зоны: '+', '.join(missing))
    domain=sam.search(base=base,scope=ldb.SCOPE_BASE,attrs=['objectGUID','objectSid'])[0]
    dns_host=value['gss'].get('dnsHost') or value['gss']['controller']
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}',dns_host) or not dns_host.lower().endswith('.'+realm.lower()):raise ValueError('DNS-сервер должен быть FQDN в выбранном домене')
    target_ip=ipaddress.ip_address(value['ddns']['dnsAddress'])
    resolved={ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(dns_host,None,type=socket.SOCK_STREAM)}
    if target_ip not in resolved:raise ValueError('IP DNS-сервера не соответствует указанному DNS FQDN')
    spn='DNS/'+dns_host.lower()
    principals=sam.search(base=base,expression='(servicePrincipalName='+ldb.binary_encode(spn)+')',attrs=['objectGUID'])
    if len(principals)!=1:raise ValueError('В AD отсутствует однозначный SPN '+spn)
    plan={'controller':value['gss']['controller'].lower(),'realm':realm,'domainGUID':text(sam.schema_format_value('objectGUID',domain['objectGUID'][0])),'account':account,'principal':principal,'dnsAccountGUID':text(sam.schema_format_value('objectGUID',principals[0]['objectGUID'][0])),'serverPrincipal':spn+'@'+realm,'accountState':existing,'zones':zones,'node':node,'members':members,'keytab':value['keytab'],'rotate':bool(value['gss'].get('rotate')),'marker':marker,'conflictMode':'no-check-without-dhcid','rights':'Создание dnsNode и чтение в выбранных зонах, обновление собственных записей; без DnsAdmins и без записи чужих узлов'}
    plan['revision']=digest(plan)
    return plan,sam,lp,sd


def schema_guid(sam,name):
    import ldb
    from samba.ndr import ndr_unpack
    from samba.dcerpc import misc
    row=sam.search(base=sam.get_schema_basedn(),expression='(lDAPDisplayName='+ldb.binary_encode(name)+')',attrs=['schemaIDGUID'])[0]
    return str(ndr_unpack(misc.GUID,row['schemaIDGUID'][0]))


def as_kea(args,env,*,data=None):return run(['runuser','-u','_kea','--',*args],env=env,data=data,timeout=30)


def credentials_units(config_dir,keytab,principal):
    # Files are created by a transient root worker outside the helper sandbox.
    cache='FILE:/run/kea/sambaadm-ddns/ccache'
    env_path=config_dir/'sambaadm-gss.env'
    atomic(env_path,f'KRB5_CONFIG={config_dir}/sambaadm-krb5.conf\nKRB5CCNAME={cache}\nKEA_DDNS_KEYTAB={keytab}\nKEA_DDNS_PRINCIPAL={principal}\n',0o600)
    service='''[Unit]
Description=Kea DDNS Kerberos credentials
Wants=network-online.target
After=network-online.target
ConditionPathExists=/etc/kea/sambaadm-gss.env
[Service]
Type=oneshot
User=_kea
Group=_kea
RuntimeDirectory=kea/sambaadm-ddns
RuntimeDirectoryPreserve=yes
RuntimeDirectoryMode=0700
EnvironmentFile=/etc/kea/sambaadm-gss.env
ExecStart=/usr/bin/kinit -k -t ${KEA_DDNS_KEYTAB} -c FILE:/run/kea/sambaadm-ddns/ccache ${KEA_DDNS_PRINCIPAL}
NoNewPrivileges=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/run/kea
'''.replace('/etc/kea/sambaadm-gss.env',str(env_path))
    timer='''[Unit]
Description=Refresh Kea DDNS Kerberos credentials
[Timer]
OnBootSec=1min
OnUnitActiveSec=30min
RandomizedDelaySec=30s
Unit=sambaadm-kea-ddns-credentials.service
[Install]
WantedBy=timers.target
'''
    dropin=f'''[Unit]
Wants=network-online.target
After=network-online.target time-sync.target
[Service]
RuntimeDirectory=kea/sambaadm-ddns
RuntimeDirectoryPreserve=yes
RuntimeDirectoryMode=0700
EnvironmentFile={env_path}
ExecStartPre=/usr/bin/kinit -k -t ${{KEA_DDNS_KEYTAB}} -c FILE:/run/kea/sambaadm-ddns/ccache ${{KEA_DDNS_PRINCIPAL}}
'''
    target=Path('/etc/systemd/system');(target/'kea-dhcp-ddns.service.d').mkdir(mode=0o755,parents=True,exist_ok=True)
    atomic(target/'sambaadm-kea-ddns-credentials.service',service,0o644);atomic(target/'sambaadm-kea-ddns-credentials.timer',timer,0o644);atomic(target/'kea-dhcp-ddns.service.d/20-sambaadm-gss.conf',dropin,0o644)
    run(['systemctl','daemon-reload']);run(['systemctl','start','sambaadm-kea-ddns-credentials.service']);run(['systemctl','enable','--now','sambaadm-kea-ddns-credentials.timer'])


def probe_zones(value,plan,env):
    address=value['ddns']['dnsAddress'];port=value['ddns']['dnsPort'];token=secrets.token_hex(12);created=[]
    try:
        for zone in plan['zones']:
            name='sambaadm-ddns-'+token+'.'+zone['name']
            script=f"server {address} {port}\nzone {zone['name']}\nprereq nxdomain {name}\n"
            if zone['name'].endswith(('.in-addr.arpa.','.ip6.arpa.')):script+=f'update add {name} 60 PTR probe.invalid.\n'
            else:script+=f'update add {name} 60 A 127.0.0.254\nupdate add {name} 60 AAAA ::1\n'
            created.append((zone['name'],name))
            try:as_kea(['nsupdate','-g','-v'],env,data=(script+'send\n').encode())
            except Exception as e:raise RuntimeError('Проверка A/AAAA или PTR в '+zone['name']+': '+str(e)+'; проверьте поддержку GSS-TSIG DNS-сервером (для Samba рекомендуется BIND9 DLZ)') from e
    finally:
        failures=[]
        for zone,name in created:
            try:as_kea(['nsupdate','-g','-v'],env,data=f'server {address} {port}\nzone {zone}\nupdate delete {name}\nsend\n'.encode())
            except Exception:failures.append(name)
        if failures:raise RuntimeError('Не удалось удалить проверочные записи: '+', '.join(failures))
    return 'no-check-without-dhcid'


def domain_apply(value):
    import ldb
    from samba.dcerpc import security
    from samba.ndr import ndr_unpack
    plan,sam,lp,sd=domain_plan(value)
    if value.get('revision')!=plan['revision']:raise ValueError('Состояние AD изменилось; повторите предпросмотр')
    config_dir=Path(value['configDir']);keytab=Path(value['keytab']);state=private_directory(Path(value['stateDir'])/'kea-gss')
    if not config_dir.is_absolute() or not keytab.is_absolute() or keytab.parent!=config_dir or any(c in str(config_dir)+str(keytab) for c in '\r\n\x00 "'):raise ValueError('keytab and configuration paths must be in the same safe Kea directory')
    config_dir.mkdir(mode=0o750,parents=True,exist_ok=True);owner=pwd.getpwnam('_kea')
    profile_path=config_dir/'sambaadm-gss-profile.json'
    profile={}
    if profile_path.is_file():profile=json.loads(profile_path.read_text())
    enrollment=value.get('enrollmentSecret','')
    if enrollment and (not plan['members'] or not re.fullmatch(r'[A-Za-z0-9_!.-]{48,128}',enrollment)):raise ValueError('Некорректный внутренний секрет HA')
    account=plan['account'];base=str(sam.domain_dn());dn=None;created=False;password=None;added=[];password_changed=False;sid=None;kvno=None
    old_key=keytab.read_bytes() if keytab.is_file() and not keytab.is_symlink() else None
    unit_root=Path('/etc/systemd/system')
    local_paths=[config_dir/'sambaadm-krb5.conf',config_dir/'sambaadm-gss.env',profile_path,unit_root/'sambaadm-kea-ddns-credentials.service',unit_root/'sambaadm-kea-ddns-credentials.timer',unit_root/'kea-dhcp-ddns.service.d/20-sambaadm-gss.conf']
    local_before={}
    for path in local_paths:
        if path.is_symlink():raise ValueError('symlink configuration rejected: '+str(path))
        if path.exists():
            info=path.stat();local_before[path]=(path.read_bytes(),info.st_mode&0o777,info.st_uid,info.st_gid)
        else:local_before[path]=None
    timer_before={}
    if not value.get('testNoSystemd'):
        for action in ['is-active','is-enabled']:
            try:timer_before[action]=run(['systemctl',action,'sambaadm-kea-ddns-credentials.timer'])
            except RuntimeError:timer_before[action]='inactive'
    journal=state/('ad-'+uuid.uuid4().hex+'.json')
    backup={'plan':plan,'descriptors':{z['dn']:sd.get_sd_as_sddl(z['dn']) for z in plan['zones']}}
    atomic(journal,json.dumps(backup))
    try:
        if plan['accountState'] is None:
            password=enrollment or 'Aa1!'+secrets.token_urlsafe(48);REDACT.append(password)
            sam.newuser(account,password,useusernameascn=True,description=plan['marker']);created=True
            dn='CN='+account+',CN=Users,'+base
        else:
            dn=plan['accountState']['dn']
            if value.get('enroll') and enrollment:
                password=enrollment;REDACT.append(password)
            elif plan['rotate']:
                password=enrollment or 'Aa1!'+secrets.token_urlsafe(48);REDACT.append(password);sam.setpassword('(sAMAccountName='+ldb.binary_encode(account)+')',password);password_changed=True
            elif not old_key or profile.get('accountSID')!=plan['accountState']['sid'] or profile.get('kvno')!=plan['accountState']['kvno'] or profile.get('keytabSHA256')!=hashlib.sha256(old_key).hexdigest():raise ValueError('Keytab отсутствует или не соответствует управляемой учётной записи; выберите явное обновление ключа')
        message=ldb.Message();message.dn=ldb.Dn(sam,dn)
        for name,item in {'userPrincipalName':plan['principal'],'msDS-SupportedEncryptionTypes':'24','userAccountControl':str(512|65536|1048576)}.items():message[name]=ldb.MessageElement(item,ldb.FLAG_MOD_REPLACE,name)
        sam.modify(message)
        row=sam.search(base=dn,scope=ldb.SCOPE_BASE,attrs=['objectSid','msDS-KeyVersionNumber'])[0]
        sid=str(ndr_unpack(security.dom_sid,row['objectSid'][0]));kvno=int(text(row['msDS-KeyVersionNumber'][0]))
        node_guid=schema_guid(sam,'dnsNode');record_guid=schema_guid(sam,'dnsRecord')
        aces=[f'(OA;;CC;{node_guid};;{sid})',f'(OA;CIIO;RP;{record_guid};{node_guid};{sid})']
        for zone in plan['zones']:
            current=sd.get_sd_as_sddl(zone['dn'])
            missing=[ace for ace in aces if ace not in current]
            if missing:sd.dacl_add_ace(zone['dn'],''.join(missing));added.append((zone['dn'],missing))
        kdc=plan['controller']
        krb=f'[libdefaults]\n default_realm = {plan["realm"]}\n rdns = false\n dns_lookup_kdc = false\n[realms]\n {plan["realm"]} = {{\n  kdc = {kdc}\n }}\n[domain_realm]\n .{plan["realm"].lower()} = {plan["realm"]}\n'
        atomic(config_dir/'sambaadm-krb5.conf',krb,0o640,owner)
        cache_dir=Path('/run/kea/sambaadm-ddns');cache_dir.mkdir(mode=0o700,parents=True,exist_ok=True);os.chown(cache_dir,owner.pw_uid,owner.pw_gid);os.chmod(cache_dir,0o700)
        env=dict(ENV,KRB5_CONFIG=str(config_dir/'sambaadm-krb5.conf'),KRB5CCNAME='FILE:'+str(cache_dir/('probe-'+uuid.uuid4().hex)))
        if password:
            fd,temporary=tempfile.mkstemp(prefix='.sambaadm-keytab-',dir=config_dir);os.close(fd);os.unlink(temporary)
            try:
                commands=''
                for enctype in ['aes256-cts-hmac-sha1-96','aes128-cts-hmac-sha1-96']:commands+=f'addent -password -p {plan["principal"]} -k {kvno} -e {enctype}\n{password}\n'
                commands+=f'write_kt {temporary}\nquit\n'
                run(['ktutil'],data=commands.encode(),env=env)
                atomic(keytab,Path(temporary).read_bytes(),0o600,owner)
            finally:
                if os.path.exists(temporary):os.unlink(temporary)
        try:
            as_kea(['kinit','-k','-t',str(keytab),'-c',env['KRB5CCNAME'],plan['principal']],env)
            conflict_mode=probe_zones(value,plan,env)
        finally:
            probe_cache=Path(env['KRB5CCNAME'][5:])
            if probe_cache.exists():probe_cache.unlink()
        profile={'account':account,'accountSID':sid,'principal':plan['principal'],'serverPrincipal':plan['serverPrincipal'],'realm':plan['realm'],'controller':plan['controller'],'kvno':kvno,'keytabSHA256':hashlib.sha256(keytab.read_bytes()).hexdigest(),'zones':[z['name'] for z in plan['zones']],'members':plan['members'],'conflictMode':conflict_mode,'verified':datetime.datetime.now(datetime.timezone.utc).isoformat()}
        if not value.get('testNoSystemd'):credentials_units(config_dir,keytab,plan['principal'])
        atomic(profile_path,json.dumps(profile),0o600)
        return {'ready':True,'principal':plan['principal'],'serverPrincipal':plan['serverPrincipal'],'keytab':str(keytab),'kvno':kvno,'conflictMode':conflict_mode,'zones':profile['zones'],'journal':str(journal),'detail':'AES keytab и права DNS проверены реальным GSS-TSIG обновлением и удалением проверочных записей'}
    except Exception as failure:
        rollback_errors=[]
        # Remove only ACEs added by this operation; never replace a concurrent ACL.
        for zone,aces in reversed(added):
            try:sd.dacl_delete_aces(zone,''.join(aces))
            except Exception:rollback_errors.append('ACL '+zone)
        if created and dn:
            try:sam.delete(dn)
            except Exception:rollback_errors.append('учётная запись '+account)
        if not password_changed:
            for path,previous in local_before.items():
                if str(path) not in WRITES:continue
                try:
                    if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest()!=WRITES[str(path)]:raise ValueError('concurrent edit')
                    if previous is None:
                        if path.exists():path.unlink()
                    else:
                        data,mode,uid,gid=previous;atomic(path,data,mode);os.chown(path,uid,gid)
                except Exception:rollback_errors.append('файл '+str(path))
            if not value.get('testNoSystemd'):
                for check,action in [('is-active','stop'),('is-enabled','disable')]:
                    if timer_before.get(check) not in ['active','enabled']:
                        try:run(['systemctl',action,'sambaadm-kea-ddns-credentials.timer'])
                        except Exception:rollback_errors.append('systemd timer '+action)
                try:run(['systemctl','daemon-reload'])
                except Exception:rollback_errors.append('systemd daemon-reload')
        if password_changed and keytab.is_file():
            pending={'account':account,'accountSID':sid,'principal':plan['principal'],'serverPrincipal':plan['serverPrincipal'],'realm':plan['realm'],'controller':plan['controller'],'kvno':kvno,'keytabSHA256':hashlib.sha256(keytab.read_bytes()).hexdigest(),'state':'needs-review'}
            atomic(profile_path,json.dumps(pending),0o600)
        elif old_key is not None:atomic(keytab,old_key,0o600,owner)
        elif keytab.exists():keytab.unlink()
        extra='; после смены пароля сохранён новый keytab, требуется повторное завершение настройки' if password_changed else ''
        if rollback_errors:extra+='; проверьте откат: '+', '.join(rollback_errors)
        raise RuntimeError(str(failure)+extra+'; журнал '+str(journal)) from failure


def main():
    if os.geteuid()!=0:raise ValueError('root helper required')
    if len(sys.argv)==3 and sys.argv[1]=='install-job':install_job(sys.argv[2]);return None
    value=json.loads(sys.stdin.buffer.read(262145))
    for name in ['secret','enrollmentSecret']:
        if value.get(name):REDACT.append(value[name])
    action=value['action']
    if action=='install-plan':return install_plan()
    if action=='ad-plan':return domain_plan(value)[0]
    if action=='ad-apply':return domain_apply(value)
    raise ValueError('unsupported GSS operation')

if __name__=='__main__':
    try:
        with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):result=main()
        if result is not None:print(json.dumps({'ok':True,'result':result}))
    except Exception as error:
        # Samba/LDAP diagnostics contain no password arguments; redact exact secrets anyway.
        detail=str(error)[-4000:]
        for secret in REDACT:
            if secret:detail=detail.replace(secret,'[скрыто]')
        print(json.dumps({'ok':False,'error':detail}));sys.exit(1)
