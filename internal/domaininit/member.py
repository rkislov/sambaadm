"""Fixed ALT domain-member file-server workflow; never provisions AD or changes an existing ID map."""
import hashlib, ipaddress, json, os, pathlib, re, shutil, socket, subprocess, tempfile, time

COMMON = ['samba', 'samba-common-tools', 'samba-winbind', 'samba-winbind-clients',
          'samba-client', 'python3-module-samba', 'krb5-kinit', 'bind-utils', 'acl', 'attr']
SSSD = ['sssd', 'sssd-ad', 'sssd-client', 'sssd-tools', 'sssd-winbind-idmap']
FILES = ['/etc/samba/smb.conf', '/etc/krb5.conf', '/etc/nsswitch.conf', '/etc/sssd/sssd.conf']
STATE = ['/var/lib/samba/private/secrets.tdb', '/var/lib/samba/secrets.tdb',
         '/var/lib/samba/winbindd_idmap.tdb', '/var/lib/samba/private/sam.ldb',
         '/var/lib/samba/private/secrets.ldb', '/var/lib/samba/sam.ldb', '/etc/krb5.keytab']

def validate(v):
    dns=lambda s: len(s)<=253 and '.' in s and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',p) for p in s.split('.'))
    if not dns(v.get('realm','')):raise RuntimeError('Недопустимый домен')
    for field in ['hostname','netbios']:
        if not re.fullmatch(r'[A-Za-z][A-Za-z0-9-]{0,14}',v.get(field,'')):raise RuntimeError('Недопустимое имя '+field)
    if v['hostname'].lower()==v['netbios'].lower():raise RuntimeError('Имя файлового сервера должно отличаться от NetBIOS домена')
    for field in ['source','panelName']:
        if not dns(v.get(field,'')) or not v[field].endswith('.'+v['realm']):raise RuntimeError('Имя '+field+' должно принадлежать домену')
    if v.get('identityProvider') not in ['winbind','sssd']:raise RuntimeError('Выберите Winbind или SSSD + Winbind')
    if any(v.get(k) for k in ['site','level','serviceUser','transferRoles','certificate','ca']):raise RuntimeError('Недопустимы параметры контроллера для файлового сервера')
    for field in ['address','forwarder']:
        ip=ipaddress.ip_address(v.get(field,''))
        if ip.version!=4 or ip.is_loopback or ip.is_multicast or ip.is_unspecified:raise RuntimeError('Нужен IPv4 сервера и доменного DNS')
    if v['address']==v['forwarder']:raise RuntimeError('Доменный DNS должен быть на другом сервере')
    if len(v.get('password',''))>1024 or len(v.get('username',''))>256 or any(c in v.get('username','')+v.get('password','') for c in '\x00\r\n') or '%' in v.get('username',''):raise RuntimeError('Недопустимые учётные данные')

def packages(v):return COMMON+(SSSD if v['identityProvider']=='sssd' else [])

def pristine(w):
    w['pristine']()
    if any(pathlib.Path(p).exists() or pathlib.Path(p).is_symlink() for p in STATE):raise RuntimeError('Сервер уже присоединялся к домену или содержит keytab/ID-map. Автоматическая смена профиля запрещена.')
    for file in FILES:
        path=pathlib.Path(file)
        if path.is_symlink() or (path.exists() and not path.is_file()):raise RuntimeError('Нештатный файл '+file)
    sssd=pathlib.Path('/etc/sssd/sssd.conf')
    if sssd.exists() and sssd.stat().st_size:
        try:w['unmodified_vendor'](sssd)
        except Exception:raise RuntimeError('SSSD уже настроен. Подготовьте чистый сервер без замены существующих UID/GID.')
    if pathlib.Path('/var/lib/sss/db').exists() and any(pathlib.Path('/var/lib/sss/db').iterdir()):raise RuntimeError('Обнаружена база SSSD; профиль не будет заменён')
    nss=pathlib.Path('/etc/nsswitch.conf').read_text()
    for line in nss.splitlines():
        if re.match(r'^\s*(passwd|group):',line) and any(p in line.split('#')[0].split()[1:] for p in ['sss','winbind','ldap']):raise RuntimeError('Доменные источники NSS уже настроены; автоматическая замена запрещена')
    root=pathlib.Path('/srv/samba')
    if root.is_symlink() or root.exists() and (not root.is_dir() or any(root.iterdir())):raise RuntimeError('/srv/samba содержит данные; мастер предназначен для нового файлового сервера')
    p=subprocess.run(['systemctl','is-active','--quiet','sssd'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    if p.returncode==0:raise RuntimeError('SSSD уже запущен; подготовьте чистый сервер')

def preflight(v,w):
    pristine(w)
    run=w['run']
    interfaces=json.loads(run(['ip','-j','address','show']))
    if not any(a.get('local')==v['address'] for i in interfaces for a in i.get('addr_info',[])):raise RuntimeError('IPv4 не назначен серверу')
    if shutil.disk_usage('/var/lib').free<2*1024**3:raise RuntimeError('Нужно 2 ГиБ свободного места в /var/lib')
    # The OS resolver must already point at AD DNS; no overwrite of managed resolv.conf.
    socket.getaddrinfo(v['source'],389)
    for port in [88,389,445]:
        with socket.create_connection((v['source'],port),timeout=5):pass
    w['check_forwarder'](v['forwarder'])
    w['local_helper_package']()
    candidates=w['repository_plan'](packages(v))
    fingerprint={'input':w['canonical'](v),'packages':candidates,'hostname':socket.gethostname(),
        'files':{p:hashlib.sha256(pathlib.Path(p).read_bytes() if pathlib.Path(p).exists() else b'').hexdigest() for p in FILES},
        'workers':{p:hashlib.sha256(pathlib.Path(__file__).with_name(p).read_bytes()).hexdigest() for p in ['member.py','worker.py']}}
    revision=hashlib.sha256(json.dumps(fingerprint,sort_keys=True).encode()).hexdigest()
    profile='SSSD + Winbind (idmap_sss)' if v['identityProvider']=='sssd' else 'Winbind (idmap_rid)'
    return {'revision':revision,'packages':[k+' = '+x for k,x in candidates.items()],
        'checks':['ALT Linux, systemd, чистый сервер без существующих ID-map и ресурсов','Постоянный IPv4; исходный DC доступен по DNS, Kerberos, LDAP и SMB','Доступны репозитории и helper той же версии','Профиль: '+profile],
        'steps':['Скачать все пакеты до изменения конфигурации','Сохранить конфигурацию и задать имя сервера','Проверить доменный DNS и свободное имя компьютера; присоединить участника AD',
        'Настроить '+profile+'; проверить доверие, SID и одинаковые UID/GID в NSS и Samba','Подготовить /srv/samba с 0755 и проверить POSIX ACL/xattr','Запустить smb после служб идентификации; ресурсы создаются отдельно в панели','Подключить helper файлового сервера из существующей панели по SSH']}

def modern_keytab(run):
    match=re.search(r'([0-9]+)\.([0-9]+)',run(['net','--version'],10))
    if not match:raise RuntimeError('Не удалось определить версию Samba')
    return tuple(map(int,match.groups()))>=(4,21)

def smb_config(v, modern_keytab=True):
    profile=v['identityProvider'];domain=v['netbios'].upper()
    backend='sss' if profile=='sssd' else 'rid'
    upper='2000200000' if profile=='sssd' else '1999999'
    lower='200000' if profile=='sssd' else '1000000'
    return ('[global]\nserver role = member server\nsecurity = ADS\nrealm = '+v['realm'].upper()+'\nworkgroup = '+domain+'\nnetbios name = '+v['hostname'].upper()+
        '\ninterfaces = lo '+v['address']+'\nbind interfaces only = yes\nkerberos method = secrets and keytab\nserver min protocol = SMB2_02\nmap to guest = Never\nwinbind use default domain = no\nwinbind refresh tickets = yes\n'+
        'idmap config * : backend = tdb\nidmap config * : range = 10000-199999\nidmap config '+domain+' : backend = '+backend+'\nidmap config '+domain+' : range = '+lower+'-'+upper+
        '\ntemplate shell = /sbin/nologin\ntemplate homedir = /home/%D/%U\nload printers = no\nprinting = bsd\nprintcap name = /dev/null\n'+
        'create mask = 0660\ndirectory mask = 0770\n'+('sync machine password to keytab = /etc/krb5.keytab:account_name:sync_kvno:machine_password\n' if profile=='sssd' and modern_keytab else 'machine password timeout = 0\n' if profile=='sssd' else ''))

def sssd_config(v, modern_keytab=True):
    return ('[sssd]\nconfig_file_version = 2\nservices = nss, pam\ndomains = '+v['realm']+'\n[domain/'+v['realm']+']\nid_provider = ad\nauth_provider = ad\naccess_provider = ad\nad_domain = '+v['realm']+
        '\nkrb5_realm = '+v['realm'].upper()+'\nad_hostname = '+v['hostname'].lower()+'.'+v['realm']+
        '\nuse_fully_qualified_names = True\nldap_id_mapping = True\nldap_idmap_range_min = 200000\nldap_idmap_range_max = 2000200000\nldap_idmap_range_size = 200000\n'+
        'cache_credentials = True\nfallback_homedir = /home/%d/%u\ndefault_shell = /sbin/nologin\n'+('ad_maximum_machine_account_password_age = 0\n' if modern_keytab else 'ad_maximum_machine_account_password_age = 30\nad_update_samba_machine_account_password = True\n'))

def nss_config(text,provider):
    lines=[];found=set()
    for line in text.splitlines():
        match=re.match(r'^(\s*)(passwd|group):(.*)$',line)
        if match:
            key=match[2];found.add(key);body,sep,comment=match[3].partition('#')
            line=match[1]+key+': '+body.strip()+' '+provider+(' #'+comment if sep else '')
        lines.append(line)
    if found!={'passwd','group'}:raise RuntimeError('В nsswitch.conf нужны отдельные строки passwd и group')
    return '\n'.join(lines)+'\n'

def inspect_domain(v):
    from samba.param import LoadParm
    from samba.credentials import Credentials, MUST_USE_KERBEROS
    from samba.samdb import SamDB
    import ldb
    lp=LoadParm();lp.set('realm',v['realm'].upper());lp.set('workgroup',v['netbios'].upper());lp.set('client ldap sasl wrapping','seal')
    creds=Credentials();creds.guess(lp);creds.parse_string(v['username']);creds.set_password(v['password']);creds.set_kerberos_state(MUST_USE_KERBEROS)
    remote=SamDB(url='ldap://'+v['source'],lp=lp,credentials=creds)
    expected=','.join('DC='+p for p in v['realm'].split('.'))
    if str(remote.domain_dn()).casefold()!=expected.casefold():raise RuntimeError('Исходный DC обслуживает другой домен')
    refs=remote.search(base='CN=Partitions,'+str(remote.get_config_basedn()),scope=ldb.SCOPE_ONELEVEL,expression='(&(objectClass=crossRef)(nCName='+ldb.binary_encode(expected)+'))',attrs=['nETBIOSName'])
    if len(refs)!=1 or 'nETBIOSName' not in refs[0] or str(refs[0]['nETBIOSName'][0]).casefold()!=v['netbios'].casefold():raise RuntimeError('NetBIOS не совпал с исходным доменом')
    node=v['hostname'].lower()+'.'+v['realm']
    found=remote.search(base=remote.domain_dn(),scope=ldb.SCOPE_SUBTREE,expression='(&(objectClass=computer)(|(sAMAccountName='+ldb.binary_encode(v['hostname'].upper()+'$')+')(dNSHostName='+ldb.binary_encode(node)+')))',attrs=['dNSHostName'])
    if found:raise RuntimeError('Имя компьютера уже занято в AD; выберите свободное имя')

def join(v,w):
    # --stdin keeps the domain password out of argv, disk and inherited environment.
    args=['net','--use-kerberos=required','--client-protection=sign','--user='+v['username'],'--stdin','ads','join','--server='+v['source']]
    result=subprocess.run(args,input=v['password']+'\n',stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,errors='replace',timeout=120,env=w['ENV'])
    if result.returncode:raise RuntimeError('Присоединение не выполнено: '+result.stdout.replace(v['password'],'[скрыто]')[-1400:])

def verify(v,w):
    run=w['run'];run(['net','ads','testjoin'],20);run(['wbinfo','--check-secret'],20)
    # Verify a well-known group by SID, not a localized Domain Users name.
    # Name localization is handled below using the actual domain SID.
    domain_info=run(['wbinfo','--domain-info='+v['netbios'].upper()],20)
    match=re.search(r'(?mi)^\s*SID\s*:\s*(S-1-5-21-[0-9-]+)',domain_info)
    if not match:raise RuntimeError('Не получен SID домена')
    sid=match.group(1)+'-513'
    gid=int(run(['wbinfo','--sid-to-gid',sid],20).strip())
    group=run(['getent','group',str(gid)],20).strip().split(':')
    if len(group)<3 or int(group[2])!=gid:raise RuntimeError('NSS и Samba не согласовали GID доменной группы')
    roundtrip=run(['wbinfo','--gid-to-sid',str(gid)],20).strip()
    if roundtrip!=sid:raise RuntimeError('Обратное сопоставление GID → SID не совпало')
    user_sid=run(['wbinfo','--name-to-sid',v['username']],20).split()[0]
    uid=int(run(['wbinfo','--sid-to-uid',user_sid],20).strip())
    account=run(['getent','passwd',str(uid)],20).strip().split(':')
    if len(account)<4 or int(account[2])!=uid or run(['wbinfo','--uid-to-sid',str(uid)],20).strip()!=user_sid:raise RuntimeError('NSS и Samba не согласовали UID пользователя')
    return {'uid':uid,'userSID':user_sid,'user':account[0],'identityProvider':v['identityProvider'],'domainSID':match.group(1),'groupSID':sid,'gid':gid,'group':group[0]}

def deploy(v,folder,save,w):
    plan=w['preflight'](v)
    if plan['revision']!=v.get('revision'):raise RuntimeError('Параметры сервера или пакеты изменились; повторите проверку')
    if not v.get('confirm') or not v.get('password') or not v.get('username'):raise RuntimeError('Нужны подтверждение и доменная учётная запись')
    run=w['run'];pkgs=packages(v)
    save('Скачивание пакетов файлового сервера','download');run(['apt-get','--download-only','-y','install',*pkgs],300)
    pristine(w);save('Установка Samba и '+v['identityProvider'],'install');run(['apt-get','-y','--no-download','install',*pkgs],300);pristine(w)
    for p in FILES:
        path=pathlib.Path(p)
        if path.exists():shutil.copy2(path,folder/(path.name+'.before'))
    (folder/'hostname.before').write_text(socket.gethostname())
    node=v['hostname'].lower()+'.'+v['realm']
    # Fail before join if domain DNS is misconfigured or the name is not available.
    srv=run(['dig','+time=2','+tries=1','+short','@'+v['forwarder'],'_ldap._tcp.dc._msdcs.'+v['realm'],'SRV'],10)
    if not srv.strip():raise RuntimeError('Доменный DNS не вернул SRV контроллеров')
    inspect_domain(v)
    run(['hostnamectl','set-hostname',node])
    modern=modern_keytab(run)
    if v['identityProvider']=='sssd' and not modern and '--add-samba-data' not in run(['adcli','update','--help'],10):raise RuntimeError('Нужен adcli с синхронизацией Samba secrets.tdb')
    pathlib.Path('/etc/samba/smb.conf').write_text(smb_config(v,modern))
    pathlib.Path('/etc/krb5.conf').write_text('[libdefaults]\ndefault_realm = '+v['realm'].upper()+'\ndns_lookup_kdc = true\ndns_lookup_realm = false\nrdns = false\n')
    nss=pathlib.Path('/etc/nsswitch.conf');nss.write_text(nss_config(nss.read_text(),'sss' if v['identityProvider']=='sssd' else 'winbind'))
    if v['identityProvider']=='sssd':
        conf=pathlib.Path('/etc/sssd/sssd.conf');conf.parent.mkdir(mode=0o700,exist_ok=True);conf.write_text(sssd_config(v,modern));conf.chmod(0o600)
        run(['sssctl','config-check'],20)
    run(['testparm','-s'],15)
    save('Присоединение файлового сервера к существующему домену','join')
    join(v,w)
    run(['net','ads','keytab','create','-P'],30)
    if v['identityProvider']=='sssd' and not pathlib.Path('/etc/krb5.keytab').is_file():raise RuntimeError('Домен присоединён, но машинный keytab не создан; службы не запущены')
    if pathlib.Path('/etc/krb5.keytab').exists():pathlib.Path('/etc/krb5.keytab').chmod(0o600)
    if v['identityProvider']=='sssd':
        bind_dropin=pathlib.Path('/etc/systemd/system/winbind.service.d');bind_dropin.mkdir(parents=True,exist_ok=True)
        (bind_dropin/'sambaadm-sssd.conf').write_text('[Unit]\nRequires=sssd.service\nAfter=sssd.service\n')
        run(['systemctl','daemon-reload'])
        run(['systemctl','enable','--now','sssd'],30)
    run(['systemctl','enable','--now','winbind'],30)
    save('Проверка доверия и сопоставления SID ↔ UID/GID','verify')
    for attempt in range(15):
        try:report=verify(v,w);break
        except Exception:
            if attempt==14:raise
            time.sleep(2)
    root=pathlib.Path('/srv/samba');root.mkdir(mode=0o755,parents=True,exist_ok=True);root.chmod(0o755)
    with tempfile.TemporaryDirectory(prefix='.sambaadm-probe-',dir=root) as probe:
        run(['setfacl','-m','g:'+str(report['gid'])+':r-x',probe]);run(['getfacl','-n',probe])
        run(['setfattr','-n','user.sambaadm_probe','-v','1',probe]);run(['getfattr','-n','user.sambaadm_probe',probe])
    package=w['local_helper_package']();run(['rpm','-Uvh','--replacepkgs',str(package)],60)
    # Explicit ordering survives reboot; winbind remains needed in both profiles.
    dropin=pathlib.Path('/etc/systemd/system/smb.service.d');dropin.mkdir(parents=True,exist_ok=True)
    deps='winbind.service'+(' sssd.service' if v['identityProvider']=='sssd' else '')
    (dropin/'sambaadm-identity.conf').write_text('[Unit]\nRequires='+deps+'\nAfter=network-online.target '+deps+'\n')
    run(['systemctl','daemon-reload']);run(['systemctl','enable','--now','smb'],30)
    v['_report']=report
    save('Файловый сервер присоединён; доверие, GID, POSIX ACL и xattr проверены. Каталог /srv/samba имеет проход x.','complete')
    save('Откройте существующую панель → Настройки → Helper и подключите '+node+' по SSH; затем создайте ресурсы и примените шаблоны прав.')
