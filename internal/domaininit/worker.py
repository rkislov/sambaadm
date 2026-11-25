"""Fixed ALT Linux AD deployment worker. Passwords enter on stdin, never argv/files.
No user command, script, package name or filesystem path is accepted.
"""
import contextlib, fcntl, hashlib, ipaddress, json, logging, os, pathlib, re
import secrets, shutil, socket, subprocess, sys, time, types, pwd

SMB = pathlib.Path('/etc/samba/smb.conf')
PACKAGES = ['samba-dc', 'samba-common-tools', 'python3-module-samba', 'bind-utils', 'openssl']
DATABASES = ['/var/lib/samba/private/sam.ldb', '/var/lib/samba/sam.ldb', '/var/lib/samba/private/secrets.ldb']
ENV = {**os.environ, 'LC_ALL': 'C', 'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'}

def run(args, timeout=30):
    p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors='replace', timeout=timeout, env=ENV)
    if p.returncode:
        raise RuntimeError('Не выполнено '+args[0]+': '+p.stdout[-1500:])
    return p.stdout

def canonical(value):
    return {k: v for k, v in value.items() if k not in ['password', 'username', 'confirm', 'revision', 'certificate', 'ca']}

def validate(value):
    realm=value.get('realm','')
    dns=lambda s: len(s)<=253 and '.' in s and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',p) for p in s.split('.'))
    if not dns(realm) or value.get('mode') not in ['forest','DC','RODC','existing']: raise RuntimeError('Недопустимые параметры домена')
    for field in ['hostname','netbios']:
        if field=='netbios' and value['mode']=='existing' and not value.get(field):continue
        if not re.fullmatch(r'[A-Za-z][A-Za-z0-9-]{0,14}',value.get(field,'')): raise RuntimeError('Недопустимое короткое имя '+field)
    if value['hostname'].lower()==value['netbios'].lower() or not dns(value['hostname'].lower()+'.'+realm):raise RuntimeError('Имя DC должно отличаться от NetBIOS домена и образовывать корректное DNS-имя')
    site=value.get('site','')
    if (not site.strip() and value['mode']!='existing') or len(site)>64 or any(c in site for c in '\r\n\x00/\\'):raise RuntimeError('Недопустимое имя сайта')
    if value['mode']=='existing' and not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,19}',value.get('serviceUser','')):raise RuntimeError('Укажите имя новой служебной записи до 20 знаков')
    if value.get('serviceUser') and value['mode']!='existing':raise RuntimeError('Имя новой служебной записи задаётся только для существующего домена')
    if value.get('transferRoles') and value['mode']!='existing':raise RuntimeError('Перенос FSMO доступен только для существующего домена')
    address=ipaddress.ip_address(value.get('address',''))
    if address.version!=4 or address.is_loopback or address.is_multicast or address.is_unspecified:raise RuntimeError('Нужен адрес IPv4 интерфейса сервера')
    forwarder=ipaddress.ip_address(value.get('forwarder',''))
    if forwarder.is_loopback or forwarder.is_multicast or forwarder.is_unspecified or forwarder==address:raise RuntimeError('Нужен доступный внешний DNS-пересыльщик')
    if value.get('level') not in (['auto'] if value['mode']=='existing' else ['2003','2008','2008_R2']):raise RuntimeError('Недопустимый функциональный уровень')
    if value['mode'] in ['forest','existing']:
        if not dns(value.get('panelName','')) or not value['panelName'].endswith('.'+realm):raise RuntimeError('HTTPS-имя должно принадлежать новому домену')
    if value['mode']!='forest' and (not dns(value.get('source','')) or not value['source'].endswith('.'+realm)):raise RuntimeError('Нужен исходный RWDC этого домена')

def unmodified_vendor(path):
    run(['rpm','-qf',str(path)],10)
    p=subprocess.run(['rpm','-Vf',str(path)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=15,env=ENV)
    if p.returncode not in (0,1) or any(line.rstrip().endswith(' '+str(path)) and line.split()[0].replace('T','.').strip('.') for line in p.stdout.splitlines()):raise RuntimeError('Изменён файл '+str(path))

def pristine():
    if any(pathlib.Path(p).exists() for p in DATABASES):raise RuntimeError('На сервере уже есть база Samba AD. Развёртывание поверх домена запрещено.')
    if SMB.is_symlink():raise RuntimeError('smb.conf является ссылкой; проверьте конфигурацию вручную')
    if SMB.exists() and SMB.stat().st_size:
        # Only the unmodified vendor configuration can be replaced automatically.
        try: unmodified_vendor(SMB)
        except Exception:raise RuntimeError('smb.conf изменён или не принадлежит пакету. Сохраните конфигурацию и подготовьте чистый сервер.')
    for unit in ['samba','smb','nmb','winbind','bind']:
        p=subprocess.run(['systemctl','is-active','--quiet',unit],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if p.returncode==0:raise RuntimeError('Служба '+unit+' уже работает. Подготовьте отдельный чистый сервер.')

def repository_plan():
    try:
        output=run(['apt-get','-o','Acquire::http::Timeout=15','-o','Acquire::Retries=0','update'],120)
        if re.search(r'(?im)^(Err:|Err\s|E:|W:.*(?:failed|fetch|resolve))',output) or 'Some index files failed' in output:
            raise RuntimeError(output[-1800:])
        candidates={}
        for name in PACKAGES:
            text=run(['apt-cache','policy',name],5)
            match=re.search(r'(?m)^\s*Candidate:\s*(\S+)',text)
            if not match or match.group(1) in ['(none)','(null)']:raise RuntimeError('Пакет '+name+' недоступен')
            candidates[name]=match.group(1)
        text=run(['apt-get','-s','install',*PACKAGES],15)
        if re.search(r'(?m)^Remv\s',text):raise RuntimeError('План пакетов удаляет установленное ПО')
        return candidates
    except Exception as error:
        raise RuntimeError('Настройте доступные репозитории ALT Linux для этой версии ОС и архитектуры. Проверьте сеть, DNS, /etc/apt/sources.list и sources.list.d, затем повторите проверку. '+str(error))

def local_helper_package():
    version=run(['/usr/bin/sambaadm','version'],10)
    match=re.search(r'sambaadm v?([0-9]+\.[0-9]+\.[0-9]+)',version)
    if not match:raise RuntimeError('Для создания леса установите релизный RPM sambaadm с комплектом helper.')
    arch=os.uname().machine
    package=pathlib.Path('/usr/share/sambaadm/helper-packages')/('sambaadm-helper-'+match.group(1)+'-alt1.'+arch+'.rpm')
    if not package.is_file():raise RuntimeError('Не найден комплект helper той же версии, что панель. Переустановите полный RPM sambaadm.')
    metadata=run(['rpm','-qp','--qf','%{NAME} %{VERSION} %{RELEASE} %{ARCH}',str(package)],15).strip()
    if metadata!='sambaadm-helper '+match.group(1)+' alt1 '+arch:raise RuntimeError('Проверьте комплект helper: не совпадают версия или архитектура')
    run(['rpm','-Uvh','--test','--replacepkgs',str(package)],20)
    return package

def install_local_helper(value,folder,save):
    save('Установка и привязка helper первого контроллера', 'helper')
    package=local_helper_package();run(['rpm','-Uvh','--replacepkgs',str(package)],60)
    account=pwd.getpwnam('sambaadm');enrollment=pathlib.Path('/var/lib/sambaadm/enrollment')
    enrollment.mkdir(mode=0o700,parents=True,exist_ok=True)
    if enrollment.is_symlink():raise RuntimeError('Каталог привязок является ссылкой')
    os.chown(enrollment,account.pw_uid,account.pw_gid);enrollment.chmod(0o700)
    private=enrollment/'management.key';public=enrollment/'management.pub'
    if not private.exists():run(['runuser','-u','sambaadm','--','/usr/bin/sambaadm-helper','keygen','--private',str(private),'--public',str(public)],10)
    helper=pathlib.Path('/etc/sambaadm-helper');helper.mkdir(mode=0o700,exist_ok=True)
    shutil.copyfile(public,helper/'management.pub');(helper/'management.pub').chmod(0o600)
    node=value['hostname'].lower()+'.'+value['realm'];tls=pathlib.Path('/var/lib/samba/private/tls')
    settings={'helper':{'node':node,'trusted_keys':[str(helper/'management.pub')],'listen':'0.0.0.0:8444','tls':{'cert':str(tls/'cert.pem'),'key':str(tls/'key.pem')},'state_dir':'/var/lib/sambaadm-helper','backup_root':'/var/lib/sambaadm-helper/backups','sysvol_prefix':value['realm']+'/Policies'},'ldap':{'uri':'ldaps://'+node+':636','base_dn':','.join('DC='+p for p in value['realm'].split('.')),'ca_cert':'/etc/sambaadm/domain-ca.pem','bind':{'user':(value['serviceUser'] if value['mode']=='existing' else 'svc-sambaadm')+'@'+value['realm'],'password_env':'SAMBAADM_PASSWORD'}},'samba':{'smb_conf':str(SMB),'shares_root':'/srv/samba'},'audit':{'file':'/var/log/sambaadm-helper/audit.log'}}
    (helper/'config.yaml').write_text(json.dumps(settings));(helper/'config.yaml').chmod(0o600)
    dropin=pathlib.Path('/etc/systemd/system/sambaadm-helper.service.d');dropin.mkdir(parents=True,exist_ok=True)
    (dropin/'domain-env.conf').write_text('[Service]\nEnvironmentFile=/etc/sambaadm/env\n')
    managed={'PrivateKey':str(private),'HostNode':node,'Nodes':[{'Name':node,'Transport':'https','Endpoint':'https://'+node+':8444','CACert':'/etc/sambaadm/domain-ca.pem'}]}
    existing_nodes=enrollment/'nodes.json'
    if existing_nodes.exists():
        current=json.loads(existing_nodes.read_text())
        if current.get('PrivateKey')!=str(private) or current.get('HostNode') not in ['',node]:raise RuntimeError('Привязки helper изменены; автоматическая замена отменена')
        if any(n.get('Name')==node for n in current.get('Nodes',[])):raise RuntimeError('Helper этого узла уже привязан; проверьте его в рабочей панели')
        managed['Nodes']=current.get('Nodes',[])+managed['Nodes']
    candidate={'server':{'enrollment_dir':''},'helpers':{'private_key':str(private),'host_node':node,'nodes':[{'name':node,'transport':'https','endpoint':'https://'+node+':8444','ca_cert':'/etc/sambaadm/domain-ca.pem'}]}}
    (folder/'helper-check.json').write_text(json.dumps(candidate))
    run(['systemctl','daemon-reload']);run(['systemctl','enable','--now','sambaadm-helper'])
    checked=False
    for _ in range(10):
        try:run(['/usr/bin/sambaadm','--config',str(folder/'helper-check.json'),'helper-check',node],25);checked=True;break
        except Exception:time.sleep(1)
    if not checked:raise RuntimeError('Helper установлен, но подпись и TLS не подтверждены. Проверьте службу; привязка не сохранена.')
    staging=enrollment/'.nodes.init';staging.write_text(json.dumps(managed));staging.chmod(0o600);os.chown(staging,account.pw_uid,account.pw_gid);staging.replace(enrollment/'nodes.json')
    save('Helper первого DC установлен; TLS и подписанный запрос проверены. Привязка сохранена.')

def check_forwarder(address):
    # A real DNS packet is required; an open UDP socket is not a reachability test.
    ident=os.urandom(2);query=ident+b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x01'
    family=socket.AF_INET6 if ipaddress.ip_address(address).version==6 else socket.AF_INET
    try:
        with socket.socket(family,socket.SOCK_DGRAM) as client:
            client.settimeout(3);client.connect((address,53));client.send(query);reply=client.recv(4096)
            if len(reply)<12 or reply[:2]!=ident or not reply[2]&0x80:raise RuntimeError('не получен ответ DNS')
    except Exception:raise RuntimeError('DNS-пересыльщик '+address+' не отвечает. Настройте доступ к DNS до развёртывания; конфигурация сервера не изменена.')

def preflight(value):
    validate(value)
    if os.geteuid()!=0:raise RuntimeError('Мастер требует root на целевом сервере')
    release=pathlib.Path('/etc/os-release').read_text()
    if not re.search(r'(?m)^ID=(?:"?altlinux"?|"?alt"?)$',release):raise RuntimeError('Автоматическое развёртывание поддерживается на ALT Linux')
    if not pathlib.Path('/run/systemd/system').is_dir():raise RuntimeError('Нужен сервер с работающим systemd')
    for cmd in ['apt-get','apt-cache','rpm','systemctl','systemd-run','hostnamectl','ip']:
        if not shutil.which(cmd):raise RuntimeError('Не установлена обязательная утилита '+cmd+'; настройте базовую ОС и репозитории')
    try:run(['rpm','-qa'],15)
    except Exception as error:raise RuntimeError('Проверьте и восстановите базу пакетов RPM до развёртывания. '+str(error))
    pristine()
    interfaces=json.loads(run(['ip','-j','address','show']))
    if not any(a.get('local')==value['address'] for i in interfaces for a in i.get('addr_info',[])):
        raise RuntimeError('Указанный IPv4 не назначен серверу. Сначала настройте постоянный адрес ОС.')
    if value['mode']!='forest':
        socket.getaddrinfo(value['source'],389)
        with socket.create_connection((value['source'],389),timeout=5):pass
    if shutil.disk_usage('/var/lib').free < 2*1024**3:raise RuntimeError('Для развёртывания нужно не менее 2 ГиБ свободного места в /var/lib')
    if value['mode'] in ['forest','existing']:
        if not pathlib.Path('/usr/sbin/sambaadm-setup').is_file():raise RuntimeError('Установите пакет sambaadm с командой sambaadm-setup перед созданием леса')
        local_helper_package()
        if subprocess.run(['systemctl','is-active','--quiet','sambaadm-helper'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:raise RuntimeError('На сервере уже работает helper. Для нового леса нужен отдельный чистый сервер.')
        existing=pathlib.Path('/etc/sambaadm-helper/config.yaml')
        if existing.exists():
            try:unmodified_vendor(existing)
            except Exception:raise RuntimeError('Helper уже настроен; его привязка не будет заменена мастером нового леса.')
        panel=pathlib.Path('/etc/sambaadm/config.yaml')
        if panel.exists():
            try:unmodified_vendor(panel)
            except Exception:raise RuntimeError('Панель уже настроена. Создавайте новый лес на отдельном чистом сервере.')
    resolver=pathlib.Path('/etc/resolv.conf')
    if resolver.is_symlink():raise RuntimeError('Настройте постоянный DNS в ОС: /etc/resolv.conf управляется ссылкой. Для мастера нужен обычный файл, защищённый от перезаписи сетевой службой.')
    check_forwarder(value['forwarder'])
    candidates=repository_plan()
    fingerprint={'input':canonical(value),'packages':candidates,'smb':hashlib.sha256(SMB.read_bytes() if SMB.exists() else b'').hexdigest(),'hostname':socket.gethostname(),'worker':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()}
    if value['mode']=='existing':fingerprint['existingWorker']=hashlib.sha256(pathlib.Path(__file__).with_name('existing.py').read_bytes()).hexdigest()
    revision=hashlib.sha256(json.dumps(fingerprint,sort_keys=True).encode()).hexdigest()
    if value['mode']=='existing':
        return {'revision':revision,'packages':[k+' = '+v for k,v in candidates.items()], 'checks':['ALT Linux, чистый сервер и systemd','IPv4 и доступность источника LDAP','Репозитории и все пакеты доступны'], 'steps':['Скачать и установить пакеты до изменения AD','Проверить Kerberos, идентичность и функциональный уровень исходного AD','Присоединить RWDC; дождаться совпадения пользователей, групп, компьютеров, OU и GPO','Скопировать SYSVOL с версиями политик и правами; до проверки слушать только localhost','Создать новую служебную запись '+value['serviceUser']+' в доменной группе администраторов и настроить панель/helper','Перенести FSMO только после проверок, без захвата' if value.get('transferRoles') else 'Оставить FSMO на прежних владельцах и завершить мастер','Исходный Windows DC не отключается; проверка на настоящем Windows ещё не выполнена']}
    return {'revision':revision,'packages':[k+' = '+v for k,v in candidates.items()],
      'checks':['ALT Linux и systemd','Постоянный IPv4 назначен серверу','Существующий домен и работающие службы Samba отсутствуют','DNS-пересыльщик отвечает на запросы','Репозитории отвечают; все пакеты доступны; удалений пакетов нет'],
      'steps':['Повторная проверка репозиториев и скачивание всех пакетов','Установка Samba AD DC и зависимостей','Настройка имени сервера и развёртывание '+('нового леса' if value['mode']=='forest' else value['mode'])+' в сайте '+value['site'],'Запуск Samba; проверка LDAP, DNS SOA и SRV','Настройка панели HTTPS' if value['mode']=='forest' else 'Проверка роли и сайта контроллера']}

def initial_sysvol(value,lp,folder,save):
    """Read-only snapshot from RWDC, ACL-preserving cutover before serving SMB."""
    from samba.auth import system_session
    from samba.credentials import Credentials,DONT_USE_KERBEROS,MUST_USE_KERBEROS,SMB_SIGNING_REQUIRED
    from samba.samba3 import libsmb_samba_internal as smb,param
    from samba.dcerpc import security
    from samba.ntacls import setntacl,getntacl
    from samba.samdb import SamDB
    ad=SamDB(lp=lp,session_info=system_session(lp));sid=ad.get_domain_sid()
    acl_lp=param.get_context();acl_lp.load(str(SMB))
    root=pathlib.Path(acl_lp.get('path','sysvol')).resolve(strict=True)
    target=root/value['realm']
    if target.is_symlink():raise RuntimeError('SYSVOL содержит ссылку; проверьте сервер')
    credentials=Credentials();credentials.guess(lp);credentials.parse_string(value['username']);credentials.set_password(value['password']);credentials.set_kerberos_state(MUST_USE_KERBEROS if value['mode']=='existing' else DONT_USE_KERBEROS);credentials.set_smb_signing(SMB_SIGNING_REQUIRED)
    lp.set('client min protocol','SMB2_02')
    client_lp=param.get_context();client_lp.load(str(SMB));client_lp.set('client min protocol','SMB2_02')
    connection=smb.Conn(value['source'],'sysvol',client_lp,credentials,force_smb1=False)
    flags=security.SECINFO_OWNER|security.SECINFO_GROUP|security.SECINFO_DACL
    save('Начальная доставка SYSVOL с '+value['source']+' с сохранением прав', 'sysvol')
    def local_revision():
        digest=hashlib.sha256()
        if not target.exists():return digest.hexdigest()
        for path in sorted(target.rglob('*')):
            if path.is_symlink() or not (path.is_dir() or path.is_file()):raise RuntimeError('Небезопасный объект в новом SYSVOL')
            st=path.stat();digest.update(str((str(path.relative_to(target)),st.st_mode,st.st_mtime_ns,st.st_size)).encode())
            if path.is_file():digest.update(hashlib.sha256(path.read_bytes()).digest())
        return digest.hexdigest()
    before=local_revision()
    def scan(stage=None):
        result={};total=0
        def visit(relative,local):
            nonlocal total
            if len(result)>200000:raise RuntimeError('SYSVOL превышает предел 200000 объектов')
            source=value['realm']+('\\'+relative.replace('/','\\') if relative else '')
            descriptor=connection.get_acl(source,sinfo=flags).as_sddl(security.dom_sid(sid))
            result[relative]=['directory',descriptor]
            for entry in connection.list(source):
                if len(result)>200000:raise RuntimeError('SYSVOL превышает предел 200000 объектов')
                name=entry['name']
                if name in ['.','..']:continue
                if not name or any(c in name for c in '/\\\x00') or entry['attrib']&0x400:raise RuntimeError('Небезопасный путь или ссылка в исходном SYSVOL')
                child=(relative+'/' if relative else '')+name;remote=value['realm']+'\\'+child.replace('/','\\');path=local/name if local else None
                if entry['attrib']&16:
                    if path:path.mkdir(mode=0o700)
                    visit(child,path)
                else:
                    if entry.get('size',0)>256<<20:raise RuntimeError('Файл SYSVOL превышает 256 МиБ')
                    data=connection.loadfile(remote);total+=len(data)
                    if total>4<<30:raise RuntimeError('Начальная копия SYSVOL превышает 4 ГиБ')
                    acl=connection.get_acl(remote,sinfo=flags).as_sddl(security.dom_sid(sid));result[child]=[hashlib.sha256(data).hexdigest(),acl]
                    if path:path.write_bytes(data)
        visit('',stage)
        return result
    import tempfile
    stage=pathlib.Path(tempfile.mkdtemp(prefix='.sambaadm-init-',dir=root))
    try:
        snapshot=scan(stage)
        if scan()!=snapshot:raise RuntimeError('SYSVOL источника изменился во время копирования; проверьте источник и завершите начальную доставку заново')
        # DRS and SYSVOL must describe the same GPO versions before this DC
        # begins serving clients. Source edits are never written back.
        import configparser
        policy_dir=next((p for p in stage.iterdir() if p.name.casefold()=='policies'),None)
        rows=ad.search(base='CN=Policies,CN=System,'+str(ad.domain_dn()),scope=2,expression='(objectClass=groupPolicyContainer)',attrs=['name','versionNumber'])
        for row in rows:
            guid=str(row['name'][0],'utf-8')
            directory=next((p for p in policy_dir.iterdir() if p.name.casefold()==guid.casefold()),None) if policy_dir else None
            ini=next((p for p in directory.iterdir() if p.name.casefold()=='gpt.ini'),None) if directory else None
            if ini is None:raise RuntimeError('В исходном SYSVOL отсутствует GPT.INI политики '+guid)
            raw=ini.read_bytes();text=raw.decode('utf-16') if raw.startswith((b'\xff\xfe',b'\xfe\xff')) else raw.decode('utf-8-sig')
            document=configparser.ConfigParser();document.read_string(text)
            if int(document.get('General','Version'))!=int(row['versionNumber'][0]):raise RuntimeError('Версии LDAP и SYSVOL различаются для '+guid+'; проверьте источник')
        session=system_session(lp)
        for name,(_,acl) in sorted(snapshot.items(),key=lambda pair:pair[0].count('/'),reverse=True):
            path=stage/name
            setntacl(acl_lp,str(path),acl,sid,session)
            if getntacl(acl_lp,str(path),session).as_sddl(security.dom_sid(sid))!=acl:raise RuntimeError('Не удалось сохранить права SYSVOL')
        if local_revision()!=before:raise RuntimeError('Новый SYSVOL изменён другим администратором; замена отменена')
        backup=root/('.sambaadm-before-'+folder.name)
        if target.exists():target.rename(backup)
        try:stage.rename(target)
        except Exception:
            if backup.exists():backup.rename(target)
            raise
        root_acl=connection.get_acl('',sinfo=flags).as_sddl(security.dom_sid(sid))
        setntacl(acl_lp,str(root),root_acl,sid,session)
        if backup.exists():shutil.rmtree(backup)
        save('SYSVOL доставлен и права проверены: '+str(len(snapshot))+' объектов')
    finally:
        if stage.exists():shutil.rmtree(stage)

def deploy(value, folder, save):
    validate(value)
    with open(folder.parent.parent/'operations.lock','a') as lock:
        os.chmod(lock.name,0o600)
        deadline=time.monotonic()+10
        while True:
            try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);break
            except BlockingIOError:
                if time.monotonic()>=deadline:raise RuntimeError('Другая операция на сервере уже выполняется; проверьте её журнал')
                time.sleep(.1)
        if value.get('_resume'):
            from existing import resume
            return resume(value,folder,save,globals())
        return deploy_locked(value,folder,save)

def deploy_locked(value,folder,save):
    save('Проверка сервера и повторная проверка репозиториев', 'preflight')
    plan=preflight(value)
    if plan['revision']!=value.get('revision'):raise RuntimeError('Параметры сервера или пакеты изменились. Выполните новый предпросмотр.')
    if not value.get('confirm') or not value.get('password') or (value['mode']=='forest' and len(value['password'])<8):raise RuntimeError('Нужно подтверждение и пароль от 8 знаков')
    save('Скачивание всех пакетов до изменения служб и конфигурации', 'download')
    # Real downloads detect missing RPM files even with valid repository metadata.
    try:run(['apt-get','--download-only','-y','install',*PACKAGES],300)
    except Exception as error:raise RuntimeError('Пакеты не скачаны. Настройте доступные репозитории и соединение с ними, затем повторите проверку. '+str(error))
    pristine()
    save('Пакеты доступны и скачаны. Установка Samba AD DC', 'install')
    run(['apt-get','-y','--no-download','install',*PACKAGES],300)
    pristine()
    if value['mode']=='existing':
        from existing import bootstrap
        return bootstrap(value,folder,save,globals())
    # Keep the vendor configuration and hostname for manual recovery. Never remove AD data on failure.
    if SMB.exists():shutil.copy2(SMB,folder/'smb.conf.before')
    (folder/'hostname.before').write_text(socket.gethostname());os.chmod(folder/'hostname.before',0o600)
    hostname=value['hostname'].lower()+'.'+value['realm']
    if socket.gethostname().lower()!=hostname:
        run(['hostnamectl','set-hostname',hostname])
    SMB.parent.mkdir(parents=True,exist_ok=True)
    SMB.write_text('[global]\nserver role = active directory domain controller\nrealm = '+value['realm'].upper()+'\nworkgroup = '+value['netbios'].upper()+'\nnetbios name = '+value['hostname'].upper()+'\n')
    SMB.chmod(0o644)
    save('Создание каталога Active Directory и SYSVOL; сайт '+value['site'], 'provision')
    # Match ALT's /usr/lib64/samba-dc/bin/samba-tool launcher. The generic
    # python3-module-samba bindings use a different Kerberos build and must not
    # be mixed with AD DC's Heimdal libraries.
    dc_python=pathlib.Path('/usr')/getattr(sys,'platlibdir','lib64')/'samba-dc'/('python%d.%d'%sys.version_info[:2])
    if not dc_python.is_dir():raise RuntimeError('Не найдены Python-модули Samba DC. Проверьте целостность пакета samba-dc.')
    sys.path.insert(0,str(dc_python))
    from samba.param import LoadParm
    from samba.netcmd.domain import cmd_domain_provision,cmd_domain_join
    from samba.credentials import Credentials
    import io
    # Use Samba's parser so version-specific defaults and option groups are
    # initialized exactly as in samba-tool. Arguments remain in Python memory;
    # passwords are never passed to an OS process or shell command line.
    SMB.unlink()
    output=io.StringIO()
    if value['mode']=='forest':
        command=cmd_domain_provision(outf=output,errf=output)
        args=['--realm='+value['realm'].upper(),'--domain='+value['netbios'].upper(),
              '--host-name='+value['hostname'].lower(),'--host-ip='+value['address'],
              '--adminpass='+value['password'],'--site='+value['site'],
              '--dns-backend=SAMBA_INTERNAL','--option=dns forwarder='+value['forwarder'],
              '--server-role=dc','--function-level='+value['level'],'--use-rfc2307']
    else:
        command=cmd_domain_join(outf=output,errf=output)
        args=[value['realm'],value['mode'],'--server='+value['source'],
              '--site='+value['site'],'--dns-backend=SAMBA_INTERNAL',
              '--username='+value['username'],'--password='+value['password'],
              '--use-kerberos=off','--realm='+value['realm'].upper(),
              '--option=netbios name='+value['hostname'].upper(),
              '--option=dns forwarder='+value['forwarder']]
    command.command_name="domain provision" if value["mode"]=="forest" else "domain join"
    try:
        try:
            with contextlib.redirect_stdout(output),contextlib.redirect_stderr(output):result=command._run(*args)
        except SystemExit:raise RuntimeError('Параметры Samba: '+output.getvalue()[-1800:])
        if result not in (None,0):raise RuntimeError('Samba: '+output.getvalue()[-1800:])
    finally:
        args.clear()
    configured=LoadParm();configured.load(str(SMB));configured.set('dns forwarder',value['forwarder'])
    configured.dump(False,str(folder/'smb.conf.generated'));shutil.copyfile(folder/'smb.conf.generated',SMB)
    tls=pathlib.Path(configured.get('private dir'))/'tls';tls.mkdir(mode=0o700,parents=True,exist_ok=True)
    for source,target in [('tls.key','key.pem'),('tls.crt','cert.pem'),('tls-ca.pem','ca.pem')]:
        shutil.copyfile(folder/source,tls/target);(tls/target).chmod(0o600 if source=='tls.key' else 0o644)
    if value['mode']!='forest':initial_sysvol(value,configured,folder,save)
    # Explicit paths and names are owned by Samba's compiled-in ALT layout.
    generated=pathlib.Path('/var/lib/samba/private/krb5.conf')
    if generated.exists():
        target=pathlib.Path('/etc/krb5.conf')
        if target.is_symlink():raise RuntimeError('Проверьте символическую ссылку /etc/krb5.conf; домен уже создан')
        if target.exists():shutil.copy2(target,folder/'krb5.conf.before')
        shutil.copy2(generated,target)
    save('Запуск службы Samba и проверка доменного DNS', 'verify')
    run(['systemctl','enable','--now','samba'])
    for attempt in range(25):
        try:
            soa=run(['dig','+time=2','+tries=1','+short','@127.0.0.1',value['realm'],'SOA'],5)
            srv=run(['dig','+time=2','+tries=1','+short','@127.0.0.1','_ldap._tcp.'+value['realm'],'SRV'],5)
            if soa.strip() and srv.strip():
                with socket.create_connection(('127.0.0.1',389),timeout=2):pass
                if value['mode']=='forest':
                    with socket.create_connection(('127.0.0.1',636),timeout=2):pass
                break
        except Exception:pass
        time.sleep(1)
    else:raise RuntimeError('Домен создан, но SOA/SRV не отвечают. Проверьте DNS и службу Samba перед повтором.')
    with socket.create_connection(('127.0.0.1',389),timeout=5):pass
    resolver=pathlib.Path('/etc/resolv.conf')
    if resolver.is_symlink():raise RuntimeError('DNS сервера изменён во время установки; проверьте /etc/resolv.conf')
    if resolver.exists():shutil.copy2(resolver,folder/'resolv.conf.before')
    resolver.write_text('search '+value['realm']+'\nnameserver 127.0.0.1\n')
    from samba.samdb import SamDB
    from samba.auth import system_session
    local=LoadParm();local.load(str(SMB));db=SamDB(url=local.samdb_url(),session_info=system_session(),lp=local)
    result=db.search(base=db.get_config_basedn(),scope=2,expression='(&(objectClass=server)(dNSHostName='+hostname+'))',attrs=['distinguishedName'])
    if len(result)!=1 or str(result[0].dn.get_component_value(2)).lower()!=value['site'].lower():raise RuntimeError('Проверьте назначение контроллера сайту: развёртывание уже выполнено')
    if db.am_rodc()!=(value['mode']=='RODC'):raise RuntimeError('Роль созданного контроллера не соответствует заданию')
    if value['mode']=='forest':
        save('Создание служебной учётной записи и настройка HTTPS панели', 'panel')
        service_password=secrets.token_urlsafe(36)+'aA1!'
        db.newuser('svc-sambaadm',service_password)
        db.add_remove_group_members('Domain Admins',['svc-sambaadm'],add_members_operation=True)
        db.setexpiry('(sAMAccountName=svc-sambaadm)',0,no_expiry_req=True)
        # Publish the HTTPS name at the first DC address through the existing DNS RPC command.
        # No administrative password is placed on the command line.
        from samba.netcmd.dns import cmd_add_record
        creds=Credentials();creds.guess(local);creds.set_username('Administrator');creds.set_password(value['password'])
        co=types.SimpleNamespace(get_credentials=lambda ignored:creds,ipaddress=None)
        so=types.SimpleNamespace(_lp=local,get_loadparm=lambda:local)
        relative=value['panelName'][:-(len(value['realm'])+1)]
        cmd_add_record().run('127.0.0.1',value['realm'],relative,'A',value['address'],sambaopts=so,credopts=co)
        ca='/var/lib/samba/private/tls/ca.pem'
        env={**ENV,'SAMBAADM_PASSWORD':service_password}
        p=subprocess.run(['/usr/sbin/sambaadm-setup','--yes','--realm',value['realm'],'--dc',hostname,'--user','svc-sambaadm@'+value['realm'],'--ca',ca,'--https-name',value['panelName']],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,errors='replace',timeout=180)
        for line in p.stdout.splitlines()[-30:]:save(line.replace(service_password,'[скрыто]'))
        env.pop('SAMBAADM_PASSWORD',None)
        if p.returncode:raise RuntimeError('Домен создан; настройка панели не завершилась. Проверьте sambaadm-setup и LDAPS; повторное создание леса запрещено.')
    if value['mode']=='forest':install_local_helper(value,folder,save)
    save('Домен, DNS, роль и сайт проверены. Развёртывание завершено.', 'complete')

def main():
    value=json.load(sys.stdin);mode=sys.argv[1];base=pathlib.Path(sys.argv[2])
    if mode=='plan':
        try:print(json.dumps(preflight(value),ensure_ascii=False))
        except Exception as error:print(json.dumps({'error':str(error)},ensure_ascii=False));return 1
        return 0
    ident=sys.argv[3]
    if not re.fullmatch('[a-f0-9]{32}',ident):return 1
    folder=base/ident
    state={'id':ident,'state':'running','log':[],'pid':os.getpid(),'realm':value['realm'],'node':value['hostname'].lower()+'.'+value['realm'],'site':value['site'],'mode':value['mode'],'ca':value.get('ca','')}
    if mode=='resume':
        previous=json.loads((folder/'status.json').read_text());state['log']=previous.get('log',[]);value['_resume']=True
    password=value.get('password','')
    def save(message=None,phase=None):
        if message:state['log'].append(time.strftime('%H:%M:%S')+' · '+str(message).replace(password,'[скрыто]')[:1800])
        state['log']=state['log'][-400:]
        if phase:state['phase']=phase
        if value.get('_report'):state['report']=value['_report']
        state['resumable']=bool(value.get('_resumable'))
        state['site']=value.get('site',state.get('site',''))
        path=folder/'status.tmp';path.write_text(json.dumps(state,ensure_ascii=False));path.chmod(0o600);path.replace(folder/'status.json')
    try:
        save();deploy(value,folder,save);state['state']='completed'
        if value['mode'] in ['forest','existing']:state['panelURL']='https://'+value['panelName']
        save()
    except Exception as error:
        state['state']='failed';state['error']=str(error).replace(password,'[скрыто]')[:1800]
        save('Операция остановлена: '+state['error']);save('Повтор не запускается автоматически. Проверьте состояние Samba и журнал; данные домена сохранены.')
        return 1
    return 0

if __name__=='__main__':sys.exit(main())
