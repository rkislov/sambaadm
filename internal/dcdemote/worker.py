"""ALT p10/p11 graceful DC retirement to an AD member. Fixed commands only.
Administrator credentials are received over stdin and never written to disk.
After demotion no path ever restores/restarts the retired DC database.
"""
import errno, contextlib, fcntl, hashlib, io, json, os, pathlib, re, shutil, socket, subprocess, sys, time
SMB=pathlib.Path('/etc/samba/smb.conf')
PACKAGES=['samba','samba-winbind','samba-winbind-clients','pam-config-control','python3-module-yaml']
ENV={**os.environ,'LC_ALL':'C','PATH':'/usr/sbin:/usr/bin:/sbin:/bin'}

def run(argv,timeout=40):
    p=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,errors='replace',env=ENV,timeout=timeout)
    if p.returncode:raise RuntimeError('Ошибка '+argv[0]+': '+p.stdout[-1800:])
    return p.stdout

def atomic(path,data,mode=0o600):
    path=pathlib.Path(path);tmp=path.with_name(path.name+'.sambaadm-tmp')
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as f:f.write(data if isinstance(data,bytes) else data.encode());f.flush();os.fsync(f.fileno())
    tmp.chmod(mode)
    try:tmp.replace(path)
    except OSError as e:
        if e.errno!=errno.EBUSY or str(path)!='/etc/resolv.conf':raise
        # Container/host resolver files can be bind mounts. Keep the mounted
        # inode and refuse links; other config writes remain atomic.
        fd=os.open(path,os.O_WRONLY|os.O_TRUNC|os.O_NOFOLLOW)
        with os.fdopen(fd,'wb') as f:f.write(tmp.read_bytes());f.flush();os.fsync(f.fileno())
        tmp.unlink()

def repositories(download=False):
    try:
        text=run(['apt-get','-o','Acquire::http::Timeout=15','-o','Acquire::Retries=0','update'],110)
        if re.search(r'(?im)^(Err:|Err\s|E:|W:.*(?:failed|fetch|resolve))',text) or 'Some index files failed' in text:raise RuntimeError(text[-1600:])
        versions={}
        for package in PACKAGES:
            text=run(['apt-cache','policy',package],5);m=re.search(r'(?m)^\s*Candidate:\s*(\S+)',text)
            if not m or m[1] in ['(none)','(null)']:raise RuntimeError('Недоступен пакет '+package)
            versions[package]=m[1]
        text=run(['apt-get','-s','install',*PACKAGES],20)
        if re.search(r'(?m)^Remv\s',text):raise RuntimeError('APT планирует удаление установленного ПО')
        if download:run(['apt-get','--download-only','-y','install',*PACKAGES],300)
        return versions
    except Exception as e:raise RuntimeError('До изменения сервера настройте доступные репозитории ALT этой версии и архитектуры: /etc/apt/sources.list и sources.list.d. '+str(e))

def bindings(local=True):
    sys.path.insert(0,'/usr/lib64/samba-dc/python%d.%d'%sys.version_info[:2])
    from samba.param import LoadParm
    from samba.samdb import SamDB
    from samba.auth import system_session
    lp=LoadParm();lp.load(str(SMB));return lp,SamDB(lp=lp,session_info=system_session(lp)) if local else None

def credentials(v,lp):
    from samba.credentials import Credentials,DONT_USE_KERBEROS,SMB_SIGNING_REQUIRED
    c=Credentials();c.guess(lp);c.parse_string(v['username']);c.set_password(v['password']);c.set_kerberos_state(DONT_USE_KERBEROS);c.set_smb_signing(SMB_SIGNING_REQUIRED)
    lp.set('client ldap sasl wrapping','seal');lp.set('client min protocol','SMB2_02');return c

def remote(v,lp):
    from samba.samdb import SamDB
    return SamDB(url='ldap://'+v['source'],lp=lp,credentials=credentials(v,lp))

def one(db,dn,attrs):
    import ldb
    rows=db.search(base=dn,scope=ldb.SCOPE_BASE,attrs=attrs)
    if len(rows)!=1:raise RuntimeError('Не найден объект AD '+str(dn))
    return rows[0]

def absent(db,dn):
    import ldb
    try:one(db,dn,['objectGUID']);return False
    except ldb.LdbError as e:
        if e.args[0]==ldb.ERR_NO_SUCH_OBJECT:return True
        raise

def text(row,key,default=''):
    return str(row[key][0]) if key in row and len(row[key]) else default

def local_sysvol(lp,realm):
    from samba.samba3 import param
    from samba.ntacls import getntacl
    from samba.auth import system_session
    client_lp=param.get_context();client_lp.load(str(SMB));root=pathlib.Path(client_lp.get('path','sysvol'))/realm;local={};total=0
    session=system_session(lp)
    for path in [root,*sorted(root.rglob('*'))]:
        if len(local)>200000 or path.is_symlink() or not (path.is_dir() or path.is_file()):raise RuntimeError('Небезопасный объект или превышен предел локального SYSVOL')
        name=str(path.relative_to(root)).replace('/','\\');name='' if name=='.' else name
        descriptor=getntacl(client_lp,str(path),session).as_sddl()
        if path.is_dir():local[name]=['dir',descriptor]
        else:
            size=path.stat().st_size;total+=size
            if size>256<<20 or total>4<<30:raise RuntimeError('Превышен предел проверки SYSVOL')
            local[name]=[hashlib.sha256(path.read_bytes()).hexdigest(),descriptor]
    return hashlib.sha256(json.dumps(local,sort_keys=True).encode()).hexdigest()

def manifest(v):
    lp,db=bindings()
    if lp.get('server role')!='active directory domain controller' or db.am_rodc():raise RuntimeError('Для проверки эталонного SYSVOL нужен RWDC')
    if lp.get('realm').lower()!=v['realm'] or lp.get('netbios name').lower()+'.'+v['realm']!=v['node']:raise RuntimeError('Не совпала идентичность helper и RWDC')
    return {'node':v['node'],'realm':v['realm'],'guid':str(db.get_ntds_GUID()),'digest':local_sysvol(lp,v['realm'])}


def preflight(v,config):
    if os.geteuid()!=0:raise RuntimeError('Снятие роли требует root')
    release=pathlib.Path('/etc/os-release').read_text()
    if not re.search(r'(?m)^ID="?(?:altlinux|alt)"?$',release) or not re.search(r'(?m)^(?:ALT_BRANCH_ID="?p(?:10|11)"?|VERSION_ID="?(?:10|11)(?:\.[0-9]+)?"?)$',release):raise RuntimeError('Поддерживаются ALT Linux p10 и p11')
    if not pathlib.Path('/run/systemd/system').is_dir():raise RuntimeError('Нужен работающий systemd')
    if run(['systemctl','is-active','samba']).strip()!='active':raise RuntimeError('Служба AD DC должна работать')
    if subprocess.run(['systemctl','is-active','--quiet','sambaadm'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:raise RuntimeError('На этом DC работает сама панель. Сначала перенесите панель на другой сервер.')
    if SMB.is_symlink() or pathlib.Path('/etc/resolv.conf').is_symlink():raise RuntimeError('smb.conf и resolv.conf должны быть обычными файлами; сначала настройте постоянный DNS ОС')
    lp,db=bindings();import ldb
    if lp.get('server role')!='active directory domain controller':raise RuntimeError('Сервер уже не является AD DC')
    if lp.get('realm').lower()!=v['realm'] or lp.get('netbios name').lower()+'.'+v['realm']!=v['node']:raise RuntimeError('Не совпадает доменная идентичность helper и Samba')
    for field,expected in [('state directory','/var/lib/samba'),('private dir','/var/lib/samba/private')]:
        if pathlib.Path(lp.get(field)).resolve()!=pathlib.Path(expected):raise RuntimeError('Нестандартный '+field+': сначала подготовьте отдельный план миграции')
    if pathlib.Path(lp.get('path','sysvol')).resolve()!=pathlib.Path('/var/lib/samba/sysvol') or pathlib.Path(lp.get('path','netlogon')).resolve()!=pathlib.Path('/var/lib/samba/sysvol')/v['realm']/'scripts':raise RuntimeError('Нестандартное размещение SYSVOL; требуется отдельный план миграции')
    if any(name.lower() not in ['global','sysvol','netlogon'] for name in lp.services()):raise RuntimeError('На DC есть дополнительные SMB-ресурсы. Перенесите их и права до смены модели идентификаторов на Winbind.')
    nss=pathlib.Path('/etc/nsswitch.conf').read_text()
    if any('sss' in line.split() or 'ldap' in line.split() for line in nss.splitlines() if re.match(r'^(passwd|group):',line)):raise RuntimeError('Сначала согласуйте существующую настройку NSS/SSSD с переходом на Winbind')
    if any((1000000<=int(line.split(':')[2])<=1999999 or 10000000<=int(line.split(':')[2])<=1999999999) for filename in ['/etc/passwd','/etc/group'] for line in pathlib.Path(filename).read_text().splitlines() if len(line.split(':'))>=4):raise RuntimeError('Локальные UID/GID пересекаются с планируемыми диапазонами Winbind. Нужна отдельная миграция идентификаторов.')
    if pathlib.Path(config).is_symlink():raise RuntimeError('Конфигурация helper не должна быть ссылкой')
    for port in [88,445]:
        with socket.create_connection((v['source'],port),timeout=5):pass
    source=remote(v,lp);local=one(db,'',['dsServiceName','namingContexts']);root=one(source,'',['dsServiceName','namingContexts','defaultNamingContext'])
    if text(root,'defaultNamingContext').lower()!=str(db.domain_dn()).lower():raise RuntimeError('Исходный RWDC относится к другому домену')
    ntds=text(local,'dsServiceName');partner=text(root,'dsServiceName')
    own=one(source,ntds,['options','msDS-isRODC','objectGUID','msDS-hasMasterNCs','hasMasterNCs'])
    other=one(source,partner,['options','msDS-isRODC','objectGUID','msDS-hasMasterNCs','hasMasterNCs'])
    if ntds.lower()==partner.lower() or text(other,'msDS-isRODC').upper()=='TRUE':raise RuntimeError('Нужен другой доступный RWDC')
    if int(text(other,'options','0'))&6 or int(text(own,'options','0'))&2 or (not db.am_rodc() and int(text(own,'options','0'))&4):raise RuntimeError('На контроллере отключена репликация; сначала устраните причину')
    if int(text(own,'options','0'))&1 and not int(text(other,'options','0'))&1:raise RuntimeError('Выберите RWDC с глобальным каталогом')
    ncs=sorted(str(x) for x in local['namingContexts'])
    remote_ncs={str(x).lower() for x in root['namingContexts']}
    masters={str(x).lower() for key in ['msDS-hasMasterNCs','hasMasterNCs'] for x in other.get(key,[])}
    if any(n.lower() not in remote_ncs or n.lower() not in masters for n in ncs):raise RuntimeError('Выбранный RWDC не содержит все записываемые разделы, включая DNS')
    roles=source.search(base=str(db.get_root_basedn()),scope=ldb.SCOPE_SUBTREE,expression='(fSMORoleOwner='+ldb.binary_encode(ntds)+')',attrs=['name'],controls=['search_options:1:2'])
    if roles:raise RuntimeError('Сначала передайте все FSMO-роли другому RWDC в разделе «Роли FSMO»')
    server=one(source,str(ldb.Dn(source,ntds).parent()),['serverReference','objectGUID'])
    computer=text(server,'serverReference');account=one(source,computer,['objectGUID','userAccountControl','msDS-KrbTgtLink','sAMAccountName','dNSHostName'])
    if text(account,'dNSHostName').lower()!=v['node'] or text(account,'sAMAccountName').lower()!=lp.get('netbios name').lower()+'$':raise RuntimeError('NTDS не соответствует выбранному компьютеру')
    partner_server=one(source,str(ldb.Dn(source,partner).parent()),['serverReference'])
    partner_account=one(source,text(partner_server,'serverReference'),['dNSHostName'])
    if text(partner_account,'dNSHostName').lower()!=v['source']:raise RuntimeError('LDAP-адрес не соответствует выбранному RWDC')
    addresses=sorted({x[4][0] for x in socket.getaddrinfo(v['source'],389,type=socket.SOCK_STREAM) if x[0]==socket.AF_INET})
    if not addresses:raise RuntimeError('Нужен IPv4 выбранного RWDC для DNS клиента')
    size=sum(p.stat().st_size for p in pathlib.Path('/var/lib/samba').rglob('*') if p.is_file())
    if shutil.disk_usage('/var/lib').free<max(1024**3,size*2):raise RuntimeError('Недостаточно места для двух локальных защитных копий состояния DC')
    versions=repositories();digest=local_sysvol(lp,v['realm']);reference=v.get('reference',{})
    from samba.ndr import ndr_unpack
    from samba.dcerpc import misc
    if reference.get('node')!=v['source'] or reference.get('realm')!=v['realm'] or reference.get('guid')!=str(ndr_unpack(misc.GUID,bytes(other['objectGUID'][0]))) or reference.get('digest')!=digest:raise RuntimeError('SYSVOL и его права отличаются от эталона RWDC. Выполните доставку GPO и новый предпросмотр.')
    # No password is part of the persisted plan or revision.
    metadata={'node':v['node'],'source':v['source'],'realm':v['realm'],'ntds':ntds,'partner':partner,'computer':computer,'serverDN':str(server.dn),'serverGUID':bytes(server['objectGUID'][0]).hex(),'guid':bytes(account['objectGUID'][0]).hex(),'netbios':lp.get('workgroup'),'rodc':db.am_rodc(),'ncs':ncs,'sourceIPs':addresses,'packages':versions,'sysvol':digest,'smb':hashlib.sha256(SMB.read_bytes()).hexdigest(),'helper':hashlib.sha256(pathlib.Path(config).read_bytes()).hexdigest(),'worker':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'account':text(account,'sAMAccountName'),'krbtgt':text(account,'msDS-KrbTgtLink')}
    revision=hashlib.sha256(json.dumps(metadata,sort_keys=True).encode()).hexdigest()
    interfaces=json.loads(run(['ip','-j','address','show']))
    addresses=sorted({a['local'] for interface in interfaces for a in interface.get('addr_info',[]) if a.get('family')=='inet' and a.get('scope')=='global'})
    if not addresses:raise RuntimeError('У сервера нет IPv4 для сохранения связи с helper')
    return {'addresses':addresses,'revision':revision,'metadata':metadata,'checks':['ALT p10/p11, работающий DC и зарегистрированный helper','Другой RWDC того же домена, глобальный каталог и все разделы DNS','FSMO переданы; репликация не отключена','SYSVOL и права совпадают с выбранным RWDC','Репозитории и пакеты доступны, удалений ПО нет','Нет дополнительных SMB-ресурсов и конфликтующей настройки NSS'], 'packages':[k+' = '+v for k,v in versions.items()], 'steps':['Скачать все пакеты; создать локальную защитную копию','Передать изменения всех разделов AD, включая DNS, выбранному RWDC','Штатно снять роль DC и сохранить адрес сервера в DNS','Отделить старую базу DC; сохранить ОС, данные и helper','Присоединить сервер к домену как обычный член; настроить Winbind','Проверить отсутствие роли DC, доверие к домену и разрешение учётных записей']}

def fence():
    # A persistent systemd mask prevents a reboot from reviving a retired DC.
    for unit in ['samba','bind']:
        subprocess.run(['systemctl','disable','--now',unit],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=ENV,timeout=40)
        run(['systemctl','mask',unit])

def verify_retired(v,m,lp):
    import ldb
    db=remote(v,lp)
    if not absent(db,m['ntds']):raise RuntimeError('Удаление NTDS пока не подтверждено на выбранном RWDC. Старую базу DC нельзя запускать; проверьте AD перед продолжением.')
    rows=db.search(base=str(db.domain_dn()),scope=ldb.SCOPE_SUBTREE,expression='(objectGUID='+ldb.binary_encode(bytes.fromhex(m['guid']))+')',attrs=['userAccountControl','serverReferenceBL'])
    if len(rows)!=1:raise RuntimeError('Не найдена исходная учётная запись компьютера по GUID')
    uac=int(text(rows[0],'userAccountControl','0'))
    if uac&0x2000 or uac&0x4000000 or not uac&0x1000:raise RuntimeError('Учётная запись ещё имеет признаки контроллера домена')
    for link in rows[0].get('serverReferenceBL',[]):
        if str(link).lower()!=m['serverDN'].lower():raise RuntimeError('Изменилась привязка сервера в AD Sites; требуется проверка')
        server=one(db,m['serverDN'],['objectGUID'])
        if bytes(server['objectGUID'][0]).hex()!=m['serverGUID'] or db.search(base=m['serverDN'],scope=ldb.SCOPE_ONELEVEL,attrs=['name']):raise RuntimeError('Объект сервера изменился или содержит дочерние объекты; требуется проверка')
        # Native Samba leaves an empty server object. Remove only the previewed
        # object by GUID after its NTDS has already been confirmed absent.
        db.delete(m['serverDN'])
    return db

def restore_host(v,m,lp):
    from samba.ndr import ndr_unpack
    from samba.dcerpc import dnsp
    import base64,ldb
    db=verify_retired(v,m,lp)
    # Only ordinary host addresses; never restore SRV/NS or the DSA GUID alias.
    try:_,current=db.dns_lookup(v['node'])
    except RuntimeError as e:
        if not e.args or e.args[0]!=9714:raise
        current=[]
    addresses=[ndr_unpack(dnsp.DnssrvRpcRecord,base64.b64decode(x)) for x in m['hostRecords']]
    combined=list(current)
    from samba.ndr import ndr_pack
    known={(x.wType,str(x.data)) for x in current}
    for record in addresses:
        if (record.wType,str(record.data)) not in known:combined.append(record);known.add((record.wType,str(record.data)))
    db.dns_replace(v['node'],combined)
    if m.get('krbtgt') and not absent(db,m['krbtgt']):
        # Native Samba demotion can leave this dedicated RODC account behind.
        links=db.search(base=str(db.domain_dn()),scope=ldb.SCOPE_SUBTREE,expression='(msDS-KrbTgtLink='+ldb.binary_encode(m['krbtgt'])+')',attrs=['objectGUID','userAccountControl'])
        # Samba may also leave the RODC-only link on the retired computer.
        # Clear only that exact member account; a reference from any other
        # computer blocks deletion of the dedicated krbtgt identity.
        for link in links:
            if bytes(link['objectGUID'][0]).hex()!=m['guid'] or int(text(link,'userAccountControl','0'))&(0x2000|0x4000000):raise RuntimeError('krbtgt RODC используется другим контроллером; требуется проверка AD')
        for link in links:
            change=ldb.Message();change.dn=link.dn;change['msDS-KrbTgtLink']=ldb.MessageElement(m['krbtgt'],ldb.FLAG_MOD_DELETE,'msDS-KrbTgtLink');db.modify(change)
        links=db.search(base=str(db.domain_dn()),scope=ldb.SCOPE_SUBTREE,expression='(msDS-KrbTgtLink='+ldb.binary_encode(m['krbtgt'])+')',attrs=['name'])
        account=one(db,m['krbtgt'],['objectGUID','sAMAccountName'])
        if links or bytes(account['objectGUID'][0]).hex()!=m['krbtgtGUID'] or not re.fullmatch('krbtgt_[0-9]+',text(account,'sAMAccountName')):raise RuntimeError('Специальная запись krbtgt RODC изменилась или используется. Нужна проверка AD.')
        db.delete(m['krbtgt'])

def member_spns(v,m,lp):
    import ldb
    db=verify_retired(v,m,lp)
    rows=db.search(base=str(db.domain_dn()),scope=ldb.SCOPE_SUBTREE,expression='(objectGUID='+ldb.binary_encode(bytes.fromhex(m['guid']))+')',attrs=['servicePrincipalName','uSNChanged','dNSHostName'])
    if len(rows)!=1:raise RuntimeError('Не найдена учётная запись будущего члена домена')
    row=rows[0];spns=[str(x) for x in row.get('servicePrincipalName',[])];short=v['node'].split('.')[0]
    # Preserve unrelated service identities, removing the DC service classes
    # and this host's obsolete three-part HOST principals.
    remove_prefixes=('ldap/','gc/','dns/','e3514235-4b06-11d1-ab04-00c04fc2dcd2/')
    retained=[x for x in spns if not x.lower().startswith(remove_prefixes) and not (x.lower().startswith(('host/','restrictedkrbhost/')) and x.split('/')[1].lower() in [short,v['node']])]
    desired=['HOST/'+short.upper(),'HOST/'+v['node'],'RestrictedKrbHost/'+short.upper(),'RestrictedKrbHost/'+v['node']]
    wanted=sorted(set(retained+desired))
    spn_changed=set(x.lower() for x in wanted)!=set(x.lower() for x in spns)
    hostname=text(row,'dNSHostName');dns_changed=hostname.lower()!=v['node']
    if hostname and hostname.lower() not in [short,v['node']]:raise RuntimeError('DNS-имя компьютера изменено другим администратором')
    if spn_changed or dns_changed:
        # AD does not provide a portable RFC4528 assertion control. Delete
        # exactly the observed values, then add the desired set in ONE LDAP
        # modify request. Concurrent additions survive; missing old values or
        # duplicate desired values reject the whole request without replacement.
        import base64
        encode=lambda value:base64.b64encode(value.encode()).decode()
        lines=['dn:: '+encode(str(row.dn)),'changetype: modify']
        if spn_changed:
            if spns:lines+=['delete: servicePrincipalName',*['servicePrincipalName:: '+encode(x) for x in spns],'-']
            lines+=['add: servicePrincipalName',*['servicePrincipalName:: '+encode(x) for x in wanted],'-']
        if dns_changed:
            if hostname:lines+=['delete: dNSHostName','dNSHostName:: '+encode(hostname),'-']
            lines+=['add: dNSHostName','dNSHostName:: '+encode(v['node']),'-']
        db.modify_ldif('\n'.join(lines)+'\n')


def member(v,m,folder,config,save,ledger):
    # No DC Python extension is loaded by this fresh process after RPM updates.
    import yaml
    cfg_path=pathlib.Path(config);cfg=yaml.safe_load(cfg_path.read_text());helper=cfg.get('helper',{})
    changed=False;secure=cfg_path.parent/'member-tls';secure.mkdir(mode=0o700,exist_ok=True)
    for section,keys in [(helper.get('tls',{}),['cert','key']),(cfg.get('ldap',{}),['ca_cert'])]:
        for key in keys:
            old=section.get(key,'')
            if old and pathlib.Path(old).is_relative_to('/var/lib/samba'):
                dest=secure/('helper-'+key+'.pem')
                if not dest.exists():atomic(dest,pathlib.Path(old).read_bytes())
                section[key]=str(dest);changed=True
    ldap=cfg.setdefault('ldap',{});uri=ldap.get('uri','')
    from urllib.parse import urlparse
    if uri and urlparse(uri).hostname and urlparse(uri).hostname.lower() in [v['node'],'127.0.0.1','localhost']:
        parsed=urlparse(uri);ldap['uri']=parsed._replace(netloc=v['source']+(':'+str(parsed.port) if parsed.port else '')).geturl();changed=True
    if changed:atomic(cfg_path,yaml.safe_dump(cfg,allow_unicode=True,sort_keys=False))
    if not ledger.get('quarantined'):
        if not ledger.get('quarantine_started'):
            ledger['quarantine_started']=True;save('Отделение старой базы DC; автоматический откат к роли DC запрещён','quarantine')
            retired=folder/'retired-dc';retired.mkdir(mode=0o700)
            run(['cp','-a','/var/lib/samba/.',str(retired)],300)
            ledger['quarantine_copied']=True;save()
        if not ledger.get('quarantine_copied'):raise RuntimeError('Защитная копия старой базы не подтверждена; требуется проверка содержимого до продолжения')
        for path in pathlib.Path('/var/lib/samba').iterdir():
            if path.is_symlink() or not path.is_dir():path.unlink()
            else:shutil.rmtree(path)
        ledger['quarantined']=True;save()
    pathlib.Path('/var/lib/samba/private').mkdir(mode=0o700,parents=True,exist_ok=True)
    version=re.search(r'(\d+)\.(\d+)',run(['/usr/bin/net','--version']))
    if not version:raise RuntimeError('Не определена версия Samba для настройки keytab')
    modern=tuple(map(int,version.groups()))>=(4,21)
    if not ledger.get('member_configured'):
        smb='[global]\nserver role = member server\nsecurity = ADS\nrealm = '+v['realm'].upper()+'\nworkgroup = '+m['netbios']+'\nnetbios name = '+v['node'].split('.')[0]+'\nkerberos method = secrets and keytab\nwinbind use default domain = no\nwinbind refresh tickets = yes\nidmap config * : backend = tdb\nidmap config * : range = 1000000-1999999\nidmap config '+m['netbios']+' : backend = rid\nidmap config '+m['netbios']+' : range = 10000000-1999999999\ntemplate shell = /bin/bash\ntemplate homedir = /home/%D/%U\n'
        if modern:smb+='dns hostname = '+v['node']+'\nsync machine password to keytab = /etc/krb5.keytab:spn_prefixes=host:sync_kvno:machine_password\n'
        atomic(SMB,smb,0o644)
        atomic('/etc/krb5.conf','[libdefaults]\n default_realm = '+v['realm'].upper()+'\n dns_lookup_kdc = true\n rdns = false\n',0o644)
        ledger['member_configured']=True;save()
    save('Присоединение обычного сервера к домену','member-join')
    from samba.netcmd.domain import cmd_domain_join
    from samba.param import LoadParm
    member_lp=LoadParm();member_lp.load(str(SMB));member_spns(v,m,member_lp)
    if not ledger.get('joined'):
        out=io.StringIO();cmd=cmd_domain_join(outf=out,errf=out);cmd.command_name='domain join'
        with contextlib.redirect_stdout(out),contextlib.redirect_stderr(out):
            code=cmd._run(v['realm'],'MEMBER','--server='+v['source'],'--username='+v['username'],'--password='+v['password'],'--use-kerberos=off')
        if code not in [None,0]:raise RuntimeError('Не завершено присоединение к домену: '+out.getvalue()[-1600:])
        ledger['joined']=True;save()
    # The native join can canonicalize SPNs to short names. Restore the FQDN
    # host identities and emit a matching keytab using only the machine secret.
    member_spns(v,m,member_lp)
    if modern:run(['/usr/bin/net','-P','-S',v['source'],'ads','changetrustpw'])
    else:run(['/usr/bin/net','-P','-S',v['source'],'ads','keytab','create'])
    if v['node'].encode() not in pathlib.Path('/etc/krb5.keytab').read_bytes():raise RuntimeError('Не создан keytab для полного DNS-имени сервера')
    run(['systemctl','unmask','smb','winbind']);run(['systemctl','enable','--now','winbind','smb'])
    nss=pathlib.Path('/etc/nsswitch.conf');content=nss.read_text()
    for kind in ['passwd','group']:
        if not re.search(r'(?m)^'+kind+':',content):raise RuntimeError('Не найдена строка '+kind+' в nsswitch.conf')
        content=re.sub(r'(?m)^'+kind+r':([^\n]*)',lambda match:kind+':'+match[1]+(' winbind' if 'winbind' not in match[1].split() else ''),content)
    atomic(nss,content,0o644);run(['control','system-auth','winbind'])
    run(['wbinfo','--check-secret']);run(['getent','passwd',m['netbios']+'\\'+v['username'].split('@')[0].split('\\')[-1]])
    save('Доверие к домену и разрешение учётной записи через Winbind подтверждены','verify')
    # Use the fresh member bindings and an explicit target for final AD checks.
    from samba.param import LoadParm
    lp=LoadParm();lp.load(str(SMB));restore_host(v,m,lp)
    if changed:run(['systemctl','restart','sambaadm-helper'])
    if run(['systemctl','is-active','sambaadm-helper']).strip()!='active':raise RuntimeError('Helper не запущен после смены роли')
    run(['testparm','-s']);save('Роль DC снята. Сервер — член домена; helper работает. Защитная копия доступна только root.','completed')

def execute(v,folder,config,save,state,ledger,resume):
    if resume:
        if not ledger.get('attempted'):raise RuntimeError('Снятие роли ещё не начиналось. Нужна новая проверка.')
        m=ledger['metadata']
        if any(m[k]!=v[k] for k in ['node','source','realm']):raise RuntimeError('Параметры не совпадают с исходным заданием')
        atomic('/etc/resolv.conf','search '+v['realm']+'\n'+''.join('nameserver '+ip+'\n' for ip in m['sourceIPs']),0o644)
        lp,_=bindings(False);verify_retired(v,m,lp);ledger['demoted']=True;save('Удаление роли подтверждено на партнёре');restore_host(v,m,lp)
    else:
        save('Повторная проверка AD, SYSVOL и репозиториев','preflight');plan=preflight(v,config)
        if plan['revision']!=v['revision']:raise RuntimeError('Состояние сервера, AD или пакетов изменилось. Выполните новый предпросмотр.')
        save('Скачивание пакетов до остановки служб','download');versions=repositories(download=True)
        if versions!=plan['metadata']['packages']:raise RuntimeError('Изменились версии пакетов; выполните новый предпросмотр')
        m=plan['metadata'];lp,db=bindings();source=remote(v,lp)
        import base64
        from samba.ndr import ndr_pack
        _,records=source.dns_lookup(v['node']);m['hostRecords']=[base64.b64encode(ndr_pack(r)).decode() for r in records if r.wType in [1,28]]
        if not m['hostRecords']:raise RuntimeError('На партнёре отсутствуют адресные DNS-записи сервера')
        if m.get('krbtgt'):m['krbtgtGUID']=bytes(one(source,m['krbtgt'],['objectGUID'])['objectGUID'][0]).hex()
        ledger['metadata']=m;save()
        # Snapshot configs and database while AD is stopped, before irreversible work.
        save('Защитная копия конфигурации и базы DC','backup')
        backup=folder/'before';backup.mkdir(mode=0o700)
        for path in [SMB,pathlib.Path('/etc/krb5.conf'),pathlib.Path('/etc/resolv.conf'),pathlib.Path('/etc/nsswitch.conf'),pathlib.Path(config)]:
            if path.exists():run(['cp','-a',str(path),str(backup/path.name)])
        run(['systemctl','stop','samba'])
        try:run(['cp','-a','/var/lib/samba',str(backup/'samba')],300)
        finally:run(['systemctl','start','samba'])
        # Check again after the backup; no stale topology or SYSVOL may be retired.
        fresh=preflight(v,config)
        if fresh['revision']!=v['revision']:raise RuntimeError('Состояние изменилось во время подготовки; выполните новый предпросмотр')
        save('Репликация всех разделов AD, включая DNS','replication')
        if not m['rodc']:
            from samba.drs_utils import drsuapi_connect
            from samba.dcerpc import drsuapi,misc
            for nc in m['ncs']:
                req=drsuapi.DsReplicaSyncRequest1();req.naming_context=drsuapi.DsReplicaObjectIdentifier();req.naming_context.dn=nc;req.options=drsuapi.DRSUAPI_DRS_WRIT_REP;req.source_dsa_guid=misc.GUID(db.get_ntds_GUID())
                # A restarted DC can invalidate the partner's cached DRS pipe.
                # Retry only this read/copy synchronization, before demotion starts.
                for attempt in range(5):
                    try:
                        conn,handle,_=drsuapi_connect(v['source'],lp,credentials(v,lp));conn.DsReplicaSync(handle,1,req);break
                    except RuntimeError:
                        if attempt==4:raise
                        time.sleep(2)
        ledger['attempted']=True;save('Штатное снятие роли DC; при сбое потребуется проверка AD','demoting')
        from samba.netcmd.domain import cmd_domain_demote
        out=io.StringIO();cmd=cmd_domain_demote(outf=out,errf=out);cmd.command_name='domain demote'
        try:
            with contextlib.redirect_stdout(out),contextlib.redirect_stderr(out):code=cmd._run('--server='+v['source'],'--username='+v['username'],'--password='+v['password'],'--use-kerberos=off')
            if code not in [None,0]:raise RuntimeError(out.getvalue()[-1600:])
            verify_retired(v,m,lp);ledger['demoted']=True;save('Удаление роли DC подтверждено на RWDC')
            restore_host(v,m,lp)
        finally:
            # Even an interrupted/uncertain native demotion must not revive on reboot.
            fence()
    fence();atomic('/etc/resolv.conf','search '+v['realm']+'\n'+''.join('nameserver '+ip+'\n' for ip in m['sourceIPs']),0o644)
    save('Проверка доступности пакетов для завершения членства','member-packages');repositories(download=True)
    run(['apt-get','--no-download','-y','install',*PACKAGES],300)
    # A new process avoids mixing DC Heimdal and upgraded generic Samba MIT libraries.
    payload={'input':v,'metadata':m}
    p=subprocess.run(['/usr/bin/python3',__file__,'member',str(folder.parent),config,folder.name],input=json.dumps(payload),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,text=True,env=ENV,timeout=600)
    state.update(json.loads((folder/'status.json').read_text()));ledger.clear();ledger.update(json.loads((folder/'ledger.json').read_text()))
    if p.returncode:raise RuntimeError('Настройка члена домена не завершена. Причина и безопасное продолжение — в журнале задания.')

def main():
    v=json.load(sys.stdin);mode=sys.argv[1];base=pathlib.Path(sys.argv[2]);config=sys.argv[3]
    password=(v.get('input',v)).get('password','')
    if mode=='manifest':
        try:print(json.dumps(manifest(v)));return 0
        except Exception as e:print(json.dumps({'error':str(e)}));return 1
    if mode=='plan':
        try:
            plan=preflight(v,config);plan.pop('metadata');print(json.dumps(plan,ensure_ascii=False));return 0
        except Exception as e:print(json.dumps({'error':str(e).replace(password,'[скрыто]')},ensure_ascii=False));return 1
    ident=sys.argv[4]
    if not re.fullmatch('[a-f0-9]{32}',ident):return 1
    folder=base/ident;state=json.loads((folder/'status.json').read_text());ledger=json.loads((folder/'ledger.json').read_text()) if (folder/'ledger.json').exists() else {}
    def save(message=None,phase=None):
        if message:state['log'].append(time.strftime('%H:%M:%S')+' · '+str(message).replace(password,'[скрыто]')[:1800])
        if phase:state['phase']=phase
        state['log']=state['log'][-400:];atomic(folder/'ledger.json',json.dumps(ledger));atomic(folder/'status.json',json.dumps(state,ensure_ascii=False))
    try:
        if mode=='member':member(v['input'],v['metadata'],folder,config,save,ledger);return 0
        with open(base.parent/'operations.lock','a') as lock:
            deadline=time.monotonic()+15
            while True:
                try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);break
                except BlockingIOError:
                    if time.monotonic()>deadline:raise RuntimeError('На сервере выполняется другая операция. Проверьте журнал и повторите.')
                    time.sleep(.1)
            state['state']='running';state.pop('error',None);save()
            execute(v,folder,config,save,state,ledger,mode=='resume');state['state']='completed';save()
    except Exception as e:
        if mode!='member' and (folder/'status.json').exists():
            current=json.loads((folder/'status.json').read_text())
            if current.get('state')=='needs_member':state.update(current)
        state['state']='needs_member' if ledger.get('demoted') or mode=='member' else ('needs_review' if ledger.get('attempted') else 'cancelled')
        state['error']=str(e).replace(password,'[скрыто]')[:1800];save('Операция остановлена: '+state['error']);return 1
    return 0
if __name__=='__main__':sys.exit(main())
