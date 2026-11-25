"""First panel/RWDC in an existing AD. No Windows helper or DFSR is assumed.
Credentials stay in the worker's memory. Nothing raises an existing AD level.
"""
import contextlib, hashlib, io, json, os, pathlib, re, secrets, shutil, socket, sys, time, types

def dc_bindings():
    path=pathlib.Path('/usr')/getattr(sys,'platlibdir','lib64')/'samba-dc'/('python%d.%d'%sys.version_info[:2])
    if not path.is_dir():raise RuntimeError('Не установлены модули Samba AD DC')
    sys.path.insert(0,str(path))

def first(row,key,default=''):
    return str(row[key][0]) if key in row and len(row[key]) else default

def paged(db,base,expression,attrs):
    import ldb
    cookie='';seen=set()
    for _ in range(10000):
        result=db.search(base=base,scope=ldb.SCOPE_SUBTREE,expression=expression,attrs=attrs,controls=['paged_results:1:500'+(':'+cookie if cookie else '')])
        yield from result
        controls=[str(c).split(':',2) for c in result.controls if str(c).startswith('paged_results:')]
        cookie=controls[0][2] if controls and len(controls[0])==3 else ''
        if not cookie:return
        if cookie in seen:raise RuntimeError('Источник повторил страницу LDAP; полнота каталога не подтверждена')
        seen.add(cookie)
    raise RuntimeError('Каталог превышает предел проверки 5 миллионов объектов')

def snapshot(db):
    attrs=['objectGUID','objectClass','sAMAccountName','userPrincipalName','displayName','userAccountControl','groupType','member','gPLink','gPOptions','versionNumber','gPCFileSysPath']
    result={};counts={'users':0,'groups':0,'computers':0,'ous':0,'gpo':0}
    expression='(|(objectClass=user)(objectClass=group)(objectClass=organizationalUnit)(objectClass=computer)(objectClass=groupPolicyContainer)(objectClass=domainDNS))'
    for row in paged(db,str(db.domain_dn()),expression,attrs):
        guid=bytes(row['objectGUID'][0]).hex();record={'dn':str(row.dn).casefold()}
        for key in attrs[1:]:
            if key in row:record[key]=sorted(str(v).casefold() for v in row[key])
        result[guid]=record;classes=record.get('objectClass',[])
        if 'computer' in classes:counts['computers']+=1
        elif 'user' in classes:counts['users']+=1
        if 'group' in classes:counts['groups']+=1
        if 'organizationalunit' in classes:counts['ous']+=1
        if 'grouppolicycontainer' in classes:counts['gpo']+=1
    return result,counts

def connect(value,folder):
    # Pin this process's KDC selection before loading Heimdal; no system Kerberos
    # file is overwritten merely to authenticate the existing-domain source.
    if '@' in value['username']:
        account,upn_realm=value['username'].rsplit('@',1)
        if upn_realm.casefold()!=value['realm'].casefold():raise RuntimeError('Для начальной Kerberos-проверки укажите NETBIOS\\логин или UPN с основным DNS-именем домена')
        value['username']=account+'@'+value['realm'].upper()
    path=folder/'source-krb5.conf';path.write_text('[libdefaults]\n default_realm = '+value['realm'].upper()+'\n dns_lookup_kdc = false\n rdns = false\n[realms]\n '+value['realm'].upper()+' = {\n  kdc = '+value['source']+'\n }\n');path.chmod(0o600)
    os.environ['KRB5_CONFIG']=str(path);os.environ['KRB5CCNAME']='MEMORY:sambaadm-bootstrap-'+secrets.token_hex(12)
    dc_bindings()
    from samba.param import LoadParm
    from samba.samdb import SamDB
    from samba.credentials import Credentials,MUST_USE_KERBEROS
    from samba import gensec
    lp=LoadParm();lp.set('realm',value['realm'].upper());lp.set('netbios name',value['hostname'].upper());lp.set('server role','active directory domain controller');lp.set('client ldap sasl wrapping','seal')
    creds=Credentials();creds.guess(lp);creds.parse_string(value['username']);creds.set_realm(value['realm'].upper());creds.set_password(value['password']);creds.set_kerberos_state(MUST_USE_KERBEROS);creds.set_gensec_features(gensec.FEATURE_SEAL);creds.get_named_ccache(lp,os.environ['KRB5CCNAME'])
    source=SamDB(url='ldap://'+value['source'],lp=lp,credentials=creds)
    return lp,creds,source

def discover(value,folder,save):
    dc_bindings()
    import ldb
    from samba import functional_level,version
    from samba.ndr import ndr_pack
    from samba.dcerpc import security
    lp,creds,source=connect(value,folder)
    expected=','.join('DC='+part for part in value['realm'].split('.'))
    if str(source.domain_dn()).casefold()!=expected.casefold():raise RuntimeError('Источник относится к другому домену; присоединение отменено')
    root=source.search(base='',scope=ldb.SCOPE_BASE,attrs=['dsServiceName','domainFunctionality','forestFunctionality','namingContexts'])[0]
    dsa=first(root,'dsServiceName');ntds=source.search(base=dsa,scope=ldb.SCOPE_BASE,attrs=['msDS-isRODC','objectGUID'])[0]
    if first(ntds,'msDS-isRODC').upper()=='TRUE':raise RuntimeError('Для присоединения нужен записываемый DC')
    server=source.search(base=str(ldb.Dn(source,dsa).parent()),scope=ldb.SCOPE_BASE,attrs=['serverReference'])[0]
    computer=source.search(base=first(server,'serverReference'),scope=ldb.SCOPE_BASE,attrs=['dNSHostName','operatingSystem'])[0]
    if first(computer,'dNSHostName').lower()!=value['source']:raise RuntimeError('LDAP-источник не соответствует выбранному контроллеру')
    cross=source.search(base='CN=Partitions,'+str(source.get_config_basedn()),scope=ldb.SCOPE_SUBTREE,expression='(&(objectClass=crossRef)(nCName='+ldb.binary_encode(str(source.domain_dn()))+'))',attrs=['nETBIOSName'])
    if len(cross)!=1:raise RuntimeError('Не определено NetBIOS-имя существующего домена')
    value['netbios']=first(cross[0],'nETBIOSName')
    if not value['netbios'] or len(value['netbios'])>15 or any(x in value['netbios'] for x in '\r\n\x00[]=\\'):raise RuntimeError('Не поддерживается NetBIOS-имя этого домена')
    source_site=str(ldb.Dn(source,dsa).get_component_value(3));value['site']=value['site'] or source_site
    sites=source.search(base='CN=Sites,'+str(source.get_config_basedn()),scope=ldb.SCOPE_SUBTREE,expression='(objectClass=site)',attrs=['name'])
    if not any(first(s,'name').casefold()==value['site'].casefold() for s in sites):raise RuntimeError('Выберите существующий сайт: '+', '.join(first(s,'name') for s in sites))
    level=max(int(first(root,'domainFunctionality','0')),int(first(root,'forestFunctionality','0')))
    match=re.search(r'(\d+)\.(\d+)',version)
    supported=7 if match and tuple(map(int,match.groups()))>=(4,20) else 4
    if level>supported:raise RuntimeError('Уровень существующего AD '+functional_level.level_to_string(level)+' не поддерживается этой версией Samba '+version+'. Установите совместимую платформу/версию; мастер не понижает уровень AD.')
    value['_dcLevel']={4:'2008_R2',5:'2012',6:'2012_R2',7:'2016'}[max(level,4)]
    for name in [value['hostname'].upper()+'$',value['serviceUser']]:
        if source.search(base=str(source.domain_dn()),scope=ldb.SCOPE_SUBTREE,expression='(sAMAccountName='+ldb.binary_encode(name)+')',attrs=['name']):raise RuntimeError('В домене уже занято имя '+name+'; существующие учётные записи не заменяются')
    try:
        _,records=source.dns_lookup(value['panelName'])
        if any(r.wType!=1 or str(r.data)!=value['address'] for r in records):raise RuntimeError('HTTPS-имя уже используется в DNS; выберите другое')
    except RuntimeError as error:
        if not error.args or error.args[0]!=9714:raise
    group=source.search(base=str(source.domain_dn()),scope=ldb.SCOPE_SUBTREE,expression='(objectSid='+ldb.binary_encode(ndr_pack(security.dom_sid(source.get_domain_sid()+'-512')))+')',attrs=['sAMAccountName'])
    if len(group)!=1:raise RuntimeError('Не найдена доменная группа администраторов по SID')
    info={'source':value['source'],'os':first(computer,'operatingSystem'),'sid':source.get_domain_sid(),'sourceNTDS':dsa,'sourceGUID':bytes(ntds['objectGUID'][0]).hex(),'netbios':value['netbios'],'site':value['site'],'domainLevel':first(root,'domainFunctionality'),'forestLevel':first(root,'forestFunctionality')}
    (folder/'source-info.json').write_text(json.dumps(info,ensure_ascii=False));(folder/'source-info.json').chmod(0o600)
    save('Источник: '+value['source']+'; '+info['os']+'; NetBIOS '+value['netbios']+'; сайт '+value['site'],'source')
    return lp,creds,source,info

def native(command,args):
    output=io.StringIO();cmd=command(outf=output,errf=output);cmd.command_name='initial domain setup'
    try:
        with contextlib.redirect_stdout(output),contextlib.redirect_stderr(output):code=cmd._run(*args)
    except SystemExit:raise RuntimeError('Не приняты параметры Samba: '+output.getvalue()[-1800:])
    if code not in [None,0]:raise RuntimeError(output.getvalue()[-1800:])
    return output.getvalue()

def wait_directory(value,source,local,save):
    from samba.netcmd.drs import cmd_drs_replicate
    import ldb
    naming=[str(x) for x in source.search(base='',scope=ldb.SCOPE_BASE,attrs=['namingContexts'])[0]['namingContexts']]
    local_names={str(x).casefold() for x in local.search(base='',scope=ldb.SCOPE_BASE,attrs=['namingContexts'])[0]['namingContexts']}
    if any(n.casefold() not in local_names for n in naming):raise RuntimeError('Новый RWDC не содержит все разделы исходного домена, включая DNS')
    deadline=time.monotonic()+1200;attempt=0;last=''
    while time.monotonic()<deadline:
        attempt+=1
        try:
            before,counts=snapshot(source)
            for nc in naming:
                native(cmd_drs_replicate,['127.0.0.1',value['source'],nc,'--machine-pass','--use-kerberos=off'])
            after,counts=snapshot(source);received,_=snapshot(local)
            if before==after==received:
                save('Каталог совпадает с источником: пользователей '+str(counts['users'])+', групп '+str(counts['groups'])+', компьютеров '+str(counts['computers'])+', OU '+str(counts['ous'])+', GPO '+str(counts['gpo']),'directory-ready')
                return counts
            last='Источник изменяется или не все объекты и атрибуты получены'
        except Exception as error:last=str(error)
        save('Ожидание репликации, проход '+str(attempt)+': '+last[:600],'replication')
        time.sleep(3)
    raise RuntimeError('Репликация не подтверждена за 20 минут. Новый RWDC остаётся изолированным до проверки. '+last[:1000])

def transfer_roles(value,local,source,save,configured,creds):
    from samba.netcmd.fsmo import transfer_role,transfer_dns_role
    import ldb
    configured.set('client ldap sasl wrapping','seal')
    target=str(local.get_dsServiceName());report=[]
    root=str(local.get_root_basedn());base=str(local.domain_dn());config=str(local.get_config_basedn())
    roles=[('schema',str(local.get_schema_basedn())),('naming','CN=Partitions,'+config),('pdc',base),('rid','CN=RID Manager$,CN=System,'+base),('infrastructure','CN=Infrastructure,'+base),('domaindns','CN=Infrastructure,DC=DomainDnsZones,'+base),('forestdns','CN=Infrastructure,DC=ForestDnsZones,'+root)]
    for role,dn in roles:
        try:
            co=types.SimpleNamespace(get_credentials=lambda ignored,**kw:creds)
            so=types.SimpleNamespace(get_loadparm=lambda:configured)
            output=io.StringIO()
            if role in ['domaindns','forestdns']:
                try:transfer_dns_role(output,so,co,role,local)
                except Exception:
                    # Native DNS transfer may have changed the owner before a
                    # pull-RPC error. Confirm that exact result before catch-up.
                    owner=first(source.search(base=dn,scope=ldb.SCOPE_BASE,attrs=['fSMORoleOwner'])[0],'fSMORoleOwner')
                    if owner.casefold()!=target.casefold():raise
                    from samba.netcmd.drs import cmd_drs_replicate
                    native(cmd_drs_replicate,['127.0.0.1',value['source'],dn[len('CN=Infrastructure,'):],'--machine-pass','--use-kerberos=off'])
            else:transfer_role(output,role,local)
            owners=[first(db.search(base=dn,scope=ldb.SCOPE_BASE,attrs=['fSMORoleOwner'])[0],'fSMORoleOwner') for db in [local,source]]
            if not all(owner.casefold()==target.casefold() for owner in owners):raise RuntimeError('Владелец роли пока не подтверждён на обоих DC')
            report.append({'role':role,'state':'transferred'});save('Роль '+role+' передана новому RWDC','fsmo')
        except Exception as error:
            report.append({'role':role,'state':'not-confirmed','error':str(error)[:700]});save('Панель готова, но роль '+role+' не подтверждена: '+str(error)[:700],'fsmo')
    return report

def bootstrap(value,folder,save,ops):
    """Join only after package gating; expose the DC only after AD/SYSVOL checks."""
    dc_bindings()
    from samba.param import LoadParm
    from samba.samdb import SamDB
    from samba.auth import system_session
    from samba.netcmd.domain import cmd_domain_join
    from samba.ndr import ndr_pack
    from samba.dcerpc import security
    import ldb
    lp,creds,source,info=discover(value,folder,save)
    run=ops['run'];smb=ops['SMB'];hostname=value['hostname'].lower()+'.'+value['realm']
    if smb.exists():shutil.copy2(smb,folder/'smb.conf.before')
    (folder/'hostname.before').write_text(socket.gethostname());(folder/'hostname.before').chmod(0o600)
    if socket.gethostname().lower()!=hostname:run(['hostnamectl','set-hostname',hostname])
    smb.parent.mkdir(parents=True,exist_ok=True)
    smb.write_text('[global]\nserver role = active directory domain controller\nrealm = '+value['realm'].upper()+'\nworkgroup = '+value['netbios']+'\nnetbios name = '+value['hostname'].upper()+'\nad dc functional level = '+value['_dcLevel']+'\n');smb.chmod(0o644)
    save('Присоединение первого Samba RWDC к существующему домену; уровень и владельцы FSMO не изменяются','join')
    smb.unlink()
    native(cmd_domain_join,[value['realm'],'DC','--server='+value['source'],'--site='+value['site'],'--dns-backend=SAMBA_INTERNAL','--username='+value['username'],'--password='+value['password'],'--use-kerberos=required','--realm='+value['realm'].upper(),'--option=netbios name='+value['hostname'].upper(),'--option=workgroup='+value['netbios'],'--option=ad dc functional level='+value['_dcLevel'],'--option=dns forwarder='+value['forwarder']])
    configured=LoadParm();configured.load(str(smb));configured.set('ad dc functional level',value['_dcLevel']);configured.set('dns forwarder',value['forwarder'])
    tls=pathlib.Path(configured.get('private dir'))/'tls';tls.mkdir(mode=0o700,parents=True,exist_ok=True)
    for name,dest in [('tls.key','key.pem'),('tls.crt','cert.pem'),('tls-ca.pem','ca.pem')]:shutil.copyfile(folder/name,tls/dest);(tls/dest).chmod(0o600 if name=='tls.key' else 0o644)
    # A loopback-only initial service permits DRS catch-up but prevents clients
    # from receiving an incomplete SYSVOL. Preserve the final native config.
    ready=folder/'smb.conf.ready';configured.dump(False,str(ready));ready.chmod(0o600)
    configured.set('interfaces','127.0.0.1');configured.set('bind interfaces only','yes');configured.set('dns update command','/usr/bin/true');configured.dump(False,str(smb));smb.chmod(0o644)
    staged_hash=hashlib.sha256(smb.read_bytes()).hexdigest()
    run(['systemctl','enable','--now','samba'])
    for _ in range(40):
        try:
            with socket.create_connection(('127.0.0.1',389),timeout=2):break
        except OSError:time.sleep(1)
    local=SamDB(lp=configured,session_info=system_session(configured))
    if local.get_domain_sid()!=info['sid'] or local.am_rodc():raise RuntimeError('Не совпала идентичность нового RWDC и исходного домена')
    counts=wait_directory(value,source,local,save)
    save('Проверяемое начальное копирование SYSVOL из существующего домена','sysvol')
    ops['initial_sysvol'](value,configured,folder,save)
    # A changing source must be read again; never label an old GPO file set as ready.
    after,_=snapshot(source);received,_=snapshot(local)
    if after!=received:raise RuntimeError('Каталог изменился после копирования SYSVOL. Проверьте репликацию перед публикацией нового DC; исходные политики не менялись.')
    if hashlib.sha256(smb.read_bytes()).hexdigest()!=staged_hash:raise RuntimeError('smb.conf изменён другим администратором; автоматическая замена отменена')
    shutil.copyfile(ready,smb);smb.chmod(0o644)
    generated=pathlib.Path('/var/lib/samba/private/krb5.conf')
    if generated.exists():
        current=pathlib.Path('/etc/krb5.conf')
        if current.is_symlink():raise RuntimeError('Проверьте ссылку /etc/krb5.conf перед запуском RWDC')
        if current.exists():shutil.copy2(current,folder/'krb5.conf.before')
        shutil.copy2(generated,current)
    run(['systemctl','restart','samba'])
    for _ in range(60):
        try:
            soa=run(['dig','+time=2','+tries=1','+short','@127.0.0.1',value['realm'],'SOA'],5)
            srv=run(['dig','+time=2','+tries=1','+short','@127.0.0.1','_ldap._tcp.dc._msdcs.'+value['realm'],'SRV'],5)
            if soa.strip() and hostname+'.' in srv.lower():break
        except Exception:pass
        time.sleep(1)
    else:raise RuntimeError('Не подтверждены DNS SOA/SRV нового RWDC; исходный Windows DC не отключайте')
    resolver=pathlib.Path('/etc/resolv.conf')
    if resolver.is_symlink():raise RuntimeError('Проверьте постоянную настройку DNS ОС')
    if resolver.exists():shutil.copy2(resolver,folder/'resolv.conf.before')
    resolver.write_text('search '+value['realm']+'\nnameserver 127.0.0.1\n')
    state={'sid':info['sid'],'ntds':str(local.get_dsServiceName()),'ntdsGUID':str(local.get_ntds_GUID()),'source':info,'directory':counts,'netbios':value['netbios'],'site':value['site']}
    checkpoint(folder,state)
    value['_resumable']=True
    return finish(value,folder,save,ops,configured,local,source,creds,state)

def checkpoint(folder,state):
    path=folder/'existing-state.tmp'
    path.write_text(json.dumps(state,ensure_ascii=False));path.chmod(0o600)
    path.replace(folder/'existing-state.json')

def resume(value,folder,save,ops):
    dc_bindings()
    from samba.param import LoadParm
    from samba.samdb import SamDB
    from samba.auth import system_session
    state=json.loads((folder/'existing-state.json').read_text())
    value['netbios']=state['netbios'];value['site']=state['site'];value['_resumable']=True
    configured=LoadParm();configured.load(str(ops['SMB']))
    if configured.get('server role')!='active directory domain controller' or configured.get('realm').casefold()!=value['realm'].casefold():raise RuntimeError('Конфигурация роли изменена; продолжение отменено')
    local=SamDB(lp=configured,session_info=system_session(configured))
    if local.get_domain_sid()!=state['sid'] or str(local.get_dsServiceName())!=state['ntds'] or str(local.get_ntds_GUID())!=state['ntdsGUID'] or local.am_rodc():raise RuntimeError('Идентичность RWDC изменилась; продолжение отменено')
    _,creds,source=connect(value,folder)
    if source.get_domain_sid()!=state['sid'] or str(source.get_dsServiceName())!=state['source']['sourceNTDS']:raise RuntimeError('Изменился исходный домен или DC; продолжение отменено')
    import ldb
    remote_dsa=source.search(base=str(source.get_dsServiceName()),scope=ldb.SCOPE_BASE,attrs=['objectGUID'])[0]
    if bytes(remote_dsa['objectGUID'][0]).hex()!=state['source']['sourceGUID']:raise RuntimeError('Изменился GUID исходного контроллера; продолжение отменено')
    save('Продолжение настройки панели и helper. Присоединение и копирование SYSVOL повторно не выполняются.','resume')
    return finish(value,folder,save,ops,configured,local,source,creds,state)

def finish(value,folder,save,ops,configured,local,source,creds,state):
    import ldb,subprocess
    from samba.ndr import ndr_pack
    from samba.dcerpc import security
    hostname=value['hostname'].lower()+'.'+value['realm']
    tls=pathlib.Path(configured.get('private dir'))/'tls'
    group=local.search(base=str(local.domain_dn()),scope=ldb.SCOPE_SUBTREE,expression='(objectSid='+ldb.binary_encode(ndr_pack(security.dom_sid(local.get_domain_sid()+'-512')))+')',attrs=['sAMAccountName'])[0]
    save('Настройка HTTPS панели и новой служебной записи '+value['serviceUser'],'panel')
    secret=folder/'service.secret'
    if not secret.exists():
        with secret.open('x') as f:
            os.fchmod(f.fileno(),0o600);f.write(secrets.token_urlsafe(36)+'aA1!')
    service_password=secret.read_text()
    marker='sambaadm bootstrap '+folder.name
    expression='(sAMAccountName='+ldb.binary_encode(value['serviceUser'])+')'
    rows=local.search(base=str(local.domain_dn()),scope=ldb.SCOPE_SUBTREE,expression=expression,attrs=['objectGUID','description','memberOf'])
    if not rows:
        if state.get('serviceGUID'):raise RuntimeError('Служебная запись удалена после создания; автоматическое восстановление отменено')
        deadline=time.monotonic()+90
        while True:
            try:
                local.newuser(value['serviceUser'],service_password,description=marker)
                break
            except ldb.LdbError as error:
                if error.args[0]!=53 or 'Remote RID Set creation needed' not in str(error) or time.monotonic()>=deadline:raise
                save('Ожидание выделения RID новому RWDC исходным владельцем роли','rid-ready')
                time.sleep(2)
        rows=local.search(base=str(local.domain_dn()),scope=ldb.SCOPE_SUBTREE,expression=expression,attrs=['objectGUID','description','memberOf'])
    row=rows[0];guid=bytes(row['objectGUID'][0]).hex()
    if len(rows)!=1 or first(row,'description')!=marker or (state.get('serviceGUID') and state['serviceGUID']!=guid):raise RuntimeError('Служебная запись не принадлежит этому заданию; замена отменена')
    state['serviceGUID']=guid;checkpoint(folder,state)
    if str(group.dn).casefold() not in [str(x).casefold() for x in (row['memberOf'] if 'memberOf' in row else [])]:local.add_remove_group_members(first(group,'sAMAccountName'),[value['serviceUser']],add_members_operation=True)
    from samba.netcmd.dns import cmd_add_record
    co=types.SimpleNamespace(get_credentials=lambda ignored:creds,ipaddress=None);so=types.SimpleNamespace(_lp=configured,get_loadparm=lambda:configured)
    try:
        _,records=local.dns_lookup(value['panelName'])
        if any(r.wType!=1 or str(r.data)!=value['address'] for r in records):raise RuntimeError('DNS-имя панели изменено другим администратором; замена отменена')
    except RuntimeError as error:
        if not error.args or error.args[0]!=9714:raise
        relative=value['panelName'][:-(len(value['realm'])+1)]
        cmd_add_record().run(hostname,value['realm'],relative,'A',value['address'],sambaopts=so,credopts=co)
    env={**ops['ENV'],'SAMBAADM_PASSWORD':service_password}
    config=pathlib.Path('/etc/sambaadm/config.yaml')
    if not state.get('panelReady'):
        # A setup interrupted after writing config is never blindly repeated.
        current_hash=hashlib.sha256(config.read_bytes()).hexdigest() if config.exists() else ''
        if state.get('panelStarted') and current_hash!=state.get('panelBeforeHash',''):
            p=subprocess.run(['/usr/bin/sambaadm','--config',str(config),'serve','--check'],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=90)
        else:
            state['panelStarted']=True;state['panelBeforeHash']=current_hash;checkpoint(folder,state)
            p=subprocess.run(['/usr/sbin/sambaadm-setup','--yes','--realm',value['realm'],'--dc',hostname,'--user',value['serviceUser']+'@'+value['realm'],'--admin-group',str(group.dn),'--ca',str(tls/'ca.pem'),'--https-name',value['panelName']],env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,errors='replace',timeout=180)
        for line in p.stdout.splitlines()[-30:]:save(line.replace(service_password,'[скрыто]'))
        if p.returncode:raise RuntimeError('RWDC готов; настройка панели не подтверждена. Проверьте журнал setup, затем продолжите это задание.')
        state['panelReady']=True;checkpoint(folder,state)
    env.pop('SAMBAADM_PASSWORD',None)
    if not state.get('helperReady'):
        if state.get('helperStarted'):raise RuntimeError('Предыдущая установка helper не подтверждена. Проверьте привязку helper в рабочей панели; автоматическая перезапись запрещена.')
        state['helperStarted']=True;checkpoint(folder,state)
        ops['install_local_helper'](value,folder,save)
        state['helperReady']=True;checkpoint(folder,state)
    report={'directory':state['directory'],'source':state['source'],'sysvol':'initial-copy-verified','fsmo':state.get('fsmo',[]),'windowsTested':False}
    if value.get('transferRoles') and not state.get('rolesAttempted'):
        state['rolesAttempted']=True;checkpoint(folder,state)
        save('Дополнительный этап: обычный перенос FSMO без захвата; исходный DC остаётся включённым','fsmo')
        report['fsmo']=transfer_roles(value,local,source,save,configured,creds)
        state['fsmo']=report['fsmo'];checkpoint(folder,state)
    elif not value.get('transferRoles'):save('Перенос FSMO пропущен. Он доступен позднее в «Домен и FSMO».','fsmo-skipped')
    value['_report']=report;value['_resumable']=False
    save('RWDC, каталог, SYSVOL, DNS, панель и helper проверены. Исходный DC не отключался.','complete')
