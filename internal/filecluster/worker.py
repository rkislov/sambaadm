"""Fixed storage/HA probes. No request-controlled command, script or filesystem path."""
import hashlib, ipaddress, json, os, pathlib, re, shutil, socket, subprocess, sys, fcntl, secrets, shlex, stat, time
ENV={**os.environ,'LC_ALL':'C','PATH':'/usr/sbin:/usr/bin:/sbin:/bin'}

def run(args,timeout=20,*,separate_stderr=False):
 p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE if separate_stderr else subprocess.STDOUT,text=True,errors='replace',timeout=timeout,env=ENV)
 if p.returncode:raise RuntimeError(args[0]+': '+(p.stderr or p.stdout)[-1600:])
 if len(p.stdout)>4*1024*1024:raise RuntimeError('Слишком большой результат проверки')
 return p.stdout

def optional(args,json_output=False):
 try:
  value=run(args)
  return {'available':True,'value':json.loads(value) if json_output else value}
 except Exception as error:return {'available':False,'error':str(error)}

def platform():
    release=pathlib.Path('/etc/os-release').read_text()
    if not re.search(r'(?m)^ID=(?:"?altlinux"?|"?alt"?)$',release):raise RuntimeError('Поддерживаются ALT p10 и p11')
    match=re.search(r'(?m)^ALT_BRANCH_ID="?(p(?:10|11))"?$',release)
    if match:return match[1]
    match=re.search(r'(?m)^VERSION_ID="?(10|11)(?:[.][^"\n]*)?"?$',release)
    if not match:raise RuntimeError('Не определена целевая ветка p10/p11; проверка остановлена')
    return 'p'+match[1]

def decorate_blocks(blocks):
    scsi_id=next((p for p in ['/usr/lib/udev/scsi_id','/lib/udev/scsi_id'] if pathlib.Path(p).exists()),None)
    for block in blocks:
        name=block.get('kname','')
        if re.fullmatch(r'[A-Za-z0-9_.!-]+',name) and block.get('type')=='disk':
            stable=''
            if scsi_id:
                try:stable=run([scsi_id,'--whitelisted','--device=/dev/'+name],5).strip()
                except Exception:pass
            if not stable and block.get('serial'):stable='serial-'+block['serial']
            block['diskWWID']=stable
        if block.get('type')=='mpath' and re.fullmatch(r'dm-[0-9]+',name):
            uuid=pathlib.Path('/sys/class/block')/name/'dm/uuid'
            if uuid.is_file() and uuid.read_text().strip().startswith('mpath-'):block['diskWWID']=uuid.read_text().strip()[6:]
        if block.get('children'):decorate_blocks(block['children'])

def zfs_readiness():
    """Read-only checks; installing a package is not proof of a usable module."""
    kernel=os.uname().release
    result={'ready':False,'runningKernel':kernel,'blockers':[]}
    checks={'moduleKernel':['modinfo','-F','vermagic','zfs'],'moduleVersion':['modinfo','-F','version','zfs'],'userVersion':['zfs','version']}
    for key,args in checks.items():
        try:result[key]=run(args,10).strip()
        except Exception:result['blockers'].append('Недоступна проверка '+key)
    if result.get('moduleKernel','').split(' ')[0]!=kernel:
        result['blockers'].append('Модуль ZFS не соответствует работающему ядру; установите совместимый модуль и перезагрузите узел')
    loaded=pathlib.Path('/sys/module/zfs/version')
    result['loadedVersion']=loaded.read_text().strip() if loaded.is_file() else ''
    if not result['loadedVersion']:
        result['blockers'].append('Модуль ZFS ещё не загружен')
    elif result.get('moduleVersion')!=result['loadedVersion']:
        result['blockers'].append('Версия загруженного модуля ZFS отличается от установленной; нужна перезагрузка')
    user=re.search(r'(?m)^zfs-([0-9][^\s]*)$',result.get('userVersion',''))
    if not user or user[1]!=result.get('moduleVersion'):
        result['blockers'].append('Версии ZFS userspace и модуля не совпадают')
    # Cloud clones can return the same network-derived hostid on both nodes.
    # MMP needs a persistent identity, checked for uniqueness by the manager.
    result['hostID']=''
    try:
        raw=pathlib.Path('/etc/hostid').read_bytes()
        if len(raw)!=4 or int.from_bytes(raw,sys.byteorder)==0:raise ValueError('invalid hostid')
        result['hostID']=format(int.from_bytes(raw,sys.byteorder),'08x')
    except Exception:
        result['blockers'].append('Для ZFS multihost нужен постоянный ненулевой /etc/hostid, уникальный на каждом узле')
    # cachefile=none does not prevent import-scan from importing every pool.
    # Do not disable global services silently: a host may have unrelated pools.
    result['autoImport']={}
    for unit in ['zfs-import-cache.service','zfs-import-scan.service']:
        try:
            properties=dict(line.split('=',1) for line in run(['systemctl','show',unit,'--property=LoadState','--property=UnitFileState'],5).splitlines() if '=' in line)
            state='absent' if properties.get('LoadState')=='not-found' else properties.get('UnitFileState','unknown')
        except Exception:state='unknown'
        result['autoImport'][unit]=state
        if state not in ['disabled','masked','masked-runtime','absent']:
            result['blockers'].append('Проверьте штатный автоимпорт '+unit+' до передачи пула кластеру')
    result['ready']=not result['blockers']
    return result

def inventory():
 blocks=json.loads(run(['lsblk','--json','--bytes','--output','NAME,KNAME,PATH,TYPE,SIZE,RO,WWN,SERIAL,FSTYPE,UUID,PTTYPE,PTUUID,MOUNTPOINTS,PKNAME']))
 decorate_blocks(blocks.get('blockdevices',[]))
 config_hashes={p:hashlib.sha256(pathlib.Path(p).read_bytes() if pathlib.Path(p).is_file() else b'').hexdigest() for p in ['/etc/samba/smb.conf','/etc/corosync/corosync.conf','/etc/multipath.conf','/etc/lvm/lvm.conf']}
 tools={name:bool(shutil.which(name)) for name in ['iscsiadm','multipath','multipathd','pcs','corosync','stonith_admin','zpool','zfs','drbdadm','lvs']}
 identity=optional(['testparm','-s','--parameter-name=server role'])
 result={'bootID':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'platform':platform(),'hostname':socket.getfqdn(),'kernel':os.uname().release,'osRelease':pathlib.Path('/etc/os-release').read_text(),'blocks':blocks,'configHashes':config_hashes,'tools':tools,'sambaRole':identity,
  'mounts':optional(['findmnt','--json'],True),'iscsiSessions':optional(['iscsiadm','-m','session']),
  'multipath':optional(['multipathd','show','maps','json'],True),'volumes':optional(['lvs','--reportformat','json','-o','vg_name,lv_name,lv_uuid,lv_attr,origin,pool_lv,devices'],True),
  'zfs':optional(['zpool','list','-H','-o','name,guid,health']), 'cluster':optional(['crm_mon','--one-shot','--output-as=xml'])}
 result['modules']={name:optional(['modinfo','-F','vermagic',name]) for name in ['iscsi_tcp','dm_multipath','drbd','zfs']}
 result['zfsReadiness']=zfs_readiness() if tools['zfs'] else {'ready':False,'blockers':['ZFS не установлен']}
 return result

def repository(packages,storage=None,filesystem=None):
 allowed={'pacemaker','corosync','resource-agents','open-iscsi','multipath-tools','drbd-utils','zfs-utils','lvm2','xfsprogs','thin-provisioning-tools','samba','samba-winbind','samba-common-tools','samba-winbind-clients','samba-client','openssl','acl','attr','fence-agents-redfish','fence-agents-ipmilan','fence-agents-pve'}
 if not packages or not set(packages)<=allowed:raise RuntimeError('Недопустимый набор пакетов')
 branch=platform()
 output=run(['apt-get','-o','Acquire::http::Timeout=15','-o','Acquire::Retries=0','update'],120)
 if re.search(r'(?im)^(Err:|Err\s|E:|W:.*(?:failed|fetch|resolve))',output) or 'Some index files failed' in output:raise RuntimeError('Репозитории доступны не полностью; исправьте источники до настройки хранилища')
 candidates={}
 for name in packages:
  match=re.search(r'(?m)^\s*Candidate:\s*(\S+)',run(['apt-cache','policy',name],5))
  if not match or match[1] in ['(none)','(null)']:raise RuntimeError('Недоступен пакет '+name+' для этой ОС/архитектуры')
  candidates[name]=match[1]
 kernel_packages=[]
 if storage=='drbd' or filesystem=='zfs':
  kernel_name=run(['rpm','-q','--qf','%{NAME}','-f','/boot/vmlinuz-'+os.uname().release],10).strip()
  if not re.fullmatch(r'kernel-image-[a-z0-9.-]{1,40}',kernel_name):raise RuntimeError('Не определён пакет работающего ядра')
  flavor=kernel_name.removeprefix('kernel-image-')
  for module in (['drbd9'] if storage=='drbd' else [])+(['zfs'] if filesystem=='zfs' else []):
   virtual='kernel-modules-'+module+'-'+flavor
   probe=run(['apt-get','-s','install',virtual],30)
   if re.search(r'(?m)^Remv\s',probe):raise RuntimeError('Модуль ядра требует удаления пакетов')
   selected=re.search(r'(?m)^Selecting (\S+) for ',probe)
   if selected:
    concrete=selected[1]
    if not concrete.startswith(virtual+'#'):raise RuntimeError('Неожиданный поставщик модуля ядра')
   else:concrete=virtual
   kernel_packages.append(concrete)
 simulation=run(['apt-get','-s','install',*packages,*kernel_packages],30)
 if re.search(r'(?m)^Remv\s',simulation):raise RuntimeError('План удаляет установленное ПО; настройка хранилища запрещена')
 result={'platform':branch,'candidates':candidates,'kernelPackages':kernel_packages,'rebootRequired':bool(re.search(r'(?m)^Inst kernel-image-',simulation)),'simulation':simulation}
 fingerprint={'packages':packages,'storage':storage,'filesystem':filesystem,'platform':branch,'candidates':candidates,'kernelPackages':kernel_packages,'kernel':os.uname().release}
 result['revision']=hashlib.sha256(json.dumps(fingerprint,sort_keys=True).encode()).hexdigest()
 return result

def discover(portals):
 if not isinstance(portals,list) or not 1<=len(portals)<=8:raise RuntimeError('Укажите от 1 до 8 iSCSI-порталов')
 result=[]
 for portal in portals:
  # Go validates AddrPort first; repeat validation at the privileged boundary.
  host,sep,port=portal.rpartition(':');host=host.strip('[]')
  address=ipaddress.ip_address(host)
  if not sep or not port.isdigit() or not 1<=int(port)<=65535 or address.is_loopback or address.is_unspecified or address.is_multicast:raise RuntimeError('Неверный iSCSI-портал')
  text=run(['iscsiadm','-m','discovery','-t','sendtargets','-p',portal,'-o','nonpersistent'],30)
  targets=[]
  for line in text.splitlines():
   parts=line.split()
   if len(parts)==2 and parts[1].startswith('iqn.'):
    targets.append({'portal':parts[0].split(',')[0],'iqn':parts[1]})
  result.append({'portal':portal,'targets':targets})
 return {'discoveries':result,'loggedIn':False,'formatted':False}

def prepare_dedicated_zfs():
    # The operator may opt in only for nodes without any existing ZFS pools.
    corosync=pathlib.Path('/etc/corosync/corosync.conf')
    cache=pathlib.Path('/etc/zfs/zpool.cache')
    if corosync.is_file() and re.search(r'(?m)^\s*cluster_name\s*:',corosync.read_text()):
        raise RuntimeError('На узле уже настроен Corosync')
    run(['modprobe','zfs'])
    imported=run(['zpool','list','-H','-o','name'],30).strip()
    available=run(['zpool','import'],30).strip()
    if imported or available not in ('','no pools available to import') or (cache.is_file() and cache.stat().st_size):
        raise RuntimeError('На узле обнаружен существующий пул или кэш ZFS; автоимпорт оставлен без изменений')
    if not pathlib.Path('/etc/hostid').exists():
        run(['zgenhostid'])
    for unit in ['zfs-import-cache.service','zfs-import-scan.service']:
        config=run(['systemctl','show',unit,'--property=LoadState','--property=UnitFileState'],5)
        if 'LoadState=loaded' in config and 'UnitFileState=enabled' in config:
            run(['systemctl','disable',unit],30)


def prepare_packages(value,save):
    profile=value['profile'];packages=profile['packages']
    save('Повторная проверка источников и версий пакетов','preflight')
    plan=repository(packages,profile['storage'],profile['filesystem'])
    if plan['revision']!=value.get('revision'):raise RuntimeError('Пакеты или ядро изменились; повторите предпросмотр')
    selected=packages+plan['kernelPackages']
    save('Скачивание всех пакетов до изменения конфигурации','download')
    run(['apt-get','--download-only','-y','install',*selected],1200)
    # Downloaded package availability, current repositories and removal policy are checked again.
    current=repository(packages,profile['storage'],profile['filesystem'])
    if current['revision']!=plan['revision']:raise RuntimeError('Набор пакетов изменился во время скачивания; установка не начата')
    save('Установка зависимостей выбранного сценария','install')
    run(['apt-get','--no-download','-y','install',*selected],1800)
    if profile['storage']=='iscsi':run(['systemctl','enable','--now','iscsid'],30)
    if profile['filesystem']=='zfs' and value.get('prepareDedicatedZFS') and not plan['rebootRequired']:
        save('Подготовка выделенного узла ZFS','host-zfs')
        prepare_dedicated_zfs()
    if profile['filesystem']=='zfs' and not plan['rebootRequired']:
        run(['modprobe','zfs'])
    return {'platform':plan['platform'],'packages':plan['candidates'],'kernelPackages':plan['kernelPackages'],'rebootRequired':plan['rebootRequired']}

def sync_directory(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)

def durable_json(path,value,exclusive=False):
    target=path if exclusive else path.with_name(path.name+'.'+secrets.token_hex(6)+'.tmp')
    fd=os.open(target,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'w') as output:
            json.dump(value,output,ensure_ascii=False);output.flush();os.fsync(output.fileno())
        if not exclusive:target.replace(path)
        sync_directory(path.parent)
    finally:
        if not exclusive and target.exists():target.unlink()

def private_directory(path):
    existed=path.exists()
    path.mkdir(mode=0o700,parents=True,exist_ok=True)
    info=path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077:raise RuntimeError('Каталог состояния должен принадлежать root с правами 0700')
    if not existed:sync_directory(path);sync_directory(path.parent)
    return path

def vault_root():
    base=pathlib.Path(sys.argv[2] if len(sys.argv)>2 else '/var/lib/sambaadm-helper')
    if not base.is_absolute():raise RuntimeError('Нужен абсолютный каталог состояния helper')
    private_directory(base)
    return private_directory(private_directory(base/'filecluster')/'vault')

def credential_put(value):
    if value.get('kind') not in ['fence','iscsi','domain-join'] or not value.get('node') or not value.get('address'):raise RuntimeError('Неверные реквизиты')
    for key in ['node','address','system','username','password']:
        text=value.get(key,'')
        if not isinstance(text,str) or len(text)>4096 or any(c in text for c in '\x00\r\n'):raise RuntimeError('Неверные реквизиты')
    if not value.get('password'):raise RuntimeError('Не задан пароль')
    root=vault_root()
    if len(list(root.iterdir()))>=1000:raise RuntimeError('Достигнут предел сохранённых реквизитов')
    ident=value.get('reference') or secrets.token_hex(16)
    if not re.fullmatch(r'[a-f0-9]{32}',ident):raise RuntimeError('Неверный идентификатор реквизитов')
    path=root/(ident+'.json')
    if path.exists():
        _,existing=credential_read(ident)
        if existing!=value:raise RuntimeError('Идентификатор реквизитов уже занят; создайте новый')
        return {'reference':ident,'kind':value['kind'],'node':value['node']}
    durable_json(path,value,exclusive=True)
    return {'reference':ident,'kind':value['kind'],'node':value['node']}

def credential_read(reference):
    if not isinstance(reference,str) or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,63}',reference):raise RuntimeError('Неверная ссылка реквизитов')
    path=vault_root()/(reference+'.json')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW);info=os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077 or info.st_nlink!=1 or info.st_size>16384:raise RuntimeError('Нештатный файл реквизитов')
    try:
        with os.fdopen(fd) as source:record=json.load(source)
    except ValueError:raise RuntimeError('Файл реквизитов повреждён; сохраните реквизиты заново')
    return path,record

def fence_fingerprint(fence):
    path,_=credential_read(fence.get('credentialRef'))
    binary=shutil.which('fence_'+fence['agent'])
    if not binary:raise RuntimeError('Fencing-агент отсутствует')
    details={'fence':fence,'vault':hashlib.sha256(path.read_bytes()).hexdigest(),'agent':hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest()}
    return hashlib.sha256(json.dumps(details,sort_keys=True).encode()).hexdigest()

def fence_test(value,save=lambda *args:None):
    cluster=value.get('cluster',{});nodes=cluster.get('nodes',[]);local=value.get('localNode');target=value.get('target')
    names=[n.get('name') for n in nodes]
    if not value.get('confirm') or len(nodes)!=2 or local not in names or target not in names or local==target:raise RuntimeError('Нужно подтверждение проверки другого узла выбранной пары')
    index=names.index(target);fence=cluster.get('fences',[])[index]
    agent=fence.get('agent')
    if agent not in ['redfish','ipmilan']:raise RuntimeError('Непроверенный fencing-агент')
    path,record=credential_read(fence.get('credentialRef'))
    if record.get('kind')!='fence' or any(record.get(key,'')!=expected for key,expected in [('node',target),('address',fence.get('address','')),('system',fence.get('system','')),('username',fence.get('username',''))]):raise RuntimeError('Реквизиты привязаны к другому устройству fencing')
    binary=shutil.which('fence_'+agent);adapter=pathlib.Path('/usr/libexec/sambaadm-filecluster-secret')
    if not binary or not adapter.is_file():raise RuntimeError('Установите fencing-агент и обновите helper')
    params={'ipaddr':fence['address'],'login':record['username'],'passwd_script':str(adapter)+' '+shlex.quote(str(path)),'login_timeout':'10','power_timeout':'60'}
    if agent=='redfish':params.update(systems_uri=fence['system'],ssl='1')
    else:params['lanplus']='1'
    # Do not let a test interrupt an already configured cluster's resources.
    if pathlib.Path('/etc/corosync/corosync.conf').exists():
        text=pathlib.Path('/etc/corosync/corosync.conf').read_text()
        if re.search(r'(?m)^\s*cluster_name\s*:',text):raise RuntimeError('Проверка установки fencing выполняется до запуска кластера')
    def call(action):
        data=''.join(k+'='+str(v)+'\n' for k,v in {**params,'action':action}.items())
        result=subprocess.run([binary],input=data,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=12 if action=='status' else 70,env=ENV)
        if result.returncode not in ([0,2] if action=='status' else [0]):raise RuntimeError('Fencing не подтверждён: '+result.stdout.replace(record['password'],'[скрыто]')[-1000:])
        return result
    save('Проверка исходного питания','checking')
    initial=call('status')
    if initial.returncode!=0:raise RuntimeError('Целевой узел уже выключен; сначала восстановите его')
    try:
        save('Выключение выбранного второго узла','powering-off')
        call('off');off=call('status')
        if off.returncode!=2:raise RuntimeError('Fencing не подтвердил выключение; автоматическое переключение запрещено')
    finally:
        save('Восстановление питания после проверки','restoring-power')
        call('on');on=call('status')
        if on.returncode!=0:raise RuntimeError('Включение после проверки не подтверждено')
    fingerprint=fence_fingerprint(fence)
    proof={'target':target,'configurationHash':fingerprint,'offConfirmed':True,'onConfirmed':True,'verifiedAt':time.time()}
    proof_root=private_directory(vault_root().parent/'fence-proofs');file=proof_root/(hashlib.sha256(target.encode()).hexdigest()+'.json')
    durable_json(file,proof)
    return proof

def job(value):
    ident=sys.argv[3];action=sys.argv[4]
    if not re.fullmatch(r'[a-f0-9]{32}',ident):raise RuntimeError('Неверное задание')
    base=pathlib.Path(sys.argv[2]);folder=base/'filecluster/jobs'/ident
    private_directory(folder)
    state={'id':ident,'state':'running','pid':os.getpid(),'log':[]}
    def save(message=None,phase=None):
        if message:state['log'].append(time.strftime('%H:%M:%S')+' · '+message)
        if phase:state['phase']=phase
        temporary=folder/'status.tmp'
        with temporary.open('w') as output:
            output.write(json.dumps(state,ensure_ascii=False));output.flush();os.fsync(output.fileno())
        temporary.chmod(0o600);temporary.replace(folder/'status.json')
        directory=os.open(folder,os.O_RDONLY|os.O_DIRECTORY);os.fsync(directory);os.close(directory)
    try:
        save()
        with open(base/'operations.lock','a') as lock:
            os.chmod(lock.name,0o600)
            deadline=time.monotonic()+120
            while True:
                try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);break
                except BlockingIOError:
                    if time.monotonic()>=deadline:raise RuntimeError('Узел занят другой операцией; проверка питания не запускалась')
                    time.sleep(.1)
            if action=='fence-test':
                state['result']=fence_test(value,save)
            elif action=='packages':
                state['result']=prepare_packages(value,save)
            elif action in ['iscsi-connect','multipath']:
                state['result']=(connect if action=='iscsi-connect' else multipath)(value,globals(),save)
            else:
                operations={'cluster-stage':cluster_stage,'cluster-online':cluster_online,'cluster-initialize':cluster_initialize,'cluster-snapshot':cluster_snapshot,'cluster-snapshot-timer':cluster_snapshot_timer,'cluster-snapshot-schedule':cluster_snapshot_schedule,'cluster-restore-browse':cluster_restore_browse,'cluster-restore-preview':cluster_restore_preview,'cluster-restore-apply':cluster_restore_apply}
                if action not in operations:raise RuntimeError('Неверное задание')
                state['result']=operations[action](value,save)
        state['state']='completed';save('Задание выполнено','complete')
    except Exception as error:
        state['state']='failed';state['error']=str(error)[:1800];save('Проверка не завершена; проверьте питание целевого узла' if action=='fence-test' else 'Задание не завершено','failed')

def main():
 operation=sys.argv[1]
 if os.geteuid()!=0:raise RuntimeError('Нужен root на узле helper')
 if operation=='snapshot-tick':
  snapshot_tick({'name':sys.argv[3],'revision':sys.argv[4]})
  return
 request=json.load(sys.stdin)
 if operation=='job':job(request);return
 if operation=='inventory':out=inventory()
 elif operation=='repository':out=repository(request.get('packages'),request.get('storage'),request.get('filesystem'))
 elif operation=='discover':out=discover(request.get('portals'))
 elif operation=='credential-put':out=credential_put(request)
 elif operation=='fence-test':out=fence_test(request)
 elif operation=='cluster-status':out=cluster_status(request)
 elif operation=='cluster-monitor':out=cluster_status(request,include_snapshots=False)
 elif operation=='cluster-catalog':out=cluster_catalog()
 else:raise RuntimeError('Недопустимая операция хранилища')
 print(json.dumps(out,ensure_ascii=False))
if __name__=='__main__':
 try:main()
 except Exception as error:
  print(json.dumps({'error':str(error)},ensure_ascii=False));sys.exit(1)
