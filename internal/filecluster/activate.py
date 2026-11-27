"""Fixed helper jobs for a dedicated two-node ZFS/iSCSI cluster."""
import base64
import datetime
import socket
import xml.etree.ElementTree as ET


def cluster_folder(name):
    root = private_directory(pathlib.Path(sys.argv[2]) / 'filecluster')
    return root / ('cluster-' + name)


def install_owned(path, data, mode=0o600):
    if isinstance(data, str):
        data = data.encode()
    if path.is_symlink():
        raise RuntimeError('Нельзя заменить ссылку: ' + str(path))
    if path.exists():
        if path.read_bytes() != data:
            raise RuntimeError('Существующий файл отличается: ' + str(path))
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())
    sync_directory(path.parent)


def cluster_stage(value, save):
    stage = value['stage']
    cluster = stage['cluster']
    name = cluster['name']
    local = value['localNode']
    index = next(i for i,node in enumerate(cluster['nodes']) if node['name']==local)
    peer = cluster['nodes'][1-index]['name']
    if socket.gethostname() not in [local, local.split('.')[0]]:
        raise RuntimeError('Имя операционной системы не совпадает с именем helper')
    proof_file = vault_root().parent / 'fence-proofs' / (hashlib.sha256(peer.encode()).hexdigest()+'.json')
    if not proof_file.is_file():
        raise RuntimeError('Сначала проверьте fencing второго узла с этого helper')
    proof = json.loads(proof_file.read_text())
    if proof.get('configurationHash') != fence_fingerprint(cluster['fences'][1-index]) or not proof.get('offConfirmed') or not proof.get('onConfirmed'):
        raise RuntimeError('Изменились реквизиты fencing, повторите проверку второго узла')
    for target, fence in zip(cluster['nodes'],cluster['fences']):
        _,record = credential_read(fence['credentialRef'])
        if record.get('kind')!='fence' or any(record.get(k)!=x for k,x in {'node':target['name'],'address':fence['address'],'system':fence['system'],'username':fence['username']}.items()):
            raise RuntimeError('Нет корректных реквизитов fencing для ' + target['name'])
    run(['modprobe','zfs'])
    ready = zfs_readiness()
    if not ready['ready']:
        raise RuntimeError(' / '.join(ready['blockers']))
    verify_map(name,cluster['nodes'][index]['diskWWID'],cluster['targetIQN'],run,cluster['portals'])

    folder = private_directory(cluster_folder(name))
    manifest_path = folder/'manifest.json'
    manifest = {'revision':value['revision'], 'cluster':cluster, 'localNode':local,
                'layout':value['layout'], 'controller':stage['controller'],
                'workgroup':stage['workgroup'], 'ownerGroupSID':stage['ownerGroupSID']}
    if manifest_path.exists() and json.loads(manifest_path.read_text())!=manifest:
        raise RuntimeError('Кластер уже подготовлен с другой ревизией')

    prefix = 'sambaadm-'+name
    runtime = '/run/'+prefix
    state = '/srv/samba-ha/'+name+'/state'
    data = '/srv/samba-ha/'+name+'/data'
    config = '/etc/samba/'+prefix+'.conf'
    workgroup = stage['workgroup']
    smb = f"""# Managed by sambaadm
[global]
server role = member server
security = ADS
realm = {cluster['realm'].upper()}
password server = {stage['controller']}
workgroup = {workgroup}
netbios name = {name.upper()}
interfaces = {cluster['virtualIP']}
bind interfaces only = yes
smb ports = 445
server signing = mandatory
server min protocol = SMB2_02
map to guest = Never
load printers = no
disable spoolss = yes
private dir = {state}/private
state directory = {state}/state
cache directory = {runtime}/cache
lock directory = {runtime}/lock
pid directory = {runtime}
winbindd socket directory = {runtime}/winbind
idmap config * : backend = tdb
idmap config * : range = 10000-199999
idmap config {workgroup} : backend = rid
idmap config {workgroup} : range = 1000000-1999999
[files]
path = {data}
read only = no
browseable = yes
inherit acls = yes
create mask = 0660
directory mask = 0770
vfs objects = shadow_copy2
"""
    smb += ''.join(f'{key} = {setting}\n' for key,setting in value['layout']['shadowCopy'].items())
    save('Установка конфигурации кластера и изолированных служб Samba','staging')
    # Prevent overwriting another cluster, including one registered by a previous run.
    install_owned(pathlib.Path('/etc/corosync/corosync.conf'), value['files']['corosync.conf'])
    install_owned(pathlib.Path('/etc/corosync/authkey'), base64.b64decode(stage['authKey'],validate=True))
    install_owned(pathlib.Path('/etc/modules-load.d/'+prefix+'.conf'), 'zfs\n')
    install_owned(pathlib.Path('/etc/systemd/system/corosync.service.d/'+prefix+'.conf'),
                  '[Unit]\nAfter=network-online.target iscsid.service iscsi.service open-iscsi.service multipathd.service\nWants=network-online.target\n')
    install_owned(pathlib.Path(config), smb)
    nss = pathlib.Path('/etc/nsswitch.conf').read_text()
    isolated_nss = re.sub(r'(?m)^[ \t]*(passwd|group|initgroups)[ \t]*:.*$', '', nss)
    isolated_nss += '\npasswd: files winbind\ngroup: files winbind\ninitgroups: files winbind\n'
    nss_path = '/etc/samba/'+prefix+'-nsswitch.conf'
    install_owned(pathlib.Path(nss_path), isolated_nss, 0o644)
    findmnt, test, install = (shutil.which(name) for name in ['findmnt','test','install'])
    if not all((findmnt,test,install)):
        raise RuntimeError('Не установлены findmnt, test или install')
    for unit,binary in [('winbind','winbindd'),('smb','smbd')]:
        executable = shutil.which(binary) or next((str(path) for path in pathlib.Path('/usr/lib64/samba/sbin').glob(binary) if path.is_file()),None)
        if not executable:
            raise RuntimeError('Команда не установлена: '+binary)
        socket_binding = f'BindPaths={runtime}/winbind:/run/samba/winbindd\nBindReadOnlyPaths={nss_path}:/etc/nsswitch.conf\n' if unit=='smb' else ''
        unit_text=f"""[Unit]
Description=sambaadm {name} {binary}

[Service]
Type=notify
RuntimeDirectory={prefix}
RuntimeDirectoryPreserve=yes
{socket_binding}ExecStartPre={findmnt} -n --mountpoint {state} --source {value['layout']['pool']}/state
ExecStartPre={findmnt} -n --mountpoint {data} --source {value['layout']['pool']}/data
ExecStartPre={test} -s {state}/private/secrets.tdb
ExecStartPre={install} -d -m 0755 {runtime}/cache {runtime}/lock
ExecStart={executable} --foreground --no-process-group --configfile={config}
TimeoutStopSec=45
"""
        install_owned(pathlib.Path('/etc/systemd/system/'+prefix+'-'+unit+'.service'),unit_text)
    run(['systemctl','daemon-reload'])
    install_owned(folder/'cib.xml',value['files']['cib.xml'])
    durable_json(manifest_path,manifest)
    return {'revision':value['revision'],'platform':platform(),'zfsVersion':ready['loadedVersion'],'hostID':ready['hostID']}


def read_cluster(value):
    folder = cluster_folder(value['name'])
    manifest = json.loads((folder/'manifest.json').read_text())
    if manifest['revision'] != value['revision']:
        raise RuntimeError('Ревизия подготовленного кластера изменилась')
    return folder,manifest


def cluster_online(value,save):
    _,manifest = read_cluster(value)
    in_config=manifest['cluster']
    verify_map(in_config['name'],in_config['nodes'][0]['diskWWID'],in_config['targetIQN'],run,in_config['portals'])
    if not zfs_readiness()['ready']:
        raise RuntimeError('ZFS не готов к запуску')
    save('Запуск Corosync и Pacemaker','online')
    run(['systemctl','enable','--now','corosync','pacemaker'],90)
    return {'started':True}


def crm_status():
    return ET.fromstring(run(['crm_mon','--one-shot','--output-as=xml'],15))


def mounted(dataset, mountpoint):
    return run(['findmnt','-n','--mountpoint',mountpoint,'--source',dataset,'-o','FSTYPE'],10).strip()=='zfs'


def cluster_join(manifest,ref,state):
    cluster=manifest['cluster']
    name=cluster['name']
    config='/etc/samba/sambaadm-'+name+'.conf'
    path,record=credential_read(ref)
    if record.get('kind')!='domain-join' or record['node']!=manifest['localNode'] or record['address']!=manifest['controller'] or record['system']!=name+'.'+cluster['realm']:
        raise RuntimeError('Реквизиты присоединения предназначены для другого кластера')
    runtime=pathlib.Path('/run/sambaadm-'+name)
    for directory in [state+'/private',state+'/state',str(runtime/'cache'),str(runtime/'lock')]:
        pathlib.Path(directory).mkdir(mode=0o700,parents=True,exist_ok=True)
    run(['testparm','-s',config])
    options=['net','--configfile='+config,'--server='+manifest['controller'],'--use-kerberos=required','--client-protection=sign']
    def authenticated(args):
        result=subprocess.run(options+['--user='+record['username'],'--stdin','ads',*args],input=record['password']+'\n',stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=90,env=ENV)
        if result.returncode:
            raise RuntimeError('AD: '+result.stdout.replace(record['password'],'[скрыто]')[-1200:])
        return result.stdout
    search=authenticated(['search','(&(objectClass=computer)(sAMAccountName='+name.upper()+'$))','sAMAccountName'])
    if not re.search(r'(?mi)^Got 0 replies\s*$',search):
        raise RuntimeError('Имя виртуального компьютера уже занято или поиск AD не подтверждён')
    authenticated(['join','--no-dns-updates','dnshostname='+record['system']])
    domain=run(['net','--configfile='+config,'getdomainsid'])
    sid=manifest['ownerGroupSID'].rsplit('-',1)[0]
    if not re.search(r'(?m)^SID for domain .* is: '+re.escape(sid)+r'\s*$',domain):
        raise RuntimeError('Группа доступа указана из другого домена')
    # The range is rendered as idmap_rid with base_rid=0.
    rid=int(manifest['ownerGroupSID'].rsplit('-',1)[1])
    if rid>=1000000:
        raise RuntimeError('SID группы вне диапазона idmap_rid')
    path.unlink()
    sync_directory(path.parent)
    return 1000000+rid


def cluster_initialize(value,save):
    folder,manifest=read_cluster(value)
    cluster,layout=manifest['cluster'],manifest['layout']
    name,pool=cluster['name'],layout['pool']
    if manifest['localNode'] != cluster['nodes'][0]['name']:
        raise RuntimeError('Только первый helper инициализирует общий LUN')
    save('Ожидание обоих узлов в кворуме','quorum')
    deadline=time.monotonic()+45
    while True:
        status=crm_status()
        online={node.get('name') for node in status.findall('./nodes/node') if node.get('online')=='true'}
        dc=status.find('./summary/current_dc')
        if online=={node['name'] for node in cluster['nodes']} and dc is not None and dc.get('with_quorum')=='true':
            break
        if time.monotonic()>=deadline:
            raise RuntimeError('Для первичной инициализации оба узла должны быть в кворуме')
        time.sleep(1)
    committed=folder/'initialized.json'
    if committed.exists():
        record=json.loads(committed.read_text())
        if record['revision']!=value['revision']:
            raise RuntimeError('Инициализированная ревизия отличается')
        return {'pool':pool,'guid':record['guid'],'vip':cluster['virtualIP']}
    cib=ET.fromstring(run(['cibadmin','--query','--scope','configuration']))
    if len(cib.find('./resources')):
        raise RuntimeError('В Pacemaker уже существуют ресурсы; повторная инициализация запрещена')
    device=verify_map(name,cluster['nodes'][0]['diskWWID'],cluster['targetIQN'],run,cluster['portals'])['device']
    block=pathlib.Path(device).resolve(strict=True)
    size=int(run(['blockdev','--getsize64',device]))
    signatures=json.loads(run(['wipefs','--no-act','--json',device]))
    if size < 1<<30 or run(['blockdev','--getro',device]).strip() != '0' or list((pathlib.Path('/sys/class/block')/block.name/'holders').iterdir()):
        raise RuntimeError('Выбранный LUN занят или меньше 1 ГиБ')
    if any(line.strip() in [device,str(block)] for line in run(['findmnt','-n','-o','SOURCE']).splitlines()):
        raise RuntimeError('Выбранный LUN смонтирован')
    if not zfs_readiness()['ready']:
        raise RuntimeError('ZFS не готов к созданию пула')
    stamp=folder/'initialization.json'
    expected={'device':device,'wwid':cluster['nodes'][0]['diskWWID'],'revision':value['revision']}
    resume=stamp.exists()
    if resume:
        if json.loads(stamp.read_text())!=expected:
            raise RuntimeError('Начатая инициализация относится к другой ревизии')
    else:
        if signatures.get('signatures'):
            raise RuntimeError('На выбранном LUN обнаружены сигнатуры')
        durable_json(stamp,expected,exclusive=True)
    create=['zpool','create']
    for key,v in layout['poolProperties'].items():
        create+=['-o',key+'='+v]
    for key,v in layout['datasets'][0]['properties'].items():
        create+=['-O',key+'='+v]
    create+=['-O','org.sambaadm:revision='+value['revision'],pool,device]
    save('Создание пула только на проверенном multipath LUN','pool')
    # Never force create/import during bootstrap. A previous attempt may be
    # resumed only through the same map with the matching on-disk revision.
    if resume and signatures.get('signatures'):
        run(['zpool','import','-d',device,'-o','cachefile=none',pool],70)
    else:
        run(create,60)
    data,state=None,None
    try:
        if run(['zfs','get','-H','-o','value','org.sambaadm:revision',pool]).strip()!=value['revision']:
            raise RuntimeError('На диске другая ревизия пула')
        datasets=set(run(['zfs','list','-H','-r','-o','name',pool]).splitlines())
        for dataset in layout['datasets'][1:]:
            args=['zfs','create']
            for key,v in dataset['properties'].items():
                args+=['-o',key+'='+v]
            if dataset['name'] not in datasets:
                run(args+[dataset['name']],60)
            mountpoint=dataset['properties']['mountpoint']
            if not mounted(dataset['name'],mountpoint):
                raise RuntimeError('Dataset не смонтирован: '+dataset['name'])
            os.chmod(mountpoint,int(dataset['mode'],8))
            if dataset['name'].endswith('/data'):
                data=mountpoint
            else:
                state=mountpoint
        save('Присоединение виртуального SMB-сервера к AD','join')
        gid=cluster_join(manifest,value['credentialRef'],state)
        os.chown(data,0,gid)
        os.chmod(data,0o2770)
        run(['setfacl','-m','d:u::rwx,d:g::rwx,d:o::---',data])
        guid=run(['zpool','get','-H','-o','value','guid',pool]).strip()
    finally:
        run(['zpool','export',pool],60)
    save('Передача пула, VIP и Samba под управление Pacemaker','activate')
    configuration=ET.parse(folder/'cib.xml').getroot().find('./configuration')
    run(['cibadmin','--replace','--scope','configuration','--xml-text',ET.tostring(configuration,encoding='unicode')],30)
    run(['crm_resource','--resource','sambaadm-'+name+'-group','--meta','--set-parameter','target-role','--parameter-value','Started'],30)
    durable_json(folder/'initialized.json',{'guid':guid,'revision':value['revision']})
    return {'pool':pool,'guid':guid,'vip':cluster['virtualIP']}


def smb_owner(status,name):
    resource=status.find("./resources/group[@id='sambaadm-"+name+"-group']/resource[@id='sambaadm-"+name+"-smb']")
    if resource is None or resource.get('active')!='true' or resource.get('failed')=='true':
        return ''
    nodes=resource.findall('node')
    return nodes[0].get('name','') if len(nodes)==1 else ''


def cluster_catalog():
    """Expose only the identity of clusters staged on this helper."""
    result=[]
    root=pathlib.Path(sys.argv[2])/'filecluster'
    for folder in sorted(root.glob('cluster-*'))[:64]:
        if folder.is_symlink():
            continue
        try:
            manifest=json.loads((folder/'manifest.json').read_text())
            cluster=manifest['cluster']
            result.append({'name':cluster['name'],'revision':manifest['revision'],
                           'realm':cluster['realm'],'vip':cluster['virtualIP'],
                           'nodes':[node['name'] for node in cluster['nodes']]})
        except (OSError,ValueError,KeyError,TypeError):
            continue
    return {'clusters':result}


def cluster_paths(cluster):
    name='sambaadm-'+cluster['name']
    wwid=cluster['nodes'][0]['diskWWID']
    paths={portal(address):{'portal':address,'state':'missing','ready':False}
           for address in cluster['portals']}
    maps=json.loads(run(['multipathd','show','maps','json'],8,separate_stderr=True)).get('maps',[])
    mapping=next((entry for entry in maps if entry.get('name')==name and entry.get('uuid')==wwid),None)
    if mapping:
        for group in mapping.get('path_groups',[]):
            for path in group.get('paths',[]):
                device=path.get('dev','')
                if not re.fullmatch(r'[A-Za-z0-9_.!-]+',device):
                    continue
                try:
                    host,port=scsi_path_session(device,cluster['targetIQN'])
                    key=(str(ipaddress.ip_address(host)),port)
                except (RuntimeError,OSError,ValueError):
                    continue
                if key in paths:
                    paths[key].update(device=device,state=path.get('chk_st','unknown'),
                                      ready=path.get('dm_st')=='active' and path.get('chk_st')=='ready'
                                            and path.get('dev_st')=='running')
    return {'map':name,'wwid':wwid,'paths':list(paths.values())}

def cluster_status(value, include_snapshots=True):
    _,manifest=read_cluster(value)
    result={'owner':'','localNode':manifest['localNode'],'onlineNodes':[],
            'quorum':False,'snapshots':[]}
    try:
        status=crm_status()
        result['owner']=smb_owner(status,value['name'])
        result['onlineNodes']=[n.get('name') for n in status.findall('./nodes/node') if n.get('online')=='true']
        dc=status.find('./summary/current_dc')
        result['quorum']=dc is not None and dc.get('with_quorum')=='true'
    except (RuntimeError,ET.ParseError,subprocess.TimeoutExpired):
        result['clusterError']='Не удалось получить состояние Pacemaker'
    owner=result['owner']
    try:
        result['multipath']=cluster_paths(manifest['cluster'])
    except (RuntimeError,ValueError,OSError,subprocess.TimeoutExpired):
        result['storageError']='Не удалось прочитать карту multipath'
    result['platform']=platform()
    result['vip']=manifest['cluster']['virtualIP']
    if not include_snapshots and result['quorum'] and owner == manifest['localNode']:
        result['smbReady'] = False
        try:
            unit = 'sambaadm-' + value['name'] + '-smb.service'
            if run(['systemctl', 'show', '-p', 'ActiveState', '--value', unit], 2).strip() == 'active':
                with socket.create_connection((result['vip'], 445), timeout=0.7):
                    result['smbReady'] = True
        except (RuntimeError, OSError, subprocess.TimeoutExpired):
            pass
    if include_snapshots and owner==manifest['localNode']:
        dataset=manifest['layout']['snapshotDataset']
        try:
            result['snapshots']=snapshot_inventory(dataset,manifest['revision'])
            result['schedule']=snapshot_policy(dataset)
        except (RuntimeError,ValueError,subprocess.TimeoutExpired):
            result['snapshotError']='Не удалось прочитать снимки или расписание'
    return result


def cluster_snapshot(value,save):
    _,manifest=read_cluster(value)
    dataset=owned_snapshot_dataset(value,manifest)
    tag=datetime.datetime.now(datetime.timezone.utc)
    timestamp=tag.strftime('sambaadm_%Y.%m.%d-%H.%M.%S')
    save('Создание именного снимка данных','snapshot')
    run(['zfs','snapshot','-o','org.sambaadm:label='+value['label'],dataset+'@'+timestamp],40)
    return {'name':timestamp,'label':value['label'],'smbTimestamp':tag.strftime('@GMT-%Y.%m.%d-%H.%M.%S')}
