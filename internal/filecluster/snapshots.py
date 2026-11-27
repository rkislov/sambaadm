"""Cluster-owned snapshot timers. The policy and last successful slot live on ZFS."""
SNAPSHOT_POLICY = 'org.sambaadm:snapshot-policy'
AUTO_OWNER = 'org.sambaadm:auto-owner'
AUTO_SLOT = 'org.sambaadm:auto-slot'
DEFAULT_POLICY = {'enabled':False,'intervalMinutes':60,'retain':14}
SNAPSHOT_TAG = re.compile(r'^sambaadm_\d{4}\.\d{2}\.\d{2}-\d{2}\.\d{2}\.\d{2}$')


def snapshot_policy(dataset):
    text=run(['zfs','get','-H','-o','value',SNAPSHOT_POLICY,dataset]).strip()
    return validate_policy(json.loads(text)) if text!='-' else dict(DEFAULT_POLICY)


def validate_policy(value):
    if (type(value.get('enabled')) is not bool
            or type(value.get('intervalMinutes')) is not int
            or value['intervalMinutes'] not in (60,360,1440)
            or type(value.get('retain')) is not int or not 1<=value['retain']<=168):
        raise RuntimeError('Неверное расписание автоснимков')
    return {key:value[key] for key in DEFAULT_POLICY}


def snapshot_property_rows(dataset,prop):
    output=run(['zfs','get','-H','-s','local','-t','snapshot','-o','name,value','-r',prop,dataset])
    for line in output.splitlines():
        full,sep,value=line.partition('\t')
        name=full.removeprefix(dataset+'@')
        if sep and name!=full and SNAPSHOT_TAG.fullmatch(name):
            yield name,value


def snapshot_inventory(dataset,revision):
    auto={name for name,owner in snapshot_property_rows(dataset,AUTO_OWNER) if owner==revision}
    return [{'name':name,'label':label,'automatic':name in auto}
            for name,label in snapshot_property_rows(dataset,'org.sambaadm:label') if label!='-']


def owned_snapshot_dataset(value,manifest,required=True):
    try:
        status=crm_status()
    except (RuntimeError,ET.ParseError,subprocess.TimeoutExpired):
        if not required:
            return None
        raise
    dc=status.find('./summary/current_dc')
    if dc is None or dc.get('with_quorum')!='true' or smb_owner(status,value['name'])!=manifest['localNode']:
        if not required:
            return None
        raise RuntimeError('Для снимков нужен активный узел с кворумом')
    dataset=manifest['layout']['snapshotDataset']
    mountpoint='/srv/samba-ha/'+value['name']+'/data'
    if not mounted(dataset,mountpoint) or run(['zfs','get','-H','-o','value','org.sambaadm:revision',dataset]).strip()!=value['revision']:
        raise RuntimeError('Dataset не принадлежит активному кластеру')
    return dataset


def cluster_snapshot_timer(value,save):
    folder,_=read_cluster(value)
    # Systemd treats % and $ specially. The package's state path and the
    # validated cluster identifiers are the only interpolated values.
    state=pathlib.Path(sys.argv[2])
    if not re.fullmatch(r'/[A-Za-z0-9_./-]+',str(state)):
        raise RuntimeError('Каталог helper не подходит для установки таймера')
    prefix='sambaadm-'+value['name']+'-snapshots'
    script=folder/'scheduler.py'
    data=pathlib.Path(__file__).read_bytes()
    if script.is_symlink():
        raise RuntimeError('Файл таймера является ссылкой')
    if script.exists() and script.read_bytes()!=data:
        temp=script.with_name('scheduler-'+secrets.token_hex(8)+'.tmp')
        try:
            install_owned(temp,data)
            temp.replace(script)
            sync_directory(folder)
        finally:
            if temp.exists():
                temp.unlink()
    else:
        install_owned(script,data)
    service=f"""[Unit]
Description=Samba Admin scheduled ZFS snapshots for {value['name']}
After=pacemaker.service

[Service]
Type=oneshot
User=root
UMask=0077
NoNewPrivileges=true
LimitCORE=0
TimeoutStartSec=100
ExecStart=/usr/bin/python3 {script} snapshot-tick {state} {value['name']} {value['revision']}
"""
    timer=f"""[Unit]
Description=Samba Admin snapshot timer for {value['name']}

[Timer]
OnCalendar=*-*-* *:*:00
AccuracySec=5s
Unit={prefix}.service

[Install]
WantedBy=timers.target
"""
    save('Установка таймера на хелпере','timer')
    install_owned(pathlib.Path('/etc/systemd/system')/(prefix+'.service'),service)
    install_owned(pathlib.Path('/etc/systemd/system')/(prefix+'.timer'),timer)
    run(['systemctl','daemon-reload'],30)
    run(['systemctl','enable','--now',prefix+'.timer'],30)
    return {'timer':prefix+'.timer'}


def cluster_snapshot_schedule(value,save):
    _,manifest=read_cluster(value)
    dataset=owned_snapshot_dataset(value,manifest)
    policy=validate_policy(value['policy'])
    if policy['enabled']:
        run(['systemctl','is-active','sambaadm-'+value['name']+'-snapshots.timer'],10)
    save('Сохранение расписания на общем dataset','policy')
    run(['zfs','set',SNAPSHOT_POLICY+'='+json.dumps(policy,separators=(',',':')),dataset],30)
    return policy


def snapshot_tick(value):
    _,manifest=read_cluster(value)
    with open(pathlib.Path(sys.argv[2])/'operations.lock','a') as lock:
        try:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            return
        dataset=owned_snapshot_dataset(value,manifest,required=False)
        if not dataset:
            return
        policy=snapshot_policy(dataset)
        if not policy['enabled']:
            return
        run_scheduled_snapshot(dataset,value['revision'],policy,datetime.datetime.now(datetime.timezone.utc))


def run_scheduled_snapshot(dataset,revision,policy,now):
    interval=policy['intervalMinutes']*60
    slot=int(now.timestamp())//interval*interval
    owned={name for name,owner in snapshot_property_rows(dataset,AUTO_OWNER) if owner==revision}
    last=max((int(value) for name,value in snapshot_property_rows(dataset,AUTO_SLOT)
              if name in owned and value.isdecimal()),default=0)
    if last<slot:
        name=now.strftime('sambaadm_%Y.%m.%d-%H.%M.%S')
        label=now.strftime('Автоснимок %Y-%m-%d %H:%M UTC')
        run(['zfs','snapshot','-o','org.sambaadm:label='+label,'-o',AUTO_OWNER+'='+revision,
             '-o',AUTO_SLOT+'='+str(slot),dataset+'@'+name],40)
        owned.add(name)
    # Destruction is scoped to locally marked snapshots created by this
    # scheduler. Standard ZFS holds and dependent clones remain respected.
    for expired in sorted(owned,reverse=True)[policy['retain']:policy['retain']+4]:
        run(['zfs','destroy',dataset+'@'+expired],15)
