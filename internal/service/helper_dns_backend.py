"""Fixed ALT DNS backend migration worker. No shell or user-supplied commands."""
import contextlib, fcntl, glob, grp, hashlib, json, re, os, pathlib, shutil, subprocess, sys, tempfile, time
from helper_dns_bind_config import configure_alt_bind,ad_network_settings,pristine_alt_bind_options
job = pathlib.Path(sys.argv[1])
request = json.loads((job/'request.json').read_text())
plan = request['plan']
state = {'id':request['id'], 'state':'running', 'log':[], 'actor':request['actor'], 'created':time.time()}
def save(message=None):
    if message: state['log'].append(message)
    state['log'] = state['log'][-400:]
    tmp = job/'status.tmp'
    tmp.write_text(json.dumps(state,ensure_ascii=False)); tmp.chmod(0o600); tmp.replace(job/'status.json')
def run(args, timeout=60, check=True):
    save('> '+' '.join(args))
    result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,errors='replace',timeout=timeout,env={**os.environ,'LC_ALL':'C','PATH':'/usr/sbin:/usr/bin:/sbin:/bin'})
    for line in result.stdout.splitlines()[-60:]: save(line[:500])
    if check and result.returncode: raise RuntimeError('Ошибка команды: '+args[0])
    return result.stdout.strip()
def atomic(path, data):
    path=pathlib.Path(path); st=path.stat(); fd,name=tempfile.mkstemp(prefix='.sambaadm-dns-',dir=str(path.parent))
    try:
        with os.fdopen(fd,'wb') as f: f.write(data); os.fchmod(f.fileno(),st.st_mode&0o777); os.fchown(f.fileno(),st.st_uid,st.st_gid); f.flush(); os.fsync(f.fileno())
        os.replace(name,path)
    finally:
        with contextlib.suppress(FileNotFoundError):os.unlink(name)
def active(unit): return subprocess.run(['systemctl','is-active','--quiet',unit]).returncode==0
def enabled(unit): return subprocess.run(['systemctl','is-enabled','--quiet',unit],stdout=subprocess.DEVNULL).returncode==0
lock=open(pathlib.Path(request['stateDir'])/'operations.lock','a')
fcntl.flock(lock,fcntl.LOCK_EX)
smb=pathlib.Path(plan['smbPath']); bind=pathlib.Path(plan['bindPath'])
old_smb=smb.read_bytes(); old_bind=bind.read_bytes() if bind.exists() else None
old_bind_active=active('bind.service'); old_bind_enabled=enabled('bind.service');old_samba_enabled=enabled('samba.service')
mutated=False
fresh_bind=old_bind is None or pristine_alt_bind_options()
extra_files={}
def remember(path):
    path=pathlib.Path(path)
    if str(path) not in extra_files:
        extra_files[str(path)]=path.read_bytes()
        backup=job/(path.name+'.before');backup.write_bytes(extra_files[str(path)]);backup.chmod(0o600)
try:
    if hashlib.sha256(old_smb).hexdigest()!=request['smbHash'] or hashlib.sha256(old_bind or b'').hexdigest()!=request['bindHash']:raise RuntimeError('Конфигурация изменилась после предпросмотра')
    save('Создание резервной копии конфигурации')
    (job/'smb.conf.before').write_bytes(old_smb)
    if old_bind is not None:(job/'named.conf.before').write_bytes(old_bind)
    for name in ['smb.conf.before','named.conf.before']:
        if (job/name).exists():(job/name).chmod(0o600)
    if plan['target']=='BIND9_DLZ':
        run(['apt-get','update'],timeout=180)
        simulation=['apt-get','-s','install']
        if plan['reinstall']:simulation.append('--reinstall')
        package_plan=run(simulation+['bind','bind-utils'],timeout=60)
        if re.search(r'(?m)^Remv\s',package_plan) or re.search(r'(?m)^Inst\s+samba(?:-|\s)',package_plan):
            raise RuntimeError('План пакетов удаляет пакеты или обновляет Samba; службы не остановлены')
        args=['apt-get','install','-y']
        if plan['reinstall']: args.append('--reinstall')
        run(args+['bind','bind-utils'],timeout=360)
        version=run(['named','-v']);minor=re.search(r'BIND 9\.(\d+)',version)
        if not minor:raise RuntimeError('Не удалось определить версию BIND')
        selected='dlz_bind9_'+minor.group(1)+'.so'
        modules=glob.glob('/usr/lib*/samba*/bind9/'+selected)+glob.glob('/usr/lib/*/samba/bind9/'+selected)
        if not any(pathlib.Path(p).is_file() for p in modules):raise RuntimeError('Нет совместимого DLZ-модуля Samba для установленного BIND; службы не остановлены')
        bind=bind.resolve(strict=True)
        if old_bind is None: old_bind=bind.read_bytes(); (job/'named.conf.before').write_bytes(old_bind); (job/'named.conf.before').chmod(0o600)
    if fresh_bind and plan['target']=='BIND9_DLZ' and pathlib.Path('/etc/sysconfig/bind').exists():ad_network_settings(smb)
    # Reject outside edits made while the job was waiting or installing packages.
    if smb.read_bytes()!=old_smb or bind.exists() and old_bind is not None and bind.read_bytes()!=old_bind:raise RuntimeError('Конфигурация изменилась; повторите предпросмотр')
    mutated=True
    run(['systemctl','stop','bind.service'],check=False)
    run(['systemctl','stop','samba.service'])
    run(['samba_upgradedns','--configfile='+str(smb),'--dns-backend='+plan['target']],timeout=120)
    atomic(smb,request['smb'].encode())
    if plan['target']=='BIND9_DLZ':
        generated=pathlib.Path('/var/lib/samba/bind-dns/named.conf')
        text=generated.read_text(); found=False; patched=[]
        for line in text.splitlines():
            match=re.search(r'database "dlopen ([^"]+)";',line)
            if match:
                module=pathlib.Path(match.group(1))
                use=module.name==selected and module.is_file()
                if use:found=True
                patched.append(('    ' if use else '    # ')+match.group(0))
            else:patched.append(line)
        if not found:raise RuntimeError('Samba не предоставляет DLZ-модуль для установленного BIND: '+selected)
        atomic(generated,('\n'.join(patched)+'\n').encode())
        group=None
        for name in ['named','bind']:
            try:group=grp.getgrnam(name).gr_gid;break
            except KeyError:pass
        if group is None:raise RuntimeError('Не найдена группа службы BIND')
        os.chown(generated.parent,0,group);os.chmod(generated.parent,0o770)
        key=generated.parent/'dns.keytab'
        os.chown(key,0,group);os.chmod(key,0o640)
        include='include "/var/lib/samba/bind-dns/named.conf";'
        current=bind.read_text()
        if include not in current:atomic(bind,(current.rstrip()+'\n'+include+'\n').encode())
        configure_alt_bind(smb,fresh_bind,run,atomic,remember)
        run(['named-checkconf',str(bind)])
    run(['testparm','-s','--parameter-name=server services',str(smb)],check=True)
    run(['systemctl','enable','samba.service'])
    run(['systemctl','restart','samba.service'])
    if plan['target']=='BIND9_DLZ':run(['systemctl','enable','--now','bind.service'])
    else:run(['systemctl','disable','bind.service'])
    realm=run(['testparm','-s','--parameter-name=realm',str(smb)]).splitlines()[-1].lower()
    checked=False
    for _ in range(20):
        try:
            soa=run(['dig','+time=2','+tries=1','+short','@127.0.0.1',realm,'SOA'])
            srv=run(['dig','+time=2','+tries=1','+short','@127.0.0.1','_ldap._tcp.'+realm,'SRV'])
            if soa and srv:checked=True;break
        except Exception:pass
        time.sleep(1)
    if not checked:raise RuntimeError('После переключения недоступны SOA или SRV LDAP')
    state['state']='completed';save('DNS-бэкенд переключён. SOA домена и SRV LDAP отвечают.')
except Exception as error:
    save(str(error));state['state']='running';state['phase']='rollback' if mutated else 'failed'
    if mutated:
        try:
            save('Попытка возврата к прежнему DNS-бэкенду')
            run(['systemctl','stop','bind.service'],check=False);run(['systemctl','stop','samba.service'],check=False)
            run(['samba_upgradedns','--configfile='+str(smb),'--dns-backend='+plan['backend']],timeout=120)
            atomic(smb,old_smb)
            if old_bind is not None:atomic(bind,old_bind)
            for path,data in extra_files.items():atomic(path,data)
            run(['systemctl','restart','samba.service'])
            run(['systemctl','enable' if old_samba_enabled else 'disable','samba.service'])
            run(['systemctl','enable' if old_bind_enabled else 'disable','bind.service'])
            if old_bind_active:run(['systemctl','start','bind.service'])
            state['rollback']='completed';save('Прежняя конфигурация и состояние BIND восстановлены; проверьте DNS.')
        except Exception as rollback:state['rollback']='failed';save('Откат не завершён: '+str(rollback)+'. Резервные копии: '+str(job))
    state['state']='failed';save()
finally:
    state['finished']=time.time();save();fcntl.flock(lock,fcntl.LOCK_UN)
