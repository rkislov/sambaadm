"""Typed iSCSI/multipath steps, no filesystem initialization or arbitrary paths."""
import ipaddress,json,os,pathlib,re,stat,time
IQN=re.compile(r'^iqn\.[0-9]{4}-[0-9]{2}\.[A-Za-z0-9][A-Za-z0-9.:-]{1,210}$')

def portal(value):
 host,sep,port=value.rpartition(':');host=host.strip('[]');address=ipaddress.ip_address(host)
 if not sep or not port.isdigit() or not 1<=int(port)<=65535 or getattr(address,'scope_id',None) or address.is_loopback or address.is_unspecified or address.is_multicast:raise RuntimeError('Неверный портал')
 return str(address),int(port)

def records(target,host=None,port=None):
 result=[]
 for base in ['/etc/iscsi/nodes','/var/lib/iscsi/nodes']:
  directory=pathlib.Path(base)/target
  if not directory.exists():continue
  if directory.is_symlink():raise RuntimeError('Каталог iSCSI является ссылкой')
  for node in directory.iterdir():
   parts=node.name.split(',')
   if len(parts) not in (2,3) or node.is_symlink():continue
   if host is not None:
    try:
     if ipaddress.ip_address(parts[0])!=ipaddress.ip_address(host) or int(parts[1])!=port:continue
    except ValueError:continue
   if node.is_file():
    result.append(node)
   elif node.is_dir():
    for file in node.iterdir():
     if not file.is_symlink() and file.is_file():result.append(file)
 return result

def read_record(path):
 if path.is_symlink():raise RuntimeError('Файл iSCSI является ссылкой')
 data={}
 for line in path.read_text().splitlines():
  if line.lstrip().startswith('#'):continue
  key,sep,value=line.partition('=')
  if sep:data[key.strip()]=value.strip()
 return data

def write_auth(path,auth,sync_directory):
 info=path.lstat()
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1:raise RuntimeError('Нештатный файл iSCSI')
 allowed={'node.session.auth.authmethod','node.session.auth.username','node.session.auth.password','node.session.auth.username_in','node.session.auth.password_in','node.session.auth.chap_algs'}
 if any(key not in allowed or any(c in value for c in '\r\n\x00') for key,value in auth.items()):
  raise RuntimeError('Неверный параметр CHAP')
 lines=path.read_text().splitlines();remaining=dict(auth);output=[]
 for line in lines:
  key=line.partition('=')[0].strip()
  if key in remaining:output.append(key+' = '+remaining.pop(key))
  else:output.append(line)
 for key,value in remaining.items():
  output.append(key+' = '+value)
 temporary=path.with_name(path.name+'.sambaadm-new')
 fd=os.open(temporary,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(fd,'w') as stream:stream.write('\n'.join(output)+'\n');stream.flush();os.fsync(stream.fileno())
  temporary.replace(path);sync_directory(path.parent)
 finally:
  if temporary.exists():temporary.unlink()

def sessions():
 result=[]
 base=pathlib.Path('/sys/class/iscsi_session')
 if not base.exists():return result
 for session in base.iterdir():
  name=(session/'targetname').read_text().strip();ident=session.name.removeprefix('session')
  for conn in pathlib.Path('/sys/class/iscsi_connection').glob('connection'+ident+':*'):
   try:result.append({'targetIQN':name,'host':(conn/'persistent_address').read_text().strip(),'port':int((conn/'persistent_port').read_text().strip()),'session':session.name})
   except (OSError,ValueError):continue
 return result

def connect(value,w,save):
 target=value.get('targetIQN','');portals=value.get('portals',[])
 if not IQN.fullmatch(target) or not 1<=len(portals)<=8:raise RuntimeError('Неверная iSCSI-цель')
 addresses=[portal(p) for p in portals]
 if len(set(addresses))!=len(addresses):raise RuntimeError('Повторный портал')
 run=w['run'];run(['modprobe','iscsi_tcp']);run(['systemctl','enable','--now','iscsid'],30)
 auth=None
 if value.get('credentialRef'):
  _,credential=w['credential_read'](value['credentialRef'])
  canonical=','.join(sorted(portals))
  if credential.get('kind')!='iscsi' or credential.get('node')!=value.get('localNode') or credential.get('system')!=target or credential.get('address')!=canonical:raise RuntimeError('Реквизиты CHAP привязаны к другой цели или узлу')
  auth={'node.session.auth.authmethod':'CHAP','node.session.auth.username':credential['username'],'node.session.auth.password':credential['password']}
 else:
  # Reuse an existing connection's protected credentials locally; never export them.
  existing=records(target)
  if existing:auth={k:v for k,v in read_record(existing[0]).items() if k.startswith('node.session.auth.')}
 for original,(host,port) in zip(portals,addresses):
  active=[s for s in sessions() if s['targetIQN']==target and ipaddress.ip_address(s['host'])==ipaddress.ip_address(host) and s['port']==port]
  if active:
   save('Существующая сессия сохранена: '+original,'connecting');continue
  save('Подключение выбранной цели через '+original,'connecting')
  existing=records(target,host,port)
  if not existing:
   run(['iscsiadm','-m','node','-T',target,'-p',original,'--op','new'],30)
   existing=records(target,host,port)
  if len(existing)!=1:raise RuntimeError('Неоднозначная запись iSCSI; выберите интерфейс/группу порталов вручную')
  if auth and not read_record(existing[0]).get('node.session.auth.username'):
   write_auth(existing[0],auth,w['sync_directory'])
  run(['iscsiadm','-m','node','-T',target,'-p',original,'--op','update','--name','node.startup','--value','automatic'],20)
  run(['iscsiadm','-m','node','-T',target,'-p',original,'--login'],60)
  for record in records(target,host,port):
   fd=os.open(record,os.O_RDONLY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd);w['sync_directory'](record.parent)
 run(['udevadm','settle','--timeout=20'],25)
 for service in ['iscsi.service','open-iscsi.service']:
  try:
   if run(['systemctl','show','--property=LoadState','--value',service],10).strip()=='loaded':run(['systemctl','enable',service],20);break
  except RuntimeError:continue
 inventory=w['inventory']()
 candidates={}
 for block in inventory['blocks'].get('blockdevices',[]):
  if block.get('type')!='disk' or not block.get('diskWWID') or block.get('size',0)<1<<30:
   continue
  try:endpoint=scsi_path_session(block['kname'],target)
  except (RuntimeError,OSError,ValueError):continue
  if (str(ipaddress.ip_address(endpoint[0])),endpoint[1]) not in addresses:continue
  row=candidates.setdefault(block['diskWWID'],{'size':block['size'],'ports':set()})
  row['ports'].add(endpoint)
 luns=[{'wwid':identifier,'size':row['size']} for identifier,row in sorted(candidates.items()) if len(row['ports'])==len(addresses)]
 return {'targetIQN':target,'sessions':[s for s in sessions() if s['targetIQN']==target],'formatted':False,'inventory':inventory,'luns':luns}

def scsi_path_session(name,target):
 device=(pathlib.Path('/sys/class/block')/name/'device').resolve(strict=True)
 match=next((part for part in device.parts if re.fullmatch(r'session[0-9]+',part)),None)
 if not match:raise RuntimeError('Устройство не относится к iSCSI-сессии')
 matching=[(entry['host'],entry['port']) for entry in sessions() if entry['session']==match and entry['targetIQN']==target]
 if len(matching)!=1:raise RuntimeError('Путь не принадлежит выбранной iSCSI-цели')
 return matching[0]

def verify_map(name,wwid,target,run,expected_portals=None):
 path=pathlib.Path('/dev/mapper')/('sambaadm-'+name)
 resolved=path.resolve(strict=True);dm=pathlib.Path('/sys/class/block')/resolved.name
 if (dm/'dm/uuid').read_text().strip()!='mpath-'+wwid:raise RuntimeError('Карта указывает на другой WWID')
 slaves=list((dm/'slaves').iterdir())
 endpoints={scsi_path_session(slave.name,target) for slave in slaves}
 if expected_portals is not None:
  expected={portal(address) for address in expected_portals}
  observed={(str(ipaddress.ip_address(host)),port) for host,port in endpoints}
  if observed!=expected:
   raise RuntimeError('Фактические порталы выбранного WWID отличаются от плана')
 topology=run(['multipath','-ll',wwid],20)
 healthy=[slave.name for slave in slaves if re.search(r'(?m)\b'+re.escape(slave.name)+r'\s+[0-9]+:[0-9]+\s+active\s+ready\s+running\s*$',topology)]
 if len(endpoints)<2 or len(healthy)<2:raise RuntimeError('Нужны два исправных пути через разные порталы выбранной цели: '+topology)
 return {'wwid':wwid,'device':str(path),'paths':healthy,'topology':topology}

def multipath(value,w,save):
 name=value.get('name','');wwid=value.get('wwid','');target=value.get('targetIQN','')
 if not re.fullmatch(r'[a-z][a-z0-9-]{0,14}',name) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{7,255}',wwid) or not IQN.fullmatch(target):raise RuntimeError('Неверная карта multipath')
 inventory=w['inventory']();found=[]
 def visit(blocks):
  for b in blocks:
   if b.get('diskWWID')==wwid:found.append(b)
   visit(b.get('children',[]))
 visit(inventory['blocks'].get('blockdevices',[]))
 if not found:raise RuntimeError('WWID не обнаружен на этом узле')
 endpoints={scsi_path_session(b['kname'],target) for b in found if b['type']=='disk'}
 if len(endpoints)<2:raise RuntimeError('WWID должен быть виден через два разных портала выбранной iSCSI-цели')
 def used(b):return bool(b.get('fstype') not in (None,'','mpath_member') or b.get('uuid') or b.get('pttype') or b.get('ptuuid') or any(b.get('mountpoints',[])) or b.get('ro') or b.get('type')=='part' or any(used(c) for c in b.get('children',[])))
 if any(used(b) for b in found):raise RuntimeError('Перед созданием карты выбранный новый LUN должен быть свободен от данных и монтирований')
 for entry in found:
  source='/dev/'+entry['kname']
  if json.loads(w['run'](['wipefs','--no-act','--json',source])).get('signatures'):
   raise RuntimeError('На пути выбранного LUN найдена сигнатура: '+source)
 run=w['run'];run(['modprobe','dm_multipath'])
 alias='sambaadm-'+name;directory=pathlib.Path('/etc/multipath/conf.d');directory.mkdir(mode=0o755,parents=True,exist_ok=True)
 path=directory/('sambaadm-'+name+'.conf')
 text='# Managed by sambaadm; selected WWID only\nmultipaths {\n multipath {\n  wwid "'+wwid+'"\n  alias "'+alias+'"\n  no_path_retry fail\n }\n}\n'
 if path.is_symlink() or path.exists() and path.read_text()!=text:raise RuntimeError('Конфигурация этой карты уже изменена; замена запрещена')
 if not path.exists():
  fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
  with os.fdopen(fd,'w') as output:output.write(text);output.flush();os.fsync(output.fileno())
  w['sync_directory'](directory)
 run(['multipath','-a',wwid]);run(['systemctl','enable','--now','multipathd'],30);run(['multipathd','reconfigure'],20)
 save('Проверка карты и двух доступных путей','verifying-paths')
 path=pathlib.Path('/dev/mapper')/alias
 for attempt in range(20):
  if path.exists():break
  time.sleep(.5)
 if not path.exists():raise RuntimeError('Карта multipath не создана')
 return {**verify_map(name,wwid,target,run),'formatted':False}
