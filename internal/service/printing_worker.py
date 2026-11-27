"""Closed CUPS helper operations. Device credentials never belong in a URI."""
import tarfile,time,struct
import base64,contextlib,datetime,hashlib,io,json,os,pathlib,pwd,re,shutil,subprocess,sys,tempfile,urllib.parse,zipfile
P=pathlib.Path
ENV=dict(os.environ,PATH='/usr/sbin:/usr/bin:/sbin:/bin',LC_ALL='C',CUPS_SERVER='/run/cups/cups.sock')
SECRET=[]

def run(args,data=None,timeout=45,env=None):
 r=subprocess.run(args,input=data,capture_output=True,timeout=timeout,env=env or ENV)
 if r.returncode:raise ValueError((r.stderr or r.stdout).decode(errors='replace')[-3000:])
 return r.stdout.decode(errors='replace').strip()
def atomic(path,data,mode=0o600):
 path=P(path);path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 if path.is_symlink():raise ValueError('symlink destination rejected')
 fd,tmp=tempfile.mkstemp(dir=path.parent,prefix='.sambaadm-')
 try:
  with os.fdopen(fd,'wb') as f:f.write(data if isinstance(data,bytes) else data.encode());os.fchmod(f.fileno(),mode);f.flush();os.fsync(f.fileno())
  os.replace(tmp,path)
 finally:
  if os.path.exists(tmp):os.unlink(tmp)
def atomic_preserve(path,data,mode=0o640):
 path=P(path);metadata=path.stat() if path.exists() else None
 atomic(path,data,metadata.st_mode&0o777 if metadata else mode)
 if metadata:os.chown(path,metadata.st_uid,metadata.st_gid)
def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,default=str).encode()).hexdigest()
def safe_name(name):
 if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,126}',name):raise ValueError('Недопустимое имя очереди')
 return name
def connection():
 import cups
 cups.setUser('root');return cups.Connection(host='/run/cups/cups.sock')
def service():
 result={}
 for action,key in [('is-active','state'),('is-enabled','enabled')]:
  try:result[key]=run(['systemctl',action,'cups.service'])
  except ValueError:result[key]='inactive' if key=='state' else 'disabled'
 return result
def queues():
 import cups
 result=[]
 for name,a in connection().getPrinters().items():
  uri=a.get('device-uri','');parsed=urllib.parse.urlsplit(uri)
  if parsed.username or parsed.password or parsed.query:uri=urllib.parse.urlunsplit((parsed.scheme,('[credentials-hidden]@' if parsed.username or parsed.password else '')+(parsed.hostname or '')+(':'+str(parsed.port) if parsed.port else ''),parsed.path,'[hidden]' if parsed.query else '',''))
  result.append({'name':name,'uri':uri,'description':a.get('printer-info',''),'location':a.get('printer-location',''),'state':a.get('printer-state',0),'reason':a.get('printer-state-message',''),'accepting':a.get('printer-is-accepting-jobs',not bool(int(a.get('printer-type',0))&cups.CUPS_PRINTER_REJECTING)),'shared':a.get('printer-is-shared',False),'model':a.get('printer-make-and-model','')})
 return sorted(result,key=lambda x:x['name'].lower())
def snapshot(name):return next((q for q in queues() if q['name']==name),None)
def filter_exists(binary):return binary=='-' or any((P(d)/binary).is_file() for d in ['/usr/lib/cups/filter','/usr/lib64/cups/filter'])
def model_readiness(rows):
 for row in rows:
  missing=[f for f in row.get('filters',[]) if not filter_exists(f)]
  row.update(available=not missing and not row.get('validationError'),missingFilters=missing)
 return rows
def models(root):
 stamp=[int(P('/var/lib/rpm/Packages').stat().st_mtime) if P('/var/lib/rpm/Packages').exists() else 0,int((root/'ppd').stat().st_mtime_ns) if (root/'ppd').exists() else 0]
 cache=root/'models-cache.json'
 if cache.exists():
  try:
   saved=json.loads(cache.read_text())
   if saved['stamp']==stamp and time.time()-saved['created']<300:return model_readiness(saved['rows'])
  except Exception:pass
 rows=[]
 for line in run(['lpinfo','-m'],timeout=120).splitlines():
  name,_,label=line.partition(' ')
  if name and label:rows.append({'id':name,'label':label,'source':'installed'})
 for path in (root/'ppd').glob('*.json'):
  row=json.loads(path.read_text());rows.append(row)
 atomic(cache,json.dumps({'stamp':stamp,'created':time.time(),'rows':rows}));return model_readiness(rows)
def page(rows,value,fields):
 search=str(value.get('search','')).casefold();rows=[r for r in rows if not search or any(search in str(r.get(f,'')).casefold() for f in fields)]
 sort=value.get('sort',fields[0]);sort=sort if sort in fields else fields[0]
 rows.sort(key=lambda r:str(r.get(sort,'')).casefold(),reverse=value.get('descending',False) is True)
 offset=max(0,int(value.get('offset',0)));limit=min(250,max(1,int(value.get('limit',50))))
 return {'rows':rows[offset:offset+limit],'total':len(rows),'offset':offset,'limit':limit}
def jobs():
 rows=[]
 attributes=['job-id','job-printer-uri','job-originating-user-name','job-name','job-state','job-state-reasons','job-impressions-completed','job-media-sheets-completed','time-at-creation','time-at-completed']
 for job,attrs in connection().getJobs(which_jobs='all',my_jobs=False,limit=10000,requested_attributes=attributes).items():
  rows.append({'id':job,'printer':attrs.get('job-printer-uri','').rsplit('/',1)[-1],'user':attrs.get('job-originating-user-name',''),'title':attrs.get('job-name',''),'state':attrs.get('job-state',0),'reasons':([attrs['job-state-reasons']] if isinstance(attrs.get('job-state-reasons'),str) else attrs.get('job-state-reasons',[])),'pages':attrs.get('job-impressions-completed',0),'sheets':attrs.get('job-media-sheets-completed',0),'created':attrs.get('time-at-creation',0),'completed':attrs.get('time-at-completed',0)})
 return sorted(rows,key=lambda r:(r['created'],r['id']),reverse=True)
def queue_plan(value,root):
 name=safe_name(value.get('name'));before=snapshot(name);action=value.get('action','save')
 if action not in ['save','delete','pause','resume','accept','reject','default']:raise ValueError('Неизвестное действие очереди')
 settings={'name':name,'action':action,'publishSMB':value.get('publishSMB',False) is True,'removeSMB':value.get('removeSMB',False) is True}
 if action=='save':
  uri=str(value.get('uri',''));parsed=urllib.parse.urlsplit(uri)
  if parsed.scheme not in ['ipp','ipps','socket','lpd','smb','usb'] or len(uri)>2048 or any(c in uri for c in '\r\n\x00') or parsed.username or parsed.password:raise ValueError('Укажите IPP/IPPS, socket, LPD, SMB или USB URI без логина и пароля')
  if parsed.scheme!='usb' and (not parsed.hostname or parsed.fragment or parsed.query):raise ValueError('Некорректный URI устройства')
  model=str(value.get('model','everywhere'))
  if model not in ['everywhere','existing'] and model not in {r['id'] for r in models(root)}:raise ValueError('Драйвер отсутствует в каталоге этого сервера')
  if model.startswith('uploaded:') and not next((r.get('available',True) for r in models(root) if r['id']==model),False):raise ValueError('Установите фильтры производителя; этот PPD пока доступен только в каталоге')
  if model=='existing' and before is None:raise ValueError('Существующий драйвер допустим только для уже созданной очереди')
  if model=='everywhere' and parsed.scheme not in ['ipp','ipps']:raise ValueError('IPP Everywhere требует IPP/IPPS устройства; для старого принтера выберите драйвер')
  if parsed.scheme=='smb' and (not P('/etc/cups/sambaadm/smb.json').exists() or json.loads(P('/etc/cups/sambaadm/smb.json').read_text()).get('state')!='ready'):raise ValueError('Сначала настройте SMB keytab')
  for key in ['description','location']:
   text=str(value.get(key,''))
   if len(text)>512 or any(c in text for c in '\r\n\x00'):raise ValueError('Недопустимое описание')
   settings[key]=text
  settings.update(uri=uri,model=model,shared=value.get('shared',True) is True)
 if action!='save' and before is None:raise ValueError('Очередь не найдена')
 plan={'before':before,'settings':settings,'node':value['_node']};plan['revision']=digest(plan);return plan

def apply_queue(value,root):
 plan=queue_plan(value,root)
 if not value.get('confirm') or value.get('revision')!=plan['revision']:raise ValueError('Подтвердите актуальный план очереди')
 s=plan['settings'];name=s['name'];action=s['action'];c=connection()
 if action=='save':
  args=['lpadmin','-p',name,'-v',s['uri'],'-D',s['description'],'-L',s['location'],'-o','printer-is-shared='+str(s['shared']).lower()]
  if s['model'].startswith('uploaded:'):
   token=s['model'][9:]
   if not re.fullmatch('[a-f0-9]{64}',token):raise ValueError('invalid PPD id')
   args+=['-P',str(root/'ppd'/(token+'.ppd'))]
  elif s['model']!='existing':args+=['-m',s['model']]
  if s['uri'].startswith('smb:'):args+=['-o','auth-info-required=negotiate']
  run(args)
  if plan['before'] is None:c.enablePrinter(name);c.acceptJobs(name)
 elif action=='delete':
  if any(j['printer']==name and j['state']<7 for j in jobs()):raise ValueError('Сначала отмените или завершите активные задания очереди')
  c.deletePrinter(name)
 elif action=='pause':c.disablePrinter(name,reason='Paused by sambaadm operator')
 elif action=='resume':c.enablePrinter(name)
 elif action=='accept':c.acceptJobs(name)
 elif action=='reject':c.rejectJobs(name,reason='Disabled by sambaadm operator')
 elif action=='default':c.setDefault(name)
 return {'detail':'Настройки очереди применены','queues':queues()}

def ppd_upload(value,root):
 data=base64.b64decode(value.get('data',''),validate=True)
 if len(data)>2*1024*1024 or not data.startswith(b'*PPD-Adobe:'):raise ValueError('Ожидается PPD до 2 МиБ')
 text=data.decode('latin1')
 if re.search(r'^\*(?:FoomaticRIPCommandLine|FoomaticRIPPostPipe|cupsBackend)\b',text,re.M):raise ValueError('PPD содержит исполняемую команду; используйте драйвер из доверенного пакета ALT')
 filters=[]
 for line in text.splitlines():
  if line.startswith(('*cupsFilter:','*cupsFilter2:')):
   binary=line.strip().rstrip('"').split()[-1]
   if binary!='-' and (any(part in ['.','..'] for part in pathlib.PurePosixPath(binary).parts) or not re.fullmatch(r'[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_.+-]+)*',binary) ):raise ValueError('Недопустимый путь фильтра PPD: '+binary)
   filters.append(binary)
 token=hashlib.sha256(data).hexdigest();path=root/'ppd'/(token+'.ppd')
 root.mkdir(mode=0o700,parents=True,exist_ok=True);fd,tmp=tempfile.mkstemp(dir=root,prefix='.ppd-');os.close(fd);temporary=P(tmp)
 validation_error=''
 try:
  atomic(temporary,data)
  try:run(['cupstestppd','-q','-I','filters',str(temporary)])
  except ValueError as error:validation_error=str(error)
 finally:temporary.unlink(missing_ok=True)
 atomic(path,data)
 match=re.search(r'^\*NickName:\s*"([^"]+)"',text,re.M);label=match.group(1) if match else str(value.get('filename','Uploaded PPD'))
 row={'id':'uploaded:'+token,'label':label,'source':'uploaded','sha256':token,'filters':filters,'validationError':validation_error,'available':not validation_error and all(filter_exists(f) for f in filters),'missingFilters':[f for f in filters if not filter_exists(f)]};atomic(path.with_suffix('.json'),json.dumps(row));return row

def archive_ppds(data):
 # Read archive members in memory; never extract paths or execute vendor installers.
 entries=[];budget=[0,0]
 def visit(blob,name,depth):
  if depth>4:raise ValueError('Слишком глубокая вложенность архива')
  def member(label,size,reader):
   budget[0]+=1;budget[1]+=size
   if budget[0]>8192 or budget[1]>256*1024*1024:raise ValueError('Превышен лимит распаковки архива')
   lower=label.lower()
   if lower.endswith('.ppd'):
    if size>2*1024*1024:raise ValueError('PPD больше 2 МиБ')
    entries.append((label,reader()))
   elif lower.endswith(('.zip','.tar','.tgz','.tar.gz','.tar.xz','.tar.bz2','.deb')):
    if size>64*1024*1024:raise ValueError('Вложенный архив больше 64 МиБ')
    visit(reader(),label,depth+1)
  if blob.startswith(b'!<arch>\n'):
   offset=8
   while offset<len(blob):
    header=blob[offset:offset+60]
    if len(header)!=60 or header[-2:]!=b'`\n':raise ValueError('Некорректный DEB/ar')
    size=int(header[48:58]);label=header[:16].decode('ascii').strip().rstrip('/');offset+=60
    if size<0 or offset+size>len(blob):raise ValueError('Обрезанный DEB/ar')
    if label.startswith('data.tar'):member(label,size,lambda:blob[offset:offset+size])
    offset+=size+size%2
  elif blob.startswith((b'PK\x03\x04',b'PK\x05\x06')):
   with zipfile.ZipFile(io.BytesIO(blob)) as archive:
    if len(archive.infolist())>8192:raise ValueError('Слишком много файлов в архиве')
    for item in archive.infolist():
     if not item.is_dir() and (item.external_attr>>16)&0o170000!=0o120000:member(item.filename,item.file_size,lambda:archive.read(item))
  else:
   with tarfile.open(fileobj=io.BytesIO(blob),mode='r:*') as archive:
    for item in archive:
     if item.isfile():member(item.name,item.size,lambda:archive.extractfile(item).read())
 visit(data,'archive',0)
 return entries

def ppd_import(value,root):
 data=base64.b64decode(value.get('data',''),validate=True)
 if len(data)>48*1024*1024:raise ValueError('Архив больше 48 МиБ')
 entries=archive_ppds(data)
 if not entries:raise ValueError('В архиве нет PPD; исполняемые установщики не запускаются')
 added=[];failed=[];seen=set()
 for name,body in entries:
  token=hashlib.sha256(body).hexdigest()
  if token in seen:continue
  seen.add(token)
  try:added.append(ppd_upload({'data':base64.b64encode(body).decode(),'filename':name},root))
  except Exception as error:failed.append({'filename':name,'error':str(error)})
 return {'added':added,'failed':failed}

def install_plan():
 base=['cups','cups-filters','cups-ipptool','python3-module-cups','krb5-kinit','samba-client','fonts-ttf-dejavu']
 optional=['gutenprint-cups','gutenprint-cups-ppds','foomatic','foomatic-db','foomatic-db-engine','hplip-hpcups','splix','foo2zjs','cups-backend-bjnp','carps-cups']
 packages=list(base)
 for name in optional:
  try:run(['apt-cache','show',name]);packages.append(name)
  except ValueError:pass
 simulation=run(['apt-get','-s','install',*packages],timeout=90)
 if any(line.startswith('Remv ') for line in simulation.splitlines()):raise ValueError('План удаляет пакеты; устраните конфликт')
 p={'packages':packages,'simulation':simulation};p['revision']=digest(p);return p

def print_owner():
 for name in ['lp','_lp','cups','_cups']:
  try:return pwd.getpwnam(name)
  except KeyError:pass
 raise ValueError('Не найден системный пользователь CUPS; установите cups')
def keytab_alias(data,source,target):
 # A server SPN is not an AD client principal. Validate HTTP keys using a
 # temporary account-UPN alias, then decrypt the KDC's HTTP service ticket.
 offset=2;entries=[]
 def counted(blob,pos):
  length=struct.unpack_from('>H',blob,pos)[0];pos+=2
  if length>1024 or pos+length>len(blob):raise ValueError('Некорректная строка keytab')
  return blob[pos:pos+length],pos+length
 def encode(text):
  raw=text.encode();return struct.pack('>H',len(raw))+raw
 while offset<len(data):
  length=struct.unpack_from('>i',data,offset)[0];offset+=4
  if length<0:offset-=length;continue
  if length==0:continue
  end=offset+length
  if end>len(data):raise ValueError('Обрезанная запись keytab')
  blob=data[offset:end];offset=end;count=struct.unpack_from('>H',blob,0)[0]
  if count<1 or count>16:raise ValueError('Некорректный principal keytab')
  realm,pos=counted(blob,2);parts=[]
  for _ in range(count):part,pos=counted(blob,pos);parts.append(part)
  principal=b'/'.join(parts).decode()+'@'+realm.decode()
  if principal!=source:continue
  # Preserve timestamp, KVNO and secret keys; replace only principal labels.
  name,realm=target.rsplit('@',1);names=name.split('/')
  replacement=struct.pack('>H',len(names))+encode(realm)+b''.join(encode(part) for part in names)+struct.pack('>I',1)+blob[pos+4:]
  entries.append(struct.pack('>i',len(replacement))+replacement)
 if not entries:raise ValueError('Ключ HTTP principal не найден')
 return b'\x05\x02'+b''.join(entries)

def keytab_upload(value):
 kind=value.get('kind');principal=str(value.get('principal',''));controller=str(value.get('controller',''))
 if kind not in ['http','smb','windows'] or not re.fullmatch(r'[A-Za-z0-9_./-]+@[A-Za-z0-9.-]+',principal):raise ValueError('Выберите назначение и principal keytab')
 if kind=='http' and principal.split('@')[0].lower()!='http/'+value['_node'].lower():raise ValueError('Для CUPS требуется HTTP/'+value['_node']+'@REALM')
 if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{1,252}',controller):raise ValueError('Укажите FQDN KDC')
 realm=principal.rsplit('@',1)[1].upper();data=base64.b64decode(value.get('data',''),validate=True)
 if not data.startswith(b'\x05\x02') or len(data)>1024*1024:raise ValueError('Ожидается keytab v2 до 1 МиБ')
 directory=P('/etc/cups/sambaadm');directory.mkdir(mode=0o750,parents=True,exist_ok=True);os.chown(directory,0,print_owner().pw_gid);os.chmod(directory,0o750)
 for other in directory.glob('*.json'):
  if json.loads(other.read_text()).get('realm')!=realm:raise ValueError('Назначения keytab должны относиться к одному Kerberos realm')
 krb=f'[libdefaults]\n default_realm = {realm}\n rdns = false\n dns_lookup_kdc = false\n[realms]\n {realm} = {{\n  kdc = {controller}\n }}\n'
 fd,tmp=tempfile.mkstemp(prefix='.test-keytab-',dir=directory);os.close(fd);test=P(tmp);cache=P(tmp+'.ccache');krbtest=P(tmp+'.conf')
 try:
  atomic(test,data);atomic(krbtest,krb,0o644)
  listed=run(['klist','-k',str(test)])
  if principal not in [line.split()[-1] for line in listed.splitlines() if line.split()]:raise ValueError('В keytab отсутствует выбранный principal')
  environment=dict(ENV,KRB5_CONFIG=str(krbtest))
  if kind=='http':
   account=str(value.get('accountPrincipal',''))
   if not re.fullmatch(r'[A-Za-z0-9_.-]+@'+re.escape(realm),account):raise ValueError('Для проверки HTTP keytab укажите UPN его служебной учётной записи (account@REALM)')
   alias=P(tmp+'.alias');atomic(alias,keytab_alias(data,principal,account))
   try:run(['kinit','-k','-t',str(alias),'-c','FILE:'+str(cache),account],env=environment)
   finally:alias.unlink(missing_ok=True)
   run(['kvno','-c','FILE:'+str(cache),'-k',str(test),principal],env=environment)
  else:run(['kinit','-k','-t',str(test),'-c','FILE:'+str(cache),principal],env=environment)
 finally:
  for path in [test,cache,krbtest]:
   if path.exists():path.unlink()
 path=directory/(kind+'.keytab');atomic(path,data)
 owner=print_owner() if kind=='smb' else pwd.getpwnam('root');os.chown(path,owner.pw_uid,owner.pw_gid)
 atomic(directory/'krb5.conf',krb,0o644)
 profile={'kind':kind,'principal':principal,'realm':realm,'controller':controller,'state':'pending','verified':datetime.datetime.now(datetime.timezone.utc).isoformat()};atomic(directory/(kind+'.json'),json.dumps(profile))
 if kind!='http':
  env=directory/(kind+'.env');atomic(env,f'KRB5_CONFIG={directory}/krb5.conf\nPRINT_PRINCIPAL={principal}\nPRINT_KEYTAB={path}\n')
  unit=f'''[Unit]
Description=Sambaadm printing Kerberos credentials ({kind})
Wants=network-online.target
After=network-online.target time-sync.target
[Service]
Type=oneshot
User={owner.pw_name}
Group={owner.pw_gid}
RuntimeDirectory=sambaadm-cups/{kind}
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
EnvironmentFile={env}
ExecStart=/usr/bin/kinit -k -t ${{PRINT_KEYTAB}} -c FILE:/run/sambaadm-cups/{kind}/ccache ${{PRINT_PRINCIPAL}}
NoNewPrivileges=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/run/sambaadm-cups/{kind}
'''
  name='sambaadm-cups-'+kind+'-credentials';atomic(P('/etc/systemd/system')/(name+'.service'),unit,0o644)
  timer=f'[Unit]\nDescription=Refresh printing Kerberos credentials ({kind})\n[Timer]\nOnBootSec=1min\nOnUnitActiveSec=30min\nUnit={name}.service\n[Install]\nWantedBy=timers.target\n';atomic(P('/etc/systemd/system')/(name+'.timer'),timer,0o644)
  run(['systemctl','daemon-reload']);run(['systemctl','start',name+'.service']);run(['systemctl','enable','--now',name+'.timer'])
 profile['state']='ready';atomic(directory/(kind+'.json'),json.dumps(profile));return profile

def security_plan(value):
 path=P('/etc/cups/cupsd.conf');before=path.read_text();remote=value.get('remote',False) is True;kerberos=value.get('kerberos',False) is True
 if kerberos and (not P('/etc/cups/sambaadm/http.json').is_file() or json.loads(P('/etc/cups/sambaadm/http.json').read_text()).get('state')!='ready'):raise ValueError('Сначала загрузите и проверьте HTTP keytab')
 proposed=re.sub(r'\n?# BEGIN SAMBAADM PRINTING\n.*?# END SAMBAADM PRINTING\n?','\n',before,flags=re.S)
 proposed=re.sub(r'^[ \t]*<Location[ \t]+/[ \t]*>.*?^[ \t]*</Location>[ \t]*$','',proposed,flags=re.M|re.S)
 # Replace only global listen directives; existing access policies are retained.
 lines=[];depth=0
 for line in proposed.splitlines():
  stripped=line.strip()
  if depth==0 and re.match(r'^(?:Listen|Port)\s',stripped,re.I) and '/cups.sock' not in stripped:continue
  lines.append(line)
  if stripped.startswith('</'):depth=max(0,depth-1)
  elif stripped.startswith('<') and not stripped.startswith('</'):depth+=1
 proposed='\n'.join(lines).rstrip()+'\n# BEGIN SAMBAADM PRINTING\n'+('Port 631\n' if remote else 'Listen localhost:631\n')+'WebInterface Yes\nDefaultEncryption Required\nPreserveJobHistory Yes\nPreserveJobFiles No\nMaxJobs 10000\n'
 proposed+='<Location />\n Order allow,deny\n '+('Allow all\n' if remote else 'Allow localhost\n')+(' AuthType Negotiate\n Require valid-user\n' if kerberos else '')+'</Location>\n'
 if kerberos:
  proposed+='DefaultAuthType Negotiate\nGSSServiceName HTTP\n'
  for location in ['/printers','/jobs']:
   proposed+=f'<Location {location}>\n AuthType Negotiate\n Require valid-user\n Order allow,deny\n Allow all\n</Location>\n'
 proposed+='ServerName '+value['_node']+'\nServerAlias '+value['_node']+'\n# END SAMBAADM PRINTING\n'
 profile={}
 for kind in ['http','smb','windows']:
  p=P('/etc/cups/sambaadm')/(kind+'.json')
  if p.is_file():profile[kind]=json.loads(p.read_text())
 files_path=P('/etc/cups/cups-files.conf');files_before=files_path.read_text()
 files_proposed=re.sub(r'\n?# BEGIN SAMBAADM PRINT ENV\n.*?# END SAMBAADM PRINT ENV\n?','\n',files_before,flags=re.S)
 if 'smb' in profile:files_proposed=files_proposed.rstrip()+'\n# BEGIN SAMBAADM PRINT ENV\nPassEnv KRB5_CONFIG KRB5CCNAME\n# END SAMBAADM PRINT ENV\n'
 p={'before':before,'proposed':proposed,'filesBefore':files_before,'filesProposed':files_proposed,'remote':remote,'kerberos':kerberos,'profiles':profile,'node':value['_node']};p['revision']=digest(p);return p

def security_apply(value,root):
 p=security_plan(value)
 if not value.get('confirm') or value.get('revision')!=p['revision']:raise ValueError('Подтвердите актуальный план CUPS')
 directory=P('/etc/cups');fd,tmp=tempfile.mkstemp(dir=directory,prefix='.sambaadm-cups-');os.close(fd);temporary=P(tmp)
 files_temporary=P(tmp+'.files')
 try:
  atomic(temporary,p['proposed'],0o640);atomic(files_temporary,p['filesProposed'],0o640);run(['cupsd','-t','-c',str(temporary),'-s',str(files_temporary)])
 finally:temporary.unlink(missing_ok=True);files_temporary.unlink(missing_ok=True)
 dropin=P('/etc/systemd/system/cups.service.d/20-sambaadm-kerberos.conf');old_dropin=dropin.read_bytes() if dropin.exists() else None
 env=['[Service]','Environment=KRB5_CONFIG=/etc/cups/sambaadm/krb5.conf']
 if p['kerberos']:env.append('Environment=KRB5_KTNAME=FILE:/etc/cups/sambaadm/http.keytab')
 if 'smb' in p['profiles']:
  env+=['Environment=KRB5CCNAME=FILE:/run/sambaadm-cups/smb/ccache','Wants=sambaadm-cups-smb-credentials.service']
  # Unit dependencies belong in [Unit], not [Service].
  env.remove('Wants=sambaadm-cups-smb-credentials.service');env=['[Unit]','Wants=sambaadm-cups-smb-credentials.service','After=sambaadm-cups-smb-credentials.service',*env]
 backup=root/'backups'/('cupsd-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d%H%M%S')+'.conf');atomic(backup,p['before'])
 active=service()['state']=='active'
 try:
  atomic_preserve(directory/'cupsd.conf',p['proposed'],0o640);atomic_preserve(directory/'cups-files.conf',p['filesProposed'],0o640);atomic(dropin,'\n'.join(env)+'\n',0o644);run(['systemctl','daemon-reload'])
  if value.get('enable'):run(['systemctl','enable','cups.service'])
  if active:run(['systemctl','restart','cups.service'])
  elif value.get('enable'):run(['systemctl','start','cups.service'])
  return {'detail':'IPP/IPPS и политика CUPS настроены','backup':str(backup),'service':service()}
 except Exception:
  atomic_preserve(directory/'cupsd.conf',p['before'],0o640);atomic_preserve(directory/'cups-files.conf',p['filesBefore'],0o640)
  if old_dropin is None:dropin.unlink(missing_ok=True)
  else:atomic(dropin,old_dropin,0o644)
  run(['systemctl','daemon-reload'])
  if active:run(['systemctl','restart','cups.service'])
  raise

def windows_upload(value,root):
 data=base64.b64decode(value.get('data',''),validate=True)
 if len(data)>48*1024*1024:raise ValueError('ZIP драйвера не должен превышать 48 МиБ')
 token=hashlib.sha256(data).hexdigest();directory=root/'windows'/token
 allowed={'.inf','.dll','.cat','.ppd','.gpd','.dat','.ini','.cfg','.xml','.icm','.icc','.manifest','.mui','.cab','.txt','.vxd','.drv','.hlp'}
 entries=[];total=0
 with zipfile.ZipFile(io.BytesIO(data)) as archive:
  if len(archive.infolist())>4096:raise ValueError('Слишком много файлов драйвера')
  for entry in archive.infolist():
   name=pathlib.PurePosixPath(entry.filename.replace('\\','/'))
   if entry.is_dir():continue
   total+=entry.file_size
   if total>128*1024*1024 or name.is_absolute() or '..' in name.parts or (entry.external_attr>>16)&0o170000==0o120000 or name.suffix.lower() not in allowed or not re.fullmatch(r'[A-Za-z0-9_. /()+-]+',str(name)):raise ValueError('Недопустимый файл или размер ZIP: '+str(name))
   entries.append((str(name),archive.read(entry)))
 if not any(name.lower().endswith('.inf') for name,_ in entries):raise ValueError('В ZIP отсутствует INF; загрузите распакованный пакет драйвера, а не EXE установщик')
 for name,body in entries:atomic(directory/name,body,0o644)
 manifest={'id':token,'files':[name for name,_ in entries],'size':total,'state':'uploaded','label':str(value.get('filename','Windows driver'))[:256]};atomic(directory/'manifest.json',json.dumps(manifest));return manifest

def windows_catalog(root):return [json.loads(path.read_text()) for path in (root/'windows').glob('*/manifest.json')]
def windows_register(value,root):
 if not value.get('confirm'):raise ValueError('Подтвердите публикацию драйвера Windows')
 token=value.get('id','');architecture=value.get('architecture');architectures={'Windows x64':'x64','Windows NT x86':'W32X86','Windows ARM64':'ARM64'}
 if not re.fullmatch('[a-f0-9]{64}',token) or architecture not in architectures:raise ValueError('Неверный пакет или архитектура драйвера')
 directory=root/'windows'/token;manifest=json.loads((directory/'manifest.json').read_text());name=str(value.get('driverName',''))
 if not re.fullmatch(r'[A-Za-z0-9А-Яа-яЁё ._()+-]{1,200}',name):raise ValueError('Недопустимое имя драйвера')
 fields=[]
 for field in ['driverFile','dataFile','configFile','helpFile']:
  path=value.get(field,'')
  if not path and field=='helpFile':fields.append('NULL');continue
  if path not in manifest['files']:raise ValueError('Файл драйвера отсутствует в пакете: '+str(path))
  fields.append(P(path).name)
 dependents=value.get('dependentFiles',[])
 if not isinstance(dependents,list) or len(dependents)>256 or any(p not in manifest['files'] for p in dependents):raise ValueError('Неверные зависимые файлы драйвера')
 profile_path=P('/etc/cups/sambaadm/windows.json')
 if not profile_path.exists():raise ValueError('Сначала настройте keytab администратора печати Windows с правом регистрации драйверов на этом сервере')
 profile=json.loads(profile_path.read_text())
 if profile.get('state')!='ready':raise ValueError('Завершите проверку keytab администратора печати')
 try:uid=int(run(['id','-u',profile['principal']]))
 except ValueError:
  sid=run(['wbinfo','--name-to-sid',profile['principal']]).split()[0]
  if not re.fullmatch(r'S-1-[0-9-]+',sid):raise ValueError('Не удалось сопоставить администратора печати с SID')
  uid=int(run(['wbinfo','--sid-to-uid',sid]))
 if uid<=0:raise ValueError('Администратор печати должен иметь отдельный Unix UID')
 server=value['_node'];store=P('/var/lib/samba/printers')/architectures[architecture];store.mkdir(parents=True,exist_ok=True,mode=0o755)
 for area in [store,store/'3']:
  area.mkdir(mode=0o755,exist_ok=True);os.chown(area,uid,0);os.chmod(area,0o755)
 # Stage in the architecture directory returned by getdriverdir; spoolss moves
 # registered version-3 files into its 3/ subdirectory. The store is flattened. Reject colliding file basenames.
 mapping={}
 for path in manifest['files']:
  base=P(path).name
  if base.lower() in mapping:raise ValueError('В пакете повторяется имя файла: '+base)
  mapping[base.lower()]=path
 for path in manifest['files']:
  destination=store/P(path).name;body=(directory/path).read_bytes()
  for existing in [destination,store/'3'/P(path).name]:
   if existing.exists():
    if existing.read_bytes()!=body:raise ValueError('В print$ уже имеется другой файл '+existing.name)
    os.chown(existing,uid,0)
 for path in manifest['files']:
  target=store/P(path).name;atomic(target,(directory/path).read_bytes(),0o644);os.chown(target,uid,0)
 config=P(value['_smbConf']);before=config.read_text();metadata=config.stat()
 if not re.search(r'^\s*\[print\$\]',before,re.M|re.I):
  proposed=before.rstrip()+'\n\n[print$]\n path = /var/lib/samba/printers\n read only = yes\n browseable = no\n guest ok = no\n write list = '+profile['principal']+'\n'
  fd,tmp=tempfile.mkstemp(dir=config.parent);os.close(fd);temporary=P(tmp)
  try:atomic(temporary,proposed);run(['testparm','-s',str(temporary)])
  finally:temporary.unlink(missing_ok=True)
  atomic(root/'backups'/'smb-before-print.conf',before);atomic(config,proposed,config.stat().st_mode&0o777);os.chown(config,metadata.st_uid,metadata.st_gid);run(['smbcontrol','all','reload-config'])
 else:
  actual=run(['testparm','-s','--section-name=print$','--parameter-name=path',str(config)])
  if actual!='/var/lib/samba/printers':raise ValueError('Существующий print$ использует другой каталог; требуется согласовать хранилище драйверов')
 env=dict(ENV,KRB5_CONFIG='/etc/cups/sambaadm/krb5.conf',KRB5CCNAME='FILE:/run/sambaadm-cups/windows/ccache')
 descriptor=':'.join([name,*fields,'NULL','RAW',','.join(P(p).name for p in dependents) or 'NULL'])
 run(['rpcclient','--use-kerberos=required','--no-pass','-U',profile['principal'],server,'-c','adddriver "'+architecture+'" "'+descriptor+'" 3'],env=env)
 if value.get('queue'):
  queue=safe_name(value['queue']);run(['rpcclient','--use-kerberos=required','--no-pass','-U',profile['principal'],server,'-c','setdriver "'+queue+'" "'+name+'"'],env=env)
 manifest.update(state='registered',driverName=name,architecture=architecture);atomic(directory/'manifest.json',json.dumps(manifest));return manifest

def main(value):
 root=P(value['_state'])/'printing';root.mkdir(mode=0o700,parents=True,exist_ok=True)
 if not root.is_absolute() or root.is_symlink():raise ValueError('unsafe helper state directory')
 action=value['operation']
 if action=='inspect':
  status=service();status.update(node=value['_node'],queues=[],warning='',kerberos={})
  for kind in ['http','smb','windows']:
   profile=P('/etc/cups/sambaadm')/(kind+'.json')
   if profile.is_file():
    data=json.loads(profile.read_text());status['kerberos'][kind]={k:data.get(k) for k in ['state','principal','verified']}
  try:status['queues']=queues()
  except Exception as e:status['warning']=str(e)
  return status
 if action=='keytab.upload':return keytab_upload(value)
 if action=='security.plan':return security_plan(value)
 if action=='security.apply':return security_apply(value,root)
 if action=='windows.upload':return windows_upload(value,root)
 if action=='windows.catalog':return page(windows_catalog(root),value,['label','state','driverName','architecture'])
 if action=='windows.register':return windows_register(value,root)
 if action=='models':return page(models(root),value,['label','id','source'])
 if action=='jobs':return {'rows':jobs(),'node':value['_node']}
 if action=='queue.plan':return queue_plan(value,root)
 if action=='queue.apply':return apply_queue(value,root)
 if action=='ppd.upload':return ppd_upload(value,root)
 if action=='ppd.import':return ppd_import(value,root)
 if action=='job.cancel':
  if not value.get('confirm'):raise ValueError('Подтвердите отмену задания')
  job=int(value['id'])
  if job<1 or job not in connection().getJobs(which_jobs='not-completed',my_jobs=False):raise ValueError('Задание уже завершено или не найдено')
  connection().cancelJob(job);return {'detail':'Задание отменено'}
 if action=='service':
  verb=value.get('action')
  if verb not in ['start','stop','restart','enable','disable'] or not value.get('confirm'):raise ValueError('Подтвердите действие службы')
  run(['systemctl',verb,*(['--now'] if verb=='enable' else []),'cups.service']);return service()
 if action=='install.plan':return install_plan()
 if action=='install.apply':
  p=install_plan()
  if not value.get('confirm') or value.get('revision')!=p['revision']:raise ValueError('Подтвердите актуальный план установки')
  run(['apt-get','-y','install',*p['packages']],timeout=900);return {'detail':'CUPS и доступные открытые драйверы установлены; настройте IPP и доступ'}
 raise ValueError('unsupported printing operation')

if __name__=='__main__':
 try:
  if os.geteuid()!=0:raise ValueError('root helper required')
  if len(sys.argv)==3 and sys.argv[1]=='install-job':
   import fcntl
   directory=P(sys.argv[2]);value=json.loads((directory/'input.json').read_text())
   lock=open(P(value['_state'])/'operations.lock','a+b');fcntl.flock(lock,fcntl.LOCK_EX)
   atomic(directory/'status.json',json.dumps({'state':'running','phase':'Установка CUPS и драйверов'}))
   try:
    with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):result=main(value)
    atomic(directory/'status.json',json.dumps({'state':'complete','phase':'CUPS установлен','detail':result['detail']}))
   except Exception as error:atomic(directory/'status.json',json.dumps({'state':'failed','phase':'Установка не завершена','detail':str(error)[-4000:]}))
   sys.exit(0)
  value=json.loads(sys.stdin.buffer.read(72*1024*1024+1))
  with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):result=main(value)
  print(json.dumps({'ok':True,'result':result},default=str))
 except Exception as error:
  text=str(error)[-4000:]
  for secret in SECRET:
   if secret:text=text.replace(secret,'[скрыто]')
  print(json.dumps({'ok':False,'error':text}));sys.exit(1)
