"""Configure ALT BIND for AD without replacing unrelated BIND directives."""
import ipaddress
import pathlib
import re
import sys

def patch_bind_options(text, values, remove_resolvconf=False):
    pattern=r'//[^\n]*|\#[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|[A-Za-z0-9_.:/-]+|[{};]|[^\s]'
    tokens=[m for m in re.finditer(pattern,text,re.S) if not m.group().startswith(('//','#','/*'))]
    starts=[i for i,t in enumerate(tokens[:-1]) if t.group()=='options' and tokens[i+1].group()=='{']
    if len(starts)!=1:raise ValueError('BIND: требуется один явный блок options')
    first=starts[0]+2;depth=0;statement=first;remove=[];end=None
    for i in range(first,len(tokens)):
        word=tokens[i].group()
        if word=='{' :depth+=1
        elif word=='}':
            if depth==0:end=tokens[i].start();break
            depth-=1
        elif word==';' and depth==0:
            key=tokens[statement].group()
            included=key=='include' and remove_resolvconf and any('resolvconf-options.conf' in t.group() for t in tokens[statement:i])
            if key in values or included:remove.append((tokens[statement].start(),tokens[i].end()))
            statement=i+1
    if end is None:raise ValueError('BIND: блок options не закрыт')
    proposed='\n'+''.join('    '+key+' '+value+';\n' for key,value in values.items())
    out=text[:end]+proposed+text[end:]
    for a,b in reversed(remove):out=out[:a]+out[b:]
    return out

def ad_network_settings(smb):
    for directory in ['/usr/lib64/samba-dc','/usr/lib/samba-dc']:
        for p in pathlib.Path(directory).glob('python*'):sys.path.insert(0,str(p))
    import ldb
    from samba.param import LoadParm
    from samba.auth import system_session
    from samba.samdb import SamDB
    lp=LoadParm();lp.load(str(smb));db=SamDB(url=lp.private_path('sam.ldb'),session_info=system_session(),lp=lp)
    nets=[]
    for row in db.search(base='CN=Subnets,CN=Sites,'+str(db.get_config_basedn()),scope=ldb.SCOPE_SUBTREE,expression='(objectClass=subnet)',attrs=['cn']):
        for value in row.get('cn',[]):
            network=ipaddress.ip_network(str(value),strict=False)
            if network.prefixlen==0:raise ValueError('В подсетях AD найден глобальный диапазон /0; автоматическая рекурсия запрещена')
            nets.append(str(network))
    return sorted(set(nets)),normalize_forwarders(lp.get('dns forwarder'))

def normalize_forwarders(values):
    forwarders=[]
    if isinstance(values,str):values=values.split()
    for value in values or []:
        try:address=ipaddress.ip_address(value)
        except ValueError:raise ValueError('Нестандартный dns forwarder Samba: проверьте конфигурацию перед переключением')
        if not address.is_loopback and not address.is_unspecified:forwarders.append(str(address))
    return forwarders

def configure_alt_bind(smb,fresh,run,atomic,remember):
    sysconfig=pathlib.Path('/etc/sysconfig/bind')
    if not sysconfig.exists():return
    options=pathlib.Path('/etc/bind/options.conf')
    remember(sysconfig);remember(options)
    run(['control','bind-chroot','disabled'])
    text=sysconfig.read_text()
    line='KRB5RCACHETYPE="none"'
    if re.search(r'(?m)^\s*KRB5RCACHETYPE\s*=',text):text=re.sub(r'(?m)^\s*KRB5RCACHETYPE\s*=.*$',line,text)
    else:text=text.rstrip()+'\n'+line+'\n'
    atomic(sysconfig,text.encode())
    values={'tkey-gssapi-keytab':'"/var/lib/samba/bind-dns/dns.keytab"','minimal-responses':'yes'}
    if fresh:
        networks,forwarders=ad_network_settings(smb)
        allowed='{ localhost; localnets; '+''.join(n+'; ' for n in networks)+'}'
        values.update({'listen-on':'{ any; }','listen-on-v6':'{ any; }','allow-query':'{ any; }','allow-recursion':allowed,'allow-query-cache':allowed,'forward':'first','forwarders':'{ '+''.join(a+'; ' for a in forwarders)+'}'})
    atomic(options,patch_bind_options(options.read_text(),values,remove_resolvconf=fresh).encode())
