"""Install this checkout's signed helper on the two owned QEMU lab guests."""
import json,pathlib,subprocess,sys
root=pathlib.Path(sys.argv[1] if len(sys.argv)>1 else '/tmp/sambaadm-ha-lab').resolve();repo=pathlib.Path(__file__).resolve().parents[2]
key=str(root/'lab_ed25519');known=str(root/'known_hosts')
def ssh(port,command):return subprocess.check_output(['ssh','-i',key,'-p',str(port),'-o','UserKnownHostsFile='+known,'-o','BatchMode=yes','root@127.0.0.1',command],text=True)
def put(port,path,destination):subprocess.run(['scp','-i',key,'-P',str(port),'-o','UserKnownHostsFile='+known,'-o','BatchMode=yes',str(path),'root@127.0.0.1:'+destination],check=True)
def get(port,path,destination):subprocess.run(['scp','-i',key,'-P',str(port),'-o','UserKnownHostsFile='+known,'-o','BatchMode=yes','root@127.0.0.1:'+path,str(destination)],check=True)
metadata=json.loads((root/'vms.json').read_text())
nodes=[]
for i in [1,2]:
 name='fs'+str(i)+'.sambaadm.test';port=metadata['fs'+str(i)]['sshPort']
 endpoint=next(part.split('-:8444')[0].rsplit(':',1)[1] for argument in metadata['fs'+str(i)]['args'] for part in argument.split(',') if part.endswith('-:8444'))
 ssh(port,'apt-get update && apt-get -s install openssl && apt-get --download-only -y install openssl && apt-get --no-download -y install openssl')
 ssh(port,'install -d -m 0700 /etc/sambaadm-helper /var/lib/sambaadm-helper /var/log/sambaadm-helper; install -d -m 0755 /usr/libexec /etc/pki/ca-trust/source/anchors /srv/samba')
 put(port,root/'sambaadm-helper-linux-arm64','/tmp/sambaadm-helper.new');put(port,root/'management.pub','/etc/sambaadm-helper/management.pub');put(port,repo/'deploy/sambaadm-filecluster-secret','/usr/libexec/sambaadm-filecluster-secret');put(port,repo/'deploy/sambaadm-helper.service','/etc/systemd/system/sambaadm-helper.service');put(port,root/'power.crt','/etc/pki/ca-trust/source/anchors/sambaadm-ha-lab.pem')
 ssh(port,'install -m 0755 /tmp/sambaadm-helper.new /usr/bin/sambaadm-helper.new; mv -f /usr/bin/sambaadm-helper.new /usr/bin/sambaadm-helper; chmod 0700 /usr/libexec/sambaadm-filecluster-secret; update-ca-trust; umask 077; openssl req -new -newkey rsa:2048 -nodes -keyout /etc/sambaadm-helper/tls.key -out /tmp/sambaadm-helper.csr -subj /CN='+name+' >/dev/null 2>&1')
 csr=root/('fs'+str(i)+'.csr');get(port,'/tmp/sambaadm-helper.csr',csr)
 ext=root/('fs'+str(i)+'.ext');ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:'+name+',IP:127.0.0.1\n')
 cert=root/('fs'+str(i)+'.crt');subprocess.run(['openssl','x509','-req','-in',str(csr),'-CA',str(root/'power.crt'),'-CAkey',str(root/'power.key'),'-CAcreateserial','-out',str(cert),'-days','7','-extfile',str(ext)],check=True,stdout=subprocess.DEVNULL)
 put(port,cert,'/etc/sambaadm-helper/tls.crt')
 config={'helper':{'node':name,'listen':'0.0.0.0:8444','trusted_keys':['/etc/sambaadm-helper/management.pub'],'tls':{'cert':'/etc/sambaadm-helper/tls.crt','key':'/etc/sambaadm-helper/tls.key'},'state_dir':'/var/lib/sambaadm-helper','backup_root':'/var/lib/sambaadm-helper/backups'},'ldap':{'uri':'ldaps://dc1.sambaadm.test:636','base_dn':'DC=sambaadm,DC=test','bind':{'user':'Administrator@sambaadm.test','password_env':'SAMBAADM_PASSWORD'}},'samba':{'smb_conf':'/etc/samba/smb.conf','shares_root':'/srv/samba'},'audit':{'file':'/var/log/sambaadm-helper/audit.log'}}
 file=root/('fs'+str(i)+'-helper.json');file.write_text(json.dumps(config));file.chmod(0o600);put(port,file,'/etc/sambaadm-helper/config.yaml')
 ssh(port,'chmod 0600 /etc/sambaadm-helper/config.yaml /etc/sambaadm-helper/tls.key /etc/sambaadm-helper/management.pub; systemctl daemon-reload; systemctl enable sambaadm-helper; systemctl restart sambaadm-helper; systemctl is-active sambaadm-helper')
 nodes.append({'name':name,'transport':'https','endpoint':'https://127.0.0.1:'+endpoint,'ca_cert':str(root/'power.crt')})
(root/'agent-config.json').write_text(json.dumps({'private_key':str(root/'management.key'),'nodes':nodes},indent=2)+'\n')
print('Installed two signed HTTPS helpers; private TLS keys stayed on their guests')
