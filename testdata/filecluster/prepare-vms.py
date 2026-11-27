"""Create only disposable QEMU guests, using a checksum-verified ALT cloud image."""
import argparse, hashlib, json, pathlib, secrets, shutil, subprocess, sys
parser=argparse.ArgumentParser()
parser.add_argument("root",nargs="?",default="/tmp/sambaadm-ha-lab")
parser.add_argument("--branch",choices=["p10","p11"],default="p11")
parser.add_argument("--ssh-base",type=int,default=2220)
parser.add_argument("--cluster-base",type=int,default=19100)
options=parser.parse_args()
root=pathlib.Path(options.root).resolve();root.mkdir(exist_ok=True)
image=root/('alt-'+options.branch+'-cloud-aarch64.qcow2')
expected=next(line.split()[0] for line in (root/'SHA256SUMS').read_text().splitlines() if line.endswith('  '+image.name))
if hashlib.file_digest(image.open('rb'),'sha256').hexdigest()!=expected:raise SystemExit('Cloud image checksum mismatch or download incomplete')
key=root/'lab_ed25519'
if not key.exists():subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True)
pub=(root/'lab_ed25519.pub').read_text().strip();qemu=shutil.which('qemu-system-aarch64');imgtool=shutil.which('qemu-img')
firmware=pathlib.Path(qemu).resolve().parent.parent/'share/qemu/edk2-aarch64-code.fd'
# Homebrew versioned Cellar paths retain share/qemu next to bin.
if not firmware.exists():firmware=pathlib.Path('/opt/homebrew/share/qemu/edk2-aarch64-code.fd')
configs={}
for i in [1,2]:
 name='fs'+str(i);node=root/name;node.mkdir(exist_ok=True)
 if (node/'qemu.pid').exists():raise SystemExit('Refusing to rewrite a prepared/running VM: '+name)
 disk=node/'root.qcow2'
 if not disk.exists():
  subprocess.run([imgtool,'create','-f','qcow2','-F','qcow2','-b',str(image),str(disk),'8G'],check=True)
 data=node/'data.qcow2'
 if not data.exists():subprocess.run([imgtool,'create','-f','qcow2',str(data),'2G'],check=True)
 seed=node/'seed';seed.mkdir(exist_ok=True)
 (seed/'meta-data').write_text('instance-id: sambaadm-ha-'+name+'\nlocal-hostname: '+name+'.sambaadm.test\n')
 config={'hostname':name,'fqdn':name+'.sambaadm.test','disable_root':False,'ssh_pwauth':False,
 'runcmd':[['sh','-c','sed -i -E "s/^[#[:space:]]*UsePAM[[:space:]]+.*/UsePAM no/" /etc/openssh/sshd_config; systemctl reload sshd']],
 'users':[{'name':'root','lock_passwd':False,'hashed_passwd':subprocess.run(['openssl','passwd','-6','-stdin'],input=secrets.token_urlsafe(48),text=True,stdout=subprocess.PIPE,check=True).stdout.strip(),'ssh_authorized_keys':[pub]}],
 'bootcmd':[['sh','-c','iface=$(ip -o link | awk -F": " \'/52:54:00:77:00:0'+str(i)+'/ {print $2}\'); test -n "$iface" && ip link set "$iface" up && ip address replace 10.77.0.'+str(10+i)+'/24 dev "$iface"']],
 'write_files':[{'path':'/etc/sambaadm-ha-lab','permissions':'0600','content':'disposable QEMU lab\n'}]}
 (seed/'user-data').write_text('#cloud-config\n'+json.dumps(config)+'\n')
 iso=node/'seed.iso'
 subprocess.run(['hdiutil','makehybrid','-iso','-joliet','-default-volume-name','cidata','-o',str(iso),str(seed)],check=True,stdout=subprocess.DEVNULL)
 args=[qemu,'-machine','virt,accel=hvf','-cpu','host','-smp','2','-m','1536','-bios',str(firmware),'-display','none','-monitor','none','-serial','file:'+str(node/'console.log'),'-pidfile',str(node/'qemu.pid'),'-qmp','unix:'+str(node/'qmp.sock')+',server=on,wait=off','-daemonize',
 '-drive','if=virtio,format=qcow2,file='+str(disk),'-drive','if=virtio,format=qcow2,file='+str(data),'-drive','if=virtio,media=cdrom,format=raw,file='+str(iso),
 '-netdev','user,id=nat,hostfwd=tcp:127.0.0.1:'+str(options.ssh_base+i)+'-:22','-device','virtio-net-pci,netdev=nat,mac=52:54:00:10:00:0'+str(i),
 '-netdev','socket,id=cluster,udp=127.0.0.1:'+str(options.cluster_base+(2 if i==1 else 1))+',localaddr=127.0.0.1:'+str(options.cluster_base+i),'-device','virtio-net-pci,netdev=cluster,mac=52:54:00:77:00:0'+str(i)]
 configs[name]={'args':args,'qmp':str(node/'qmp.sock'),'sshPort':options.ssh_base+i}
(root/'vms.json').write_text(json.dumps(configs,indent=2)+'\n')
print('Prepared two disposable guests; start with their fixed argument arrays in',root/'vms.json')
