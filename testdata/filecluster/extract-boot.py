"""Extract boot files read-only from a verified lab cloud image (macOS host)."""
import json,pathlib,struct,subprocess,sys,tempfile
root=pathlib.Path(sys.argv[1]).resolve()
config=json.loads((root/'vms.json').read_text())
# prepare-vms.py verified the checksum; derive the image only from its fixed backing path.
info=json.loads(subprocess.check_output(['qemu-img','info','--output=json',str(root/'fs1/root.qcow2')]))
image=pathlib.Path(info['full-backing-filename'])
with tempfile.TemporaryDirectory(prefix='boot-',dir=root) as tmp:
 tmp=pathlib.Path(tmp);raw=tmp/'disk.raw'
 subprocess.run(['qemu-img','convert','-O','raw',str(image),str(raw)],check=True)
 with raw.open('rb') as source:
  source.seek(512);header=source.read(512)
  if header[:8]!=b'EFI PART':raise SystemExit('Expected GPT lab image')
  table,count,size=struct.unpack_from('<QII',header,72)
  for n in range(count):
   source.seek(table*512+n*size);entry=source.read(size)
   if entry[:16]==b'\0'*16:continue
   start,end=struct.unpack_from('<QQ',entry,32)
   source.seek(start*512+1024+56)
   if source.read(2)!=b'\x53\xef':continue
   source.seek(start*512+1024+104);uuid=source.read(16).hex()
   uuid='-'.join([uuid[:8],uuid[8:12],uuid[12:16],uuid[16:20],uuid[20:]])
   part=tmp/'root.ext4';source.seek(start*512);left=(end-start+1)*512
   with part.open('wb') as target:
    while left:
     block=source.read(min(left,1024*1024))
     if not block:raise SystemExit('Truncated image')
     target.write(block);left-=len(block)
   break
  else:raise SystemExit('No ext4 partition')
 boot=root/'guestboot';boot.mkdir(exist_ok=True)
 subprocess.run(['docker','run','--rm','-v',str(tmp)+':/in:ro','-v',str(boot)+':/out','debian:12-slim','debugfs','-R','rdump /boot /out','/in/root.ext4'],check=True)
 kernel=sorted((boot/'boot').glob('vmlinuz-*'))[-1];version=kernel.name.removeprefix('vmlinuz-');initrd=boot/'boot'/('initrd-'+version+'.img')
 if not initrd.exists():raise SystemExit('Matching initrd missing')
 for node in config.values():
  if '-kernel' in node['args']:raise SystemExit('Already configured direct boot')
  node['args']+=['-kernel',str(kernel),'-initrd',str(initrd),'-append','root=UUID='+uuid+' rw console=ttyAMA0']
 (root/'vms.json').write_text(json.dumps(config,indent=2)+'\n')
 print('Prepared direct boot with kernel',version)
