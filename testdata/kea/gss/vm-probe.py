#!/usr/bin/env python3
"""Submit NCR to the already-running D2 systemd service on a disposable VM."""
import ipaddress,json,os,socket,struct,subprocess,time,uuid
address='10.0.2.2';port='1053';token=uuid.uuid4().hex[:12]
def query(name,kind):return subprocess.check_output(['dig','+time=1','+tries=1','+short','@'+address,'-p',port,name,kind],text=True).strip()
sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
def wait(check,request):
 for attempt in range(60):
  if check():return
  if attempt%4==0:
   data=json.dumps(request).encode();sock.sendto(struct.pack('!H',len(data))+data,('127.0.0.1',15999))
  time.sleep(.25)
 raise RuntimeError('DNS result timed out')
for ip,kind in [('10.0.0.'+os.environ.get('GSS_TEST_OCTET','210'),'A'),('2001:db8::'+os.environ.get('GSS_TEST_V6','f10'),'AAAA')]:
 name='vm-'+token+'-'+kind.lower()+'.sambaadm.test.';ptr=ipaddress.ip_address(ip).reverse_pointer+'.'
 req={'change-type':0,'forward-change':True,'reverse-change':True,'fqdn':name,'ip-address':ip,'dhcid':'000101'+'bd'*32,'lease-expires-on':'20300101000000','lease-length':3600,'conflict-resolution-mode':'no-check-without-dhcid'}
 wait(lambda:query(name,kind)==ip and query(ptr,'PTR')==name,req)
 req['change-type']=1;data=json.dumps(req).encode();sock.sendto(struct.pack('!H',len(data))+data,('127.0.0.1',15999))
 wait(lambda:not query(name,kind) and not query(ptr,'PTR'),req)
print('PASS: live systemd D2 signed A/AAAA/PTR add and delete')
