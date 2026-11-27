"""Loopback-only test Redfish controller: actually powers the named QEMU guests off/on."""
import base64, hmac, os, http.server, json, pathlib, socket, ssl, subprocess, sys, threading, time
root=pathlib.Path(sys.argv[1]).resolve();(root/'power.pid').write_text(str(os.getpid())+'\n');config=json.loads((root/'vms.json').read_text());secret=(root/'power.secret').read_text().strip();locks={name:threading.Lock() for name in config}
def command(name,operation):
 with socket.socket(socket.AF_UNIX) as sock:
  sock.settimeout(5);sock.connect(config[name]['qmp']);stream=sock.makefile('rwb');stream.readline()
  for op in ['qmp_capabilities',operation]:
   stream.write(json.dumps({'execute':op}).encode()+b'\n');stream.flush()
   while True:
    reply=json.loads(stream.readline())
    if 'return' in reply:break
    if 'error' in reply:raise RuntimeError('QMP operation failed')
def powered(name):
 # A lost QMP connection must never be reported as successful power fencing.
 try:
  pid=pathlib.Path(config[name]['qmp']).with_name('qemu.pid').read_text().strip()
  if not pid.isdigit():return False
  result=subprocess.run(['ps','-p',pid,'-o','command='],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,timeout=5)
  return result.returncode==0 and config[name]['qmp'] in result.stdout and 'qemu-system-' in result.stdout
 except (OSError,ValueError):return False
class Handler(http.server.BaseHTTPRequestHandler):
 def log_message(self,*_):pass
 def authorize(self):
  supplied=self.headers.get('Authorization','');expected='Basic '+base64.b64encode(('lab:'+secret).encode()).decode()
  if not hmac.compare_digest(supplied,expected):self.send_error(401);return False
  return True
 def reply(self,data,code=200):
  raw=json.dumps(data).encode();self.send_response(code);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
 def do_GET(self):
  if not self.authorize():return
  if self.path.rstrip('/')=='/redfish/v1':return self.reply({'Systems':{'@odata.id':'/redfish/v1/Systems'}})
  if self.path.rstrip('/')=='/redfish/v1/Systems':return self.reply({'Members':[{'@odata.id':'/redfish/v1/Systems/'+name} for name in config]})
  name=self.path.removeprefix('/redfish/v1/Systems/')
  if name not in config:return self.send_error(404)
  self.reply({'Id':name,'PowerState':'On' if powered(name) else 'Off','Actions':{'#ComputerSystem.Reset':{'target':'/redfish/v1/Systems/'+name+'/Actions/ComputerSystem.Reset'}}})
 def do_POST(self):
  if not self.authorize():return
  parts=self.path.split('/')
  if len(parts)!=7 or parts[1:4]!=['redfish','v1','Systems'] or parts[4] not in config or parts[5:]!=['Actions','ComputerSystem.Reset']:return self.send_error(404)
  name=parts[4]
  try:
   length=int(self.headers.get('Content-Length','0'))
   if length<1 or length>1024:return self.send_error(400)
   action=json.loads(self.rfile.read(length)).get('ResetType')
   if action not in ['On','ForceOff','ForceRestart']:return self.send_error(400)
   with locks[name]:
    if action=='On' and powered(name):return self.reply({},204)
    if action in ['ForceOff','ForceRestart'] and powered(name):command(name,'quit')
    if action in ['On','ForceRestart']:
     deadline=time.monotonic()+10
     while powered(name) and time.monotonic()<deadline:time.sleep(.1)
     subprocess.run(config[name]['args'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=10)
   with (root/'power-events.jsonl').open('a') as log:log.write(json.dumps({'time':time.time(),'node':name,'action':action,'powered':powered(name)})+'\n')
   self.reply({},204)
  except Exception:self.send_error(503)
server=http.server.ThreadingHTTPServer(('127.0.0.1',int(sys.argv[2]) if len(sys.argv)>2 else 18081),Handler);tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(root/'power.crt',root/'power.key');server.socket=tls.wrap_socket(server.socket,server_side=True);server.serve_forever()
