#!/usr/bin/env python3
"""Run two isolated Kea processes, observe HA convergence, kill primary, verify takeover.
Uses loopback HA ports and no DHCP interfaces; does not test client packet delivery.
"""
import json
import os
import pathlib
import socket
import subprocess
import tempfile
import time
import urllib.request

hooks = next(p for p in [pathlib.Path('/usr/lib64/kea/hooks'),pathlib.Path('/usr/lib/kea/hooks')] if (p/'libdhcp_ha.so').exists())

def heartbeat(port):
    req=urllib.request.Request(f'http://127.0.0.1:{port}/', json.dumps({'command':'ha-heartbeat'}).encode(), {'Content-Type':'application/json'})
    with urllib.request.urlopen(req, timeout=1) as response:
        out=json.load(response)
    if isinstance(out,list):out=out[0]
    if out['result']!=0:raise RuntimeError(out)
    return out['arguments']['state']

def live_status(path):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(2)
        conn.connect(str(path))
        conn.sendall(b'{"command":"status-get"}')
        with conn.makefile() as stream:
            out=json.load(stream)
    if isinstance(out,list):out=out[0]
    if out['result']!=0 or 'uptime' not in out['arguments']:raise RuntimeError(out)
    return out['arguments']['high-availability'][0]

def wait_state(ports,expected,timeout=15):
    deadline=time.monotonic()+timeout
    last=[]
    while time.monotonic()<deadline:
        try:
            last=[heartbeat(port) for port in ports]
            if all(state==expected for state in last):return
        except Exception as e:last=[str(e)]
        time.sleep(.2)
    raise RuntimeError(f'Expected {expected}, got {last}')

pathlib.Path('/run/kea').mkdir(mode=0o750, exist_ok=True)
os.chmod('/run/kea', 0o750)
os.environ.setdefault('KEA_CONTROL_SOCKET_DIR', '/run/kea')
with tempfile.TemporaryDirectory(prefix='sambaadm-kea-ha-') as tmp:
    for family in (4,6):
        for mode in ('hot-standby','load-balancing'):
            processes=[];logs=[];sockets=[]
            try:
                for i,name in enumerate(('primary','secondary')):
                    work=pathlib.Path(tmp)/f'{family}-{mode}-{name}';work.mkdir()
                    peers=[{'name':'primary','url':'http://127.0.0.1:18000/','role':'primary','auto-failover':True},
                           {'name':'secondary','url':'http://127.0.0.1:18001/','role':'standby' if mode=='hot-standby' else 'secondary','auto-failover':True}]
                    control=pathlib.Path('/run/kea')/f'test-ha-{os.getpid()}-{family}-{mode}-{name}.sock'
                    sockets.append(control)
                    service={'interfaces-config':{'interfaces':[]},'valid-lifetime':3600,'multi-threading':{'enable-multi-threading':True,'thread-pool-size':2},
                        'control-socket':{'socket-type':'unix','socket-name':str(control)},
                        'lease-database':{'type':'memfile','persist':False},'subnet'+str(family):[{'id':1,'subnet':'10.0.0.0/24' if family==4 else '2001:db8:1::/64'}],
                        'hooks-libraries':[{'library':str(hooks/'libdhcp_lease_cmds.so')},{'library':str(hooks/'libdhcp_ha.so'),'parameters':{'high-availability':[{
                            'this-server-name':name,'mode':mode,'heartbeat-delay':1000,'max-response-delay':2000,'max-ack-delay':1000,'max-unacked-clients':0,
                            'multi-threading':{'enable-multi-threading':True,'http-dedicated-listener':True,'http-listener-threads':1,'http-client-threads':1},'peers':peers}]}}]}
                    config=work/'kea.conf';config.write_text(json.dumps({'Dhcp'+str(family):service}))
                    log=open(work/'log','w+');logs.append(log)
                    processes.append(subprocess.Popen(['kea-dhcp'+str(family),'-d','-c',str(config)],stdout=log,stderr=log,env=dict(os.environ,KEA_PIDFILE_DIR=str(work),KEA_LOCKFILE_DIR=str(work))))
                wait_state([18000,18001],mode)
                for control in sockets:
                    health=live_status(control)
                    assert health['ha-mode']==mode and health['ha-servers']['local']['state']==mode,health
                processes[0].terminate();processes[0].wait(timeout=5)
                wait_state([18001],'partner-down')
                health=live_status(sockets[1])
                assert health['ha-servers']['local']['state']=='partner-down',health
                print(f'PASS IPv{family} {mode}: status-get reports both peers healthy, then secondary partner-down after primary stopped',flush=True)
            except Exception:
                for log in logs:
                    log.flush();log.seek(0);print(log.read()[-12000:])
                raise
            finally:
                for proc in processes:
                    if proc.poll() is None:proc.terminate();proc.wait(timeout=5)
                for log in logs:log.close()
                for control in sockets:control.unlink(missing_ok=True)
