#!/usr/bin/env python3
"""Send real DHCPv4 and DHCPv6 relay packets to isolated Kea daemons.
Run as root in a disposable network namespace/container with installed Kea.
"""
import ipaddress
import json
import os
import pathlib
import socket
import struct
import subprocess
import tempfile
import time


def options6(data):
    result={}
    while data:
        code,size=struct.unpack('!HH',data[:4]);result[code]=data[4:4+size];data=data[4+size:]
    return result


def option6(code,data):return struct.pack('!HH',code,len(data))+data


def options4(data):
    result={}
    while data:
        code=data[0];data=data[1:]
        if code==255:break
        if code==0:continue
        size=data[0];result[code]=data[1:1+size];data=data[1+size:]
    return result

with tempfile.TemporaryDirectory(prefix='sambaadm-kea-relay-') as tmp:
    for family in (4,6):
        work=pathlib.Path(tmp)/str(family);work.mkdir()
        subnet={'id':1,'subnet':'192.0.2.0/24' if family==4 else '2001:db8:10::/64',
            'pools':[{'pool':'192.0.2.10 - 192.0.2.20' if family==4 else '2001:db8:10::10 - 2001:db8:10::20'}],
            'relay':{'ip-addresses':['127.0.0.1' if family==4 else '2001:db8:ffff::1']}}
        service={'interfaces-config':{'interfaces':['lo']},'valid-lifetime':3600,
            'lease-database':{'type':'memfile','persist':False},'subnet'+str(family):[subnet]}
        if family==4:
            service['interfaces-config']['dhcp-socket-type']='udp'
            service['client-classes']=[{'name':'relay-vlan100','test':'relay4[1].hex == 0x766c616e313030'}]
            subnet['client-class']='relay-vlan100'
        else:
            service['interfaces-config']['interfaces']=['lo/::1']
            subnet['interface-id']='vlan100'
            service['server-id']={'type':'LLT','persist':False}
        config=work/'kea.conf';config.write_text(json.dumps({'Dhcp'+str(family):service}))
        with open(work/'log','w+') as log:
            proc=subprocess.Popen(['kea-dhcp'+str(family),'-d','-p',str(1067 if family==4 else 1547),'-c',str(config)],stdout=log,stderr=log,env=dict(os.environ,KEA_PIDFILE_DIR=str(work),KEA_LOCKFILE_DIR=str(work)))
            try:
                time.sleep(.8)
                with socket.socket(socket.AF_INET if family==4 else socket.AF_INET6,socket.SOCK_DGRAM) as sock:
                    sock.settimeout(4)
                    sock.bind(('127.0.0.1',67) if family==4 else ('::1',547))
                    if family==4:
                        xid=0x12345678;mac=bytes.fromhex('001122334455');zero=b'\0'*4
                        bootp=struct.pack('!BBBBIHH4s4s4s4s16s64s128s',1,1,6,1,xid,0,0,zero,zero,zero,socket.inet_aton('127.0.0.1'),mac+b'\0'*10,b'',b'')
                        circuit=b'\x01\x07vlan100'
                        discover=bootp+b'\x63\x82\x53\x63'+b'\x35\x01\x01'+bytes([82,len(circuit)])+circuit+b'\xff'
                        sock.sendto(discover,('127.0.0.1',1067));response,_=sock.recvfrom(65535)
                        assert response[0]==2 and struct.unpack('!I',response[4:8])[0]==xid
                        address=socket.inet_ntoa(response[16:20]);opts=options4(response[240:]);assert opts[53]==b'\x02';assert opts[82]==circuit
                        assert ipaddress.ip_address(address) in ipaddress.ip_network('192.0.2.0/24')
                        print('PASS DHCPv4 relay giaddr outside scope + Option 82: offered '+address,flush=True)
                    else:
                        xid=b'\x12\x34\x56';duid=bytes.fromhex('00030001001122334455')
                        solicit=b'\x01'+xid+option6(1,duid)+option6(3,struct.pack('!III',1,0,0))
                        relay=b'\x0c\x00'+socket.inet_pton(socket.AF_INET6,'2001:db8:ffff::1')+socket.inet_pton(socket.AF_INET6,'2001:db8:10::2')+option6(18,b'vlan100')+option6(9,solicit)
                        sock.sendto(relay,('::1',1547));response,_=sock.recvfrom(65535)
                        assert response[0]==13;outer=options6(response[34:]);assert outer[18]==b'vlan100';advertise=outer[9];assert advertise[:4]==b'\x02'+xid
                        opts=options6(advertise[4:]);ia=options6(opts[3][12:]);address=socket.inet_ntop(socket.AF_INET6,ia[5][:16]);assert ipaddress.ip_address(address) in ipaddress.ip_network('2001:db8:10::/64')
                        print('PASS DHCPv6 relay link-address outside scope + Interface-ID: advertised '+address,flush=True)
            except Exception:
                log.flush();log.seek(0);print(log.read()[-14000:]);raise
            finally:
                proc.terminate();proc.wait(timeout=5)
