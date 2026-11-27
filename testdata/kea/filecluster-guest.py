#!/usr/bin/env python3
"""Configure Kea in an existing disposable ALT file-cluster guest after package installation."""
import json
import os
import pathlib
import shutil
import subprocess
import sys

node = int(sys.argv[1])
tag = sys.argv[2]
primary = int(sys.argv[3])
assert node in (1, 2) and primary in (1, 2)
assert pathlib.Path('/etc/sambaadm-ha-lab').is_file(), 'Run only on a disposable Samba Admin lab VM'
address = 10 + node
branch = pathlib.Path('/etc/altlinux-release').read_text()
assert tag in branch and os.uname().nodename.split('.')[0] == 'fs' + str(node)
def run(*command):
    subprocess.run(command, check=True)
unit_file = pathlib.Path('/etc/systemd/system/sambaadm-lab-dhcp-network.service')
script_file = pathlib.Path('/usr/local/sbin/sambaadm-lab-dhcp-network')
script_file.write_text('''#!/bin/sh
set -eu
ip netns list | cut -d' ' -f1 | grep -qx sambaadm-dhcp || ip netns add sambaadm-dhcp
ip link show sa-dhcp0 >/dev/null 2>&1 || ip link add sa-dhcp0 type veth peer name sa-client0 netns sambaadm-dhcp
sysctl -qw net.ipv6.conf.sa-dhcp0.accept_dad=0
ip -6 addr replace fe80::__NODE__/64 dev sa-dhcp0 nodad
ip addr replace 198.18.77.__NODE__/24 dev sa-dhcp0
ip -6 addr replace fd77:77:77::__NODE__/64 dev sa-dhcp0 nodad
ip link set sa-dhcp0 up
ip -n sambaadm-dhcp link set lo up
ip -n sambaadm-dhcp addr replace 198.18.77.2/24 dev sa-client0
ip -n sambaadm-dhcp -6 addr replace fd77:77:77::2/64 dev sa-client0 nodad
ip -n sambaadm-dhcp link set sa-client0 up
'''.replace('__NODE__', str(address)))
script_file.chmod(0o750)
unit_file.write_text('''[Unit]
Description=Samba Admin lab DHCP test link
Before=kea-dhcp4.service kea-dhcp6.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/sambaadm-lab-dhcp-network
RemainAfterExit=yes
''')
run('systemctl', 'daemon-reload')
run('systemctl', 'restart', 'sambaadm-lab-dhcp-network.service')
kea = pathlib.Path('/run/kea')
kea.mkdir(mode=0o750, exist_ok=True)
# Same account and directory mode as ALT's packaged units.
shutil.chown(kea, '_kea', '_kea')
kea.chmod(0o750)
hooks = next(path for path in (pathlib.Path('/usr/lib64/kea/hooks'), pathlib.Path('/usr/lib/kea/hooks'))
             if (path / 'libdhcp_ha.so').is_file())
for family in (4, 6):
    keaunit = f'kea-dhcp{family}.service'
    dropin = pathlib.Path('/etc/systemd/system', keaunit+'.d', '90-sambaadm-lab-network.conf')
    dropin.parent.mkdir(exist_ok=True)
    dropin.write_text('[Unit]\nRequires=sambaadm-lab-dhcp-network.service\nAfter=sambaadm-lab-dhcp-network.service\n')
    peers = [{'name':f'fs{n}', 'url':f'http://10.77.0.{10+n}:{18100+family}/',
              'role':'primary' if n == primary else 'standby', 'auto-failover':True} for n in (1,2)]
    interfaces = {'interfaces':['sa-dhcp0']} if family == 4 else {'interfaces':[f'sa-dhcp0/fd77:77:77::{address}']}
    if family == 4:
        interfaces['dhcp-socket-type'] = 'udp'
    subnet = {'id':1, 'subnet':'198.18.77.0/24' if family==4 else 'fd77:77:77::/64',
              'pools':[{'pool':'198.18.77.100 - 198.18.77.199' if family==4 else 'fd77:77:77::1000 - fd77:77:77::10ff'}]}
    if family == 6:
        subnet['interface-id'] = 'sambaadm-lab'
    service = {
        'interfaces-config':interfaces, 'valid-lifetime':1800,
        'multi-threading':{'enable-multi-threading':True,'thread-pool-size':2},
        'control-socket':{'socket-type':'unix','socket-name':f'/run/kea/kea{family}-ctrl-socket'},
        'lease-database':{'type':'memfile','persist':True,'name':f'/var/lib/kea/sambaadm-lab-lease{family}.csv'},
        f'subnet{family}':[subnet],
        'hooks-libraries':[
            {'library':str(hooks/'libdhcp_lease_cmds.so')},
            {'library':str(hooks/'libdhcp_ha.so'),'parameters':{'high-availability':[{
                'this-server-name':f'fs{node}','mode':'hot-standby','heartbeat-delay':1000,
                'max-response-delay':4000,'max-ack-delay':1000,'max-unacked-clients':0,
                'multi-threading':{'enable-multi-threading':True,'http-dedicated-listener':True,
                                   'http-listener-threads':1,'http-client-threads':1},'peers':peers}]}}]}
    config = pathlib.Path('/etc/kea', f'kea-dhcp{family}.conf')
    backup = config.with_suffix('.conf.pre-sambaadm-ha')
    if config.exists() and not backup.exists():
        run('cp','-p',str(config),str(backup))
    candidate = config.with_suffix('.conf.sambaadm-ha-new')
    candidate.write_text(json.dumps({f'Dhcp{family}':service},indent=2)+'\n')
    shutil.chown(candidate, 'root', '_kea')
    candidate.chmod(0o640)
    env = os.environ.copy()
    env['KEA_CONTROL_SOCKET_DIR'] = '/run/kea'
    subprocess.run([f'kea-dhcp{family}', '-t', str(candidate)], env=env, check=True)
    candidate.replace(config)
run('systemctl', 'unmask', 'kea-dhcp4.service', 'kea-dhcp6.service', 'kea-dhcp-ddns.service')
run('systemctl', 'daemon-reload')
run('systemctl', 'enable', '--now', 'kea-dhcp4.service', 'kea-dhcp6.service')
run('systemctl', 'restart', 'kea-dhcp4.service', 'kea-dhcp6.service')
run('systemctl', 'is-active', 'kea-dhcp4.service', 'kea-dhcp6.service')
