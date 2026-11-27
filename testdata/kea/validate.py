#!/usr/bin/env python3
"""Exercise the real ALT Kea parser: IPv4/v6, relays, Option 82 and both HA modes.
Run inside ALT p10/p11 after installing Kea and kea-hooks. No live service changes.
"""
import copy
import json
import pathlib
import subprocess
import tempfile
import os
import time

hook_root = next(p for p in [pathlib.Path('/usr/lib64/kea/hooks'), pathlib.Path('/usr/lib/kea/hooks')] if (p / 'libdhcp_ha.so').exists())
with tempfile.TemporaryDirectory(prefix='sambaadm-kea-') as tmp:
    count = 0
    for family in (4, 6):
        binary = 'kea-dhcp' + str(family)
        version = subprocess.check_output([binary, '-v'], text=True).strip()
        subnet = {'id': 1, 'subnet': '10.10.0.0/24' if family == 4 else '2001:db8:10::/64',
                  'pools': [{'pool': '10.10.0.10 - 10.10.0.100' if family == 4 else '2001:db8:10::10 - 2001:db8:10::100'}],
                  'relay': {'ip-addresses': ['192.0.2.1' if family == 4 else '2001:db8:ffff::1']}}
        if family == 4:
            subnet['reservations'] = [{'hw-address': '00:11:22:33:44:55', 'ip-address': '10.10.0.110', 'hostname': 'reserved'}]
        else:
            subnet['interface-id'] = 'vlan100'
            subnet['reservations'] = [{'duid': '00:01:00:01:12:34:56:78:00:11:22:33:44:55', 'ip-addresses': ['2001:db8:10::110']}]
        service = {'interfaces-config': {'interfaces': []}, 'valid-lifetime': 3600, 'renew-timer': 900, 'rebind-timer': 1800,
                   'multi-threading': {'enable-multi-threading': True}, 'lease-database': {'type': 'memfile', 'persist': False}, 'subnet'+str(family): [subnet]}
        if family == 4:
            service['client-classes'] = [{'name': 'relay-vlan100', 'test': 'relay4[1].hex == 0x766c616e313030'}]
        for mode in ('hot-standby', 'load-balancing'):
            for local in ('dhcp-primary', 'dhcp-secondary'):
                candidate = copy.deepcopy(service)
                candidate['hooks-libraries'] = [
                    {'library': str(hook_root / 'libdhcp_lease_cmds.so')},
                    {'library': str(hook_root / 'libdhcp_ha.so'), 'parameters': {'high-availability': [{
                        'this-server-name': local, 'mode': mode, 'multi-threading': {'enable-multi-threading': True, 'http-dedicated-listener': True},
                        'peers': [{'name': 'dhcp-primary', 'url': 'http://127.0.0.1:18000/', 'role': 'primary', 'auto-failover': True},
                                  {'name': 'dhcp-secondary', 'url': 'http://127.0.0.1:18001/', 'role': 'standby' if mode == 'hot-standby' else 'secondary', 'auto-failover': True}]}]}}]
                file = pathlib.Path(tmp) / 'kea.conf'
                file.write_text(json.dumps({'Dhcp'+str(family): candidate}))
                result = subprocess.run([binary, '-t', str(file)], capture_output=True, text=True)
                if result.returncode:
                    raise RuntimeError(f'{version} IPv{family} {mode} {local}:\n{result.stdout}\n{result.stderr}')
                # Kea 2.6 -T starts the HA listener before enabling the core's MT mode.
                # Exercise a real daemon instead, with no DHCP interfaces and isolated PID files.
                env = dict(os.environ, KEA_PIDFILE_DIR=tmp, KEA_LOCKFILE_DIR=tmp)
                with open(pathlib.Path(tmp) / 'daemon.log', 'w+') as log:
                    proc = subprocess.Popen([binary, '-d', '-c', str(file)], stdout=log, stderr=log, env=env)
                    try:
                        time.sleep(0.6)
                        if proc.poll() is not None:
                            log.seek(0)
                            raise RuntimeError(log.read())
                        log.seek(0)
                        output = log.read()
                        if 'HA_SERVICE_STARTED' not in output:
                            raise RuntimeError('HA did not start: '+output)
                    finally:
                        proc.terminate()
                        proc.wait(timeout=5)
                count += 1
                print(f'PASS {version} IPv{family} {mode} {local}, relay + reservations, hooks loaded')
    print(f'{count} real Kea configurations verified')
