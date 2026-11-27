#!/usr/bin/env python3
"""Integration driver for disposable containers only. Uses the documented lab password.
The production worker receives login credentials solely over stdin.
"""
import json
import pathlib
import subprocess
import sys

repo=pathlib.Path(__file__).resolve().parents[3]
DC='sambaadm-gss-dc-test'
PASSWORD='Lab-Only-Adm1n-Pass!'

def command(args, data=None):return subprocess.check_output(args,input=data)

def execute(container,value):
    result=subprocess.run(['docker','exec','-i',container,'python3','/tmp/gss-worker.py'],input=json.dumps(value).encode(),capture_output=True)
    try:reply=json.loads(result.stdout)
    except Exception:raise RuntimeError(result.stderr.decode()+result.stdout.decode())
    if not reply.get('ok'):raise RuntimeError(reply.get('error','failed'))
    return reply['result']

if __name__=='__main__':
    dc_ip=command(['docker','inspect',DC,'--format','{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}']).decode().strip()
    zone='0.0.10.in-addr.arpa'
    zone6='0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa'
    zone_command=['docker','exec','-i',DC,'samba-tool','dns','zonecreate','127.0.0.1',zone,'-U','Administrator']
    result=subprocess.run(zone_command,input=(PASSWORD+'\n').encode(),capture_output=True)
    if result.returncode and b'WERR_DNS_ERROR_ZONE_ALREADY_EXISTS' not in result.stderr:raise RuntimeError(result.stderr.decode()+result.stdout.decode())
    ipv6_command=zone_command.copy();ipv6_command[-3]=zone6
    result=subprocess.run(ipv6_command,input=(PASSWORD+'\n').encode(),capture_output=True)
    if result.returncode and b'WERR_DNS_ERROR_ZONE_ALREADY_EXISTS' not in result.stderr:raise RuntimeError(result.stderr.decode()+result.stdout.decode())
    ca=command(['docker','exec',DC,'cat','/var/lib/samba/private/tls/cert.pem'])
    for container in sys.argv[1:] or ['sambaadm-gss-ad-p11','sambaadm-gss-build-p10']:
        subprocess.check_call(['docker','cp',str(repo/'internal/service/kea_gss_worker.py'),container+':/tmp/gss-worker.py'])
        command(['docker','exec','-i',container,'sh','-c','cat > /tmp/dc-ca.pem'],ca)
        value={'action':'ad-plan','node':container+'.sambaadm.test','baseDN':'DC=sambaadm,DC=test','ca':'/tmp/dc-ca.pem','user':'Administrator@sambaadm.test','secret':PASSWORD,'stateDir':'/var/lib/sambaadm-helper','configDir':'/etc/kea','keytab':'/etc/kea/ddns.keytab','gss':{'controller':'dc1.sambaadm.test','dnsHost':'dc1.sambaadm.test','rotate':True},'ddns':{'forwardZone':'sambaadm.test.','reverseZones':[zone+'.',zone6+'.'],'dnsAddress':dc_ip,'dnsPort':1053},'testNoSystemd':True}
        plan=execute(container,value)
        print(container,': PLAN',plan['principal'],plan['rights'],flush=True)
        invalid=dict(value,action='ad-apply',revision='stale-plan')
        try:execute(container,invalid);raise AssertionError('stale AD plan accepted')
        except RuntimeError as error:assert 'повторите предпросмотр' in str(error)
        missing=json.loads(json.dumps(value));missing['ddns']['forwardZone']='missing-zone.sambaadm.test.'
        try:execute(container,missing);raise AssertionError('missing DNS zone accepted')
        except RuntimeError as error:assert 'Сначала создайте DNS-зоны' in str(error)
        value.update(action='ad-apply',revision=plan['revision'])
        applied=execute(container,value)
        assert applied['ready']
        value['gss']['rotate']=False;value['action']='ad-plan';again=execute(container,value)
        assert again['accountState'] is not None
        value.update(action='ad-apply',revision=again['revision'])
        assert execute(container,value)['ready']
        print(container,': PASS keytab, narrow zone ACL, signed A/AAAA/PTR probes and deletion, idempotent reuse',flush=True)
    if len(sys.argv[1:] or ['sambaadm-gss-ad-p11','sambaadm-gss-build-p10'])==2:
        import secrets
        members=['sambaadm-gss-ad-p11.sambaadm.test','sambaadm-gss-build-p10.sambaadm.test']
        enrollment='Aa1!'+secrets.token_hex(48)
        principal=None
        for index,container in enumerate(['sambaadm-gss-ad-p11','sambaadm-gss-build-p10']):
            value.update(node=container+'.sambaadm.test',action='ad-plan',gss={'controller':'dc1.sambaadm.test','dnsHost':'dc1.sambaadm.test','members':members,'rotate':True})
            value.pop('enrollmentSecret',None);value.pop('enroll',None)
            plan=execute(container,value)
            if principal:assert plan['principal']==principal
            principal=plan['principal']
            value.update(action='ad-apply',revision=plan['revision'],enrollmentSecret=enrollment,enroll=index>0)
            assert execute(container,value)['ready']
            mode=command(['docker','exec',container,'stat','-c','%a:%U','/etc/kea/ddns.keytab']).decode().strip()
            assert mode=='600:_kea',mode
        # Simulate D2 ExecStartPre on containers without systemd PID 1.
        for container in ['sambaadm-gss-ad-p11','sambaadm-gss-build-p10']:
            command(['docker','exec',container,'env','KRB5_CONFIG=/etc/kea/sambaadm-krb5.conf','KRB5CCNAME=FILE:/run/kea/sambaadm-ddns/ccache','runuser','-u','_kea','--','kinit','-k','-t','/etc/kea/ddns.keytab',principal])
        name='ha-'+secrets.token_hex(10)+'.sambaadm.test.'
        for index,container in enumerate(['sambaadm-gss-ad-p11','sambaadm-gss-build-p10']):
            script=f'server {dc_ip} 1053\nzone sambaadm.test.\n'
            script+=f'update add {name} 60 A 10.0.0.249\nsend\n' if index==0 else f'update delete {name}\nsend\n'
            command(['docker','exec','-i',container,'env','KRB5_CONFIG=/etc/kea/sambaadm-krb5.conf','KRB5CCNAME=FILE:/run/kea/sambaadm-ddns/ccache','runuser','-u','_kea','--','nsupdate','-g','-v'],script.encode())
        print('PASS HA shared identity: private AES keytabs on both ALT nodes; partner deletes signed DNS record',flush=True)

        foreign='foreign-'+secrets.token_hex(6)
        command(['docker','exec','-i',DC,'samba-tool','dns','add','127.0.0.1','sambaadm.test',foreign,'A','10.0.0.199','-U','Administrator'],(PASSWORD+'\n').encode())
        signed=f'server {dc_ip} 1053\nzone sambaadm.test.\nupdate delete {foreign}.sambaadm.test.\nsend\n'
        response=subprocess.run(['docker','exec','-i','sambaadm-gss-ad-p11','env','KRB5_CONFIG=/etc/kea/sambaadm-krb5.conf','KRB5CCNAME=FILE:/run/kea/sambaadm-ddns/ccache','runuser','-u','_kea','--','nsupdate','-g','-v'],input=signed.encode(),capture_output=True)
        assert response.returncode and b'REFUSED' in response.stderr, response.stderr.decode()
        answer=command(['docker','exec','sambaadm-gss-ad-p11','dig','+short','@'+dc_ip,'-p','1053',foreign+'.sambaadm.test.','A']).decode().strip()
        assert answer=='10.0.0.199',answer
        print('PASS foreign AD-owned DNS record remains protected; stale plans and missing zones rejected',flush=True)
