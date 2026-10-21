#!/bin/sh
# Persistent, loopback-only lab for the native macOS client. No host trust changes.
set -eu
cd "$(dirname "$0")/../.."
export SAMBAADM_LDAP_PORT=1389 SAMBAADM_LDAPS_PORT=1636
docker compose -p sambaadm-lab -f testdata/docker-compose.yml -f testdata/docker-compose.mac.yml up -d --build --wait
mkdir -p bin/lab
docker compose -p sambaadm-lab -f testdata/docker-compose.yml -f testdata/docker-compose.mac.yml cp dc:/var/lib/samba/private/tls/cert.pem bin/lab/ca.pem
python3 - <<'PY'
import json,pathlib
root=pathlib.Path.cwd(); lab=root/'bin/lab'
config={'server':{'listen':'127.0.0.1:8081'},'ldap':{'uri':'ldaps://127.0.0.1:1636','ca_cert':str(lab/'ca.pem'),'base_dn':'DC=sambaadm,DC=test','bind':{'type':'simple','user':'Administrator@sambaadm.test','password_env':'SAMBAADM_PASSWORD'}},'auth':{'roles':{'admins':['CN=Domain Admins,CN=Users,DC=sambaadm,DC=test']}},'gpo':{'smb_port':1445,'sync_mode':'both','editor_enabled':True,'admx_path':''},'audit':{'file':str(lab/'audit.log')},'logging':{'level':'debug'}}
(lab/'config.yaml').write_text(json.dumps(config,indent=2))
PY
make build
cp bin/sambaadm bin/sambaadm-lab
export SAMBAADM_PASSWORD='Lab-Only-Adm1n-Pass!'
exec ./bin/sambaadm-lab --config bin/lab/config.yaml serve --debug
