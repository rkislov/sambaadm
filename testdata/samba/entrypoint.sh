#!/bin/sh
set -eu
# This fixed password is only for the disposable, loopback-only test domain.
: "${SAMBAADM_LAB_PASSWORD:=Lab-Only-Adm1n-Pass!}"
if [ ! -f /var/lib/samba/private/sam.ldb ]; then
    rm -f /etc/samba/smb.conf
    if [ -n "${SAMBAADM_JOIN_DC:-}" ]; then
        upstream=$(getent ahostsv4 "$SAMBAADM_JOIN_DC" | awk 'NR==1 {print $1}')
        printf 'nameserver %s\nsearch sambaadm.test\n' "$upstream" > /etc/resolv.conf
        samba-tool domain join SAMBAADM.TEST DC --server="$SAMBAADM_JOIN_DC" \
          --username=Administrator --password="$SAMBAADM_LAB_PASSWORD" \
          --dns-backend=SAMBA_INTERNAL --option='netbios name = DC2' \
          --option='vfs objects = dfs_samba4 acl_xattr xattr_tdb' \
          --option='xattr_tdb:file = /var/lib/samba/private/xattr.tdb' \
          --option='acl_xattr:ignore system acls = yes'
    else
    samba-tool domain provision --use-rfc2307 --realm=SAMBAADM.TEST \
        --domain=SAMBAADM --server-role=dc --dns-backend=SAMBA_INTERNAL \
        --adminpass="$SAMBAADM_LAB_PASSWORD" --host-name=dc1 \
        --option='dns forwarder = 1.1.1.1' \
        --option='vfs objects = dfs_samba4 acl_xattr xattr_tdb' \
        --option='xattr_tdb:file = /var/lib/samba/private/xattr.tdb' \
        --option='acl_xattr:ignore system acls = yes'
    fi
fi
cp /var/lib/samba/private/krb5.conf /etc/krb5.conf
printf 'nameserver 127.0.0.1\nsearch sambaadm.test\n' > /etc/resolv.conf
tls=/var/lib/samba/private/tls
mkdir -p "$tls"
openssl req -x509 -newkey rsa:2048 -nodes -days 7 \
  -keyout "$tls/key.pem" -out "$tls/cert.pem" \
  -subj "/CN=$(hostname -s).sambaadm.test" \
  -addext "subjectAltName=DNS:$(hostname -s).sambaadm.test,DNS:$(hostname -s),IP:127.0.0.1" \
  -addext 'basicConstraints=critical,CA:TRUE' 2>/dev/null
chmod 600 "$tls/key.pem"
cp "$tls/cert.pem" "$tls/ca.pem"
cp "$tls/cert.pem" /usr/local/share/ca-certificates/sambaadm-lab.crt
update-ca-certificates >/dev/null

if [ -n "${SAMBAADM_RPC_PORT_RANGE:-}" ]; then
    exec samba --foreground --no-process-group --debug-stdout --option="rpc server dynamic port range = $SAMBAADM_RPC_PORT_RANGE"
fi
exec samba --foreground --no-process-group --debug-stdout
