#!/bin/sh
set -eu
# This fixed password is only for the disposable, loopback-only test domain.
: "${SAMBAADM_LAB_PASSWORD:=Lab-Only-Adm1n-Pass!}"
if [ ! -f /var/lib/samba/private/sam.ldb ]; then
    rm -f /etc/samba/smb.conf
    samba-tool domain provision --use-rfc2307 --realm=SAMBAADM.TEST \
        --domain=SAMBAADM --server-role=dc --dns-backend=SAMBA_INTERNAL \
        --adminpass="$SAMBAADM_LAB_PASSWORD" --host-name=dc1 \
        --option='dns forwarder = 1.1.1.1' \
        --option='vfs objects = dfs_samba4 acl_xattr xattr_tdb' \
        --option='xattr_tdb:file = /var/lib/samba/private/xattr.tdb' \
        --option='acl_xattr:ignore system acls = yes'
fi
cp /var/lib/samba/private/krb5.conf /etc/krb5.conf
printf 'nameserver 127.0.0.1\nsearch sambaadm.test\n' > /etc/resolv.conf
tls=/var/lib/samba/private/tls
mkdir -p "$tls"
openssl req -x509 -newkey rsa:2048 -nodes -days 7 \
  -keyout "$tls/key.pem" -out "$tls/cert.pem" \
  -subj '/CN=dc1.sambaadm.test' \
  -addext 'subjectAltName=DNS:dc1.sambaadm.test,DNS:dc1,IP:127.0.0.1' \
  -addext 'basicConstraints=critical,CA:TRUE' 2>/dev/null
chmod 600 "$tls/key.pem"
cp "$tls/cert.pem" "$tls/ca.pem"
cp "$tls/cert.pem" /usr/local/share/ca-certificates/sambaadm-lab.crt
update-ca-certificates >/dev/null

exec samba --foreground --no-process-group --debug-stdout
