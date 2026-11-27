#!/bin/sh
set -eu
groupadd -g 1000 cajaqa
useradd -u 1000 -g cajaqa -m -s /bin/bash cajaqa
install -d -m 0755 /srv/sambaadm-caja-test
printf 'sambaadm-caja-only\n' > /srv/sambaadm-caja-test/.disposable-caja-lab
install -d -m 0700 /tmp/caja-runtime
chown cajaqa:cajaqa /tmp/caja-runtime
install -d -m 0755 /tmp/caja-artifacts
chown cajaqa:cajaqa /tmp/caja-artifacts
for name in mode-r-x mode-r-- acl-mask-no-x; do
 mkdir -p "/srv/sambaadm-caja-test/$name/nested"
 printf 'directory traversal verified\n' > "/srv/sambaadm-caja-test/$name/nested/inside.txt"
 chmod 0755 "/srv/sambaadm-caja-test/$name/nested"
 chmod 0644 "/srv/sambaadm-caja-test/$name/nested/inside.txt"
 chown root:cajaqa "/srv/sambaadm-caja-test/$name"
done
chmod 0750 /srv/sambaadm-caja-test/mode-r-x
chmod 0740 /srv/sambaadm-caja-test/mode-r--
chown root:root /srv/sambaadm-caja-test/acl-mask-no-x
chmod 0700 /srv/sambaadm-caja-test/acl-mask-no-x
setfacl -m g:1000:r-x,m::r-- /srv/sambaadm-caja-test/acl-mask-no-x
printf 'ordinary file needs read, not execute\n' > /srv/sambaadm-caja-test/file-no-exec.txt
chmod 0644 /srv/sambaadm-caja-test/file-no-exec.txt
cat > /tmp/caja-smb.conf <<'CONFIG'
[global]
 workgroup = WORKGROUP
 security = user
 server role = standalone server
 interfaces = 127.0.0.1
 bind interfaces only = yes
 smb ports = 445
 map to guest = never
 load printers = no
 disable spoolss = yes
 log file = /tmp/caja-smbd.log
[acl-test]
 path = /srv/sambaadm-caja-test
 read only = no
 valid users = cajaqa
 inherit acls = no
 create mask = 0666
 directory mask = 0777
CONFIG
printf '%s\n%s\n' 'Lab-Caja-Only1!' 'Lab-Caja-Only1!' | smbpasswd -s -c /tmp/caja-smb.conf -a cajaqa
smbd --daemon --configfile=/tmp/caja-smb.conf
Xvfb :99 -screen 0 1280x800x24 -ac -nolisten tcp >/tmp/caja-xvfb.log 2>&1 &
getfacl -p -n /srv/sambaadm-caja-test/* > /tmp/caja-artifacts/before-acl.txt
rpm -q mate-file-manager gvfs gvfs-backend-smb samba samba-client > /tmp/caja-artifacts/versions.txt
