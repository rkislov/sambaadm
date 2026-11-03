#!/bin/sh
# Sourced by run-integration.sh after compose and architecture discovery.
if [ "${SAMBAADM_TWO_DC:-0}" != 1 ]; then
 echo 'SAMBAADM_HELPERS=1 requires SAMBAADM_TWO_DC=1' >&2
 exit 2
fi
CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -o "$work/sambaadm-helper" ./cmd/sambaadm-helper
compose cp "$work/sambaadm-helper" dc:/tmp/sambaadm-helper
compose cp "$work/sambaadm-helper" dc2:/tmp/sambaadm-helper
compose exec -T dc /tmp/sambaadm-helper keygen --private /tmp/helper-signing.key --public /tmp/helper-signing.pub
compose cp dc:/tmp/helper-signing.pub "$work/helper-signing.pub"
compose cp "$work/helper-signing.pub" dc2:/tmp/helper-signing.pub
for helper_service in dc dc2; do
 if [ "$helper_service" = dc ]; then helper_node=dc1.sambaadm.test; else helper_node=dc2.sambaadm.test; fi
 cat > "$work/helper.yaml" <<EOF
helper:
  node: $helper_node
  trusted_keys: [/tmp/helper-signing.pub]
  listen: 0.0.0.0:8444
  tls:
    cert: /var/lib/samba/private/tls/cert.pem
    key: /var/lib/samba/private/tls/key.pem
  sysvol_prefix: sambaadm.test/Policies
  backup_root: /tmp
  state_dir: /tmp/helper-state
  admx_root: /tmp
  password_file: /tmp/helper-password
ldap:
  uri: ldaps://127.0.0.1:636
  base_dn: DC=sambaadm,DC=test
  bind:
    user: Administrator@sambaadm.test
samba:
  shares_root: /srv/samba
audit:
  file: /tmp/helper-audit.log
EOF
 compose cp "$work/helper.yaml" "$helper_service:/tmp/helper.yaml"
 compose exec -T "$helper_service" sh -c 'chown root:root /tmp/helper.yaml /tmp/helper-signing.pub; chmod 600 /tmp/helper.yaml; umask 077; printf "%s\n" "$SAMBAADM_LAB_PASSWORD" > /tmp/helper-password; mkdir -p /srv/samba /tmp/helper-state'
 compose exec -d "$helper_service" sh -c 'exec /tmp/sambaadm-helper serve --config /tmp/helper.yaml >/tmp/helper-server.log 2>&1'
done

# Transport SSH key is separate from the request signing key. Pin the test
# server key by copying it from our own disposable container, not ssh-keyscan.
compose exec -T dc ssh-keygen -q -t ed25519 -N '' -f /tmp/helper-ssh
compose cp dc:/tmp/helper-ssh.pub "$work/helper-ssh.pub"
{ printf '%s ' 'restrict,command="/tmp/sambaadm-helper stdio --config /tmp/helper.yaml"'; cat "$work/helper-ssh.pub"; } > "$work/authorized_keys"
compose exec -T dc2 sh -c 'mkdir -p /root/.ssh /run/sshd; chmod 700 /root/.ssh'
compose cp "$work/authorized_keys" dc2:/root/.ssh/authorized_keys
compose exec -T dc2 sh -c 'chown root:root /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys; /usr/sbin/sshd -E /tmp/helper-sshd.log -o PermitRootLogin=prohibit-password -o PasswordAuthentication=no'
compose cp dc2:/etc/ssh/ssh_host_ed25519_key.pub "$work/ssh-host.pub"
{ printf '%s ' dc2.sambaadm.test; cat "$work/ssh-host.pub"; } > "$work/helper-known-hosts"
compose cp "$work/helper-known-hosts" dc:/tmp/helper-known-hosts
