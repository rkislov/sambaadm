FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    samba-ad-dc samba-ad-provision samba-dsdb-modules samba-vfs-modules smbclient \
    ldap-utils krb5-user acl attr ca-certificates openssl procps \
    && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /usr/local/sbin/sambaadm-lab
RUN chmod 755 /usr/local/sbin/sambaadm-lab
ENTRYPOINT ["/usr/local/sbin/sambaadm-lab"]
