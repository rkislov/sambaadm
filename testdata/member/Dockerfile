ARG ALT_BRANCH=p11
FROM alt:${ALT_BRANCH}
RUN apt-get update && apt-get install -y samba samba-common-tools samba-winbind samba-winbind-clients samba-client python3 python3-module-samba krb5-kinit bind-utils acl attr sssd sssd-ad sssd-client sssd-tools sssd-winbind-idmap iproute2 && apt-get clean
