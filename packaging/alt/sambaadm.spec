# Binary distribution package built from a verified static Go executable.
# Override package_version / package_release / payload_dir via build-rpm.sh.
%define debug_package %{nil}
%define __find_requires %{nil}
%define __find_provides %{nil}
%define _unpackaged_files_terminate_build 1

Name: sambaadm
Version: %{package_version}
Release: %{package_release}
Summary: Samba AD administration with CLI, Web UI and REST API
License: Apache-2.0
Group: System/Servers
URL: https://github.com/rkislov/sambaadm
ExclusiveArch: x86_64 aarch64
Requires: bash coreutils tar util-linux systemd
Requires(pre): shadow-utils
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd
AutoReqProv: no

%description
Single static Go executable for Samba AD administration. Includes a systemd
service and a local RPM update/rollback helper. Local Samba and CUPS tools
are optional and must be installed separately for file-server features.

%prep

%build

%install
mkdir -p %buildroot/usr/bin %buildroot/usr/sbin %buildroot/lib/systemd/system
mkdir -p %buildroot/etc/sambaadm %buildroot/usr/share/doc/sambaadm
mkdir -p %buildroot/var/lib/sambaadm %buildroot/var/log/sambaadm
mkdir -p %buildroot/var/lib/sambaadm-packages %buildroot/var/cache/sambaadm-packages
install -m755 %{payload_dir}/sambaadm %buildroot/usr/bin/sambaadm
install -m755 %{payload_dir}/sambaadm-package %buildroot/usr/sbin/sambaadm-package
install -m644 %{payload_dir}/sambaadm.service %buildroot/lib/systemd/system/sambaadm.service
install -m640 %{payload_dir}/config.yaml %buildroot/etc/sambaadm/config.yaml
install -m600 %{payload_dir}/env %buildroot/etc/sambaadm/env
install -m644 %{payload_dir}/LICENSE %{payload_dir}/NOTICE %{payload_dir}/alt-install.md %buildroot/usr/share/doc/sambaadm/

%pre
set -e
getent group sambaadm >/dev/null || groupadd -r sambaadm
getent passwd sambaadm >/dev/null || useradd -r -g sambaadm -d /var/lib/sambaadm -s /bin/false sambaadm

%post
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || :
fi
# Do not enable, start or restart here: the transactional helper owns activation.

%preun
if [ "$1" -eq 0 ] && [ -d /run/systemd/system ]; then
    systemctl stop sambaadm.service || :
    systemctl disable sambaadm.service || :
fi

%postun
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || :
fi

%files
%defattr(-,root,root)
/usr/bin/sambaadm
/usr/sbin/sambaadm-package
/lib/systemd/system/sambaadm.service
%dir %attr(0750,root,sambaadm) /etc/sambaadm
%config(noreplace) %attr(0640,root,sambaadm) /etc/sambaadm/config.yaml
%config(noreplace) %attr(0600,root,root) /etc/sambaadm/env
%dir %attr(0750,sambaadm,sambaadm) /var/lib/sambaadm
%dir %attr(0750,sambaadm,sambaadm) /var/log/sambaadm
%dir %attr(0700,root,root) /var/lib/sambaadm-packages
%dir %attr(0700,root,root) /var/cache/sambaadm-packages
/usr/share/doc/sambaadm
