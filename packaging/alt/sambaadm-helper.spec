%define debug_package %{nil}
%define __find_requires %{nil}
%define __find_provides %{nil}
%define _unpackaged_files_terminate_build 1
Name: sambaadm-helper
Version: %{package_version}
Release: %{package_release}
Summary: Key-authenticated host agent for sambaadm
License: Apache-2.0
Group: System/Servers
URL: https://github.com/rkislov/sambaadm
ExclusiveArch: x86_64 aarch64
Requires: coreutils systemd
Requires(pre): shadow-utils
AutoReqProv: no

%description
Separate host agent for Samba file, SYSVOL, ACL and operating-system operations.
Accepts signed requests over SSH stdio or HTTPS. The private signing key stays
on the sambaadm management server. Samba/Python/CUPS tools are feature-specific
dependencies installed on the managed server. LDAP/DNS administration remains
on the management server.

%prep
%build
%install
mkdir -p %buildroot/usr/bin %buildroot/lib/systemd/system
mkdir -p %buildroot/etc/sambaadm-helper %buildroot/var/lib/sambaadm-helper
mkdir -p %buildroot/var/lib/sambaadm-helper/backups
mkdir -p %buildroot/var/log/sambaadm-helper %buildroot/usr/share/doc/sambaadm-helper
install -m755 %{payload_dir}/sambaadm-helper %buildroot/usr/bin/sambaadm-helper
install -m644 %{payload_dir}/sambaadm-helper.service %buildroot/lib/systemd/system/sambaadm-helper.service
install -m600 %{payload_dir}/helper-config.yaml %buildroot/etc/sambaadm-helper/config.yaml
install -m644 %{payload_dir}/helper.md %{payload_dir}/LICENSE %{payload_dir}/NOTICE %buildroot/usr/share/doc/sambaadm-helper/

%pre
getent group sambaadm-agent >/dev/null || groupadd -r sambaadm-agent
getent passwd sambaadm-agent >/dev/null || useradd -r -g sambaadm-agent -d /var/lib/sambaadm-agent -s /bin/sh sambaadm-agent

%post
if [ -d /run/systemd/system ]; then systemctl daemon-reload || :; fi
# No keys are trusted and no network service is started automatically.

%preun
if [ "$1" -eq 0 ] && [ -d /run/systemd/system ]; then
 systemctl stop sambaadm-helper.service || :
 systemctl disable sambaadm-helper.service || :
fi
%postun
if [ -d /run/systemd/system ]; then systemctl daemon-reload || :; fi

%files
%defattr(-,root,root)
/usr/bin/sambaadm-helper
/lib/systemd/system/sambaadm-helper.service
%dir %attr(0700,root,root) /etc/sambaadm-helper
%config(noreplace) %attr(0600,root,root) /etc/sambaadm-helper/config.yaml
%dir %attr(0700,root,root) /var/lib/sambaadm-helper
%dir %attr(0700,root,root) /var/lib/sambaadm-helper/backups
%dir %attr(0700,root,root) /var/log/sambaadm-helper
/usr/share/doc/sambaadm-helper
