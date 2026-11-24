Name: caja-smb-previous-versions
Version: 0.1.1
Release: alt1
Summary: Previous versions of SMB files and directories in Caja
License: Apache-2.0
Group: File tools
URL: https://github.com/rkislov/sambaadm
BuildArch: noarch
Source0: sambaadm_previous_versions.py
Source1: README.md
Source2: LICENSE

Requires: mate-file-manager
Requires: python3-module-caja
Requires: python3-module-pygobject3
Requires: gvfs-backend-smb
Requires: samba-client
AutoReqProv: no

%description
Adds a Previous Versions action to Caja for SMB files and directories. Lists
shadow copies using the current Kerberos session and opens or copies older
versions through GVfs. An existing file is never overwritten by the extension.

%prep

%build

%install
install -Dpm644 %SOURCE0 %buildroot%_datadir/caja-python/extensions/sambaadm_previous_versions.py
install -Dpm644 %SOURCE1 %buildroot%_docdir/%name/README.md
install -Dpm644 %SOURCE2 %buildroot%_docdir/%name/LICENSE

%files
%dir %_datadir/caja-python/extensions
%_datadir/caja-python/extensions/sambaadm_previous_versions.py
%_docdir/%name

%changelog
* Thu Nov 19 2026 SambaADM contributors <https://github.com/rkislov/sambaadm> 0.1.1-alt1
- Detect SMB snapshot query failures for Windows VSS and Samba ZFS/LVM shares.
- Document automatic protocol selection and server prerequisites.

* Mon Nov 16 2026 SambaADM contributors <https://github.com/rkislov/sambaadm> 0.1.0-alt1
- Package the SMB Previous Versions extension for Caja.
