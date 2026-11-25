# Disposable CI fixture only. Production packages are installed by the wizard.
ARG BASE=sambaadm-rpm-builder:p10-amd64
FROM ${BASE}
ARG PANEL_RPM
COPY ${PANEL_RPM} /tmp/panel.rpm
# Use the repository already selected and verified by the disposable builder.
# The base ALT image also contains default FTP mirrors, unreachable on CI.
RUN test -s /etc/apt/sources.list.d/sambaadm-builder.list && printf '%s\n' 'Dir::Etc::sourcelist "/etc/apt/sources.list.d/sambaadm-builder.list";' 'Dir::Etc::sourceparts "/etc/apt/sambaadm-empty-sources";' > /etc/apt/apt.conf.d/99sambaadm-ci-source
RUN apt-get -o Acquire::http::Timeout=30 -o Acquire::Retries=1 update && apt-get -o Acquire::http::Timeout=30 -o Acquire::Retries=1 install -y systemd iproute2 samba-dc samba-common-tools python3-module-samba bind-utils openssl && rpm -Uvh /tmp/panel.rpm && rm /tmp/panel.rpm
