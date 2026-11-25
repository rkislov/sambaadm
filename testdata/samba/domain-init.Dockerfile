# Disposable CI fixture only. Production packages are installed by the wizard.
ARG BASE=sambaadm-rpm-builder:p10-amd64
FROM ${BASE}
ARG PANEL_RPM
COPY ${PANEL_RPM} /tmp/panel.rpm
# Use the repository already selected and verified by the disposable builder.
# The base ALT image also contains default FTP mirrors, unreachable on CI.
RUN test -s /etc/apt/sources.list.d/sambaadm-builder.list && mkdir -p /etc/apt/sambaadm-ci-disabled && find /etc/apt/sources.list.d -maxdepth 1 -type f -name '*.list' ! -name sambaadm-builder.list -exec mv -t /etc/apt/sambaadm-ci-disabled {} + && printf '# Isolated CI repository\n' > /etc/apt/sources.list
RUN apt-get -o Acquire::http::Timeout=30 -o Acquire::Retries=1 update && apt-get -o Acquire::http::Timeout=30 -o Acquire::Retries=1 install -y systemd iproute2 samba-dc samba-common-tools python3-module-samba bind-utils openssl && rpm -Uvh /tmp/panel.rpm && rm /tmp/panel.rpm
