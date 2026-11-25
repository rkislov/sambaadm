# Disposable CI fixture only. Production packages are installed by the wizard.
ARG BASE=sambaadm-rpm-builder:p10-amd64
FROM ${BASE}
ARG PANEL_RPM
COPY ${PANEL_RPM} /tmp/panel.rpm
RUN apt-get update && apt-get install -y systemd iproute2 samba-dc samba-common-tools python3-module-samba bind-utils openssl && rpm -Uvh /tmp/panel.rpm && rm /tmp/panel.rpm
