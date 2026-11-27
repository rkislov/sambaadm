#!/bin/sh
set -eu
mkdir -p /run/tgtd /var/lib/tgt
truncate -s 2G /var/lib/tgt/lun.img
tgtd -f &
pid=$!
trap 'kill "$pid" 2>/dev/null || :; wait "$pid" || :' EXIT
for i in $(seq 1 50); do
 if tgtadm --lld iscsi --mode system --op show >/dev/null 2>&1; then break;fi
 sleep .1
done
tgtadm --lld iscsi --op new --mode target --tid 1 --targetname iqn.2026-11.test.sambaadm:ha
tgtadm --lld iscsi --op new --mode logicalunit --tid 1 --lun 1 --backing-store /var/lib/tgt/lun.img
tgtadm --lld iscsi --op update --mode logicalunit --tid 1 --lun 1 --params scsi_sn=SAMBAADM-HALUN1
tgtadm --lld iscsi --op bind --mode target --tid 1 --initiator-address ALL
wait "$pid"
