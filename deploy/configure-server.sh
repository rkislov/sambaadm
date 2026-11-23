#!/bin/bash
# Compatibility entry point for installation kits; the wizard is also in the RPM.
set -euo pipefail
if [[ -x /usr/sbin/sambaadm-setup ]]; then exec /usr/sbin/sambaadm-setup "$@";fi
exec bash "$(dirname "$0")/sambaadm-setup" "$@"
