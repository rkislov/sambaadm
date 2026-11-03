#!/usr/bin/python3
"""Embedded RODC operation run only by sambaadm-helper on that controller."""
import contextlib
import io
import json
import os
import re
import subprocess
import sys
import uuid


def main():
    if len(sys.argv) != 1 or os.geteuid() != 0:
        raise ValueError("root helper with no arguments required")
    request = json.loads(sys.stdin.buffer.read(16385))
    if set(request) != {"Controller", "Source", "DSAGUID", "Account"}:
        raise ValueError("invalid request")
    for key in ("Controller", "Source"):
        if not isinstance(request[key], str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}", request[key]):
            raise ValueError("invalid controller")
    if request["Controller"].lower() == request["Source"].lower():
        raise ValueError("source must be a writable peer")
    # Imports and all Samba diagnostic output stay away from stdout.
    from samba import param
    from samba.auth import system_session
    from samba.samdb import SamDB
    import ldb
    lp = param.LoadParm()
    lp.load_default()
    local = SamDB(session_info=system_session(), lp=lp)
    if not local.am_rodc() or uuid.UUID(str(local.get_ntds_GUID())) != uuid.UUID(request["DSAGUID"]):
        raise ValueError("RODC destination identity mismatch")
    root = local.search(base="", scope=ldb.SCOPE_BASE, attrs=["dsServiceName"])[0]
    own_ntds = local.search(base=str(root["dsServiceName"][0]), scope=ldb.SCOPE_BASE, attrs=[])[0]
    server_dn = own_ntds.dn.parent()
    server = local.search(base=server_dn, scope=ldb.SCOPE_BASE, attrs=["dNSHostName"])[0]
    if str(server["dNSHostName"][0]).lower() != request["Controller"].lower():
        raise ValueError("RODC hostname mismatch")
    account = ldb.Dn(local, request["Account"])
    if not account.is_valid() or not account.is_child_of(ldb.Dn(local, local.domain_dn())):
        raise ValueError("account must be in the local domain")
    found = local.search(base=account, scope=ldb.SCOPE_BASE, expression="(objectClass=user)", attrs=[])
    if len(found) != 1:
        raise ValueError("user or computer must already be replicated to the RODC")
    # fallback_machine=True in Samba rodc preload uses this RODC's machine
    # credentials. RWDC enforces this RODC's PRP; no administrator password.
    completed = subprocess.run(
        ["/usr/bin/samba-tool", "rodc", "preload", "--server=" + request["Source"], "--", str(account)],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        timeout=35, check=False,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
    )
    if completed.returncode != 0:
        raise ValueError("Samba preload failed")
    return {"status": "preloaded", "controller": request["Controller"], "account": request["Account"]}


if __name__ == "__main__":
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            response = main()
        print(json.dumps(response))
    except Exception:
        print('{"status":"unconfirmed"}')
        sys.exit(1)
