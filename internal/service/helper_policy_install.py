"""Build one SYSVOL policy locally, with SMB authorization and cutover."""
import base64
import contextlib
import errno
import io
import json
import os
from pathlib import Path
import re
import shutil
import signal
import sys
import tempfile

import ldb
from samba import param as adparam
from samba.auth import session_info_set_unix, system_session
from samba.credentials import Credentials, DONT_USE_KERBEROS, SMB_SIGNING_REQUIRED
from samba.dcerpc import security
from samba.ndr import ndr_unpack
from samba.samdb import SamDB
from samba.samba3 import libsmb_samba_internal as libsmb, param, smbd


ACL_INFO = security.SECINFO_OWNER | security.SECINFO_GROUP | security.SECINFO_DACL
FILE_ADD_SUBDIRECTORY = 0x0004
FILE_DIRECTORY = 0x00000001
FILE_NON_DIRECTORY = 0x00000040
FILE_OPEN_REPARSE_POINT = 0x00200000
POSIX_DEFAULT_ACL = "system.posix_acl_default"
POSIX_ACCESS_ACL = "system.posix_acl_access"


def check_directory_access(connection, relative, access):
    handle = connection.create(relative, DesiredAccess=access, ShareAccess=7,
                               CreateDisposition=1, CreateOptions=FILE_DIRECTORY | FILE_OPEN_REPARSE_POINT)
    connection.close(handle)


def check_staged_policy_readable(connection, stage_relative, paths, files):
    # Reading a descriptor as root does not test whether the domain session can
    # enumerate the directory or open its files through SYSVOL.
    for name in ("", *paths):
        relative = stage_relative + "\\" + name.replace("/", "\\") if name else stage_relative
        try:
            if name not in files:
                check_directory_access(connection, relative, security.SEC_GENERIC_READ)
                connection.list(relative)
            else:
                handle = connection.create(relative, DesiredAccess=security.SEC_GENERIC_READ,
                                           ShareAccess=7, CreateDisposition=1,
                                           CreateOptions=FILE_NON_DIRECTORY | FILE_OPEN_REPARSE_POINT)
                connection.close(handle)
        except Exception as error:
            raise ValueError(f"SYSVOL read verification before replacement failed at {name or '.'}: {error}") from error


def smb_connect(request, lp):
    credentials = Credentials()
    credentials.guess(lp)
    credentials.parse_string(request["User"])
    credentials.set_password(request["Secret"])
    credentials.set_kerberos_state(DONT_USE_KERBEROS)
    credentials.set_smb_signing(SMB_SIGNING_REQUIRED)
    return libsmb.Conn("127.0.0.1", "SYSVOL", lp, credentials, force_smb1=False)


def policy_paths(files, permissions):
    if len(permissions) > 10000 or len(files) > 10000 or files.keys() - permissions.keys():
        raise ValueError("invalid policy snapshot entry list")
    seen = set()
    for name in permissions:
        parts = name.split("/")
        if (len(parts) > 33 or any(p in ("", ".", "..") or p.endswith((".", " ")) for p in parts)
                or any(c in name for c in "\\:\x00") or name.casefold() in seen):
            raise ValueError("invalid or duplicate policy snapshot path")
        if len(parts) > 1:
            parent = "/".join(parts[:-1])
            if parent not in permissions or parent in files:
                raise ValueError("policy snapshot is missing a parent directory")
        seen.add(name.casefold())
    if sum(len(data or "") for data in files.values()) > (64 << 20) * 4 // 3 + 40000:
        raise ValueError("policy snapshot exceeds file limit")
    if "gpt.ini" not in {name.casefold() for name in files}:
        raise ValueError("policy snapshot is missing GPT.INI")


def set_acl(path, encoded, session):
    descriptor = ndr_unpack(security.descriptor, base64.b64decode(encoded, validate=True))
    smbd.set_nt_acl(str(path), ACL_INFO, descriptor, session, service="sysvol")
    installed = smbd.get_nt_acl(str(path), ACL_INFO, session, service="sysvol")
    if installed.as_sddl() != descriptor.as_sddl():
        raise ValueError("destination Samba did not preserve the policy ACL")


def inherited_posix_acl(path):
    try:
        return os.getxattr(path, POSIX_DEFAULT_ACL)
    except OSError as error:
        if error.errno not in (errno.ENODATA, errno.EOPNOTSUPP):
            raise
        return None


def install(request):
    domain, container, guid = request["Target"].split("/")
    if (not re.fullmatch(r"[a-zA-Z0-9.-]+", domain) or domain in (".", "..")
            or container != "Policies"
            or not re.fullmatch(r"\{[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}", guid)):
        raise ValueError("target must be one domain GPO directory")
    files, permissions = request["Files"], request["Permissions"]
    policy_paths(files, permissions)

    lp = adparam.LoadParm()
    lp.load(request["Config"])
    session = system_session(lp)
    sam = SamDB(lp=lp, session_info=session)
    dn = "CN=" + guid + ",CN=Policies,CN=System," + str(sam.domain_dn())
    rows = sam.search(base=dn, scope=ldb.SCOPE_BASE, expression="(objectClass=groupPolicyContainer)",
                      attrs=["gPCFileSysPath"])
    if (len(rows) != 1 or "gPCFileSysPath" not in rows[0]
            or str(rows[0]["gPCFileSysPath"][0], "utf-8").replace("\\", "/").casefold().split("/")[-4:]
            != ["sysvol", domain.casefold(), "policies", guid.casefold()]):
        raise ValueError("target is not the SYSVOL path of a local AD policy")

    local_lp = param.get_context()
    local_lp.load(request["Config"])
    sysvol = Path(local_lp.get("path", "sysvol")).resolve(strict=True)
    parent = sysvol / domain / container
    if parent.resolve(strict=True) != parent or not parent.is_dir():
        raise ValueError("SYSVOL policy parent must be a real directory")
    target = parent / guid
    if target.is_symlink() or (target.exists() and not target.is_dir()):
        raise ValueError("SYSVOL policy target must be a real directory")

    smb_lp = adparam.LoadParm()
    smb_lp.load(request["Config"])
    smb_lp.set("client min protocol", "SMB2_02")
    if request["Port"] not in (0, 445):
        raise ValueError("local policy staging requires SMB on port 445")
    connection = smb_connect(request, smb_lp)
    parent_relative = domain + "\\" + container
    target_relative = parent_relative + "\\" + guid
    exists = target.is_dir()
    original = os.lstat(target) if exists else None
    try:
        check_directory_access(connection, parent_relative, FILE_ADD_SUBDIRECTORY)
    except Exception as error:
        raise ValueError("the domain session lacks rights to replace this SYSVOL policy (create in Policies)") from error
    if exists:
        try:
            check_directory_access(connection, target_relative,
                                   FILE_ADD_SUBDIRECTORY | security.SEC_STD_READ_CONTROL | security.SEC_STD_DELETE
                                   | security.SEC_STD_WRITE_DAC | security.SEC_STD_WRITE_OWNER)
        except Exception as error:
            raise ValueError("the domain session lacks rights to replace this SYSVOL policy (existing policy directory)") from error

    session_info_set_unix(session, "root", 0, 0, lp)
    stage = Path(tempfile.mkdtemp(prefix=".sambaadm-policy-", dir=parent))
    stage_relative = parent_relative + "\\" + stage.name
    old = parent / (stage.name + ".old")
    old_relative = stage_relative + ".old"
    try:
        default_acl = inherited_posix_acl(stage)
        paths = sorted(permissions, key=lambda name: name.count("/"))
        total = 0
        for name in paths:
            path = stage / name
            if name not in files:
                # Linux intersects the inherited ACL mask with the creation mode.
                path.mkdir(mode=0o770 if default_acl is not None else 0o700)
                continue
            data = base64.b64decode(files[name] or "", validate=True)
            total += len(data)
            if total > 64 << 20:
                raise ValueError("policy snapshot exceeds file limit")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                         0o660 if default_acl is not None else 0o666)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
        for name in reversed(paths):
            set_acl(stage / name, permissions[name], session)
        if default_acl is not None:
            # mkdtemp creates the root with 0700, masking all named ACL entries.
            # Keep it private while populating it, then restore the inherited
            # access ACL before Samba applies the policy's NT descriptor.
            os.setxattr(stage, POSIX_ACCESS_ACL, default_acl)
            stage.chmod(stage.stat().st_mode & 0o770)
        set_acl(stage, request["ACL"], session)
        check_staged_policy_readable(connection, stage_relative, paths, files)
        # Finish the SMB cutover or its rollback if the caller disconnects.
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
        try:
            if exists:
                current = os.lstat(target)
                if (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino):
                    raise ValueError("SYSVOL policy changed while staging; retry")
                connection.rename(target_relative, old_relative)
            try:
                connection.rename(stage_relative, target_relative)
            except Exception:
                if exists:
                    try:
                        connection.rename(old_relative, target_relative)
                    except Exception as error:
                        raise ValueError("SYSVOL cutover and rollback failed; original retained as " + old.name) from error
                raise
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        if exists:
            shutil.rmtree(old)
    finally:
        if stage.is_dir() and not stage.is_symlink():
            shutil.rmtree(stage)


def cancel_install(_signal, _frame):
    raise InterruptedError("SYSVOL policy install interrupted; verify the destination before retrying")


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, cancel_install)
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            install(json.load(sys.stdin))
        print(json.dumps({"OK": True}))
    except Exception as error:
        print(json.dumps({"Error": str(error)}))
        sys.exit(1)
