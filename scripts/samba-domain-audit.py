#!/usr/bin/env python3
"""Read-only, local Samba AD DC audit for ALT p10. Python standard library only."""
import argparse
import base64
import datetime as dt
import hashlib
import html
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time

VERSION = "1.0.0"
SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "LANG": "C", "TZ": "UTC"}


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def ldif_records(text):
    """Decode LDIF continuations and base64; retain multiple attribute values."""
    lines = []
    for line in text.splitlines():
        if line.startswith(" ") and lines:
            lines[-1] += line[1:]
        else:
            lines.append(line)
    records, record = [], {}
    for line in lines + [""]:
        if not line:
            if "dn" in record:
                records.append(record)
            record = {}
        elif not line.startswith("#") and ":" in line:
            key, value = line.split(":", 1)
            if value.startswith(":"):
                try:
                    value = base64.b64decode(value[1:].strip(), validate=True).decode("utf-8")
                except (ValueError, UnicodeError):
                    continue
            record.setdefault(key.lower(), []).append(value.lstrip())
    return records


def dns_name(value):
    value = value.strip().rstrip(".").lower()
    if not value or len(value) > 253:
        raise ValueError("DNS name is empty or too long")
    labels = value.split(".")
    if len(labels) < 2 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in labels):
        raise ValueError("Expected a DNS domain/FQDN (ASCII or IDNA form), not an IP or DN")
    if all(x.isdigit() for x in labels):
        raise ValueError("Expected a DNS name, not an IP address")
    return value


def interpret(kind, execution, rc, text):
    """Status concerns only the explicitly named check, never the whole domain."""
    if execution != "completed":
        return "unknown", "Execution: " + execution
    clean = re.sub(r"\x1b\[[0-9;]*m", "", text)
    if kind == "dbcheck":
        match = re.search(r"Checked (\d+) objects \((\d+) errors\)", clean)
        if match:
            count = int(match[2])
            return ("error" if count or rc else "ok"), "{} objects; {} dbcheck errors; exit {}".format(match[1], count, rc)
        return "unknown", "dbcheck did not return its final object/error count"
    if kind == "drs":
        inbound = clean.split("==== INBOUND NEIGHBORS ====", 1)
        if len(inbound) < 2 or rc:
            return "unknown", "DRS inbound information could not be read"
        inbound = inbound[1].split("==== OUTBOUND NEIGHBORS ====", 1)[0]
        failures = [int(x) for x in re.findall(r"(\d+) consecutive failure", inbound)]
        if not failures:
            return "unknown", "No inbound neighbors; topology and replication health need separate verification"
        if any(failures) or re.search(r"last attempt[^\n]*(?:failed|unsuccessful)", inbound, re.I):
            return "error", "Inbound replication has failures"
        if "NTTIME(0)" in inbound:
            return "unknown", "An inbound partner has no confirmed success timestamp"
        return "ok", "{} inbound observations without reported failures; compare success times with site schedules".format(len(failures))
    if kind == "failed_units":
        if rc:
            return "unknown", "Cannot read systemd failed units"
        return ("warning", "Failed systemd units present") if clean.strip() else ("ok", "No failed systemd units")
    if kind == "service":
        if "LoadState=not-found" in clean or rc:
            return "unknown", "Unit missing or unavailable"
        if re.search(r"^ActiveState=active$", clean, re.M):
            return "ok", "Required Samba service is active"
        return "error", "Required Samba service is not active"
    if kind == "time":
        match = re.search(r"Leap status\s*:\s*(.+)", clean)
        if rc or not match:
            return "unknown", "chrony synchronization could not be determined"
        if match[1].strip() != "Normal":
            return "warning", "Leap status: " + match[1].strip()
        return "ok", "chrony reports Normal; external UTC accuracy and DC-to-DC skew not measured"
    if kind == "dns":
        status = re.search(r"status: ([A-Z]+)", clean)
        answer = re.search(r"^\S+\s+\d+\s+IN\s+(?:SRV|A)\s+", clean, re.M)
        if rc or not status:
            return "unknown", "DNS response unavailable"
        if status[1] != "NOERROR" or not answer:
            return "error", "DNS status {} or expected answer missing".format(status[1])
        return "ok", "DNS answer received; this does not establish availability of its targets"
    if kind == "level":
        if "Domain function level is higher" in clean:
            return "error", "Domain level exceeds a reported DC level; compare NTDS attributes"
        return ("observed", "Functional levels read") if rc == 0 else ("unknown", "Cannot read functional levels")
    if kind == "sysvol_acl":
        return ("ok", "Local SYSVOL ACL check passed; file replication and client GPO application not tested") if rc == 0 else ("error", "SYSVOL ACL check failed; inspect raw output")
    return ("observed", "Data collected; contents require interpretation") if rc == 0 else ("unknown", "Command failed with exit {}".format(rc))


class Audit:
    def __init__(self, output, timeout=120, limit=8 * 1024 * 1024):
        self.output, self.timeout, self.limit = Path(output), timeout, limit
        self.checks = []
        (self.output / "raw").mkdir(mode=0o700)

    def command(self, key, argv, kind="observation", privileged=False, enabled=True):
        begin, started = now(), time.monotonic()
        record = {"id": key, "argv": argv, "kind": kind, "started": begin, "execution": "completed", "returncode": None, "raw": "raw/" + key + ".txt", "truncated": False}
        data, proc = bytearray(), None
        if not enabled:
            record["execution"] = "skipped"
        elif privileged and os.geteuid() != 0:
            record["execution"] = "permission-required"
        elif not shutil.which(argv[0], path=SAFE_ENV["PATH"]):
            record["execution"] = "missing-command"
        else:
            try:
                proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=SAFE_ENV, start_new_session=True)
                selector = selectors.DefaultSelector()
                selector.register(proc.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    if time.monotonic() - started >= self.timeout:
                        record["execution"] = "timeout"
                        break
                    for event, _ in selector.select(timeout=0.1):
                        block = os.read(event.fileobj.fileno(), 65536)
                        if not block:
                            selector.unregister(event.fileobj)
                            break
                        available = self.limit - len(data)
                        data.extend(block[:available])
                        if len(block) > available:
                            record["execution"], record["truncated"] = "output-limit", True
                            break
                    if record["execution"] != "completed":
                        break
                selector.close()
                if record["execution"] != "completed":
                    os.killpg(proc.pid, signal.SIGKILL)
                # A descendant can close stdout while the original command remains alive.
                remaining = max(0.1, self.timeout - (time.monotonic() - started))
                try:
                    record["returncode"] = proc.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    record["execution"] = "timeout"
                    os.killpg(proc.pid, signal.SIGKILL)
                    record["returncode"] = proc.wait()
            except (OSError, ValueError) as exc:
                record["execution"] = "launch-error"
                data.extend(str(exc).encode())
            finally:
                if proc is not None and proc.stdout is not None:
                    proc.stdout.close()
        text = data.decode("utf-8", errors="replace")
        (self.output / record["raw"]).write_text(text, encoding="utf-8")
        record["status"], record["detail"] = interpret(kind, record["execution"], record["returncode"], text)
        if record["execution"] == "skipped":
            record["status"], record["detail"] = "skipped", "Explicitly skipped by operator or discovery unavailable"
        record.update(finished=now(), durationSeconds=round(time.monotonic() - started, 3), bytes=len(data))
        self.checks.append(record)
        print("{}: {} — {}".format(key, record["status"], record["detail"]), flush=True)
        return text

    def parameter(self, name, conf):
        key = "config_" + name.replace(" ", "_")
        result = self.command(key, ["testparm", "-s", "--parameter-name=" + name, str(conf)])
        if self.checks[-1]["returncode"] != 0:
            return ""
        # testparm diagnostics are merged with stdout; the parameter is its last line.
        lines = [line.strip() for line in result.splitlines() if line.strip()]
        return lines[-1] if lines else ""


def sysvol_manifest(root, output, max_files=20000, max_bytes=256 * 1024 * 1024, timeout=120):
    result = {"root": str(root), "started": now(), "complete": True, "files": [], "issues": []}
    start, used = time.monotonic(), 0
    def problem(message):
        result["complete"] = False
        if len(result["issues"]) < 100:
            result["issues"].append(message)
    if root is None or not root.is_dir() or root.is_symlink():
        problem("SYSVOL path unavailable or is a symbolic link")
    else:
        stop = False
        for folder, dirs, names in os.walk(str(root), followlinks=False, onerror=lambda e: problem(str(e))):
            for name in sorted(names + dirs):
                path = Path(folder) / name
                relative = str(path.relative_to(root))
                try:
                    info = path.lstat()
                    if stat.S_ISLNK(info.st_mode):
                        problem("Symlink not followed: " + relative)
                        continue
                    if not stat.S_ISREG(info.st_mode):
                        continue
                    if len(result["files"]) >= max_files or used + info.st_size > max_bytes or time.monotonic() - start > timeout:
                        problem("Manifest resource limit reached")
                        stop = True
                        break
                    digest = hashlib.sha256()
                    with os.fdopen(os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
                        initial = os.fstat(stream.fileno())
                        if not stat.S_ISREG(initial.st_mode) or (initial.st_ino, initial.st_dev) != (info.st_ino, info.st_dev):
                            raise OSError("File changed while opening")
                        read = 0
                        while True:
                            if used >= max_bytes or time.monotonic() - start > timeout:
                                raise OSError("Manifest read budget exhausted")
                            block = stream.read(min(65536, max_bytes - used))
                            if not block:
                                break
                            used += len(block); read += len(block); digest.update(block)
                        final = os.fstat(stream.fileno())
                    if (initial.st_size, initial.st_mtime_ns) != (final.st_size, final.st_mtime_ns) or read != final.st_size:
                        problem("File changed during hashing: " + relative)
                        continue
                    result["files"].append({"path": relative, "bytes": read, "sha256": digest.hexdigest()})
                except OSError as exc:
                    problem(relative + ": " + str(exc))
            if stop:
                break
    result.update(finished=now(), bytesRead=used, limitations="File hashes only; NT ACLs, directory entries and live consistency need separate checks")
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


def finish_report(audit, metadata, manifest):
    required = [x for x in audit.checks if x["kind"] in ["dbcheck", "drs", "level", "sysvol_acl", "time", "dns", "service", "failed_units"]]
    incomplete = any(x["status"] in ["unknown", "skipped"] for x in required) or not manifest["complete"]
    findings = [x["id"] for x in audit.checks if x["status"] in ["warning", "error"]]
    report = {"format": "samba-domain-audit-v1", "scriptVersion": VERSION, "metadata": metadata, "finished": now(), "collectionComplete": not incomplete, "findings": findings, "checks": audit.checks, "sysvol": {"complete": manifest["complete"], "fileCount": len(manifest["files"]), "manifest": "sysvol-manifest.json"}, "limitations": ["Local DC only; run on every RWDC and RODC", "No remediation, backup restore test, user interactive logon or GPO application test", "Raw logs are bounded; timeouts/truncation/missing tools never mean healthy", "Native JSON is not a sambaadm helper import format", "No password, private key, full sam.ldb or GPO file content is intentionally collected"]}
    report["exitCode"] = 1 if findings else 3 if incomplete else 0
    (audit.output / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    summary = ["Samba domain audit " + VERSION, "Node: " + metadata["node"], "Domain: " + metadata.get("domain", "unknown"), "Collection complete: " + str(not incomplete), "Exit: " + str(report["exitCode"])]
    summary += ["{} | {} | {}".format(c["id"], c["status"], c["detail"]) for c in audit.checks]
    (audit.output / "summary.txt").write_text("\n".join(summary) + "\n", encoding="utf-8")
    rows = "".join("<tr><td>{}</td><td>{}</td><td>{}</td><td><a href='{}'>Raw output</a></td></tr>".format(*(html.escape(str(v), quote=True) for v in (c["id"], c["status"], c["detail"], c["raw"]))) for c in audit.checks)
    page = """<!doctype html><html lang=en><meta charset=utf-8><title>Samba domain audit</title><style>body{{font:16px sans-serif;max-width:1200px;margin:32px auto;padding:0 20px}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #ccc;padding:8px;text-align:left;vertical-align:top}}p{{line-height:1.5}}</style><h1>Samba domain audit</h1><p>{}</p><p>Collection complete: {}. Exit: {}. Status observed is not a health verdict. See report.json for source and time of every observation.</p><table><tr><th>Check</th><th>Status</th><th>Meaning</th><th>Evidence</th></tr>{}</table><h2>Scope</h2><p>{}</p></html>""".format(html.escape(metadata["node"] + " / " + metadata.get("domain", "unknown")), not incomplete, report["exitCode"], rows, html.escape("; ".join(report["limitations"])))
    (audit.output / "report.html").write_text(page, encoding="utf-8")
    hashes = []
    for path in sorted(audit.output.rglob("*")):
        if path.is_file():
            hashes.append(hashlib.sha256(path.read_bytes()).hexdigest() + "  " + str(path.relative_to(audit.output)))
    (audit.output / "SHA256SUMS").write_text("\n".join(hashes) + "\n", encoding="utf-8")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--version", action="version", version=VERSION)
    parser.add_argument("--output", type=Path, help="New output directory; existing paths are refused")
    parser.add_argument("--smb-conf", type=Path, default=Path("/etc/samba/smb.conf"))
    parser.add_argument("--domain", help="Override DNS domain discovery (not a URL or DN)")
    parser.add_argument("--dc", help="Override local DC FQDN discovery")
    parser.add_argument("--dns-server", help="DNS IP/name for diagnostic queries; defaults to local DC FQDN")
    parser.add_argument("--site", default="", help="Optional operator site label")
    parser.add_argument("--timeout", type=int, default=120, help="Per-command and manifest time limit in seconds")
    parser.add_argument("--max-output-mib", type=int, default=8)
    parser.add_argument("--skip-dbcheck", action="store_true", help="Skip potentially expensive local database check; report becomes partial")
    parser.add_argument("--skip-sysvol-manifest", action="store_true", help="Skip file hashing; report becomes partial")
    parser.add_argument("--allow-unprivileged", action="store_true", help="Collect limited evidence without root; privileged checks remain unknown")
    args = parser.parse_args(argv)
    if not 1 <= args.timeout <= 3600 or not 1 <= args.max_output_mib <= 64 or len(args.site) > 256:
        parser.error("Invalid time/output/site limit")
    if not args.smb_conf.is_file():
        parser.error("Samba configuration file is unavailable; use --smb-conf")
    if os.geteuid() != 0 and not args.allow_unprivileged:
        parser.error("Run locally as root, or explicitly use --allow-unprivileged")
    try:
        if args.domain: args.domain = dns_name(args.domain)
        if args.dc: args.dc = dns_name(args.dc)
    except ValueError as exc:
        parser.error(str(exc))
    if args.dns_server and (args.dns_server.startswith("-") or not re.fullmatch(r"[A-Za-z0-9_.:-]+", args.dns_server)):
        parser.error("Invalid DNS server")
    os.umask(0o077)
    try:
        if args.output:
            args.output = args.output.absolute(); args.output.mkdir(mode=0o700)
        else:
            args.output = Path(tempfile.mkdtemp(prefix="samba-domain-audit-", dir="/var/tmp"))
    except OSError as exc:
        parser.error("Cannot create a NEW output directory: " + str(exc))
    print("OUTPUT=" + str(args.output), flush=True)
    audit = Audit(args.output, args.timeout, args.max_output_mib * 1024 * 1024)
    metadata = {"node": socket.gethostname(), "started": now(), "euid": os.geteuid(), "smbConf": str(args.smb_conf), "siteLabel": args.site, "scriptSHA256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    realm = audit.parameter("realm", args.smb_conf)
    netbios = audit.parameter("netbios name", args.smb_conf)
    role = audit.parameter("server role", args.smb_conf)
    private = audit.parameter("private dir", args.smb_conf)
    sysvol = audit.command("config_sysvol_path", ["testparm", "-s", "--section-name=sysvol", "--parameter-name=path", str(args.smb_conf)])
    sysvol_lines = [s.strip() for s in sysvol.splitlines() if s.strip()]
    sysvol_path = Path(sysvol_lines[-1]) if audit.checks[-1]["returncode"] == 0 and sysvol_lines and Path(sysvol_lines[-1]).is_absolute() else None
    metadata.update(realm=realm, netbios=netbios, serverRole=role)
    try:
        domain = args.domain or dns_name(realm)
        dc = args.dc or dns_name((netbios or socket.gethostname().split(".")[0]) + "." + domain)
        metadata.update(domain=domain, dc=dc)
    except ValueError:
        domain = dc = ""
        metadata["discoveryError"] = "Cannot determine domain/DC; network checks skipped; supply --domain/--dc"
    is_dc = "active directory domain controller" in role.lower()
    samdb = Path(private) / "sam.ldb" if private and Path(private).is_absolute() else None
    metadata["samdb"] = str(samdb) if samdb else None
    for key, cmd, kind in [
        ("os", ["cat", "/etc/os-release"], "observation"),
        ("kernel", ["uname", "-srmo"], "observation"),
        ("uptime", ["uptime"], "observation"),
        ("memory", ["free", "-h"], "observation"),
        ("disk", ["df", "-hT"], "observation"),
        ("inodes", ["df", "-ih"], "observation"),
        ("interfaces", ["ip", "-br", "addr"], "observation"),
        ("routes", ["ip", "route"], "observation"),
        ("resolver", ["cat", "/etc/resolv.conf"], "observation"),
        ("packages", ["rpm", "-q", "samba", "samba-dc", "sambaadm", "sambaadm-helper", "chrony"], "observation"),
        ("samba_version", ["samba", "-V"], "observation"),
        ("failed_units", ["systemctl", "--failed", "--no-legend", "--no-pager"], "failed_units"),
        ("samba_service", ["systemctl", "show", "samba.service", "-p", "LoadState", "-p", "ActiveState", "-p", "SubState"], "service"),
        ("time", ["chronyc", "-n", "tracking"], "time"),
        ("time_sources", ["chronyc", "-n", "sources", "-v"], "observation"),
        ("listening", ["ss", "-lntup"], "observation"),
        ("journal_samba", ["journalctl", "-u", "samba", "--since=-24 hours", "-p", "warning", "--no-pager", "-n", "500"], "observation"),
        ("journal_integrity", ["journalctl", "-u", "integalert", "-b", "--no-pager", "-n", "100"], "observation"),
    ]:
        audit.command(key, cmd, kind)
    for key, cmd, kind in [
        ("domain_level", ["domain", "level", "show"], "level"),
        ("fsmo", ["fsmo", "show"], "observation"),
        ("password_policy", ["domain", "passwordsettings", "show"], "observation"),
        ("replication", ["drs", "showrepl", "-P"], "drs"),
        ("sysvol_acl", ["ntacl", "sysvolcheck"], "sysvol_acl"),
        ("dbcheck", ["dbcheck", "--cross-ncs"], "dbcheck"),
        ("gpo", ["gpo", "listall", "-P"], "observation"),
        ("sites", ["sites", "list"], "observation"),
    ]:
        audit.command(key, ["samba-tool"] + cmd + ["-s", str(args.smb_conf)], kind, privileged=True, enabled=is_dc and not (key == "dbcheck" and args.skip_dbcheck))
    for key, query, attributes in [
        ("ntds", "(objectClass=nTDSDSA)", ["dn", "msDS-Behavior-Version", "msDS-isRODC", "options"]),
        ("controllers", "(objectClass=server)", ["dn", "dNSHostName", "serverReference"]),
        ("sites_subnets", "(|(objectClass=site)(objectClass=subnet)(objectClass=siteLink))", ["dn", "siteObject", "siteList", "cost", "replInterval"]),
    ]:
        text = audit.command(key, ["ldbsearch", "-H", str(samdb), "--cross-ncs", "-b", "", query] + attributes, privileged=True, enabled=is_dc and samdb is not None)
        if key == "ntds":
            metadata["ntds"] = ldif_records(text)
            for entry in metadata["ntds"]:
                match = re.match(r"^CN=NTDS Settings,CN=" + re.escape(netbios) + r",CN=Servers,CN=([^,]+),", entry["dn"][0], re.I)
                if match:
                    metadata["role"] = "RODC" if entry.get("msds-isrodc", [""])[0].lower() == "true" else "RWDC"
                    metadata["site"] = match[1]
    if domain and dc:
        server = args.dns_server or dc
        for key, query, kind in [("dns_a", dc, "A"), ("dns_ldap", "_ldap._tcp.dc._msdcs." + domain, "SRV"), ("dns_kerberos", "_kerberos._tcp." + domain, "SRV")]:
            audit.command(key, ["dig", "+time=2", "+tries=1", "+noall", "+answer", "+comments", "@" + server, query, kind], "dns")
        audit.command("dns_tcp", ["dig", "+tcp", "+time=2", "+tries=1", "+noall", "+answer", "+comments", "@" + server, "_ldap._tcp.dc._msdcs." + domain, "SRV"], "dns")
    else:
        audit.command("dns_discovery", ["dig"], "dns", enabled=False)
    if not is_dc:
        metadata["scopeWarning"] = "Local Samba role is not AD DC; directory checks skipped"
    if args.skip_sysvol_manifest or not is_dc or os.geteuid() != 0:
        manifest = {"complete": False, "files": [], "issues": ["Manifest skipped by operator or requires a local AD DC and root"]}
        (args.output / "sysvol-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    else:
        manifest = sysvol_manifest(sysvol_path, args.output / "sysvol-manifest.json", timeout=args.timeout)
    report = finish_report(audit, metadata, manifest)
    print("REPORT=" + str(args.output / "report.html")); print("EXIT=" + str(report["exitCode"]))
    return report["exitCode"]


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("Interrupted: results are incomplete", file=sys.stderr)
        sys.exit(2)
