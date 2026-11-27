import base64
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("audit", ROOT / "scripts/samba-domain-audit.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class AuditTests(unittest.TestCase):
    def test_main_discovers_unrelated_and_child_domains_without_ipr_defaults(self):
        for realm, netbios, forest in [("OTHER.EXAMPLE", "BRANCH7", "other.example"),
                                       ("CHILD.FOREST.EXAMPLE", "EDGE2", "forest.example")]:
            with self.subTest(realm=realm), tempfile.TemporaryDirectory() as folder:
                base = Path(folder)
                conf = base / "smb.conf"; conf.write_text("[global]\n")
                calls = []
                params = {"realm": realm, "netbios name": netbios,
                          "server role": "active directory domain controller", "private dir": str(base)}
                def command(instance, key, argv, kind="observation", **kwargs):
                    calls.append(argv)
                    instance.checks.append({"id": key, "kind": kind, "status": "observed", "detail": "fixture", "raw": "raw/fixture.txt"})
                    if key == "config_sysvol_path":
                        instance.checks[-1]["returncode"] = 0
                        return str(base / "sysvol")
                    if key == "ntds":
                        return "dn: CN=NTDS Settings,CN=" + netbios + ",CN=Servers,CN=Branch,CN=Sites,CN=Configuration," + ",".join("DC="+x for x in forest.split(".")) + "\nmsDS-isRODC: TRUE\n\n"
                    return ""
                with patch.object(audit.os, "geteuid", return_value=0), patch.object(audit.Audit, "parameter", side_effect=lambda k, c: params[k]), patch.object(audit.Audit, "command", command):
                    audit.main(["--smb-conf", str(conf), "--output", str(base/"result"), "--skip-sysvol-manifest"])
                report = json.loads((base/"result/report.json").read_text())
                self.assertEqual(report["metadata"]["domain"], realm.lower())
                self.assertEqual(report["metadata"]["dc"], netbios.lower()+"."+realm.lower())
                self.assertEqual(report["metadata"]["role"], "RODC")
                self.assertEqual(report["metadata"]["site"], "Branch")
                self.assertTrue(any("--cross-ncs" in cmd and "ldbsearch" in cmd for cmd in calls))
                self.assertNotIn("ipr.loc", json.dumps(calls).lower())

    def test_ldif_folded_base64_and_multiple_domains(self):
        dn = "CN=NTDS Settings,CN=EDGE,CN=Servers,CN=Remote,CN=Sites,CN=Configuration,DC=forest,DC=example"
        text = "dn:: " + base64.b64encode(dn.encode()).decode() + "\nmsDS-isRODC: TRUE\nmsDS-Behavior-Version: 4\n\ndn: CN=Partitions,CN=Configuration,\n DC=forest,DC=example\nmsDS-Behavior-Version: 7\n\n"
        rows = audit.ldif_records(text)
        self.assertEqual(rows[0]["dn"], [dn])
        self.assertIn("DC=forest,DC=example", rows[1]["dn"][0])
        self.assertEqual(audit.dns_name("CHILD.FOREST.EXAMPLE."), "child.forest.example")
        self.assertEqual(audit.dns_name("another.test"), "another.test")
        for invalid in ["", "ldap://corp.example", "192.0.2.10", "-a.example", "a.example;id"]:
            with self.assertRaises(ValueError): audit.dns_name(invalid)

    def test_dbcheck_requires_final_counts_and_detects_error_count(self):
        self.assertEqual(audit.interpret("dbcheck", "completed", 0, "Checking 20 objects")[0], "unknown")
        self.assertEqual(audit.interpret("dbcheck", "completed", 0, "Checked 20 objects (2 errors)")[0], "error")
        self.assertEqual(audit.interpret("dbcheck", "completed", 0, "Checked 20 objects (0 errors)")[0], "ok")
        for state in ["timeout", "output-limit", "missing-command", "permission-required"]:
            self.assertEqual(audit.interpret("dbcheck", state, 0, "Checked 20 objects (0 errors)")[0], "unknown")

    def test_drs_does_not_mistake_empty_or_zero_time_for_success(self):
        head = "==== INBOUND NEIGHBORS ====\n"
        tail = "==== OUTBOUND NEIGHBORS ====\n9 consecutive failure(s)."
        self.assertEqual(audit.interpret("drs", "completed", 0, head + tail)[0], "unknown")
        self.assertEqual(audit.interpret("drs", "completed", 0, head + "0 consecutive failure(s). Last success NTTIME(0)" + tail)[0], "unknown")
        self.assertEqual(audit.interpret("drs", "completed", 0, head + "0 consecutive failure(s). Last success today" + tail)[0], "ok")
        self.assertEqual(audit.interpret("drs", "completed", 0, head + "1 consecutive failure(s)." + tail)[0], "error")

    def test_runtime_timeout_and_output_budget(self):
        with tempfile.TemporaryDirectory() as folder:
            a = audit.Audit(folder, timeout=1, limit=1024)
            a.command("timeout", [sys.executable, "-c", "import time; time.sleep(4)"], "dbcheck")
            self.assertEqual(a.checks[-1]["execution"], "timeout")
            self.assertEqual(a.checks[-1]["status"], "unknown")
            a.command("large", [sys.executable, "-c", "print('x'*10000)"], "dbcheck")
            self.assertTrue(a.checks[-1]["truncated"])
            self.assertEqual((Path(folder)/"raw/large.txt").stat().st_size, 1024)

    def test_sysvol_hashes_without_following_symlinks_and_limits(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)/"sysvol"; root.mkdir()
            (root/"GPT.INI").write_text("[General]\nVersion=1\n")
            (root/"outside").symlink_to("/etc/passwd")
            result = audit.sysvol_manifest(root, Path(folder)/"manifest.json")
            self.assertFalse(result["complete"])
            self.assertEqual([x["path"] for x in result["files"]], ["GPT.INI"])
            self.assertNotIn("Version=1", json.dumps(result))
            result = audit.sysvol_manifest(root, Path(folder)/"limited.json", max_bytes=3)
            self.assertFalse(result["complete"])
            self.assertEqual(result["files"], [])

    def test_html_escapes_host_and_partial_result_is_not_zero(self):
        with tempfile.TemporaryDirectory() as folder:
            a = audit.Audit(folder)
            a.command("skipped", ["missing-audit-probe"], "dbcheck", enabled=False)
            r = audit.finish_report(a, {"node": "<img src=x onerror=alert(1)>", "domain": "different.example"}, {"complete": False, "files": []})
            self.assertEqual(r["exitCode"], 3)
            self.assertFalse(r["collectionComplete"])
            self.assertNotIn("<img", (Path(folder)/"report.html").read_text())


if __name__ == "__main__": unittest.main()
