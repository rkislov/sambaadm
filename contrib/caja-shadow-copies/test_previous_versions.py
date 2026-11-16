import unittest
from unittest.mock import patch

from sambaadm_previous_versions import SMBPath, list_versions, parse_versions


class PreviousVersionsTests(unittest.TestCase):
    def test_names_in_smbclient_output_include_failed_path_lookups(self):
        result = parse_versions(
            "create_time: current\n"
            "@GMT-2026.11.16-07.30.00\ncreate_time: old\n"
            "@GMT-2026.11.16-06.30.00\n"
            "@GMT-2026.11.16-05.30.00\ncreate_time: older\n"
            "@GMT-2026.13.16-03.00.00\ncreate_time: invalid\n"
        )
        self.assertEqual(result, ["@GMT-2026.11.16-07.30.00", "@GMT-2026.11.16-05.30.00"])

    def test_selection_encodes_smb_path_and_uses_kerberos(self):
        target = SMBPath.parse("smb://fs.test/Public/Files/report%20draft.txt")
        command = target.list_command("/usr/bin/smbclient")
        self.assertIn("--use-kerberos=required", command)
        self.assertEqual(command[-1], 'allinfo "Files\\report draft.txt"')
        self.assertEqual(target.uri("@GMT-2026.11.16-07.30.00"),
                         "smb://fs.test/Public/@GMT-2026.11.16-07.30.00/Files/report%20draft.txt")

    def test_share_root_is_queried_as_an_absolute_smb_path(self):
        target = SMBPath.parse("smb://fs.test/Public/")
        self.assertEqual(target.list_command("smbclient")[-1], 'allinfo "/"')

    def test_selection_rejects_smbclient_command_separators(self):
        for path in ("file%3B%21touch", "x%22%3Bls", "directory%2Fx", "%2e%2e", "foo%0Abar"):
            with self.subTest(path=path):
                self.assertIsNone(SMBPath.parse("smb://fs.test/Public/" + path))

    def test_already_in_snapshot_has_no_previous_versions_menu(self):
        self.assertIsNone(SMBPath.parse("smb://fs.test/Public/@GMT-2026.11.16-07.30.00/Files"))

    def test_authentication_failure_is_not_an_empty_snapshot_list(self):
        target = SMBPath.parse("smb://fs.test/Public/report.txt")
        with patch("shutil.which", return_value="/usr/bin/smbclient"), patch("subprocess.run") as run:
            run.return_value.returncode = 1
            run.return_value.stdout = ""
            run.return_value.stderr = "NT_STATUS_LOGON_FAILURE"
            with self.assertRaisesRegex(RuntimeError, "Kerberos"):
                list_versions(target)


if __name__ == "__main__":
    unittest.main()
