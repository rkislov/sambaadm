import datetime
import pathlib
import unittest
from unittest.mock import Mock, patch


class ScheduledSnapshots(unittest.TestCase):
    def setUp(self):
        self.worker = {'__name__': 'snapshot_test'}
        directory = pathlib.Path(__file__).parent
        for filename in ['storage.py', 'activate.py', 'snapshots.py', 'worker.py']:
            path = directory / filename
            exec(compile(path.read_text(), str(path), 'exec'), self.worker)
        self.now = datetime.datetime(2026, 11, 26, 17, 12, tzinfo=datetime.timezone.utc)
        self.dataset = 'sambaadm_test/data'

    def test_one_per_slot_even_when_another_node_runs_it(self):
        slot = str(int(self.now.timestamp()) // 3600 * 3600)
        tag = 'sambaadm_2026.11.26-17.02.00'
        rows = {'org.sambaadm:auto-owner': [(tag, 'revision')],
                'org.sambaadm:auto-slot': [(tag, slot)]}
        run = Mock()
        with patch.dict(self.worker, run=run, snapshot_property_rows=lambda _, prop: rows[prop]):
            self.worker['run_scheduled_snapshot'](self.dataset, 'revision',
                                                  {'intervalMinutes': 60, 'retain': 2}, self.now)
        run.assert_not_called()

    def test_retention_only_applies_to_own_automatic_snapshots(self):
        old = 'sambaadm_2026.11.26-15.00.00'
        manual = 'sambaadm_2026.11.26-15.30.00'
        foreign = 'sambaadm_2026.11.26-16.00.00'
        rows = {'org.sambaadm:auto-owner': [(old, 'revision'), (foreign, 'elsewhere')],
                'org.sambaadm:auto-slot': [(old, '1'), (manual, '1'), (foreign, '1')]}
        run = Mock()
        with patch.dict(self.worker, run=run, snapshot_property_rows=lambda _, prop: rows[prop]):
            self.worker['run_scheduled_snapshot'](self.dataset, 'revision',
                                                  {'intervalMinutes': 60, 'retain': 1}, self.now)
        commands = [entry.args[0] for entry in run.call_args_list]
        self.assertEqual(commands[0][1], 'snapshot')
        self.assertEqual(commands[1:], [['zfs', 'destroy', self.dataset + '@' + old]])


if __name__ == '__main__':
    unittest.main()
