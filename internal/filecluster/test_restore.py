import os
import pathlib
import tempfile
import unittest


class RestorePlan(unittest.TestCase):
    def setUp(self):
        self.worker = {'__name__': 'restore_test'}
        directory = pathlib.Path(__file__).parent
        for filename in ['storage.py', 'activate.py', 'snapshots.py', 'restore.py', 'worker.py']:
            path = directory / filename
            exec(compile(path.read_text(), str(path), 'exec'), self.worker)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.live = pathlib.Path(temp.name) / 'live'
        self.source = pathlib.Path(temp.name) / 'snapshot'
        for directory in [self.live, self.source]:
            directory.mkdir()
        self.roots = [os.open(item, os.O_RDONLY | os.O_DIRECTORY) for item in [self.live, self.source]]
        for fd in self.roots:
            self.addCleanup(os.close, fd)

    def plan(self, path, overwrite):
        return self.worker['restore_plan'](*self.roots, path, overwrite, 'guid')

    def test_symlink_is_blocked_on_either_side(self):
        (self.source / 'file').write_text('snapshot')
        (self.live / 'file').symlink_to('/etc/passwd')
        rows, _ = self.plan(('file',), True)
        self.assertEqual(rows[0]['action'], 'blocked')
        (self.source / 'link').symlink_to('/etc/passwd')
        rows, _ = self.plan(('link',), True)
        self.assertEqual(rows[0]['action'], 'blocked')

    def test_missing_parents_are_included_only_for_selected_file(self):
        (self.source / 'folder').mkdir()
        (self.source / 'folder' / 'chosen').write_text('snapshot')
        (self.source / 'folder' / 'unselected').write_text('ignore')
        rows, _ = self.plan(('folder', 'chosen'), False)
        self.assertEqual([(row['path'], row['action']) for row in rows],
                         [('folder', 'create'), ('folder/chosen', 'create')])

    def test_destination_edits_invalidate_review(self):
        (self.source / 'file').write_text('snapshot')
        (self.live / 'file').write_text('live')
        _, before = self.plan(('file',), True)
        (self.live / 'file').write_text('new change')
        _, after = self.plan(('file',), True)
        self.assertNotEqual(before, after)


if __name__ == '__main__':
    unittest.main()
