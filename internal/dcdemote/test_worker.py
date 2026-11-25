import importlib.util,pathlib,unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('demote',pathlib.Path(__file__).with_name('worker.py'));worker=importlib.util.module_from_spec(spec);spec.loader.exec_module(worker)
class RepositoryGate(unittest.TestCase):
 def test_partial_update_is_failure_even_with_zero_exit(self):
  with patch.object(worker,'run',return_value='W: Some index files failed to download'):
   with self.assertRaisesRegex(RuntimeError,'репозитории'):worker.repositories()
 def test_missing_candidate_stops_before_download(self):
  calls=[]
  def run(argv,*args):
   calls.append(argv);return 'Get: index' if argv[-1]=='update' else 'Candidate: (none)'
  with patch.object(worker,'run',side_effect=run):
   with self.assertRaisesRegex(RuntimeError,'Недоступен пакет'):worker.repositories(True)
  self.assertFalse(any('--download-only' in a for a in calls))
 def test_removal_stops_before_download(self):
  def run(argv,*args):return 'Remv samba-dc' if '-s' in argv else ('Candidate: 4.19' if argv[0]=='apt-cache' else 'OK')
  with patch.object(worker,'run',side_effect=run):
   with self.assertRaisesRegex(RuntimeError,'удаление'):worker.repositories(True)
if __name__=='__main__':unittest.main()
