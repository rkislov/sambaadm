"""Safety gates: run with python3 -m unittest discover -s internal/domaininit -p 'test_*.py'."""
import importlib.util, pathlib, tempfile, unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('worker',pathlib.Path(__file__).with_name('worker.py'));w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)
class RepositoryGate(unittest.TestCase):
 def test_partial_repository_failure_is_not_success(self):
  with patch.object(w,'run',return_value='W: Failed to fetch http://unavailable/release\nSome index files failed') as command:
   with self.assertRaisesRegex(RuntimeError,'Настройте доступные репозитории'):w.repository_plan()
   self.assertEqual(command.call_count,1)
 def test_missing_package_prevents_install(self):
  def output(args,*_):return '' if args[-1]=='update' else 'Candidate: (none)'
  with patch.object(w,'run',side_effect=output) as command:
   with self.assertRaisesRegex(RuntimeError,'Пакет samba-dc недоступен'):w.repository_plan()
   self.assertFalse(any('install' in c.args[0] for c in command.call_args_list))
 def test_removal_plan_is_rejected(self):
  def output(args,*_):
   if 'policy' in args:return 'Candidate: 4.19.9-alt12'
   if '-s' in args:return 'Remv existing-service'
   return ''
  with patch.object(w,'run',side_effect=output):
   with self.assertRaisesRegex(RuntimeError,'удаляет установленное ПО'):w.repository_plan()
 def test_valid_repository_checks_all_packages_before_simulation(self):
  def output(args,*_):return 'Candidate: 4.19.9-alt12' if 'policy' in args else ''
  with patch.object(w,'run',side_effect=output) as command:
   self.assertEqual(len(w.repository_plan()),len(w.PACKAGES))
   self.assertEqual(command.call_args_list[-1].args[0],['apt-get','-s','install',*w.PACKAGES])
class DeploymentGate(unittest.TestCase):
 def input(self):return dict(mode='forest',realm='corp.example',netbios='CORP',hostname='dc1',address='192.0.2.10',forwarder='192.0.2.53',site='Main',level='2008_R2',panelName='sambaadm.corp.example',password='not-persisted-A1!',confirm=True,revision='a'*64)
 def test_download_failure_never_installs_or_changes_hostname(self):
  with tempfile.TemporaryDirectory() as root:
   folder=pathlib.Path(root)/'domain-init'/'job';folder.mkdir(parents=True)
   with patch.object(w,'preflight',return_value={'revision':'a'*64}),patch.object(w,'pristine'),patch.object(w,'run',side_effect=RuntimeError('RPM unavailable')) as command:
    with self.assertRaisesRegex(RuntimeError,'RPM unavailable'):w.deploy(self.input(),folder,lambda *args:None)
    self.assertEqual(command.call_count,1)
    self.assertIn('--download-only',command.call_args.args[0])
    self.assertFalse((folder/'hostname.before').exists())
 def test_stale_plan_does_not_download_or_install(self):
  with tempfile.TemporaryDirectory() as root:
   folder=pathlib.Path(root)/'domain-init'/'job';folder.mkdir(parents=True)
   with patch.object(w,'preflight',return_value={'revision':'b'*64}),patch.object(w,'run') as command:
    with self.assertRaisesRegex(RuntimeError,'изменились'):w.deploy(self.input(),folder,lambda *args:None)
    command.assert_not_called()
 def test_dangerous_addresses_and_names_rejected(self):
  for field,value in [('address','127.0.0.1'),('mode','MEMBER'),('site','site\ncommand'),('hostname','dc;id'),('panelName','else.example')]:
   values=self.input();values[field]=value
   with self.subTest(field=field),self.assertRaises(Exception):w.validate(values)
if __name__=='__main__':unittest.main()
