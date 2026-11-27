import importlib.util,pathlib,unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('cluster_probe',pathlib.Path(__file__).with_name('worker.py'));w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)
class ProbeTests(unittest.TestCase):
 def test_inventory_reports_config_hashes_boot_and_stable_device(self):
  fixture='{"blockdevices":[{"kname":"vdb","type":"disk","serial":"TESTDATA","size":2147483648}]}'
  def output(args,*_):
   if args[0]=='lsblk':return fixture
   raise RuntimeError('optional tool unavailable')
  with patch.object(w,'platform',return_value='p11'),patch.object(w,'run',side_effect=output),patch.object(pathlib.Path,'read_text',return_value='boot-test'),patch.object(w.socket,'getfqdn',return_value='fs1.corp.example'):
   result=w.inventory();self.assertEqual(result['blocks']['blockdevices'][0]['diskWWID'],'serial-TESTDATA');self.assertEqual(result['bootID'],'boot-test');self.assertEqual(len(result['configHashes']),4)

 def test_platforms_are_explicit(self):
  for branch in ['p10','p11']:
   with patch.object(pathlib.Path,'read_text',return_value='ID=altlinux\nALT_BRANCH_ID="'+branch+'"\n'):self.assertEqual(w.platform(),branch)
  with patch.object(pathlib.Path,'read_text',return_value='ID=altlinux\nVERSION_ID=12\n'):
   with self.assertRaisesRegex(RuntimeError,'целевая ветка'):w.platform()
 def test_partial_repository_is_not_accepted(self):
  with patch.object(w,'platform',return_value='p11'),patch.object(w,'run',return_value='W: Failed to fetch index\nSome index files failed') as command:
   with self.assertRaisesRegex(RuntimeError,'доступны не полностью'):w.repository(['pacemaker'])
   self.assertEqual(command.call_count,1)
 def test_arbitrary_packages_never_reach_package_manager(self):
  with patch.object(w,'run') as command:
   with self.assertRaisesRegex(RuntimeError,'Недопустимый'):w.repository(['package; command'])
   command.assert_not_called()
 def test_virtual_kernel_module_resolves_and_reports_reboot(self):
  def output(args,*_):
   if args[:2]==['apt-cache','policy']:return 'Candidate: 3.0.3-alt1:p11+123@100'
   if args[0]=='rpm':return 'kernel-image-6.12'
   if args[-1]=='kernel-modules-drbd9-6.12':return "Selecting kernel-modules-drbd9-6.12#1:9.3.0-alt1 for 'kernel-modules-drbd9-6.12'\nInst kernel-image-6.12#6.12.117-alt1"
   if '-s' in args:return 'Inst kernel-image-6.12#6.12.117-alt1\n'
   return ''
  with patch.object(w,'platform',return_value='p11'),patch.object(w,'run',side_effect=output) as command:
   plan=w.repository(['pacemaker'],'drbd','lvm-xfs')
   self.assertTrue(plan['rebootRequired']);self.assertEqual(plan['kernelPackages'],['kernel-modules-drbd9-6.12#1:9.3.0-alt1'])
   self.assertIn(plan['kernelPackages'][0],command.call_args.args[0]);self.assertFalse(any('--no-download' in c.args[0] or '--download-only' in c.args[0] for c in command.call_args_list))
 def test_removal_is_rejected_before_storage(self):
  with patch.object(w,'platform',return_value='p10'),patch.object(w,'run',side_effect=['','Candidate: 2.1.7-alt1','Remv samba']):
   with self.assertRaisesRegex(RuntimeError,'удаляет установленное'):w.repository(['pacemaker'])
 def test_discovery_does_not_log_in_or_persist_targets(self):
  with patch.object(w,'run',return_value='192.0.2.80:3260,1 iqn.2026-11.test:lun\n') as command:
   data=w.discover(['192.0.2.80:3260']);self.assertFalse(data['loggedIn']);self.assertFalse(data['formatted'])
   args=command.call_args.args[0];self.assertIn('nonpersistent',args);self.assertNotIn('--login',args)
   self.assertEqual(data['discoveries'][0]['targets'][0]['iqn'],'iqn.2026-11.test:lun')

class PackageJobs(unittest.TestCase):
 def test_missing_download_never_runs_install(self):
  from unittest.mock import Mock
  value={'revision':'a'*64,'profile':{'packages':['pacemaker'],'storage':'iscsi','filesystem':'lvm-xfs'}}
  with patch.object(w,'repository',return_value={'revision':'a'*64,'kernelPackages':[]}),patch.object(w,'run',side_effect=RuntimeError('download failed')) as command:
   with self.assertRaisesRegex(RuntimeError,'download failed'):w.prepare_packages(value,lambda *args:None)
   self.assertEqual(command.call_count,1);self.assertIn('--download-only',command.call_args.args[0])
 def test_changed_candidate_after_download_does_not_install(self):
  value={'revision':'a'*64,'profile':{'packages':['pacemaker'],'storage':'iscsi','filesystem':'lvm-xfs'}}
  with patch.object(w,'repository',side_effect=[{'revision':'a'*64,'kernelPackages':[]},{'revision':'b'*64}]),patch.object(w,'run') as command:
   with self.assertRaisesRegex(RuntimeError,'во время скачивания'):w.prepare_packages(value,lambda *args:None)
   self.assertEqual(command.call_count,1);self.assertIn('--download-only',command.call_args.args[0])

class ZFSReadiness(unittest.TestCase):
 def check(self,**changes):
  responses={'moduleKernel':w.os.uname().release+' SMP','moduleVersion':'2.4.2-1','userVersion':'zfs-2.4.2-1\nzfs-kmod-2.4.2-1','loadedVersion':'2.4.2-1','autoImport':'LoadState=loaded\nUnitFileState=disabled'}
  responses.update(changes)
  def output(args,*_):
   if args[0]=='modinfo':return responses['moduleKernel' if args[2]=='vermagic' else 'moduleVersion']
   if args[0]=='zfs':return responses['userVersion']
   return responses['autoImport']
  with patch.object(w,'run',side_effect=output),patch.object(pathlib.Path,'is_file',return_value=bool(responses['loadedVersion'])),patch.object(pathlib.Path,'read_text',return_value=responses['loadedVersion']),patch.object(pathlib.Path,'read_bytes',return_value=(1).to_bytes(4,w.sys.byteorder)):return w.zfs_readiness()
 def test_loaded_matching_module_ready_with_no_autoimport(self):
  self.assertTrue(self.check()['ready'])
 def test_installed_package_does_not_prove_loaded_module(self):
  self.assertFalse(self.check(loadedVersion='')['ready'])
 def test_old_kernel_or_loaded_version_requires_reboot(self):
  self.assertFalse(self.check(moduleKernel='different-kernel SMP')['ready'])
  self.assertFalse(self.check(loadedVersion='2.1.16-1')['ready'])
 def test_userspace_module_mismatch_blocks_pool_creation(self):
  self.assertFalse(self.check(userVersion='zfs-2.1.16-1')['ready'])
 def test_missing_persistent_hostid_blocks_pool_creation(self):
  with patch.object(pathlib.Path,'read_bytes',side_effect=FileNotFoundError):
   self.assertFalse(w.zfs_readiness()['ready'])
 def test_enabled_or_unknown_autoimport_blocks_handoff(self):
  for state in ['enabled','static','unknown']:
   self.assertFalse(self.check(autoImport='LoadState=loaded\nUnitFileState='+state)['ready'])

if __name__=='__main__':unittest.main()
