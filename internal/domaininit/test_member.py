import importlib.util, pathlib, tempfile, unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('member',pathlib.Path(__file__).with_name('member.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class MemberTests(unittest.TestCase):
 def values(self,profile='winbind'):
  return dict(mode='member',identityProvider=profile,realm='corp.example',netbios='CORP',hostname='fs1',address='192.0.2.20',forwarder='192.0.2.10',source='dc1.corp.example',panelName='sambaadm.corp.example',username='Administrator@corp.example',password='PrivateA1!',confirm=True,revision='a'*64)
 def test_profile_uses_one_authoritative_idmap(self):
  for profile in ['sssd','winbind']:
   v=self.values(profile);m.validate(v);conf=m.smb_config(v)
   self.assertIn('server role = member server',conf)
   self.assertIn('directory mask = 0770',conf)
   self.assertIn('create mask = 0660',conf)
   self.assertNotIn('samba-dc',m.packages(v))
   self.assertIn('samba-winbind',m.packages(v))
   self.assertIn('backend = '+('sss' if profile=='sssd' else 'rid'),conf)
   self.assertNotIn('[sysvol]',conf)
  self.assertIn('ad_maximum_machine_account_password_age = 0',m.sssd_config(self.values('sssd')))
  self.assertIn('sync machine password to keytab',m.smb_config(self.values('sssd')))
  self.assertIn('machine password timeout = 0',m.smb_config(self.values('sssd'),False))
  self.assertIn('ad_update_samba_machine_account_password = True',m.sssd_config(self.values('sssd'),False))
  self.assertNotIn('ad_maximum_machine_account_password_age = 0',m.sssd_config(self.values('sssd'),False))
 def test_nss_preserves_other_sources_and_comments(self):
  text='passwd: files systemd # local\ngroup: files\nhosts: files dns\n'
  result=m.nss_config(text,'sss');self.assertIn('passwd: files systemd sss # local',result);self.assertIn('hosts: files dns',result);self.assertNotIn('winbind',result)
  with self.assertRaisesRegex(RuntimeError,'строки passwd и group'):m.nss_config('passwd: files\n','sss')
 def test_dc_parameters_rejected(self):
  for key,value in [('identityProvider','ldap'),('transferRoles',True),('site','Main'),('level','2008_R2'),('username','user%secret')]:
   v=self.values();v[key]=value
   with self.subTest(key=key),self.assertRaises(RuntimeError):m.validate(v)
 def test_password_only_on_stdin(self):
  v=self.values()
  with patch.object(m.subprocess,'run') as run:
   run.return_value.returncode=0;m.join(v,{'ENV':{'PATH':'/usr/bin'}})
   args=run.call_args.args[0];self.assertNotIn(v['password'],' '.join(args));self.assertEqual(run.call_args.kwargs['input'],v['password']+'\n');self.assertIn('--use-kerberos=required',args)
 def test_stale_plan_and_failed_download_never_mutate_configuration(self):
  v=self.values()
  from unittest.mock import Mock
  with tempfile.TemporaryDirectory() as root:
   w={'preflight':Mock(return_value={'revision':'b'*64}),'run':Mock()}
   with self.assertRaisesRegex(RuntimeError,'изменились'):m.deploy(v,pathlib.Path(root),lambda *a:None,w)
   w['run'].assert_not_called()
   w['preflight'].return_value={'revision':'a'*64};w['run'].side_effect=RuntimeError('download unavailable')
   with self.assertRaisesRegex(RuntimeError,'download unavailable'):m.deploy(v,pathlib.Path(root),lambda *a:None,w)
   self.assertEqual(w['run'].call_count,1);self.assertIn('--download-only',w['run'].call_args.args[0]);self.assertEqual(list(pathlib.Path(root).iterdir()),[])
if __name__=='__main__':unittest.main()
