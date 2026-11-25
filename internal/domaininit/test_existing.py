"""Pure protocol guards; Windows compatibility still requires a Windows DC."""
import importlib.util,pathlib,sys,tempfile,types,unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('existing_bootstrap',pathlib.Path(__file__).with_name('existing.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
class Pages:
 def __init__(self,items,cookie):self.items=items;self.controls=['paged_results:0:'+cookie]
 def __iter__(self):return iter(self.items)
class ExistingTests(unittest.TestCase):
 def test_large_ldap_result_and_repeated_cookie(self):
  with patch.dict(sys.modules,{'ldb':types.SimpleNamespace(SCOPE_SUBTREE=2)}):
   responses=iter([Pages(range(500),'cookie'),Pages(range(500,650),'')])
   db=types.SimpleNamespace(search=lambda **kw:next(responses))
   self.assertEqual(len(list(module.paged(db,'base','filter',['name']))),650)
   db.search=lambda **kw:Pages([],'repeated')
   with self.assertRaisesRegex(RuntimeError,'повторил страницу'):list(module.paged(db,'base','filter',[]))
 def test_checkpoint_is_private_and_atomic(self):
  with tempfile.TemporaryDirectory() as directory:
   folder=pathlib.Path(directory);module.checkpoint(folder,{'sid':'domain','ntds':'own DC'})
   self.assertEqual((folder/'existing-state.json').stat().st_mode&0o777,0o600)
   self.assertFalse((folder/'existing-state.tmp').exists())
if __name__=='__main__':unittest.main()
