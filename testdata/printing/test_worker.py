"""Safety and state tests; no root, CUPS daemon, AD or network required."""
import base64,io,json,pathlib,runpy,struct,tarfile,tempfile,unittest,zipfile
from unittest.mock import Mock,patch
worker=runpy.run_path(str(pathlib.Path(__file__).resolve().parents[2]/'internal/service/printing_worker.py'))
# runpy functions retain their own globals dictionary.
g=worker['queue_plan'].__globals__
class PrintingWorkerTest(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=pathlib.Path(self.temp.name)
 def test_uri_and_model_validation(self):
  with patch.dict(g,snapshot=lambda _:None,models=lambda _:[{'id':'legacy','available':True}]):
   for uri in ['smb://user:secret@host/p','ipp://host/p?secret=yes','file:///etc/passwd','ipp://host/p\nBAD']:
    with self.subTest(uri=uri),self.assertRaises(ValueError):g['queue_plan']({'_node':'test','name':'Printer','uri':uri},self.root)
   with self.assertRaises(ValueError):g['queue_plan']({'_node':'test','name':'Printer','uri':'socket://host:9100'},self.root)
 def test_stale_plan_never_connects(self):
  conn=Mock()
  with patch.dict(g,queue_plan=lambda *_:{'revision':'fresh'},connection=conn):
   with self.assertRaises(ValueError):g['apply_queue']({'confirm':True,'revision':'stale'},self.root)
   conn.assert_not_called()
 def test_active_jobs_block_delete(self):
  conn=Mock()
  with patch.dict(g,queue_plan=lambda *_:{'revision':'r','settings':{'name':'P','action':'delete'}},connection=lambda:conn,jobs=lambda:[{'printer':'P','state':5}]):
   with self.assertRaises(ValueError):g['apply_queue']({'confirm':True,'revision':'r'},self.root)
   conn.deletePrinter.assert_not_called()
 def test_ppd_commands_and_filter_paths(self):
  for line in ['*FoomaticRIPCommandLine: "id"','*cupsBackend: "id"','*cupsFilter: "x 0 ../../bin/sh"','*cupsFilter2: "x y 0 /bin/sh"','*cupsFilter: "x 0 safe/../../bin/sh"']:
   with self.subTest(line=line),self.assertRaises(ValueError):g['ppd_upload']({'data':base64.b64encode(('*PPD-Adobe: "4.3"\n'+line).encode()).decode()},self.root)
 def test_invalid_ppd_is_catalogued_but_unavailable(self):
  with patch.dict(g,run=Mock(side_effect=ValueError('invalid constraints'))):
   row=g['ppd_upload']({'data':base64.b64encode(b'*PPD-Adobe: "4.3"\n*NickName: "Broken"').decode()},self.root)
  self.assertFalse(row['available']);self.assertIn('constraints',row['validationError'])
  with patch.dict(g,snapshot=lambda _:None,models=lambda _:[row]):
   with self.assertRaises(ValueError):g['queue_plan']({'_node':'n','name':'P','uri':'ipp://host/ipp','model':row['id']},self.root)
 def test_nested_archive_never_extracts_paths(self):
  inner=io.BytesIO()
  with tarfile.open(fileobj=inner,mode='w') as archive:
   payload=b'*PPD-Adobe: "4.3"';m=tarfile.TarInfo('../../escape.ppd');m.size=len(payload);archive.addfile(m,io.BytesIO(payload));m=tarfile.TarInfo('link.ppd');m.type=tarfile.SYMTYPE;m.linkname='/etc/shadow';archive.addfile(m)
  outer=io.BytesIO()
  with zipfile.ZipFile(outer,'w') as archive:archive.writestr('drivers.tar',inner.getvalue())
  rows=g['archive_ppds'](outer.getvalue());self.assertEqual(len(rows),1);self.assertEqual(rows[0][1],payload)
 def test_zip_traversal_rejected_before_writes(self):
  for name in ['../evil.dll','/evil.dll','installer.exe']:
   blob=io.BytesIO()
   with zipfile.ZipFile(blob,'w') as z:z.writestr(name,b'fixture');z.writestr('driver.inf',b'fixture')
   with self.subTest(name=name),self.assertRaises(ValueError):g['windows_upload']({'data':base64.b64encode(blob.getvalue()).decode()},self.root)
  self.assertFalse((self.root/'windows').exists())
 def test_keytab_alias_preserves_keys(self):
  def counted(b):return struct.pack('>H',len(b))+b
  tail=struct.pack('>IIBHH',2,1234,7,18,4)+b'KEY!'
  entry=struct.pack('>H',2)+counted(b'EXAMPLE.TEST')+counted(b'HTTP')+counted(b'print.example.test')+tail
  raw=b'\x05\x02'+struct.pack('>i',len(entry))+entry
  result=g['keytab_alias'](raw,'HTTP/print.example.test@EXAMPLE.TEST','cups@EXAMPLE.TEST')
  self.assertTrue(result.endswith(tail[4:]));self.assertIn(b'cups',result);self.assertNotIn(b'print.example.test',result)
  for bad in [raw[:-3],b'\x05\x02\xff',b'\x05\x02\x00\x00\x00\x01x']:
   with self.assertRaises((ValueError,struct.error)):g['keytab_alias'](bad,'HTTP/print.example.test@EXAMPLE.TEST','cups@EXAMPLE.TEST')
if __name__=='__main__':unittest.main()
