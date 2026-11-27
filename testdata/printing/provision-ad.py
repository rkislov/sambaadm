"""Run only inside the disposable sambaadm-kea-vm-dc fixture."""
from samba.samdb import SamDB
from samba.auth import system_session
from samba import param
import ldb,pathlib,secrets,subprocess
lp=param.LoadParm();lp.load_default();sam=SamDB(session_info=system_session(),lp=lp);base=str(sam.domain_dn());directory=pathlib.Path('/var/lib/samba/private/printing-test');directory.mkdir(mode=0o700,exist_ok=True)
for branch in ['p10','p11']:
 for kind in ['http','smb','client','windows']:
  account='cups-'+kind+'-'+branch;upn=account+'@SAMBAADM.TEST'
  rows=sam.search(expression='(sAMAccountName='+account+')',attrs=[])
  if not rows:sam.newuser(account,'Aa1!'+secrets.token_urlsafe(48),useusernameascn=True,description='sambaadm disposable printing fixture');rows=sam.search(expression='(sAMAccountName='+account+')',attrs=[])
  message=ldb.Message();message.dn=rows[0].dn
  for name,value in {'userPrincipalName':upn,'msDS-SupportedEncryptionTypes':'24'}.items():message[name]=ldb.MessageElement(value,ldb.FLAG_MOD_REPLACE,name)
  principal=upn
  if kind=='http':
   principal='HTTP/kea-'+branch+'.sambaadm.test@SAMBAADM.TEST';message['servicePrincipalName']=ldb.MessageElement(principal.split('@')[0],ldb.FLAG_MOD_REPLACE,'servicePrincipalName')
  sam.modify(message);path=directory/(kind+'-'+branch+'.keytab');path.unlink(missing_ok=True)
  result=subprocess.run(['samba-tool','domain','exportkeytab',str(path),'--principal='+principal],capture_output=True,text=True)
  if result.returncode:raise RuntimeError(result.stderr)
  print('Prepared',principal)
