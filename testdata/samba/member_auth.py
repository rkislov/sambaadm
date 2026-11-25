import ctypes as C,ctypes.util

def pam_check(username,password):
 class Message(C.Structure):_fields_=[('style',C.c_int),('msg',C.c_char_p)]
 class Response(C.Structure):_fields_=[('resp',C.c_void_p),('code',C.c_int)]
 Callback=C.CFUNCTYPE(C.c_int,C.c_int,C.POINTER(C.POINTER(Message)),C.POINTER(C.POINTER(Response)),C.c_void_p)
 class Conv(C.Structure):_fields_=[('callback',Callback),('data',C.c_void_p)]
 libc=C.CDLL(ctypes.util.find_library('c'));libc.calloc.argtypes=[C.c_size_t,C.c_size_t];libc.calloc.restype=C.c_void_p;libc.strdup.argtypes=[C.c_char_p];libc.strdup.restype=C.c_void_p
 @Callback
 def converse(count,messages,result,data):
  if count<=0 or count>32:return 19
  allocation=libc.calloc(count,C.sizeof(Response));responses=C.cast(allocation,C.POINTER(Response))
  for i in range(count):
   style=messages[i].contents.style
   if style in [1,2]:responses[i].resp=libc.strdup((password if style==1 else username).encode())
  result[0]=responses;return 0
 pam=C.CDLL(ctypes.util.find_library('pam'));handle=C.c_void_p();conv=Conv(converse,None)
 pam.pam_start.argtypes=[C.c_char_p,C.c_char_p,C.POINTER(Conv),C.POINTER(C.c_void_p)];pam.pam_authenticate.argtypes=[C.c_void_p,C.c_int];pam.pam_acct_mgmt.argtypes=[C.c_void_p,C.c_int];pam.pam_end.argtypes=[C.c_void_p,C.c_int]
 code=pam.pam_start(b'login',username.encode(),C.byref(conv),C.byref(handle))
 if code==0:code=pam.pam_authenticate(handle,0)
 if code==0:code=pam.pam_acct_mgmt(handle,0)
 pam.pam_end(handle,code)
 assert code==0,'PAM domain login failed: '+str(code)
