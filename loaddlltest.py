from ctypes import *
lib = windll.LoadLibrary(r"Debug\firefoxdecrypt.dll");
#if (lib.Add(1,2) != 3):
#  print "error!"
aa = create_string_buffer(12+1)
memset(aa,0,sizeof(aa))
#print (aa)

##print(lib.GetHello(aa))
print(lib.getAllAuthData())
print(string_at(lib.getAllAuthData()))
print (aa)
