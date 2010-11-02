#ifndef REGISTRY_INCLUDED
#define REGISTRY_INCLUDED

#include <tchar.h>

LONG	SaveDwordToRegistry(HKEY hKey,TCHAR *KeyName,DWORD Value);
LONG	ReadDwordFromRegistry(HKEY hKey,TCHAR *KeyName,DWORD *pReturnValue);
LONG	SaveStringToRegistry(HKEY hKey,TCHAR *KeyName,TCHAR *String);
LONG	ReadStringFromRegistry(HKEY hKey,TCHAR *KeyName,TCHAR *String,DWORD BufferSize);

#endif