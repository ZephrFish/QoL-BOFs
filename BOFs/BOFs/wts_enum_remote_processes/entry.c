#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <wtsapi32.h>
#include <winbase.h>
#include <sddl.h>
#include "beacon.h"

DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError();

DECLSPEC_IMPORT VOID WINAPI WTSAPI32$WTSCloseServer(
  HANDLE hServer
);
DECLSPEC_IMPORT HANDLE WINAPI WTSAPI32$WTSOpenServerA(
  LPSTR pServerName
);
DECLSPEC_IMPORT BOOL WINAPI WTSAPI32$WTSEnumerateProcessesA(
  HANDLE             hServer,
  DWORD              Reserved,
  DWORD              Version,
  PWTS_PROCESS_INFOA *ppProcessInfo,
  DWORD              *pCount
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$LookupAccountSidA(
  LPCSTR        lpSystemName,
  PSID          Sid,
  LPSTR         Name,
  LPDWORD       cchName,
  LPSTR         ReferencedDomainName,
  LPDWORD       cchReferencedDomainName,
  PSID_NAME_USE peUse
);

DECLSPEC_IMPORT HGLOBAL WINAPI KERNEL32$GlobalAlloc(
  UINT   uFlags,
  SIZE_T dwBytes
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$ConvertSidToStringSidA(
  PSID  Sid,
  LPSTR *StringSid
);

WINBASEAPI int __cdecl MSVCRT$sprintf(char *__stream, const char *__format, ...);

int GetUserInfo(LPCSTR host, PSID pSidOwner, char *username)
{
    BOOL bRtnBool;
    LPTSTR AcctName = "", DomainName = "";
    DWORD dwAcctName = 1, dwDomainName = 1;
    SID_NAME_USE eUse = SidTypeUnknown;

    bRtnBool = ADVAPI32$LookupAccountSidA(
            host,             // Local computer
            pSidOwner,        // Pointer to the SID to lookup for
            AcctName,         // The account name of the SID (pSIDOwner)
            (LPDWORD)&dwAcctName,   // Size of the AcctName in TCHAR
            DomainName,       // Pointer to the name of the Domain where the account name was found
            (LPDWORD)&dwDomainName, // Size of the DomainName in TCHAR
            &eUse);                 // Value of the SID_NAME_USE enum type that specify the SID type

    
      // Allocate memory for the AcctName.
      AcctName = (LPTSTR)KERNEL32$GlobalAlloc(GMEM_FIXED, dwAcctName);
      // VErify
      if(AcctName == NULL)
      {
            
            return -1;
      }

      DomainName = (LPTSTR)KERNEL32$GlobalAlloc(GMEM_FIXED, dwDomainName);

      // Check GetLastError() for GlobalAlloc() error condition.
      if(DomainName == NULL)
      {
            return -1;

      }

      // Second call to LookupAccountSid() to get the account name.
      bRtnBool = ADVAPI32$LookupAccountSidA(
            host,       // name of local or remote computer
            pSidOwner,  // security identifier, SID
            AcctName,   // account name buffer
            (LPDWORD)&dwAcctName,         // size of account name buffer
            DomainName, // domain name
            (LPDWORD)&dwDomainName,       // size of domain name buffer
            &eUse);           // SID type

      // Verify

      if(bRtnBool == FALSE)
      {
            DWORD dwErrorCode = KERNEL32$GetLastError();        

            if(dwErrorCode == ERROR_NONE_MAPPED)
                      BeaconPrintf(CALLBACK_ERROR  , "Account not found, error %u\n", KERNEL32$GetLastError());
            else
            {
                      BeaconPrintf(CALLBACK_ERROR  , "LookupAccountSid() failed, error %u\n", KERNEL32$GetLastError());
                  return -1;
            }
      }
      else if (bRtnBool == TRUE)
      {
// Print the account name.
            MSVCRT$sprintf(username, "%s\\%s", DomainName, AcctName);
      }
            
}

void go(char *args, int len) {
    
    CHAR *host;
    datap parser;
    WTS_PROCESS_INFOA *p;
    DWORD dwCount = 0;
    HANDLE hServer = NULL;

    BeaconDataParse(&parser, args, len);
    host = BeaconDataExtract(&parser, NULL);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Opening handle to remote server");

    hServer = WTSAPI32$WTSOpenServerA(host);

    if(hServer == INVALID_HANDLE_VALUE)
    {
       BeaconPrintf(CALLBACK_ERROR  , "WTSOpenServerA() failed, error %u\n", KERNEL32$GetLastError());
    }
    BOOL res = WTSAPI32$WTSEnumerateProcessesA(hServer, 0 , 1, &p, &dwCount);

    if (!res)
    {
        BeaconPrintf(CALLBACK_ERROR  , "WTSEnumerateProcessesA() failed, error %u\n", KERNEL32$GetLastError());
    }
    
    for (int i = 0; i < dwCount; i++)
    {
        PSID userSid = p[i].pUserSid;
        char username[100];
        LPTSTR StringSid = NULL;
        GetUserInfo(host, userSid, username);
        ADVAPI32$ConvertSidToStringSidA(userSid, &StringSid);

        BeaconPrintf(CALLBACK_OUTPUT, "[+] Process = %s, PID = %d, Owner = %s", p[i].pProcessName, p[i].ProcessId, username);

    }

    WTSAPI32$WTSOpenServerA(hServer);

}