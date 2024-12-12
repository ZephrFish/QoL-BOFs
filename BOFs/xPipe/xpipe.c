// IBM X-Force Red|Bobby Cooke|@0xBoku | https://github.com/xforcered/xPipe & https://github.com/boku7/xPipe
// Allot of code is pulled or derived from github.com/trustedsec/CS-Situational-Awareness-BOF & github.com/EspressoCake/HandleKatz_BOF
#include <windows.h>
#include "beacon.h"

#define FileDirectoryInformation 1
#define STATUS_NO_MORE_FILES 0x80000006L
#define STATUS_BUFFER_OVERFLOW 0x80000005L
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004L
#define SE_FILE_OBJECT 1
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
DECLSPEC_IMPORT BOOL	WINAPI KERNEL32$CloseHandle( HANDLE hObject);
DECLSPEC_IMPORT HANDLE	WINAPI KERNEL32$GetProcessHeap();
DECLSPEC_IMPORT LPVOID	WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT BOOL	WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);
DECLSPEC_IMPORT void* __cdecl  MSVCRT$memcpy(LPVOID, LPVOID, size_t);
DECLSPEC_IMPORT void __cdecl   MSVCRT$memset(void*, int, size_t);
WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress (HMODULE hModule, LPCSTR lpProcName);
WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR lpLibFileName);
WINBASEAPI LPWSTR WINAPI KERNEL32$lstrcatW( LPWSTR lpString1, LPCWSTR lpString2);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError (VOID);
WINBASEAPI VOID WINAPI KERNEL32$SetLastError (DWORD dwErrCode);
WINBASEAPI VOID WINAPI KERNEL32$Sleep (DWORD dwMilliseconds);
WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle (HANDLE hObject);
WINADVAPI DWORD WINAPI ADVAPI32$GetSecurityInfo(HANDLE handle, int ObjectType, SECURITY_INFORMATION SecurityInfo, PSID *ppsidOwner, PSID *ppsidGroup, PACL *ppDacl, PACL *ppSacl, PSECURITY_DESCRIPTOR *ppSecurityDescriptor);
WINADVAPI WINBOOL WINAPI ADVAPI32$LookupAccountSidW(LPCWSTR lpSystemName, PSID Sid, LPWSTR Name, LPDWORD cchName, LPWSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse);
WINADVAPI WINBOOL WINAPI ADVAPI32$GetFileSecurityW (LPCWSTR lpFileName, SECURITY_INFORMATION RequestedInformation, PSECURITY_DESCRIPTOR pSecurityDescriptor, DWORD nLength, LPDWORD lpnLengthNeeded);
WINADVAPI WINBOOL WINAPI ADVAPI32$GetAce (PACL pAcl, DWORD dwAceIndex, LPVOID *pAce);
WINADVAPI WINBOOL WINAPI ADVAPI32$GetSecurityDescriptorDacl (PSECURITY_DESCRIPTOR pSecurityDescriptor, LPBOOL lpbDaclPresent, PACL *pDacl, LPBOOL lpbDaclDefaulted);
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char *_Str);
#define intAlloc(size) KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, addr)

typedef struct { LONG Status; ULONG Information; } IO_STATUS_BLOCK;
typedef struct _FILE_DIRECTORY_INFORMATION {
    ULONG                   NextEntryOffset;
    ULONG                   FileIndex;
    LARGE_INTEGER           CreationTime;
    LARGE_INTEGER           LastAccessTime;
    LARGE_INTEGER           LastWriteTime;
    LARGE_INTEGER           ChangeTime;
    LARGE_INTEGER           EndOfFile;
    LARGE_INTEGER           AllocationSize;
    ULONG                   FileAttributes;
    ULONG                   FileNameLength;
    WCHAR                   FileName[1];
} FILE_DIRECTORY_INFORMATION, * PFILE_DIRECTORY_INFORMATION;
typedef LONG (NTAPI * NtQueryDirectoryFile_t)(HANDLE, HANDLE, PVOID, PVOID, IO_STATUS_BLOCK*, PVOID, ULONG, UINT, BOOL, LPVOID, BOOL);

void getPipeACL(wchar_t * pipeName){
    formatp stringFormatObject;  // Cobalt Strike beacon format object we will pass strings too
    BeaconFormatAlloc(&stringFormatObject, 64 * 1024); // allocate memory for our string blob
    DWORD dwRtnCode = 0;
    PSID pOwnerSid, pGroupSid = NULL; // used to return the owner of the pipe
    BOOL bRtnBool = TRUE;
    LPWSTR AcctName = NULL;
    LPWSTR DomainName = NULL;
    DWORD dwAcctName = 1, dwDomainName = 1;
    SID_NAME_USE eUse = SidTypeUnknown;
    PSECURITY_DESCRIPTOR pSD = NULL;
    PACL file_dacl = NULL;
    PSECURITY_DESCRIPTOR SecurityDescriptor;
    DWORD SDSize = 0;
    SecurityDescriptor = (PSECURITY_DESCRIPTOR)intAlloc(SDSize); // allocate memory for the security descriptor we will get for the pipe
    PACL Dacl;
    BOOL DaclPresent;
    BOOL DaclDefaulted;
    BOOL Error = FALSE, Ret = FALSE;
	
    // Get handle to named pipe
    HANDLE hPipe = NULL;
    BeaconFormatPrintf(&stringFormatObject,"Pipe: %ls\n",pipeName);
    hPipe = KERNEL32$CreateFileW(
        pipeName,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
	
    // Get the owner SID of the file.
    ADVAPI32$GetSecurityInfo(
        hPipe,
        SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION,
        &pOwnerSid,
        NULL,
        NULL,
        NULL,
        &pSD);

    // First call to LookupAccountSid to get the buffer sizes.
    ADVAPI32$LookupAccountSidW(
        NULL,    // local computer
        pOwnerSid,
        AcctName,
        (LPDWORD)&dwAcctName,
        DomainName,
        (LPDWORD)&dwDomainName,
        &eUse);

    // Reallocate memory for the buffers.
    AcctName = (LPWSTR)intAlloc((dwAcctName+2) * 2);
    DomainName = (LPWSTR)intAlloc((dwDomainName+2) * 2);
	
    // Second call to LookupAccountSid to get the account name.
    ADVAPI32$LookupAccountSidW(
        NULL,                   // name of local or remote computer
        pOwnerSid,              // security identifier
        AcctName,               // account name buffer
        (LPDWORD)&dwAcctName,   // size of account name buffer 
        DomainName,             // domain name
        (LPDWORD)&dwDomainName, // size of domain name buffer
        &eUse                   // SID type
    );
    BeaconFormatPrintf(&stringFormatObject,"Owner: %ls\\%ls\n", AcctName, DomainName);
    KERNEL32$CloseHandle(hPipe);
    intFree(AcctName);
    intFree(DomainName);
    // find out how much memory we need 
    BOOL success = FALSE;
    DWORD timeout = 0; // 5 second timeout
    // Wait for handle to open up if it is busy from the last GetFileSecurityW call above
    //BeaconPrintf(CALLBACK_OUTPUT,"timeout before 1: %d",timeout);
    while (SDSize == 0 && timeout < 20) {
        //BeaconPrintf(CALLBACK_OUTPUT,"SDSize: %d    |      timeout: %d",SDSize,timeout);
        success = ADVAPI32$GetFileSecurityW(pipeName, DACL_SECURITY_INFORMATION, NULL, 0, &SDSize);
        KERNEL32$Sleep(100);
        timeout++;
    }
    //BeaconPrintf(CALLBACK_OUTPUT,"timeout after 1: %d",timeout);
    if (!success && KERNEL32$GetLastError() != ERROR_INSUFFICIENT_BUFFER)
    {
        return;
    }
    SecurityDescriptor = (PSECURITY_DESCRIPTOR)intAlloc(SDSize);
    if (SecurityDescriptor != NULL)
    {
        //if (ADVAPI32$GetFileSecurityW(pipeName, DACL_SECURITY_INFORMATION, SecurityDescriptor, SDSize, &SDSize))
        success = FALSE;
        timeout = 0; // 5 second timeout
        // Wait for handle to open up if it is busy from the last GetFileSecurityW call above
        //BeaconPrintf(CALLBACK_OUTPUT,"timeout before 2: %d",timeout);
        while (success != TRUE && timeout < 50) {
            success = ADVAPI32$GetFileSecurityW(pipeName, DACL_SECURITY_INFORMATION, SecurityDescriptor, SDSize, &SDSize);
            KERNEL32$Sleep(100);
            timeout++;
        }
        //BeaconPrintf(CALLBACK_OUTPUT,"timeout after 2: %d",timeout);
        if (success)
        {
            if (ADVAPI32$GetSecurityDescriptorDacl(SecurityDescriptor, &DaclPresent, &Dacl, &DaclDefaulted))
            {
                if (DaclPresent)
                {
                    PACCESS_ALLOWED_ACE Ace;
                    DWORD AceIndex = 0;
                    // dump the ACL 
                    while (ADVAPI32$GetAce(Dacl, AceIndex, (PVOID*)&Ace))
                    {
                        SID_NAME_USE Use;
                        DWORD NameSize = 0;
                        DWORD DomainSize = 0;
                        LPWSTR Name = NULL;
                        LPWSTR Domain = NULL;
                        DWORD IndentAccess = 0;

                        DWORD AccessMask = Ace->Mask;
                        PSID Sid = (PSID)&Ace->SidStart;
                        if (!ADVAPI32$LookupAccountSidW(NULL,
                            Sid,
                            Name,
                            &NameSize,
                            Domain,
                            &DomainSize,
                            &Use))
                        {
                            if (KERNEL32$GetLastError() != ERROR_INSUFFICIENT_BUFFER)
                            {
                                Error = TRUE;
                                break;
                            }
                            Name = (LPWSTR)intAlloc((NameSize + DomainSize) * 2);
                            if (Name == NULL)
                            {
                                KERNEL32$SetLastError(ERROR_NOT_ENOUGH_MEMORY);
                                Error = TRUE;
                                break;
                            }
                            Domain = Name + NameSize;
                            Name[0] = L'\0';
                            if (DomainSize != 0)
                                Domain[0] = L'\0';
                            if (ADVAPI32$LookupAccountSidW(NULL,
                                Sid,
                                Name,
                                &NameSize,
                                Domain,
                                &DomainSize,
                                &Use))
                            {
                                if (Domain[0] == 0x00){
                                    BeaconFormatPrintf(&stringFormatObject,"%ls\n",Name);
                                }
                                else {
                                    BeaconFormatPrintf(&stringFormatObject,"%ls\\%ls\n",Name,Domain);
                                }
                            }
                            intFree(Name);
                            Name = NULL;
                            Domain = NULL;
                        }
                        // The access mask of the ACE will have a bunch of bits set. For each bit that is set, it maps to a permission 
                        // FILE_ALL_ACCESS #define FILE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF)
                        if (Ace->Mask == 0x1f01ff)
                        {
                            BeaconFormatPrintf(&stringFormatObject,"   + FILE_ALL_ACCESS\n");
                        }
                        else {
                            // SYNCHRONIZE #define SYNCHRONIZE   (0x00100000L)
                            if (Ace->Mask & 0x100000)
                            {
                                BeaconFormatPrintf(&stringFormatObject,"   + SYNCHRONIZE\n");
                            }
                            // READ_CONTROL = 0x00020000L // for example if the 17th bit is set in the ACE mask, then the user has READ_CONTROL rights on this pipe
                            if (Ace->Mask & 0x20000)
                            {
                                BeaconFormatPrintf(&stringFormatObject,"   + READ_CONTROL\n");
                            }
                            //  FILE_WRITE_DATA           ( 0x0002 )    // file & pipe // winnt.h // AKA FILE_ADD_FILE
                            if (Ace->Mask & 0x2)
                            {
                                BeaconFormatPrintf(&stringFormatObject,"   + FILE_WRITE_DATA\n");
                            }
                            //  FILE_READ_DATA            ( 0x0001 ) bit1 set   // file & pipe // AKA FILE_LIST_DIRECTORY
                            if (Ace->Mask & 0x1)
                            {
                                BeaconFormatPrintf(&stringFormatObject,"   + FILE_READ_DATA\n");
                            }
                            //  FILE_CREATE_PIPE_INSTANCE(0x0004)    bit3 set   // named pipe // aka FILE_ADD_SUBDIRECTORY
                            if (Ace->Mask & 0x4)
                            {
                                BeaconFormatPrintf(&stringFormatObject,"   + FILE_CREATE_PIPE_INSTANCE\n");
                            }
                            //  FILE_WRITE_ATTRIBUTES     ( 0x0100 ) bit9 set   // all
                            if (Ace->Mask & 0x100)
                            {
                                BeaconFormatPrintf(&stringFormatObject,"   + FILE_WRITE_ATTRIBUTES\n");
                            }
                            //  FILE_READ_ATTRIBUTES      ( 0x0080 ) bit8 set   // all
                            if (Ace->Mask & 0x80)
                            {
                                BeaconFormatPrintf(&stringFormatObject,"   + FILE_READ_ATTRIBUTES\n");
                            }
                        }
                        AceIndex++;
                    }
                }
            }
        }
        intFree(SecurityDescriptor);
        SecurityDescriptor = NULL;
    }
    int sizeOfObject   = 0;
    char* outputString = NULL;
    outputString = BeaconFormatToString(&stringFormatObject, &sizeOfObject);
    BeaconOutput(CALLBACK_OUTPUT, outputString, sizeOfObject);
    BeaconFormatFree(&stringFormatObject);
}

void pipelist(){
    LONG ntStatus;
    IO_STATUS_BLOCK IoStatusBlock;
    HANDLE hPipe;
    BOOL RestartScan = TRUE;
    PFILE_DIRECTORY_INFORMATION dir_info, pipe_info;
    NtQueryDirectoryFile_t NtQueryDirectoryFile = (NtQueryDirectoryFile_t)KERNEL32$GetProcAddress(KERNEL32$LoadLibraryA("ntdll.dll"),"NtQueryDirectoryFile");
    hPipe = KERNEL32$CreateFileA("\\\\.\\Pipe\\", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE){ return;}
    unsigned __int64 qwSize = 0x1000;
    LPVOID buffer = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), 0, qwSize);
    MSVCRT$memset(buffer, 0x00, qwSize);
    dir_info = (PFILE_DIRECTORY_INFORMATION)buffer;
    size_t output_size = 0x100000; // Allocate a big amount of memory in the heap write the pipe names too
    LPVOID output = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), 0, output_size);
    MSVCRT$memset(output, 0x00, output_size);
    char* outptr = (char*)output; // This keeps track of our position as we write the pipe names to the big buffer we allocated in the heap
    unsigned __int64 overflowChk = 0; // check that we are not writing into unallocated memory to prevent beacon from crashing. 
    BOOL flag = 0;
    while (1){ // This loop enumerates the directories that pipes are in. The second loop prints the pipes in the directory. On next 1st loop, we enumerate the next dir holding pipes
        ntStatus = NtQueryDirectoryFile(hPipe, NULL, NULL, NULL, &IoStatusBlock, dir_info, qwSize, FileDirectoryInformation, FALSE, NULL, RestartScan);
        if (ntStatus != NO_ERROR) {
            // If we need more memory we increase the size and reallocate
            if (ntStatus == STATUS_BUFFER_OVERFLOW || ntStatus == STATUS_INFO_LENGTH_MISMATCH) {
                KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, buffer);
                qwSize *= 2;
                buffer = KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), 0, qwSize);
            }
            // If there are no more directories holding pipes to enumerate then we exit the 1st loop and print pipes
            else if (ntStatus == STATUS_NO_MORE_FILES) { break; }
            else { return; }
        }
        pipe_info = dir_info;
        while (1){            // This loop prints all pipes located in the current directory we are enumerating
            outptr += 18;
            outptr += pipe_info->FileNameLength;
            overflowChk = (unsigned __int64)outptr - (unsigned __int64)output; // make sure we don't crash beacon
            if (overflowChk > output_size) { break; }
            KERNEL32$lstrcatW((wchar_t *)output, L"\\\\.\\pipe\\");
            KERNEL32$lstrcatW((wchar_t *)output, pipe_info->FileName);
            outptr[0] = 0x0A; // After the pipe name we put a \n so pipes will print as a list
            outptr[1] = 0x00; // These are to make sure we dont get bad characters as we concatinate all the pipes together
            outptr[2] = 0x00;
            outptr[3] = 0x00;
            outptr += 2; // move to the next character after the \n we wrote. (2 because a single unicode character in windows is 2 bytes)
            if (pipe_info->NextEntryOffset == 0){ break; }
            pipe_info = (PFILE_DIRECTORY_INFORMATION)((char*)pipe_info + pipe_info->NextEntryOffset);
        }
        if (overflowChk > output_size) { flag = 1; break; }
        RestartScan = FALSE; // This double while loop is: Loop1 = Directory, Loop 2 = Pipes in Directory
    }
    // Print all the pipes in one go
    BeaconPrintf(CALLBACK_OUTPUT,"%ls", (wchar_t*)output);
    // Error message - If this happens you got quite allot of pipes. This is mainly here in the event that does happen so beacon doesn't crash
    // If you get this, then increase the size of the `output_size` variable and recompile
    if (flag == 1){ BeaconPrintf(CALLBACK_ERROR,"\n[!] Buffer to small. Truncating pipelist and exiting..\n"); }
    // Cleanup - free heaps & close handle
    MSVCRT$memset(output, 0x00, output_size); // overwrite the heaps with 0x00's so there is no leftover strings after heap is free
    MSVCRT$memset(buffer, 0x00, qwSize);
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, output); 
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, buffer);
    KERNEL32$CloseHandle(hPipe);
}

void go(char * args, int len) {
    datap parser;
    char * pipeName = NULL;
    wchar_t * wPipeName = NULL;
    size_t pipeNameLen = 0;
    BeaconDataParse(&parser, args, len);
    pipeName = BeaconDataExtract(&parser, NULL);
    //BeaconPrintf(CALLBACK_OUTPUT,"pipeName: %s", pipeName);
    if (pipeName[0] == 'L'){
        pipelist();
        return;
    }else{
        pipeNameLen = MSVCRT$strlen(pipeName);
        pipeNameLen = pipeNameLen*2+4;
        wPipeName = (wchar_t *)intAlloc(pipeNameLen);
        toWideChar(pipeName,wPipeName,pipeNameLen); // Convert the ASCII pipe name from beacon to a Unicode pipe name
        getPipeACL(wPipeName);
    }
}
