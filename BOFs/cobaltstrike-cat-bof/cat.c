#include <windows.h>
#include "beacon.h"

// Compile with x86_64-w64-mingw32-gcc -c cat.c -o cat.x64.o
// Compile with i686-w64-mingw32-gcc -c cat.c -o cat.x86.o

#define MAX_FILE_SIZE 1000000 // Max file size we want to read

DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$ReadFile(HANDLE, PVOID, DWORD, PDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileW(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetLastError (void);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetFileAttributesW (LPCWSTR);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetFileSize (HANDLE, PDWORD);
WINBASEAPI void *__cdecl MSVCRT$malloc(size_t size);
WINBASEAPI void __cdecl MSVCRT$free(void *);

void go(IN PCHAR argv,IN ULONG argc ) {
    datap parser;
	wchar_t * file = NULL;

    BeaconDataParse(&parser, argv, argc);
    file = (wchar_t *) BeaconDataExtract(&parser, NULL);

    // Check if file exists
    DWORD dwAttrib = KERNEL32$GetFileAttributesW(file);
    if (dwAttrib == INVALID_FILE_ATTRIBUTES || dwAttrib & FILE_ATTRIBUTE_DIRECTORY) {
        BeaconPrintf(CALLBACK_ERROR, "File %S does not exist!", file);
        return;
    }

    // Open handle to file
    HANDLE hFile = KERNEL32$CreateFileW((LPCSTR) file, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (hFile == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "Error opening file %S: %d!", file, KERNEL32$GetLastError());
        return;
    }

    // Determine file size
    DWORD dwFileSize = KERNEL32$GetFileSize(hFile, NULL);
    if (dwFileSize == INVALID_FILE_SIZE) {
        BeaconPrintf(CALLBACK_ERROR, "Invalid file size (error %d)!", KERNEL32$GetLastError());
        goto Cleanup;
    }
    // We don't want to read large files
    if (dwFileSize > MAX_FILE_SIZE) {
        BeaconPrintf(CALLBACK_ERROR, "File size too large: %d bytes (max is %d).", dwFileSize, MAX_FILE_SIZE);
        BeaconPrintf(CALLBACK_ERROR, "You should use 'download %S' for large files.", file);
        goto Cleanup;
    }

    // Allocate a buffer
    PVOID buffer = (PVOID) MSVCRT$malloc((size_t) dwFileSize);
    if (buffer == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "Could not allocate %d bytes!", dwFileSize);
        goto Cleanup;
    }

    // Read the file
    DWORD dwRead;
    BOOL bReadSuccess = KERNEL32$ReadFile(hFile, buffer, dwFileSize, &dwRead, NULL);
    if (bReadSuccess == FALSE || dwRead == 0) {
        BeaconPrintf(CALLBACK_ERROR, "Error during read: %d", KERNEL32$GetLastError());
        goto Cleanup;
    }

    // Check if we read enough bytes
    if (dwRead != dwFileSize) {
        BeaconPrintf(CALLBACK_ERROR, "Did not read enough bytes! File is %d bytes, while I could only read %d bytes.", dwFileSize, dwRead);
        goto Cleanup;
    }

    // Success! Print the output to the Cobalt Strike console & free the buffer.
    BeaconOutput(CALLBACK_OUTPUT, buffer, dwFileSize);
    MSVCRT$free(buffer);

    // Close file handle & exit
Cleanup:
    KERNEL32$CloseHandle(hFile);
    return;
}
