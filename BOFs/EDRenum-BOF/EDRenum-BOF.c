#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include "beacon.h"

#define MAX_EDR_STRINGS 200
#define MAX_EDR_STRING_LENGTH 50
#define MAX_PATH_LENGTH MAX_PATH

//KERNEL32
WINBASEAPI HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD dwFlags,DWORD th32ProcessID);
WINBASEAPI WINBOOL WINAPI KERNEL32$Process32First(HANDLE hSnapshot,LPPROCESSENTRY32 lppe);
WINBASEAPI WINBOOL WINAPI KERNEL32$Process32Next(HANDLE hSnapshot,LPPROCESSENTRY32 lppe);
WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, WINBOOL bInheritHandle, DWORD dwProcessId);
WINBASEAPI DWORD WINAPI KERNEL32$QueryFullProcessImageNameA(HANDLE hProcess, DWORD dwFlags, LPSTR lpExeName, PDWORD lpdwSize);
WINBASEAPI HANDLE WINAPI KERNEL32$FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
WINBASEAPI BOOL WINAPI KERNEL32$FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData);
WINBASEAPI BOOL WINAPI KERNEL32$FindClose(HANDLE hFindFile);
//ADVAPI
WINBASEAPI SC_HANDLE WINAPI ADVAPI32$OpenSCManagerA(LPCSTR lpMachineName, LPCSTR lpDatabaseName, DWORD dwDesiredAccess);
WINBASEAPI SC_HANDLE WINAPI ADVAPI32$OpenServiceA(SC_HANDLE hSCManager, LPCSTR lpServiceName, DWORD dwDesiredAccess);
WINBASEAPI BOOL WINAPI ADVAPI32$QueryServiceConfigA(SC_HANDLE hService, LPQUERY_SERVICE_CONFIGA lpServiceConfig, DWORD cbBufSize, LPDWORD pcbBytesNeeded);
WINBASEAPI BOOL WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE hSCObject);
WINBASEAPI BOOL WINAPI ADVAPI32$EnumServicesStatusExA(SC_HANDLE hSCManager, SC_ENUM_TYPE InfoLevel, DWORD dwServiceType, DWORD dwServiceState, LPBYTE lpServices, DWORD cbBufSize, LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned, LPDWORD lpResumeHandle, LPCSTR pszGroupName);
//PSAPI
WINBASEAPI DWORD WINAPI PSAPI$GetModuleFileNameExA(HANDLE hProcess, HMODULE hModule, LPSTR lpFilename, DWORD nSize);
//MSVCRT
WINBASEAPI void *__cdecl MSVCRT$memcpy(void * __restrict__ _Dst,const void * __restrict__ _Src,size_t _MaxCount);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI int __cdecl MSVCRT$strcmp(const char *_Str1,const char *_Str2);
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char *_Str);
WINBASEAPI int __cdecl MSVCRT$_stricmp(const char *string1,const char *string2);
WINBASEAPI char * __cdecl MSVCRT$strstr(const char *haystack, const char *needle);
WINBASEAPI char * __cdecl MSVCRT$strcpy(char * __restrict__ _Dest, const char * __restrict__ _Source);
WINBASEAPI int __cdecl MSVCRT$sprintf(char *__stream, const char *__format, ...);
WINBASEAPI void* WINAPI MSVCRT$malloc(SIZE_T);
DECLSPEC_IMPORT void WINAPI MSVCRT$free(void*);

char edrList[MAX_EDR_STRINGS][MAX_EDR_STRING_LENGTH] = {
    "activeconsole", "ADA-PreCheck", "ahnlab", "amsi.dll", "anti malware", "anti-malware",
    "antimalware", "anti virus", "anti-virus", "antivirus", "appsense", "attivo networks",
    "attivonetworks", "authtap", "avast", "avecto", "bitdefender", "blackberry", "canary",
    "carbonblack", "carbon black", "cb.exe", "check point", "ciscoamp", "cisco amp",
    "countercept", "countertack", "cramtray", "crssvc", "crowdstrike", "csagent", "csfalcon",
    "csshell", "cybereason", "cyclorama", "cylance", "cynet", "cyoptics", "cyupdate", "cyvera",
    "cyserver", "cytray", "darktrace", "deep instinct", "defendpoint", "defender", "eectrl",
    "elastic", "endgame", "f-secure", "forcepoint", "fortinet", "fireeye", "groundling",
    "GRRservic", "harfanglab", "inspector", "ivanti", "juniper networks", "kaspersky", "lacuna",
    "logrhythm", "malware", "malwarebytes", "mandiant", "mcafee", "morphisec", "msascuil",
    "msmpeng", "mssense", "nissrv", "omni", "omniagent", "osquery", "Palo Alto Networks", "pgeposervice",
    "pgsystemtray", "privilegeguard", "procwall", "protectorservic", "qianxin", "qradar",
    "qualys", "rapid7", "redcloak", "red canary", "SanerNow", "sangfor", "secureworks",
    "securityhealthservice", "semlaunchsv", "sentinel", "sentinelone", "sepliveupdat",
    "sisidsservice", "sisipsservice", "sisipsutil", "smc.exe", "smcgui", "snac64", "somma",
    "sophos", "splunk", "srtsp", "symantec", "symcorpu", "symefasi", "sysinternal", "sysmon",
    "tanium", "tda.exe", "tdawork", "tehtris", "threat", "trellix", "tpython", "trend micro",
    "uptycs", "vectra", "watchguard", "wincollect", "windowssensor", "wireshark", "withsecure",
    "xagt.exe", "xagtnotif.exe"
};

char bof_tolower(char c) {
    if (c >= 'A' && c <= 'Z') {
        return c + 32;
    }
    return c;
}

void toLower(char* str) {
    for (int i = 0; str[i]; i++) {
        str[i] = bof_tolower(str[i]);
    }
}

void safe_strncpy(char* dest, const char* src, size_t n) {
    size_t src_len = MSVCRT$strlen(src);
    size_t copy_len = (src_len < n) ? src_len : n - 1;
    MSVCRT$memcpy(dest, src, copy_len);
    dest[copy_len] = '\0';
}

int isEDRString(const char* str) {
    char lowerStr[MAX_PATH];
    safe_strncpy(lowerStr, str, MAX_PATH);
    toLower(lowerStr);

    for (int i = 0; i < MAX_EDR_STRINGS && edrList[i][0] != '\0'; i++) {
        char lowerEDR[MAX_EDR_STRING_LENGTH];
        safe_strncpy(lowerEDR, edrList[i], MAX_EDR_STRING_LENGTH);
        toLower(lowerEDR);

        if (MSVCRT$strstr(lowerStr, lowerEDR) != NULL) {
            return 1;
        }
    }
    return 0;
}

void checkProcesses(formatp *obj) {
    BeaconFormatPrintf(obj, "\n===== Processes =====\n");

    HANDLE hSnapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        BeaconFormatPrintf(obj, "[-] Failed to create process snapshot\n");
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!KERNEL32$Process32First(hSnapshot, &pe32)) {
        BeaconFormatPrintf(obj, "[-] Failed to get first process\n");
        KERNEL32$CloseHandle(hSnapshot);
        return;
    }

    int foundSuspicious = 0;
    do {
        char path[MAX_PATH_LENGTH] = {0};

        HANDLE hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
        if (hProcess) {
            if (PSAPI$GetModuleFileNameExA(hProcess, NULL, path, MAX_PATH_LENGTH) == 0) {
                DWORD pathSize = MAX_PATH_LENGTH;
                if (!KERNEL32$QueryFullProcessImageNameA(hProcess, 0, path, &pathSize)) {
                    MSVCRT$strcpy(path, "Path unavailable");
                }
            }
            KERNEL32$CloseHandle(hProcess);
        } else {
            MSVCRT$strcpy(path, "Access denied");
        }

        if (isEDRString(pe32.szExeFile) || isEDRString(path)) {
            BeaconFormatPrintf(obj, "[!] Suspicious process found:\n");
            BeaconFormatPrintf(obj, "\tName: %s\n", pe32.szExeFile);
            BeaconFormatPrintf(obj, "\tPath: %s\n", path);
            BeaconFormatPrintf(obj, "\tPID: %lu\n\n", pe32.th32ProcessID);
            foundSuspicious = 1;
        }

    } while (KERNEL32$Process32Next(hSnapshot, &pe32));

    KERNEL32$CloseHandle(hSnapshot);

    if (!foundSuspicious) {
        BeaconFormatPrintf(obj, "[+] No suspicious processes found\n\n");
    }
}

void checkDirectories(formatp *obj) {
    BeaconFormatPrintf(obj, "\n===== Directories =====\n");
    const char* directories[] = {
        "C:\\Program Files",
        "C:\\Program Files (x86)",
        "C:\\ProgramData"
    };
    int foundSuspicious = 0;
    for (int i = 0; i < 3; i++) {
        WIN32_FIND_DATAA findFileData;
        char searchPath[MAX_PATH];
        MSVCRT$sprintf(searchPath, "%s\\*", directories[i]);
        HANDLE hFind = KERNEL32$FindFirstFileA(searchPath, &findFileData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    if (MSVCRT$strcmp(findFileData.cFileName, ".") != 0 && MSVCRT$strcmp(findFileData.cFileName, "..") != 0) {
                        if (isEDRString(findFileData.cFileName)) {
                            BeaconFormatPrintf(obj, "[!] Suspicious directory found: %s\\%s\n", directories[i], findFileData.cFileName);
                            foundSuspicious = 1;
                        }
                    }
                }
            } while (KERNEL32$FindNextFileA(hFind, &findFileData) != 0);
            KERNEL32$FindClose(hFind);
        }
    }
    if (!foundSuspicious) {
        BeaconFormatPrintf(obj, "[+] No suspicious directories found\n\n");
    }
}

void checkServices(formatp *obj) {
    BeaconFormatPrintf(obj, "\n===== Services =====\n");
    SC_HANDLE hSCManager = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (hSCManager == NULL) {
        BeaconFormatPrintf(obj, "[-] Failed to open Service Control Manager\n");
        return;
    }
    DWORD bytesNeeded = 0;
    DWORD servicesReturned = 0;
    DWORD resumeHandle = 0;
    ADVAPI32$EnumServicesStatusExA(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &bytesNeeded, &servicesReturned, &resumeHandle, NULL);
    ENUM_SERVICE_STATUS_PROCESSA* services = (ENUM_SERVICE_STATUS_PROCESSA*)MSVCRT$malloc(bytesNeeded);
    if (services == NULL) {
        BeaconFormatPrintf(obj, "[-] Failed to allocate memory for services\n");
        ADVAPI32$CloseServiceHandle(hSCManager);
        return;
    }
    if (!ADVAPI32$EnumServicesStatusExA(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, (LPBYTE)services, bytesNeeded, &bytesNeeded, &servicesReturned, &resumeHandle, NULL)) {
        BeaconFormatPrintf(obj, "[-] Failed to enumerate services\n");
        MSVCRT$free(services);
        ADVAPI32$CloseServiceHandle(hSCManager);
        return;
    }
    int foundSuspicious = 0;
    for (DWORD i = 0; i < servicesReturned; i++) {
        SC_HANDLE hService = ADVAPI32$OpenServiceA(hSCManager, services[i].lpServiceName, SERVICE_QUERY_CONFIG);
        if (hService) {
            DWORD bytesNeeded = 0;
            ADVAPI32$QueryServiceConfigA(hService, NULL, 0, &bytesNeeded);
            QUERY_SERVICE_CONFIGA* pServiceConfig = (QUERY_SERVICE_CONFIGA*)MSVCRT$malloc(bytesNeeded);
            if (pServiceConfig != NULL) {
                if (ADVAPI32$QueryServiceConfigA(hService, pServiceConfig, bytesNeeded, &bytesNeeded)) {
                    char serviceInfo[MAX_PATH * 3];
                    MSVCRT$sprintf(serviceInfo, "%s - %s - %s",
                        services[i].lpServiceName,
                        services[i].lpDisplayName,
                        pServiceConfig->lpBinaryPathName);
                    if (isEDRString(serviceInfo)) {
                        BeaconFormatPrintf(obj, "[!] Suspicious service found:\n");
                        BeaconFormatPrintf(obj, "\tName: %s\n", services[i].lpServiceName);
                        BeaconFormatPrintf(obj, "\tDisplay Name: %s\n", services[i].lpDisplayName);
                        BeaconFormatPrintf(obj, "\tBinary Path: %s\n\n", pServiceConfig->lpBinaryPathName);
                        foundSuspicious = 1;
                    }
                }
                MSVCRT$free(pServiceConfig);
            }
            ADVAPI32$CloseServiceHandle(hService);
        }
    }
    MSVCRT$free(services);
    ADVAPI32$CloseServiceHandle(hSCManager);
    if (!foundSuspicious) {
        BeaconFormatPrintf(obj, "[+] No suspicious services found\n\n");
    }
}

void go(char* args, int len) {
    formatp obj;
    BeaconFormatAlloc(&obj, 8192);
    
    checkProcesses(&obj);
    checkDirectories(&obj);
    checkServices(&obj);
    
    int size = 0;
    char* output = BeaconFormatToString(&obj, &size);
    BeaconOutput(CALLBACK_OUTPUT, output, size);
    BeaconFormatFree(&obj);
}
