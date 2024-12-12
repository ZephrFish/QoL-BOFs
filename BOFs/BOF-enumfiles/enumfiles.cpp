#include <Windows.h>
#include "base\helpers.h"

// Basic enumeration BOF for finding local files/folders of interest during post-exploitation

/**
 * For the debug build we want:
 *   a) Include the mock-up layer
 *   b) Undefine DECLSPEC_IMPORT since the mocked Beacon API
 *      is linked against the the debug build.
 */
#ifdef _DEBUG
#include "base\mock.h"
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#endif


extern "C" {
#include "beacon.h"

	// Function definitions
	DFR(KERNEL32, GetLastError);
	#define GetLastError KERNEL32$GetLastError 
	DFR(KERNEL32, GetFileAttributesA)
	#define GetFileAttributesA KERNEL32$GetFileAttributesA
	DFR(KERNEL32, GetEnvironmentVariableA)
	#define GetEnvironmentVariableA KERNEL32$GetEnvironmentVariableA

	// String function definitions
	DFR(MSVCRT, strcmp);
	#define strcmp MSVCRT$strcmp
	DFR(MSVCRT, strlen);
	#define strlen MSVCRT$strlen
	DFR(MSVCRT, strcat);
	#define strcat MSVCRT$strcat
	DFR(MSVCRT, strcpy);
	#define strcpy MSVCRT$strcpy
	DFR(MSVCRT, malloc);
	#define malloc MSVCRT$malloc
	DFR(MSVCRT, free);
	#define free MSVCRT$free

	void getFile(char* lolbin, char* filePath)
	{
		DWORD dwAttrs = GetFileAttributesA(filePath);
		if (dwAttrs == INVALID_FILE_ATTRIBUTES) { // File/folder not found
			//BeaconPrintf(CALLBACK_ERROR, "Error: %i", GetLastError());
			return;
		}
		else {
			BeaconPrintf(CALLBACK_OUTPUT, "[*] Found %s: %s", lolbin, filePath);
			return;
		}
	}
	
	// Get environment variable
	char* GetEnv(char* name)
	{
		DWORD size = 0;
		DWORD buffSize = 256; //max path size
		char* buffer = NULL;
		buffer = (char*)malloc(buffSize);

		size = GetEnvironmentVariableA(name, buffer, buffSize);
		if (size > 0) { //success
			return buffer;
		}
		else { //failed
			free(buffer); //Cleanup
			return NULL;
		}
	}
	
	// Function to concatenate two char* strings
	char* concatenateChar(char* str1, char* str2) 
	{
		// Allocate memory for the concatenated string
		char* result = NULL;
		result = (char*)malloc(strlen(str1) + strlen(str2) + 1); // +1 for the null terminator

		// Copy the first string to the result buffer
		strcpy(result, str1);
		// Concatenate the second string to the result buffer
		strcat(result, str2);

		return result;
	}
	
	// BOF entry point
	void go(char* args, int len) 
	{
		datap parser;
		char* enumType;

		BeaconDataParse(&parser, args, len);
		enumType = BeaconDataExtract(&parser, NULL); // Arg: Type of enumeration

		if (enumType == NULL) {
			BeaconPrintf(CALLBACK_OUTPUT, "[*] Missing enum type argument. Exiting...\n");
			return;
		}
		
		// Print input argument back to console
		BeaconPrintf(CALLBACK_OUTPUT, "[*] Target file enumeration: %s\n", enumType);
		
		// Get required environment variables
		char* env_localAppData = GetEnv("LOCALAPPDATA");
		char* env_appData = GetEnv("APPDATA");
		char* env_system = GetEnv("WINDIR");
		
		// Concat environment variable paths
		char* path_teams = concatenateChar(env_localAppData, "\\Microsoft\\Teams");
		char* path_onedrive = concatenateChar(env_localAppData, "\\Microsoft\\OneDrive");
		char* path_chrome = concatenateChar(env_localAppData, "\\Google\\Chrome\\User Data");
		char* path_edge = concatenateChar(env_localAppData, "\\Microsoft\\Edge\\User Data");
		char* path_firefox = concatenateChar(env_appData, "\\Mozilla\\Firefox\\Profiles");
		char* path_sys32 = concatenateChar(env_system, "\\System32");
		char* path_syswow64 = concatenateChar(env_system, "\\SysWOW64");
		char* path_python1 = concatenateChar(env_localAppData, "\\Microsoft\\WindowsApps\\python.exe");
		char* path_python2 = concatenateChar(env_localAppData, "\\Programs\\Python");
		char* path_powershellhist = concatenateChar(env_appData, "\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt");
		
		// Search for all lolbins
		if (strcmp(enumType, "all") == 0) {
			BeaconPrintf(CALLBACK_OUTPUT, "\nLOLBins:");
			getFile("System32 Folder", path_sys32); // System32 directory
			getFile("SysWOW64 Folder", path_syswow64); // SysWOW64 directory
			getFile("DotNet Folder", "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319"); // DotNet directory
			getFile("DotNet Folder (x86)", "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319"); // DotNet directory
			getFile("Teams Folder", path_teams); // Teams directory
			getFile("OneDrive Folder", path_onedrive); // OneDrive directory
			getFile("VS Diagnostics EXE", "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\Team Tools\\DiagnosticsHub\\Collector\\VSDiagnostics.exe"); // VS diagnostics
			getFile("Remote Debugger EXE", "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\remote.exe"); // Remote.exe
			getFile("Remote Debugger (x86) EXE", "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x86\\remote.exe"); // Remote.exe
			getFile("Protocol Handler EXE", "C:\\Program Files\\Microsoft Office\\Office15\\ProtocolHandler.exe"); // ProtocolHandler.exe
			getFile("Protocol Handler EXE", "C:\\Program Files\\Microsoft Office\\Office16\\ProtocolHandler.exe"); // ProtocolHandler.exe
			getFile("Bash EXE", "C:\\Windows\\System32\\bash.exe"); // Bash.exe
			getFile("Bash EXE (x86)", "C:\\Windows\\SysWOW64\\bash.exe"); // Bash.exe

			BeaconPrintf(CALLBACK_OUTPUT, "\nRemoting:");
			getFile("SSH", "C:\\windows\\system32\\OpenSSH\\ssh.exe"); // SSH
			getFile("Putty", "C:\\Program Files\\PuTTY"); // Putty
			getFile("Putty (x86)", "C:\\Program Files (x86)\\PuTTY"); // Putty
			getFile("TeamViewer", "C:\\Program Files\\TeamViewer"); // TeamViewer directory
			getFile("TeamViewer (x86)", "C:\\Program Files (x86)\\TeamViewer"); // TeamViewer directory
			getFile("AnyDesk", "C:\\Program Files (x86)\\AnyDesk"); // AnyDesk directory

			BeaconPrintf(CALLBACK_OUTPUT, "\nUnattended Files:");
			getFile("Unattended Install File", "C:\\Windows\\Panther\\Unattend.xml"); // Unattended files
			getFile("Unattended Install File", "C:\\Windows\\Panther\\Unattended.xml"); // Unattended files
			getFile("Unattended Install File", "C:\\Windows\\Panther\\Unattend\\Unattended.xml"); // Unattended files

			BeaconPrintf(CALLBACK_OUTPUT, "\nBrowsers:");
			getFile("Chrome - Installation (x86)", "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe"); // Chrome installation
			getFile("Chrome - Installation", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"); // Chrome installation
			getFile("Chrome - Installation (Win7)", "C:\\Program Files (x86)\\Google\\Application\\chrome.exe"); // Chrome installation
			getFile("Chrome - User Data Folder", path_chrome); // Chrome User Data directory
			getFile("Edge - Installation", "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"); // Edge installation
			getFile("Edge - User Data Folder", path_edge); // Edge User Data directory
			getFile("IE - Installation", "C:\\Program Files\\Internet Explorer\\iexplore.exe"); // Internet Explorer installation
			getFile("FireFox - Installation (x86)", "C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe"); // Firefox installation
			getFile("FireFox - Installation", "C:\\Program Files\\Mozilla Firefox\\firefox.exe"); // Firefox installation
			getFile("FireFox - Profiles Folder", path_firefox); // Firefox Profiles directory
			
			BeaconPrintf(CALLBACK_OUTPUT, "\nWeb Servers:");
			getFile("IIS", "C:\\inetpub"); // IIS directory
			getFile("Apache - Access Log", "C:\\apache\\logs\\access.log"); // Apache log
			getFile("Apache - Error Log", "C:\\apache\\logs\\error.log"); // Apache log
			getFile("Apache - PHP config", "C:\\apache\\php\\php.ini"); // Apache PHP
			getFile("Apache - PHP config", "C:\\Program Files\\Apache Group\\Apache"); // Apache installation
			getFile("PHP - Config", "C:\\php\\php.ini"); // PHP
			getFile("PHP - Config", "C:\\WINNT\\php.ini"); // PHP
			getFile("PHP - Config", "C:\\WINDOWS\\php.ini"); // PHP
			getFile("PHP 4 - Config", "C:\\php4\\php.ini"); // PHP
			getFile("PHP 5 - Config", "C:\\php5\\php.ini"); // PHP
			getFile("XAMPP Folder", "C:\\xampp"); // XAMPP
			getFile("XAMPP - Installation", "C:\\Program Files\\xampp"); // XAMPP

			BeaconPrintf(CALLBACK_OUTPUT, "\nPython:");
			getFile("Python", path_python1); // Python directory
			getFile("Python", path_python2); // Python directory
			getFile("Python", "C:\\Python"); // Python directory

			BeaconPrintf(CALLBACK_OUTPUT, "\nPowerShell History:");
			getFile("PowerShell History", path_powershellhist); // PowerShell console history file 
			
		}
		else if (strcmp(enumType, "remoting") == 0) {
			getFile("SSH", "C:\\windows\\system32\\OpenSSH\\ssh.exe"); // SSH
			getFile("Putty", "C:\\Program Files\\PuTTY"); // Putty directory
			getFile("Putty (x86)", "C:\\Program Files (x86)\\PuTTY"); // Putty directory
			getFile("TeamViewer", "C:\\Program Files\\TeamViewer"); // TeamViewer directory
			getFile("TeamViewer (x86)", "C:\\Program Files (x86)\\TeamViewer"); // TeamViewer directory
			getFile("AnyDesk", "C:\\Program Files (x86)\\AnyDesk"); // AnyDesk directory
		}
		else if (strcmp(enumType, "lolbins") == 0) {
			getFile("System32 Folder", path_sys32); // System32 directory
			getFile("SysWOW64 Folder", path_syswow64); // SysWOW64 directory
			getFile("DotNet Folder", "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319"); // DotNet directory
			getFile("DotNet Folder (x86)", "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319"); // DotNet directory
			getFile("Teams Folder", path_teams); // Teams directory
			getFile("OneDrive Folder", path_onedrive); // OneDrive directory
			getFile("VS Diagnostics EXE", "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\Team Tools\\DiagnosticsHub\\Collector\\VSDiagnostics.exe"); // VS diagnostics
			getFile("Remote Debugger EXE", "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\remote.exe"); // Remote.exe
			getFile("Remote Debugger (x86) EXE", "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x86\\remote.exe"); // Remote.exe
			getFile("Protocol Handler EXE", "C:\\Program Files\\Microsoft Office\\Office15\\ProtocolHandler.exe"); // ProtocolHandler.exe
			getFile("Protocol Handler EXE", "C:\\Program Files\\Microsoft Office\\Office16\\ProtocolHandler.exe"); // ProtocolHandler.exe
			getFile("Bash EXE", "C:\\Windows\\System32\\bash.exe"); // Bash.exe
			getFile("Bash EXE (x86)", "C:\\Windows\\SysWOW64\\bash.exe"); // Bash.exe
		}
		else if (strcmp(enumType, "browser-installs") == 0) {
			getFile("Chrome - Installation (x86)", "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe"); // Chrome installation
			getFile("Chrome - Installation", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"); // Chrome installation
			getFile("Chrome - Installation (Win7)", "C:\\Program Files (x86)\\Google\\Application\\chrome.exe"); // Chrome installation
			getFile("Edge - Installation", "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"); // Edge installation
			getFile("IE - Installation", "C:\\Program Files\\Internet Explorer\\iexplore.exe"); // Internet Explorer installation
			getFile("FireFox - Installation (x86)", "C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe"); // Firefox installation
			getFile("FireFox - Installation", "C:\\Program Files\\Mozilla Firefox\\firefox.exe"); // Firefox installation
		}
		else if (strcmp(enumType, "browser-userdata") == 0) {
			getFile("Chrome - User Data Folder", path_chrome); // Chrome User Data directory
			getFile("Edge - User Data Folder", path_edge); // Edge User Data directory
			getFile("FireFox - Profiles Folder", path_firefox); // Firefox Profiles directory
		}
		else if (strcmp(enumType, "webservers") == 0) {
			getFile("IIS", "C:\\inetpub"); // IIS directory
			getFile("Apache - Access Log", "C:\\apache\\logs\\access.log"); // Apache log
			getFile("Apache - Error Log", "C:\\apache\\logs\\error.log"); // Apache log
			getFile("Apache - PHP config", "C:\\apache\\php\\php.ini"); // Apache PHP
			getFile("Apache - PHP config", "C:\\Program Files\\Apache Group\\Apache"); // Apache installation
			getFile("PHP - Config", "C:\\php\\php.ini"); // PHP
			getFile("PHP - Config", "C:\\WINNT\\php.ini"); // PHP
			getFile("PHP - Config", "C:\\WINDOWS\\php.ini"); // PHP
			getFile("PHP 4 - Config", "C:\\php4\\php.ini"); // PHP
			getFile("PHP 5 - Config", "C:\\php5\\php.ini"); // PHP
			getFile("XAMPP Folder", "C:\\xampp"); // XAMPP
			getFile("XAMPP - Installation", "C:\\Program Files\\xampp"); // XAMPP
		}
		else if (strcmp(enumType, "unattended") == 0) {
			getFile("Unattended Install File", "C:\\Windows\\Panther\\Unattend.xml"); // Unattended files
			getFile("Unattended Install File", "C:\\Windows\\Panther\\Unattended.xml"); // Unattended files
			getFile("Unattended Install File", "C:\\Windows\\Panther\\Unattend\\Unattended.xml"); // Unattended files
		}
		else if (strcmp(enumType, "powershell-hist") == 0) {
			getFile("PowerShell History", path_powershellhist); // PowerShell console history file
		}
		else if (strcmp(enumType, "python") == 0) {
			getFile("Python", path_python1); // Python directory
			getFile("Python", path_python2); // Python directory
			getFile("Python", "C:\\Python"); // Python directory
		}
		
		// Cleanup stuff & exit
		return;
	}
}

// Define a main function for the bebug build
#if defined(_DEBUG) && !defined(_GTEST)

int main(int argc, char* argv[]) {
	// Run BOF's entrypoint
	// To pack arguments for the bof use e.g.: bof::runMocked<int, short, const char*>(go, 6502, 42, "foobar");
	bof::runMocked<char*>(go, "all"); // Ignore error, it compiles properly
	return 0;
}

// Define unit tests
#elif defined(_GTEST)
#include <gtest\gtest.h>
#include "bof.h"

TEST(BofTest, Test1) {
	std::vector<bof::output::OutputEntry> got =
		bof::runMocked<>(go);
	std::vector<bof::output::OutputEntry> expected = {
		{CALLBACK_OUTPUT, "System Directory: C:\\Windows\\system32"}
	};
	// It is possible to compare the OutputEntry vectors, like directly
	// ASSERT_EQ(expected, got);
	// However, in this case, we want to compare the output, ignoring the case.
	ASSERT_EQ(expected.size(), got.size());
	ASSERT_STRCASEEQ(expected[0].output.c_str(), got[0].output.c_str());
}
#endif