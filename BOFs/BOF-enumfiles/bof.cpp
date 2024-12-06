#include <Windows.h>
#include "base\helpers.h"

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
    // Define the Dynamic Function Resolution declaration for the GetLastError function
    DFR(KERNEL32, GetLastError);
    #define GetLastError KERNEL32$GetLastError 
    
    // EXAMPLE of DFR
    DFR(KERNEL32, GetSystemDirectoryA)
    #define GetSystemDirectoryA KERNEL32$GetSystemDirectoryA

    // BOF entry point
    void go(char* args, int len) 
    {
        datap parser;
        char* path;
        char* filename;

        BeaconDataParse(&parser, args, len);
        path = BeaconDataExtract(&parser, NULL); // directory to enumerate
        /*if (path == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "Error extracting path argument");
            return;
        }*/

        filename = BeaconDataExtract(&parser, NULL); // file name to search
        /*if (filename == NULL) {
            BeaconPrintf(CALLBACK_ERROR, "Error extracting filename argument");
            return;
        }*/

        // Print input argument back to console
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Target path: %s\n", path);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Target file: %s\n", filename);

        char pathSys[MAX_PATH + 1];
        UINT bytesCopied = GetSystemDirectoryA(pathSys, sizeof(pathSys));

        if (bytesCopied == 0) {
            BeaconPrintf(CALLBACK_ERROR, "Error: %i", GetLastError());
        }
        else if (bytesCopied <= sizeof(pathSys)) {
            BeaconPrintf(CALLBACK_OUTPUT, "System Directory: %s", pathSys);
        }
    }
}

// Define a main function for the bebug build
#if defined(_DEBUG) && !defined(_GTEST)

int main(int argc, char* argv[]) {
    // Run BOF's entrypoint
    // To pack arguments for the bof use e.g.: bof::runMocked<int, short, const char*>(go, 6502, 42, "foobar");
    bof::runMocked<char*>(go, "C:\\users\\admin\\", "File.txt"); // Ignore error, it compiles properly
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