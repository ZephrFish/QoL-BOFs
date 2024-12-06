# xPipe Cobalt Strike BOF (x64)
Cobalt Strike Beacon Object File (BOF) to list active Pipes & return their Owner & Discretionary Access Control List (DACL) permissions.

![](/xpipe.png)

https://github.com/xforcered/xPipe & https://github.com/boku7/xPipe
## Usage
### List All Local Active Pipes
To list all the pipes, simply run the `xpipe` command from Cobalt Strikes interactive beacon console after importing the `xpipe.cna` aggressor script.
```
beacon> xpipe
[*] xpipe (IBM X-Force Red|Bobby Cooke|@0xBoku)
\\.\pipe\InitShutdown
\\.\pipe\lsass
\\.\pipe\ntsvcs
\\.\pipe\scerpc
\\.\pipe\atsvc
++
```

### Show Pipe Owner & DACL Permissions
To show the Owner & DACL permissions of a pipe, simply supply the pipe name as the first argument to the `xpipe` command.
+ If you lack permissions to query the pipe, the BOF will timeout after 5 seconds and return thread control to the operator.
```
beacon> xpipe \\.\pipe\lsass
[*] xpipe (IBM X-Force Red|Bobby Cooke|@0xBoku)
Pipe: \\.\pipe\lsass
Owner: Administrators\BUILTIN
Everyone
   + SYNCHRONIZE
   + READ_CONTROL
   + FILE_WRITE_DATA
   + FILE_READ_DATA
   + FILE_WRITE_ATTRIBUTES
   + FILE_READ_ATTRIBUTES
ANONYMOUS LOGON\NT AUTHORITY
   + SYNCHRONIZE
++
```

## Compile with x64 MinGW:
```bash
x86_64-w64-mingw32-gcc xpipe.c -c -o xpipe.o -Os
```
+ Only tested from macOS

## Why I Created This?
Recently I have been exploring C2 channels using SMB/pipes and also dabbling in privilege escalation research. To better understand how windows pipes worked, I decided to create some projects. I personally find that getting my hands dirty with the windows APIs, debugging, and tinkering is the best way I learn.

## To Do's
+ For pipes which we don't have access to query, the BOF will just timeout after 5 seconds. Create error handler which checks if access was denied and return error code to operator. As of now it will just timeout after 5 seconds and return nothing.
+ Code cleanup, make sure there are no leaks and handles are closed, etc.
+ Update the `pipelist()` function use the same CS beacon print formatting as the `getPipeACL()` function. Its cleaner and less prone to errors.

## Detection & Mitigation
This BOF is for situational awareness. It does not perform any malicious behavior as of December 7th 2021. For detecting pipe enumeration for threat actors in their enumeration phase, it may be possible to detect attempts to query all named pipes which exist within `\\.\pipe\*`.

## Credits & References
#### Cobalt Strike BOF Code Projects 
+ [trustedsec/CS-Situational-Awareness-BOF/src/SA/cacls/](https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/master/src/SA/cacls/entry.c)
  + The code for the `getPipeACL()` function is derived from TrustedSecs awesome work from the CACL BOF project. 
+ [EspressoCake/HandleKatz_BOF](https://github.com/EspressoCake/HandleKatz_BOF)
  + This project taught me how to use Cobalt Strikes beacon output formatting APIs and output text to beacon with `BeaconOutput()`. This is great because it makes the text display in the CS GUI so much cleaner. The code to make this happen is pulled from this project. 
#### Malware Dev Skill References
+ [Sektor7 Malware Dev Essentials course](https://institute.sektor7.net/red-team-operator-malware-development-essentials)
+ [OxDarkVortex Blogs](https://0xdarkvortex.dev/blogs/)
+ [Brute Ratel Blogs](https://bruteratel.com/blog/)
#### DACL Permissions Code Projects & References
+ [microsoft/Windows-classic-samples/SecPrint.c](https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/Win7Samples/security/authorization/secprint/SecPrint.c)
+ [fasterthanlime/share.c](https://gist.github.com/fasterthanlime/ea38871666bc7cc486c272650523c9e1)
+ [Microsoft Developer Documentation](https://docs.microsoft.com/en-us/windows/win32/api/winbase/)
+ StackOverFlow - Sorry I can't find references to add. LMK and I will add them here
#### Pipe Code Projects
+ [Mark Russinovich - Sysinternals pipelist & accesscheck](https://docs.microsoft.com/en-us/sysinternals/)
  + This BOF pretty much does the same thing as `pipelist.exe`. I used `pipelist` while developing to make sure I was getting the correct listing of named pipes.
  + `accesscheck.exe -lv` will query the permissions of the named pipes like this BOF will.  
+ Decoder's Blog / Project - Windows Named Pipes & Impersonation
  + [GitHub PowerShell Project](https://github.com/decoder-it/pipeserverimpersonate)
  + [PowerShell Pipe Blog](https://decoder.cloud/2019/03/06/windows-named-pipes-impersonation/)
+ [peter-bloomfield/win32-named-pipes-example](https://github.com/peter-bloomfield/win32-named-pipes-example)
#### Cobalt Strike - How to Develop a BOF
##### Raphael Mudge - Beacon Object Files - Luser Demo
+ https://www.youtube.com/watch?v=gfYswA_Ronw
##### Cobalt Strike - Beacon Object Files
+ https://www.cobaltstrike.com/help-beacon-object-files
