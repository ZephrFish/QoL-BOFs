A Beacon Object File (BOF) implementation of the `cat` command, for easy reading of text files. 

## Usage

Load `cat.cna` into Cobalt Strike's Script Manager. The `cat` command is now available in beacons.

## Compile

Compile with `x86_64-w64-mingw32-gcc -c cat.c -o cat.x64.o` and `i686-w64-mingw32-gcc -c cat.c -o cat.x86.o` for x64/x86 respectively. 

## Notes

This implementation limits the maximum file size to 1MB (to avoid overflowing Cobalt Strike's scrollback buffer). For files larger than 1MB, you should really use the `download` command.
