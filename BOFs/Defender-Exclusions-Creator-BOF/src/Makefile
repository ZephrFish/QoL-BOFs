BOFNAME := cGenerateDefenderExclusion

CC_x64 := x86_64-w64-mingw32-g++
CC_x86 := i686-w64-mingw32-g++

COMPILER_SILENCE_WARNINGS := -Wno-unused-variable -Wno-write-strings -Wno-conversion-null

all:
	$(CC_x64) $(COMPILER_SILENCE_WARNINGS) -o ../dist/$(BOFNAME).x64.o -c $(BOFNAME).cpp -masm=intel
	$(CC_x86) $(COMPILER_SILENCE_WARNINGS) -o ../dist/$(BOFNAME).x86.o -c $(BOFNAME).cpp -masm=intel

debug:
	$(CC_x64) -DDEBUGBUILD $(COMPILER_SILENCE_WARNINGS) -o ../dist/$(BOFNAME).x64.o -c $(BOFNAME).cpp -masm=intel
	$(CC_x86) -DDEBUGBUILD $(COMPILER_SILENCE_WARNINGS) -o ../dist/$(BOFNAME).x86.o -c $(BOFNAME).cpp -masm=intel
clean:
	rm -f ../dist/$(BOFNAME).x64.o
	rm -f ../dist/$(BOFNAME).x86.o