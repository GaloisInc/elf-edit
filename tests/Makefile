all: simple.elf simple.static.elf libsymbol_versions.2.so

simple.elf: Makefile simple.c
	gcc simple.c -o simple.elf

simple.static.elf: Makefile simple.c
	gcc -static simple.c -o simple.static.elf

libsymbol_versions.2.so: symbol_versions.c
	gcc $< -Wl,--version-script=symbol_versions.map -fpic -o $@ -Wl,-soname,libsymbol_versions.so -shared
