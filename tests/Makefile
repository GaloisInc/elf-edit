all: simple.elf simple.static.elf libsymbol_versions.2.so fmax.elf ppc32-relocs.elf ppc64-relocs.elf riscv32-relocs.elf riscv64-relocs.elf

simple.elf: Makefile simple.c
	gcc simple.c -o simple.elf

simple.static.elf: Makefile simple.c
	gcc -static simple.c -o simple.static.elf

libsymbol_versions.2.so: symbol_versions.c
	gcc $< -Wl,--version-script=symbol_versions.map -fpic -o $@ -Wl,-soname,libsymbol_versions.so -shared

fmax.elf: fmax.c
	gcc $< -o $@ -lm

ppc32-relocs.elf: ppc32-relocs.c
	powerpc-linux-musl-gcc $< -o $@

ppc64-relocs.elf: ppc64-relocs.c
	powerpc64-linux-musl-gcc $< -o $@

riscv32-relocs.elf: riscv-relocs.c
	riscv32-linux-musl-gcc $< -o $@

riscv64-relocs.elf: riscv-relocs.c
	riscv64-linux-musl-gcc $< -o $@
