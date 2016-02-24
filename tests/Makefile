all: simple.elf simple.static.elf

simple.elf: Makefile simple.c
	gcc simple.c -o simple.elf

simple.static.elf: Makefile simple.c
	gcc -static simple.c -o simple.static.elf

