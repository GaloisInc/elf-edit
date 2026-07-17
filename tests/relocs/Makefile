# Checked-in objects are generated with:
#   - Debian clang 19.1.7 (3+b1), source package llvm-toolchain-19 1:19.1.7-3:
#     https://sources.debian.org/src/llvm-toolchain-19/1%3A19.1.7-3/
#   - GNU binutils 2.44:
#     https://ftp.gnu.org/gnu/binutils/binutils-2.44.tar.xz
#
# LLVM's ARM assembler cannot emit R_ARM_THM_GOT_BREL12.  GNU as cannot
# emit R_PPC64_ADDR30 or R_PPC64_TPREL16_LO.  It encodes
# R_PPC64_PLT16_LO_DS as R_PPC64_TPREL16_LO.
CLANG ?= clang
PPC64AS ?= powerpc64-linux-gnu-as
X86_64AS ?= as
RISCV32CC ?= riscv32-linux-musl-gcc
RISCV64CC ?= riscv64-linux-musl-gcc

.PHONY: all clean

all: aarch64/relocs.o arm32/relocs.o ppc32/relocs.o ppc64/relocs.o \
     riscv/relocs-rv32gc.o riscv/relocs-rv64gc.o x86_64/relocs.o

aarch64/relocs.o: aarch64/relocs.s
	$(CLANG) -c --target=aarch64-unknown-linux-gnu -o $@ $<

arm32/relocs.o: arm32/relocs.s
	$(CLANG) -c --target=arm-linux-gnueabi -o $@ $<

ppc32/relocs.o: ppc32/relocs.s
	$(CLANG) -c --target=powerpc-unknown-linux-gnu -o $@ $<

ppc64/relocs.o: ppc64/relocs.s
	$(PPC64AS) $< -o $@

riscv/relocs-rv32gc.o: riscv/relocs.s
	$(RISCV32CC) -c $< -o $@

riscv/relocs-rv64gc.o: riscv/relocs.s
	$(RISCV64CC) -c $< -o $@

x86_64/relocs.o: x86_64/relocs.s
	$(X86_64AS) -o $@ $<

clean:
	rm -f aarch64/relocs.o arm32/relocs.o ppc32/relocs.o ppc64/relocs.o \
	      riscv/relocs-rv32gc.o riscv/relocs-rv64gc.o x86_64/relocs.o
