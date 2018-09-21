Constraints on Elf files loaded by the Linux Kernel Elf loader
=

The Linux kernel is responsible for initializing a process's address
space based on the contents of the Elf file.  When generating Elf
files, it is important to understand this process as it makes certain
assumptions about the Elf file, and unanticipated behavior may occur
if the Elf file that you generate does not conform to those
assumptions.

This document describes assumptions made by the Linux kernel Elf
loader when initializing a process's initial state.  One may also wish
to read this [LWN article] which provides a high level overview of the
steps involved.  This description is current as of the [current
commit] as of June 19, 2018, and references the implementation on
GitHub.

[LWN article]: https://lwn.net/Articles/631631/
[current commit]: https://github.com/torvalds/linux/tree/ba4dbdedd3edc2798659bcd8b1a184ea8bdd04dc

How Linux loads binary formats.
-

Linux provides a dispatch mechanism that supports loading different
binary formats.  To implement a loader for a particular format, one
defines a struct with type [`linux_binfmt`] that contains callback
functions for loading files.  The callbacks support loading
executables, loading libraries, and generating core dumps.  For the
standard Elf loader, the relevant code is in [`binfmt_elf.c`].

Elf header checks
-

When loading an Elf binary [`load_elf_binary`] makes the following checks:

* The Elf magic constraint matches `ELFMAG` (0x7f 'ELF')
* The `e_type` field is `ET_EXEC` or `ET_DYN` (no load
* An architecture-specific function is called to validate the architecture
  (on `X86_64`, this function `e_machine` field matches `EM_X86_64).

It then proceeds to parsing the Elf program header table, which basically
involves checking that the size of the header table is not more than
`ELF_MIN_ALIGN`, which seems to be initialized to the page table size
(or `4096` on most `x86_64` systems).  This means there can be at most
`4096 / 56` or 73 program headers.

After these checks, Linux searches for a PT_DYNAMIC section, and
initializes the `elf_interpreter` and `interpreter` variables (which were
initially null) to store information about the interpreter.  We do not
describe these steps here as we are concerned with static variables.

The kernel then iterates a second time through all the headers, and
processes `PT_GNU_STACK` (which sets the `executable_stack` variable
and segments between `PT_LOPROC` and `PT_HIPROC`.  These are sent to
`arch_elf_pt_proc`, which on `x86_64` appears to be a dummy function.

The kernel then does consistency checks on `elf_interpreter` if
defined, and a final architecture-specific check `arch_check_elf`.
These are the last checks that can fail, and exit still returns.
Following this, the program flushes the old executable.

TODO: Provide additional content if this file actually is useful to
somebody.


[`linux_binfmt`]: https://github.com/torvalds/linux/blob/1c8c5a9d38f607c0b6fd12c91cbe1a4418762a21/include/linux/binfmts.h#L94-L101
[`binfmt_elf.c`]: https://github.com/torvalds/linux/blob/ba4dbdedd3edc2798659bcd8b1a184ea8bdd04dc/fs/binfmt_elf.c
