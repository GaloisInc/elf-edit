# Changelog for the `elf-edit` package

## next -- *TBA*

  * The type of `dynSymEntry` has gained an additional `VersionDefMap` argument
    in case the symbol's version information is located in a version definition
    (i.e., in a `.gnu.version_d` section) rather than a version requirement
    (i.e., in a `.gnu.version_r` section). The new `dynVersionDefMap` function
    can be used to construct the `VersionDefMap`.
  * Add a `decodeHeaderDynsym` function that computes the dynamic symbol table
    directly from an `ElfHeaderInfo`, much like `decodeHeaderSymtab` computes
    the static symbol table.

## 0.32 -- *2018 Sep 17*

  * Added support for `DT_REL` PLT relocations.  This includes 3 new
    possible `DynamicError` error values and a new `PLTEntries tp`
    datatype that provides information about the PLT relocations in a
    dynamic section.

  * *Bugfix*: Miscellaneous pretty printing updates.

  * Reorganized modules to improve Haddock documentation flow.

## 0.31 -- *2018 Sep 10*

  * The `relOffset` call is deprecated in favor of `relAddr` which
    replaces it.  This fixes the relocation code and clarifies the
    relocation address intent.

  * *Bugfix*: Fix relocation code
