# Changelog for the `elf-edit` package

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
