{-|

This module contains the "primitive" interface to Elf edit.

See `ElfHeaderInfo` and `decodeElfHeaderInfo` for the top level type.
-}
module Data.ElfEdit.Prim
  ( module Data.ElfEdit.Prim.HeaderInfo
  , module Data.ElfEdit.Prim.Ehdr
  , module Data.ElfEdit.Prim.Phdr
  , module Data.ElfEdit.Prim.Shdr
  , module Data.ElfEdit.Prim.SymbolTable
  , module Data.ElfEdit.Prim.StringTable
  , module Data.ElfEdit.Prim.File
    -- * Dynamic section
  , module Data.ElfEdit.Dynamic
    -- * Relocations
  , module Data.ElfEdit.Relocations.Common
    -- ** 32-bit x86 relocations
  , module Data.ElfEdit.Relocations.I386
    -- ** 64-bit x86 relocations
  , module Data.ElfEdit.Relocations.X86_64
    -- ** ARM32 relocations
  , module Data.ElfEdit.Relocations.ARM32
    -- ** ARM64 relocations
  , module Data.ElfEdit.Relocations.AArch64
    -- ** PPC32 relocations
  , module Data.ElfEdit.Relocations.PPC32
    -- ** PPC64 relocations
  , module Data.ElfEdit.Relocations.PPC64
    -- ** Android-specific
  , module Data.ElfEdit.Relocations.Android
  ) where

import Data.ElfEdit.Dynamic
import Data.ElfEdit.Prim.Ehdr
import Data.ElfEdit.Prim.File
import Data.ElfEdit.Prim.HeaderInfo
import Data.ElfEdit.Prim.Phdr
import Data.ElfEdit.Prim.Shdr
import Data.ElfEdit.Prim.StringTable
import Data.ElfEdit.Prim.SymbolTable
import Data.ElfEdit.Relocations.AArch64
import Data.ElfEdit.Relocations.ARM32
import Data.ElfEdit.Relocations.Android
import Data.ElfEdit.Relocations.Common
import Data.ElfEdit.Relocations.I386
import Data.ElfEdit.Relocations.PPC32
import Data.ElfEdit.Relocations.PPC64
import Data.ElfEdit.Relocations.X86_64
