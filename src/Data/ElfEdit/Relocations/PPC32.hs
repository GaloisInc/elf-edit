{-
Copyright        : (c) Galois, Inc 2023
Maintainer       : Ryan Scott <rscott@galois.com>

PPC32 relocation types. The list of relocation types is taken from Section 4-14
(Relocation) of <http://refspecs.linux-foundation.org/elf/elfspec_ppc.pdf>.
-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE TypeFamilies #-}
module Data.ElfEdit.Relocations.PPC32
  ( PPC32_RelocationType(..)
  , pattern R_PPC_NONE
  , pattern R_PPC_ADDR32
  , pattern R_PPC_ADDR24
  , pattern R_PPC_ADDR16
  , pattern R_PPC_ADDR16_LO
  , pattern R_PPC_ADDR16_HI
  , pattern R_PPC_ADDR16_HA
  , pattern R_PPC_ADDR14
  , pattern R_PPC_ADDR14_BRTAKEN
  , pattern R_PPC_ADDR14_BRNTAKEN
  , pattern R_PPC_REL24
  , pattern R_PPC_REL14
  , pattern R_PPC_REL14_BRTAKEN
  , pattern R_PPC_REL14_BRNTAKEN
  , pattern R_PPC_GOT16
  , pattern R_PPC_GOT16_LO
  , pattern R_PPC_GOT16_HI
  , pattern R_PPC_GOT16_HA
  , pattern R_PPC_PLTREL24
  , pattern R_PPC_COPY
  , pattern R_PPC_GLOB_DAT
  , pattern R_PPC_JMP_SLOT
  , pattern R_PPC_RELATIVE
  , pattern R_PPC_LOCAL24PC
  , pattern R_PPC_UADDR32
  , pattern R_PPC_UADDR16
  , pattern R_PPC_REL32
  , pattern R_PPC_PLT32
  , pattern R_PPC_PLTREL32
  , pattern R_PPC_PLT16_LO
  , pattern R_PPL_PLT16_HI
  , pattern R_PPC_PLT16_HA
  , pattern R_PPC_SDAREL16
  , pattern R_PPC_SECTOFF
  , pattern R_PPC_SECTOFF_LO
  , pattern R_PPC_SECTOFF_HI
  , pattern R_PPC_SECTOFF_HA
  , pattern R_PPC_ADDR30
  , ppc32_RelocationTypes
  ) where

import qualified Data.Map.Strict          as Map
import           Data.Word

import           Data.ElfEdit.Prim.Ehdr (ElfClass(..))
import           Data.ElfEdit.Relocations.Common
import           Data.ElfEdit.Utils (ppHex)

------------------------------------------------------------------------
-- PPC32_RelocationType

-- | Relocation types for 32-bit PPC code.
newtype PPC32_RelocationType = PPC32_RelocationType { fromPPC32_RelocationType :: Word32 }
  deriving (Eq,Ord)

-- These values are derived from Table 4-8 (Relocation Types) of
-- http://refspecs.linux-foundation.org/elf/elfspec_ppc.pdf.

pattern R_PPC_NONE :: PPC32_RelocationType
pattern R_PPC_NONE = PPC32_RelocationType 0 -- none

pattern R_PPC_ADDR32 :: PPC32_RelocationType
pattern R_PPC_ADDR32 = PPC32_RelocationType 1 -- S + A

pattern R_PPC_ADDR24 :: PPC32_RelocationType
pattern R_PPC_ADDR24 = PPC32_RelocationType 2 -- (S + A) >> 2

pattern R_PPC_ADDR16 :: PPC32_RelocationType
pattern R_PPC_ADDR16 = PPC32_RelocationType 3 -- S + A

pattern R_PPC_ADDR16_LO :: PPC32_RelocationType
pattern R_PPC_ADDR16_LO = PPC32_RelocationType 4 -- #lo(S + A)

pattern R_PPC_ADDR16_HI :: PPC32_RelocationType
pattern R_PPC_ADDR16_HI = PPC32_RelocationType 5 -- #hi(S + A)

pattern R_PPC_ADDR16_HA :: PPC32_RelocationType
pattern R_PPC_ADDR16_HA = PPC32_RelocationType 6 -- #ha(S + A)

pattern R_PPC_ADDR14 :: PPC32_RelocationType
pattern R_PPC_ADDR14 = PPC32_RelocationType 7 -- (S + A) >> 2

pattern R_PPC_ADDR14_BRTAKEN :: PPC32_RelocationType
pattern R_PPC_ADDR14_BRTAKEN = PPC32_RelocationType 8 -- (S + A) >> 2

pattern R_PPC_ADDR14_BRNTAKEN :: PPC32_RelocationType
pattern R_PPC_ADDR14_BRNTAKEN = PPC32_RelocationType 9 -- (S + A) >> 2

pattern R_PPC_REL24 :: PPC32_RelocationType
pattern R_PPC_REL24 = PPC32_RelocationType 10 -- (S + A - P) >> 2

pattern R_PPC_REL14 :: PPC32_RelocationType
pattern R_PPC_REL14 = PPC32_RelocationType 11 -- (S + A - P) >> 2

pattern R_PPC_REL14_BRTAKEN :: PPC32_RelocationType
pattern R_PPC_REL14_BRTAKEN = PPC32_RelocationType 12 -- (S + A - P) >> 2

pattern R_PPC_REL14_BRNTAKEN :: PPC32_RelocationType
pattern R_PPC_REL14_BRNTAKEN = PPC32_RelocationType 13 -- (S + A - P) >> 2

pattern R_PPC_GOT16 :: PPC32_RelocationType
pattern R_PPC_GOT16 = PPC32_RelocationType 14 -- G + A

pattern R_PPC_GOT16_LO :: PPC32_RelocationType
pattern R_PPC_GOT16_LO = PPC32_RelocationType 15 -- #lo(G + A)

pattern R_PPC_GOT16_HI :: PPC32_RelocationType
pattern R_PPC_GOT16_HI = PPC32_RelocationType 16 -- #hi(G + A)

pattern R_PPC_GOT16_HA :: PPC32_RelocationType
pattern R_PPC_GOT16_HA = PPC32_RelocationType 17 -- #ha(G + A)

pattern R_PPC_PLTREL24 :: PPC32_RelocationType
pattern R_PPC_PLTREL24 = PPC32_RelocationType 18 -- (L + A - P) >> 2

pattern R_PPC_COPY :: PPC32_RelocationType
pattern R_PPC_COPY = PPC32_RelocationType 19 -- none

pattern R_PPC_GLOB_DAT :: PPC32_RelocationType
pattern R_PPC_GLOB_DAT = PPC32_RelocationType 20 -- S + A

pattern R_PPC_JMP_SLOT :: PPC32_RelocationType
pattern R_PPC_JMP_SLOT = PPC32_RelocationType 21

pattern R_PPC_RELATIVE :: PPC32_RelocationType
pattern R_PPC_RELATIVE = PPC32_RelocationType 22 -- B + A

pattern R_PPC_LOCAL24PC :: PPC32_RelocationType
pattern R_PPC_LOCAL24PC = PPC32_RelocationType 23

pattern R_PPC_UADDR32 :: PPC32_RelocationType
pattern R_PPC_UADDR32 = PPC32_RelocationType 24 -- S + A

pattern R_PPC_UADDR16 :: PPC32_RelocationType
pattern R_PPC_UADDR16 = PPC32_RelocationType 25 -- S + A

pattern R_PPC_REL32 :: PPC32_RelocationType
pattern R_PPC_REL32 = PPC32_RelocationType 26 -- S + A - P

pattern R_PPC_PLT32 :: PPC32_RelocationType
pattern R_PPC_PLT32 = PPC32_RelocationType 27 -- L + A

pattern R_PPC_PLTREL32 :: PPC32_RelocationType
pattern R_PPC_PLTREL32 = PPC32_RelocationType 28 -- L + A - P

pattern R_PPC_PLT16_LO :: PPC32_RelocationType
pattern R_PPC_PLT16_LO = PPC32_RelocationType 29 -- #lo(L + A)

pattern R_PPL_PLT16_HI :: PPC32_RelocationType
pattern R_PPL_PLT16_HI = PPC32_RelocationType 30 -- #hi(L + A)

pattern R_PPC_PLT16_HA :: PPC32_RelocationType
pattern R_PPC_PLT16_HA = PPC32_RelocationType 31 -- #ha(L + A)

pattern R_PPC_SDAREL16 :: PPC32_RelocationType
pattern R_PPC_SDAREL16 = PPC32_RelocationType 32 -- S + A - _SDA_BASE_

pattern R_PPC_SECTOFF :: PPC32_RelocationType
pattern R_PPC_SECTOFF = PPC32_RelocationType 33 -- R + A

pattern R_PPC_SECTOFF_LO :: PPC32_RelocationType
pattern R_PPC_SECTOFF_LO = PPC32_RelocationType 34 -- #lo(R + A)

pattern R_PPC_SECTOFF_HI :: PPC32_RelocationType
pattern R_PPC_SECTOFF_HI = PPC32_RelocationType 35 -- #hi(R + A)

pattern R_PPC_SECTOFF_HA :: PPC32_RelocationType
pattern R_PPC_SECTOFF_HA = PPC32_RelocationType 36 -- #ha(R + A)

pattern R_PPC_ADDR30 :: PPC32_RelocationType
pattern R_PPC_ADDR30 = PPC32_RelocationType 37 -- (S + A - P) >> 2

ppc32Reloc :: PPC32_RelocationType
           -> String
           -> Int
           -> (PPC32_RelocationType, (String,Int))
ppc32Reloc tp nm c = (tp, (nm, c))

-- These values are derived from Figure 4-1 (Relocation Fields) of
-- http://refspecs.linux-foundation.org/elf/elfspec_ppc.pdf.
--
-- Note that some of these values are not currently supported. See
-- https://github.com/GaloisInc/elf-edit/issues/39 for more information.

none :: Int
none = 0

word32 :: Int
word32 = 32

word30 :: Int
word30 = 30

low24 :: Int
low24 = error "low24 relocation entries not currently supported"

low14 :: Int
low14 = error "low14 relocation entries not currently supported"

half16 :: Int
half16 = 16

-- This map is derived from Table 4-8 (Relocation Types) of
-- http://refspecs.linux-foundation.org/elf/elfspec_ppc.pdf.

ppc32_RelocationTypes :: Map.Map PPC32_RelocationType (String, Int)
ppc32_RelocationTypes = Map.fromList
  [ ppc32Reloc R_PPC_NONE "R_PPC_NONE" none
  , ppc32Reloc R_PPC_ADDR32 "R_PPC_ADDR32" word32
  , ppc32Reloc R_PPC_ADDR24 "R_PPC_ADDR24" low24
  , ppc32Reloc R_PPC_ADDR16 "R_PPC_ADDR16" half16
  , ppc32Reloc R_PPC_ADDR16_LO "R_PPC_ADDR16_LO" half16
  , ppc32Reloc R_PPC_ADDR16_HI "R_PPC_ADDR16_HI" half16
  , ppc32Reloc R_PPC_ADDR16_HA "R_PPC_ADDR16_HA" half16
  , ppc32Reloc R_PPC_ADDR14 "R_PPC_ADDR14" low14
  , ppc32Reloc R_PPC_ADDR14_BRTAKEN "R_PPC_ADDR14_BRTAKEN" low14
  , ppc32Reloc R_PPC_ADDR14_BRNTAKEN "R_PPC_ADDR14_BRNTAKEN" low14
  , ppc32Reloc R_PPC_REL24 "R_PPC_REL24" low24
  , ppc32Reloc R_PPC_REL14 "R_PPC_REL14" low14
  , ppc32Reloc R_PPC_REL14_BRTAKEN "R_PPC_REL14_BRTAKEN" low14
  , ppc32Reloc R_PPC_REL14_BRNTAKEN "R_PPC_REL14_BRNTAKEN" low14
  , ppc32Reloc R_PPC_GOT16 "R_PPC_GOT16" half16
  , ppc32Reloc R_PPC_GOT16_LO "R_PPC_GOT16_LO" half16
  , ppc32Reloc R_PPC_GOT16_HI "R_PPC_GOT16_HI" half16
  , ppc32Reloc R_PPC_GOT16_HA "R_PPC_GOT16_HA" half16
  , ppc32Reloc R_PPC_PLTREL24 "R_PPC_PLTREL24" low24
  , ppc32Reloc R_PPC_COPY "R_PPC_COPY" none
  , ppc32Reloc R_PPC_GLOB_DAT "R_PPC_GLOB_DAT" word32
  , ppc32Reloc R_PPC_JMP_SLOT "R_PPC_JMP_SLOT" none
  , ppc32Reloc R_PPC_RELATIVE "R_PPC_RELATIVE" word32
  , ppc32Reloc R_PPC_LOCAL24PC "R_PPC_LOCAL24PC" low24
  , ppc32Reloc R_PPC_UADDR32 "R_PPC_UADDR32" word32
  , ppc32Reloc R_PPC_UADDR16 "R_PPC_UADDR16" half16
  , ppc32Reloc R_PPC_REL32 "R_PPC_REL32" word32
  , ppc32Reloc R_PPC_PLT32 "R_PPC_PLT32" word32
  , ppc32Reloc R_PPC_PLTREL32 "R_PPC_PLTREL32" word32
  , ppc32Reloc R_PPC_PLT16_LO "R_PPC_PLT16_LO" half16
  , ppc32Reloc R_PPL_PLT16_HI "R_PPL_PLT16_HI" half16
  , ppc32Reloc R_PPC_PLT16_HA "R_PPC_PLT16_HA" half16
  , ppc32Reloc R_PPC_SDAREL16 "R_PPC_SDAREL16" half16
  , ppc32Reloc R_PPC_SECTOFF "R_PPC_SECTOFF" half16
  , ppc32Reloc R_PPC_SECTOFF_LO "R_PPC_SECTOFF_LO" half16
  , ppc32Reloc R_PPC_SECTOFF_HI "R_PPC_SECTOFF_HI" half16
  , ppc32Reloc R_PPC_SECTOFF_HA "R_PPC_SECTOFF_HA" half16
  , ppc32Reloc R_PPC_ADDR30 "R_PPC_ADDR30" word30
  ]

instance Show PPC32_RelocationType where
  show i =
    case Map.lookup i ppc32_RelocationTypes of
      Just (s,_) -> s
      Nothing -> ppHex (fromPPC32_RelocationType i)

instance IsRelocationType PPC32_RelocationType where
  type RelocationWidth PPC32_RelocationType = 32

  relaWidth _ = ELFCLASS32

  toRelocType = PPC32_RelocationType . fromIntegral

  isRelative R_PPC_RELATIVE = True
  isRelative _              = False

  relocTargetBits tp =
    case Map.lookup tp ppc32_RelocationTypes of
      Just (_,w) -> w
      Nothing -> 32
