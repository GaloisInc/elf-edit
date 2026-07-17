{-
Copyright        : (c) Galois, Inc 2023
Maintainer       : Ryan Scott <rscott@galois.com>

PPC64 relocation types. The ELFv1 relocation types are taken from Section 4.5
(Relocation) of <https://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf64abi-1.9.pdf>.
Additional ELFv2 relocation types are taken from
<https://github.com/OpenPOWERFoundation/ELFv2-ABI/blob/2c052b1ec5a5e2c51989eb109f8559a9df6d8202/specification/ch_3.xml>.
-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE TypeFamilies #-}
module Data.ElfEdit.Relocations.PPC64
  ( PPC64_RelocationType(..)
  , pattern R_PPC64_NONE
  , pattern R_PPC64_ADDR32
  , pattern R_PPC64_ADDR24
  , pattern R_PPC64_ADDR16
  , pattern R_PPC64_ADDR16_LO
  , pattern R_PPC64_ADDR16_HI
  , pattern R_PPC64_ADDR16_HA
  , pattern R_PPC64_ADDR14
  , pattern R_PPC64_ADDR14_BRTAKEN
  , pattern R_PPC64_ADDR14_BRNTAKEN
  , pattern R_PPC64_REL24
  , pattern R_PPC64_REL14
  , pattern R_PPC64_REL14_BRTAKEN
  , pattern R_PPC64_REL14_BRNTAKEN
  , pattern R_PPC64_GOT16
  , pattern R_PPC64_GOT16_LO
  , pattern R_PPC64_GOT16_HI
  , pattern R_PPC64_GOT16_HA
  , pattern R_PPC64_COPY
  , pattern R_PPC64_GLOB_DAT
  , pattern R_PPC64_JMP_SLOT
  , pattern R_PPC64_RELATIVE
  , pattern R_PPC64_UADDR32
  , pattern R_PPC64_UADDR16
  , pattern R_PPC64_REL32
  , pattern R_PPC64_PLT32
  , pattern R_PPC64_PLTREL32
  , pattern R_PPC64_PLT16_LO
  , pattern R_PPC64_PLT16_HI
  , pattern R_PPC64_PLT16_HA
  , pattern R_PPC64_SECTOFF
  , pattern R_PPC64_SECTOFF_LO
  , pattern R_PPC64_SECTOFF_HI
  , pattern R_PPC64_SECTOFF_HA
  , pattern R_PPC64_REL30
  , pattern R_PPC64_ADDR30
  , pattern R_PPC64_ADDR64
  , pattern R_PPC64_ADDR16_HIGHER
  , pattern R_PPC64_ADDR16_HIGHERA
  , pattern R_PPC64_ADDR16_HIGHEST
  , pattern R_PPC64_ADDR16_HIGHESTA
  , pattern R_PPC64_UADDR64
  , pattern R_PPC64_REL64
  , pattern R_PPC64_PLT64
  , pattern R_PPC64_PLTREL64
  , pattern R_PPC64_TOC16
  , pattern R_PPC64_TOC16_LO
  , pattern R_PPC64_TOC16_HI
  , pattern R_PPC64_TOC16_HA
  , pattern R_PPC64_TOC
  , pattern R_PPC64_PLTGOT16
  , pattern R_PPC64_PLTGOT16_LO
  , pattern R_PPC64_PLTGOT16_HI
  , pattern R_PPC64_PLTGOT16_HA
  , pattern R_PPC64_ADDR16_DS
  , pattern R_PPC64_ADDR16_LO_DS
  , pattern R_PPC64_GOT16_DS
  , pattern R_PPC64_GOT16_LO_DS
  , pattern R_PPC64_PLT16_LO_DS
  , pattern R_PPC64_SECTOFF_DS
  , pattern R_PPC64_SECTOFF_LO_DS
  , pattern R_PPC64_TOC16_DS
  , pattern R_PPC64_TOC16_LO_DS
  , pattern R_PPC64_PLTGOT16_DS
  , pattern R_PPC64_PLTGOT16_LO_DS
  , pattern R_PPC64_TLS
  , pattern R_PPC64_DTPMOD64
  , pattern R_PPC64_TPREL16
  , pattern R_PPC64_TPREL16_LO
  , pattern R_PPC64_TPREL16_HI
  , pattern R_PPC64_TPREL16_HA
  , pattern R_PPC64_TPREL64
  , pattern R_PPC64_DTPREL16
  , pattern R_PPC64_DTPREL16_LO
  , pattern R_PPC64_DTPREL16_HI
  , pattern R_PPC64_DTPREL16_HA
  , pattern R_PPC64_DTPREL64
  , pattern R_PPC64_GOT_TLSGD16
  , pattern R_PPC64_GOT_TLSGD16_LO
  , pattern R_PPC64_GOT_TLSGD16_HI
  , pattern R_PPC64_GOT_TLSGD16_HA
  , pattern R_PPC64_GOT_TLSLD16
  , pattern R_PPC64_GOT_TLSLD16_LO
  , pattern R_PPC64_GOT_TLSLD16_HI
  , pattern R_PPC64_GOT_TLSLD16_HA
  , pattern R_PPC64_GOT_TPREL16_DS
  , pattern R_PPC64_GOT_TPREL16_LO_DS
  , pattern R_PPC64_GOT_TPREL16_HI
  , pattern R_PPC64_GOT_TPREL16_HA
  , pattern R_PPC64_GOT_DTPREL16_DS
  , pattern R_PPC64_GOT_DTPREL16_LO_DS
  , pattern R_PPC64_GOT_DTPREL16_HI
  , pattern R_PPC64_GOT_DTPREL16_HA
  , pattern R_PPC64_TPREL16_DS
  , pattern R_PPC64_TPREL16_LO_DS
  , pattern R_PPC64_TPREL16_HIGHER
  , pattern R_PPC64_TPREL16_HIGHERA
  , pattern R_PPC64_TPREL16_HIGHEST
  , pattern R_PPC64_TPREL16_HIGHESTA
  , pattern R_PPC64_DTPREL16_DS
  , pattern R_PPC64_DTPREL16_LO_DS
  , pattern R_PPC64_DTPREL16_HIGHER
  , pattern R_PPC64_DTPREL16_HIGHERA
  , pattern R_PPC64_DTPREL16_HIGHEST
  , pattern R_PPC64_DTPREL16_HIGHESTA
  , pattern R_PPC64_TLSGD
  , pattern R_PPC64_TLSLD
  , pattern R_PPC64_TOCSAVE
  , pattern R_PPC64_ADDR16_HIGH
  , pattern R_PPC64_ADDR16_HIGHA
  , pattern R_PPC64_TPREL16_HIGH
  , pattern R_PPC64_TPREL16_HIGHA
  , pattern R_PPC64_DTPREL16_HIGH
  , pattern R_PPC64_DTPREL16_HIGHA
  , pattern R_PPC64_REL24_NOTOC
  , pattern R_PPC64_ADDR64_LOCAL
  , pattern R_PPC64_ENTRY
  , pattern R_PPC64_PLTSEQ
  , pattern R_PPC64_PLTCALL
  , pattern R_PPC64_PLTSEQ_NOTOC
  , pattern R_PPC64_PLTCALL_NOTOC
  , pattern R_PPC64_PCREL_OPT
  , pattern R_PPC64_D34
  , pattern R_PPC64_D34_LO
  , pattern R_PPC64_D34_HI30
  , pattern R_PPC64_D34_HA30
  , pattern R_PPC64_PCREL34
  , pattern R_PPC64_GOT_PCREL34
  , pattern R_PPC64_PLT_PCREL34
  , pattern R_PPC64_PLT_PCREL34_NOTOC
  , pattern R_PPC64_ADDR16_HIGHER34
  , pattern R_PPC64_ADDR16_HIGHERA34
  , pattern R_PPC64_ADDR16_HIGHEST34
  , pattern R_PPC64_ADDR16_HIGHESTA34
  , pattern R_PPC64_REL16_HIGHER34
  , pattern R_PPC64_REL16_HIGHERA34
  , pattern R_PPC64_REL16_HIGHEST34
  , pattern R_PPC64_REL16_HIGHESTA34
  , pattern R_PPC64_D28
  , pattern R_PPC64_PCREL28
  , pattern R_PPC64_TPREL34
  , pattern R_PPC64_DTPREL34
  , pattern R_PPC64_GOT_TLSGD_PCREL34
  , pattern R_PPC64_GOT_TLSLD_PCREL34
  , pattern R_PPC64_GOT_TPREL_PCREL34
  , pattern R_PPC64_GOT_DTPREL_PCREL34
  , pattern R_PPC64_REL16_HIGH
  , pattern R_PPC64_REL16_HIGHA
  , pattern R_PPC64_REL16_HIGHER
  , pattern R_PPC64_REL16_HIGHERA
  , pattern R_PPC64_REL16_HIGHEST
  , pattern R_PPC64_REL16_HIGHESTA
  , pattern R_PPC64_REL16DX_HA
  , pattern R_PPC64_IRELATIVE
  , pattern R_PPC64_REL16
  , pattern R_PPC64_REL16_LO
  , pattern R_PPC64_REL16_HI
  , pattern R_PPC64_REL16_HA
  , pattern R_PPC64_GNU_VTINHERIT
  , pattern R_PPC64_GNU_VTENTRY
  , ppc64_RelocationTypes
  ) where

import qualified Data.Map.Strict          as Map
import           Data.Word

import           Data.ElfEdit.Prim.Ehdr (ElfClass(..))
import           Data.ElfEdit.Relocations.Common
import           Data.ElfEdit.Utils (ppHex)

------------------------------------------------------------------------
-- PPC64_RelocationType

-- | Relocation types for 64-bit PPC code.
newtype PPC64_RelocationType = PPC64_RelocationType { fromPPC64_RelocationType :: Word32 }
  deriving (Eq,Ord)

-- The ELFv1 values are derived from Figure 4-1 (Relocation Types) of
-- https://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf64abi-1.9.pdf.

pattern R_PPC64_NONE :: PPC64_RelocationType
pattern R_PPC64_NONE = PPC64_RelocationType 0 -- none

pattern R_PPC64_ADDR32 :: PPC64_RelocationType
pattern R_PPC64_ADDR32 = PPC64_RelocationType 1 -- S + A

pattern R_PPC64_ADDR24 :: PPC64_RelocationType
pattern R_PPC64_ADDR24 = PPC64_RelocationType 2 -- (S + A) >> 2

pattern R_PPC64_ADDR16 :: PPC64_RelocationType
pattern R_PPC64_ADDR16 = PPC64_RelocationType 3 -- S + A

pattern R_PPC64_ADDR16_LO :: PPC64_RelocationType
pattern R_PPC64_ADDR16_LO = PPC64_RelocationType 4 -- #lo(S + A)

pattern R_PPC64_ADDR16_HI :: PPC64_RelocationType
pattern R_PPC64_ADDR16_HI = PPC64_RelocationType 5 -- #hi(S + A)

pattern R_PPC64_ADDR16_HA :: PPC64_RelocationType
pattern R_PPC64_ADDR16_HA = PPC64_RelocationType 6 -- #ha(S + A)

pattern R_PPC64_ADDR14 :: PPC64_RelocationType
pattern R_PPC64_ADDR14 = PPC64_RelocationType 7 -- (S + A) >> 2

pattern R_PPC64_ADDR14_BRTAKEN :: PPC64_RelocationType
pattern R_PPC64_ADDR14_BRTAKEN = PPC64_RelocationType 8 -- (S + A) >> 2

pattern R_PPC64_ADDR14_BRNTAKEN :: PPC64_RelocationType
pattern R_PPC64_ADDR14_BRNTAKEN = PPC64_RelocationType 9 -- (S + A) >> 2

pattern R_PPC64_REL24 :: PPC64_RelocationType
pattern R_PPC64_REL24 = PPC64_RelocationType 10 -- (S + A - P) >> 2

pattern R_PPC64_REL14 :: PPC64_RelocationType
pattern R_PPC64_REL14 = PPC64_RelocationType 11 -- (S + A - P) >> 2

pattern R_PPC64_REL14_BRTAKEN :: PPC64_RelocationType
pattern R_PPC64_REL14_BRTAKEN = PPC64_RelocationType 12 -- (S + A - P) >> 2

pattern R_PPC64_REL14_BRNTAKEN :: PPC64_RelocationType
pattern R_PPC64_REL14_BRNTAKEN = PPC64_RelocationType 13 -- (S + A - P) >> 2

pattern R_PPC64_GOT16 :: PPC64_RelocationType
pattern R_PPC64_GOT16 = PPC64_RelocationType 14 -- G

pattern R_PPC64_GOT16_LO :: PPC64_RelocationType
pattern R_PPC64_GOT16_LO = PPC64_RelocationType 15 -- #lo(G)

pattern R_PPC64_GOT16_HI :: PPC64_RelocationType
pattern R_PPC64_GOT16_HI = PPC64_RelocationType 16 -- #hi(G)

pattern R_PPC64_GOT16_HA :: PPC64_RelocationType
pattern R_PPC64_GOT16_HA = PPC64_RelocationType 17 -- #ha(G)

pattern R_PPC64_COPY :: PPC64_RelocationType
pattern R_PPC64_COPY = PPC64_RelocationType 19 -- none

pattern R_PPC64_GLOB_DAT :: PPC64_RelocationType
pattern R_PPC64_GLOB_DAT = PPC64_RelocationType 20 -- S + A

pattern R_PPC64_JMP_SLOT :: PPC64_RelocationType
pattern R_PPC64_JMP_SLOT = PPC64_RelocationType 21 -- see below

pattern R_PPC64_RELATIVE :: PPC64_RelocationType
pattern R_PPC64_RELATIVE = PPC64_RelocationType 22 -- B + A

pattern R_PPC64_UADDR32 :: PPC64_RelocationType
pattern R_PPC64_UADDR32 = PPC64_RelocationType 24 -- S + A

pattern R_PPC64_UADDR16 :: PPC64_RelocationType
pattern R_PPC64_UADDR16 = PPC64_RelocationType 25 -- S + A

pattern R_PPC64_REL32 :: PPC64_RelocationType
pattern R_PPC64_REL32 = PPC64_RelocationType 26 -- S + A - P

pattern R_PPC64_PLT32 :: PPC64_RelocationType
pattern R_PPC64_PLT32 = PPC64_RelocationType 27 -- L

pattern R_PPC64_PLTREL32 :: PPC64_RelocationType
pattern R_PPC64_PLTREL32 = PPC64_RelocationType 28 -- L - P

pattern R_PPC64_PLT16_LO :: PPC64_RelocationType
pattern R_PPC64_PLT16_LO = PPC64_RelocationType 29 -- #lo(L)

pattern R_PPC64_PLT16_HI :: PPC64_RelocationType
pattern R_PPC64_PLT16_HI = PPC64_RelocationType 30 -- #hi(L)

pattern R_PPC64_PLT16_HA :: PPC64_RelocationType
pattern R_PPC64_PLT16_HA = PPC64_RelocationType 31 -- #ha(L)

pattern R_PPC64_SECTOFF :: PPC64_RelocationType
pattern R_PPC64_SECTOFF = PPC64_RelocationType 33 -- R + A

pattern R_PPC64_SECTOFF_LO :: PPC64_RelocationType
pattern R_PPC64_SECTOFF_LO = PPC64_RelocationType 34 -- #lo(R + A)

pattern R_PPC64_SECTOFF_HI :: PPC64_RelocationType
pattern R_PPC64_SECTOFF_HI = PPC64_RelocationType 35 -- #hi(R + A)

pattern R_PPC64_SECTOFF_HA :: PPC64_RelocationType
pattern R_PPC64_SECTOFF_HA = PPC64_RelocationType 36 -- #ha(R + A)

-- ELFv2 uses the canonical name 'R_PPC64_REL30'.  Keep the ELFv1 spelling as
-- a pattern synonym for source compatibility.
pattern R_PPC64_REL30 :: PPC64_RelocationType
pattern R_PPC64_REL30 = PPC64_RelocationType 37 -- (S + A - P) >> 2

pattern R_PPC64_ADDR30 :: PPC64_RelocationType
pattern R_PPC64_ADDR30 = R_PPC64_REL30

pattern R_PPC64_ADDR64 :: PPC64_RelocationType
pattern R_PPC64_ADDR64 = PPC64_RelocationType 38 -- S + A

pattern R_PPC64_ADDR16_HIGHER :: PPC64_RelocationType
pattern R_PPC64_ADDR16_HIGHER = PPC64_RelocationType 39 -- #higher(S + A)

pattern R_PPC64_ADDR16_HIGHERA :: PPC64_RelocationType
pattern R_PPC64_ADDR16_HIGHERA = PPC64_RelocationType 40 -- #highera(S + A)

pattern R_PPC64_ADDR16_HIGHEST :: PPC64_RelocationType
pattern R_PPC64_ADDR16_HIGHEST = PPC64_RelocationType 41 -- #highest(S + A)

pattern R_PPC64_ADDR16_HIGHESTA :: PPC64_RelocationType
pattern R_PPC64_ADDR16_HIGHESTA = PPC64_RelocationType 42 -- #highesta(S + A)

pattern R_PPC64_UADDR64 :: PPC64_RelocationType
pattern R_PPC64_UADDR64 = PPC64_RelocationType 43 -- S + A

pattern R_PPC64_REL64 :: PPC64_RelocationType
pattern R_PPC64_REL64 = PPC64_RelocationType 44 -- S + A - P

pattern R_PPC64_PLT64 :: PPC64_RelocationType
pattern R_PPC64_PLT64 = PPC64_RelocationType 45 -- L

pattern R_PPC64_PLTREL64 :: PPC64_RelocationType
pattern R_PPC64_PLTREL64 = PPC64_RelocationType 46 -- L - P

pattern R_PPC64_TOC16 :: PPC64_RelocationType
pattern R_PPC64_TOC16 = PPC64_RelocationType 47 -- S + A - .TOC.

pattern R_PPC64_TOC16_LO :: PPC64_RelocationType
pattern R_PPC64_TOC16_LO = PPC64_RelocationType 48 -- #lo(S + A - .TOC.)

pattern R_PPC64_TOC16_HI :: PPC64_RelocationType
pattern R_PPC64_TOC16_HI = PPC64_RelocationType 49 -- #hi(S + A - .TOC.)

pattern R_PPC64_TOC16_HA :: PPC64_RelocationType
pattern R_PPC64_TOC16_HA = PPC64_RelocationType 50 -- #ha(S + A - .TOC.)

pattern R_PPC64_TOC :: PPC64_RelocationType
pattern R_PPC64_TOC = PPC64_RelocationType 51 -- .TOC.

pattern R_PPC64_PLTGOT16 :: PPC64_RelocationType
pattern R_PPC64_PLTGOT16 = PPC64_RelocationType 52 -- M

pattern R_PPC64_PLTGOT16_LO :: PPC64_RelocationType
pattern R_PPC64_PLTGOT16_LO = PPC64_RelocationType 53 -- #lo(M)

pattern R_PPC64_PLTGOT16_HI :: PPC64_RelocationType
pattern R_PPC64_PLTGOT16_HI = PPC64_RelocationType 54 -- #hi(M)

pattern R_PPC64_PLTGOT16_HA :: PPC64_RelocationType
pattern R_PPC64_PLTGOT16_HA = PPC64_RelocationType 55 -- #ha(M)

pattern R_PPC64_ADDR16_DS :: PPC64_RelocationType
pattern R_PPC64_ADDR16_DS = PPC64_RelocationType 56 -- (S + A) >> 2

pattern R_PPC64_ADDR16_LO_DS :: PPC64_RelocationType
pattern R_PPC64_ADDR16_LO_DS = PPC64_RelocationType 57 -- #lo(S + A) >> 2

pattern R_PPC64_GOT16_DS :: PPC64_RelocationType
pattern R_PPC64_GOT16_DS = PPC64_RelocationType 58 -- G >> 2

pattern R_PPC64_GOT16_LO_DS :: PPC64_RelocationType
pattern R_PPC64_GOT16_LO_DS = PPC64_RelocationType 59 -- #lo(G) >> 2

pattern R_PPC64_PLT16_LO_DS :: PPC64_RelocationType
pattern R_PPC64_PLT16_LO_DS = PPC64_RelocationType 60 -- #lo(L) >> 2

pattern R_PPC64_SECTOFF_DS :: PPC64_RelocationType
pattern R_PPC64_SECTOFF_DS = PPC64_RelocationType 61 -- (R + A) >> 2

pattern R_PPC64_SECTOFF_LO_DS :: PPC64_RelocationType
pattern R_PPC64_SECTOFF_LO_DS = PPC64_RelocationType 62 -- #lo(R + A) >> 2

pattern R_PPC64_TOC16_DS :: PPC64_RelocationType
pattern R_PPC64_TOC16_DS = PPC64_RelocationType 63 -- (S + A - .TOC.) >> 2

pattern R_PPC64_TOC16_LO_DS :: PPC64_RelocationType
pattern R_PPC64_TOC16_LO_DS = PPC64_RelocationType 64 -- #lo(S + A - .TOC.) >> 2

pattern R_PPC64_PLTGOT16_DS :: PPC64_RelocationType
pattern R_PPC64_PLTGOT16_DS = PPC64_RelocationType 65 -- M >> 2

pattern R_PPC64_PLTGOT16_LO_DS :: PPC64_RelocationType
pattern R_PPC64_PLTGOT16_LO_DS = PPC64_RelocationType 66 -- #lo(M) >> 2

pattern R_PPC64_TLS :: PPC64_RelocationType
pattern R_PPC64_TLS = PPC64_RelocationType 67 -- none

pattern R_PPC64_DTPMOD64 :: PPC64_RelocationType
pattern R_PPC64_DTPMOD64 = PPC64_RelocationType 68 -- @dtpmod

pattern R_PPC64_TPREL16 :: PPC64_RelocationType
pattern R_PPC64_TPREL16 = PPC64_RelocationType 69 -- @tprel

pattern R_PPC64_TPREL16_LO :: PPC64_RelocationType
pattern R_PPC64_TPREL16_LO = PPC64_RelocationType 70 -- #lo(@tprel)

pattern R_PPC64_TPREL16_HI :: PPC64_RelocationType
pattern R_PPC64_TPREL16_HI = PPC64_RelocationType 71 -- #hi(@tprel)

pattern R_PPC64_TPREL16_HA :: PPC64_RelocationType
pattern R_PPC64_TPREL16_HA = PPC64_RelocationType 72 -- #ha(@tprel)

pattern R_PPC64_TPREL64 :: PPC64_RelocationType
pattern R_PPC64_TPREL64 = PPC64_RelocationType 73 -- @tprel

pattern R_PPC64_DTPREL16 :: PPC64_RelocationType
pattern R_PPC64_DTPREL16 = PPC64_RelocationType 74 -- @dtprel

pattern R_PPC64_DTPREL16_LO :: PPC64_RelocationType
pattern R_PPC64_DTPREL16_LO = PPC64_RelocationType 75 -- #lo(@dtprel)

pattern R_PPC64_DTPREL16_HI :: PPC64_RelocationType
pattern R_PPC64_DTPREL16_HI = PPC64_RelocationType 76 -- #hi(@dtprel)

pattern R_PPC64_DTPREL16_HA :: PPC64_RelocationType
pattern R_PPC64_DTPREL16_HA = PPC64_RelocationType 77 -- #ha(@dtprel)

pattern R_PPC64_DTPREL64 :: PPC64_RelocationType
pattern R_PPC64_DTPREL64 = PPC64_RelocationType 78 -- @dtprel

pattern R_PPC64_GOT_TLSGD16 :: PPC64_RelocationType
pattern R_PPC64_GOT_TLSGD16 = PPC64_RelocationType 79 -- @got@tlsgd

pattern R_PPC64_GOT_TLSGD16_LO :: PPC64_RelocationType
pattern R_PPC64_GOT_TLSGD16_LO = PPC64_RelocationType 80 -- #lo(@got@tlsgd)

pattern R_PPC64_GOT_TLSGD16_HI :: PPC64_RelocationType
pattern R_PPC64_GOT_TLSGD16_HI = PPC64_RelocationType 81 -- #hi(@got@tlsgd)

pattern R_PPC64_GOT_TLSGD16_HA :: PPC64_RelocationType
pattern R_PPC64_GOT_TLSGD16_HA = PPC64_RelocationType 82 -- #ha(@got@tlsgd)

pattern R_PPC64_GOT_TLSLD16 :: PPC64_RelocationType
pattern R_PPC64_GOT_TLSLD16 = PPC64_RelocationType 83 -- @got@tlsld

pattern R_PPC64_GOT_TLSLD16_LO :: PPC64_RelocationType
pattern R_PPC64_GOT_TLSLD16_LO = PPC64_RelocationType 84 -- #lo(@got@tlsld)

pattern R_PPC64_GOT_TLSLD16_HI :: PPC64_RelocationType
pattern R_PPC64_GOT_TLSLD16_HI = PPC64_RelocationType 85 -- #hi(@got@tlsld)

pattern R_PPC64_GOT_TLSLD16_HA :: PPC64_RelocationType
pattern R_PPC64_GOT_TLSLD16_HA = PPC64_RelocationType 86 -- #ha(@got@tlsld)

pattern R_PPC64_GOT_TPREL16_DS :: PPC64_RelocationType
pattern R_PPC64_GOT_TPREL16_DS = PPC64_RelocationType 87 -- @got@tprel

pattern R_PPC64_GOT_TPREL16_LO_DS :: PPC64_RelocationType
pattern R_PPC64_GOT_TPREL16_LO_DS = PPC64_RelocationType 88 -- #lo(@got@tprel)

pattern R_PPC64_GOT_TPREL16_HI :: PPC64_RelocationType
pattern R_PPC64_GOT_TPREL16_HI = PPC64_RelocationType 89 -- #hi(@got@tprel)

pattern R_PPC64_GOT_TPREL16_HA :: PPC64_RelocationType
pattern R_PPC64_GOT_TPREL16_HA = PPC64_RelocationType 90 -- #ha(@got@tprel)

pattern R_PPC64_GOT_DTPREL16_DS :: PPC64_RelocationType
pattern R_PPC64_GOT_DTPREL16_DS = PPC64_RelocationType 91 -- @got@dtprel

pattern R_PPC64_GOT_DTPREL16_LO_DS :: PPC64_RelocationType
pattern R_PPC64_GOT_DTPREL16_LO_DS = PPC64_RelocationType 92 -- #lo(@got@dtprel)

pattern R_PPC64_GOT_DTPREL16_HI :: PPC64_RelocationType
pattern R_PPC64_GOT_DTPREL16_HI = PPC64_RelocationType 93 -- #hi(@got@dtprel)

pattern R_PPC64_GOT_DTPREL16_HA :: PPC64_RelocationType
pattern R_PPC64_GOT_DTPREL16_HA = PPC64_RelocationType 94 -- #ha(@got@dtprel)

pattern R_PPC64_TPREL16_DS :: PPC64_RelocationType
pattern R_PPC64_TPREL16_DS = PPC64_RelocationType 95 -- @tprel

pattern R_PPC64_TPREL16_LO_DS :: PPC64_RelocationType
pattern R_PPC64_TPREL16_LO_DS = PPC64_RelocationType 96 -- #lo(@tprel)

pattern R_PPC64_TPREL16_HIGHER :: PPC64_RelocationType
pattern R_PPC64_TPREL16_HIGHER = PPC64_RelocationType 97 -- #higher(@tprel)

pattern R_PPC64_TPREL16_HIGHERA :: PPC64_RelocationType
pattern R_PPC64_TPREL16_HIGHERA = PPC64_RelocationType 98 -- #highera(@tprel)

pattern R_PPC64_TPREL16_HIGHEST :: PPC64_RelocationType
pattern R_PPC64_TPREL16_HIGHEST = PPC64_RelocationType 99 -- #highest(@tprel)

pattern R_PPC64_TPREL16_HIGHESTA :: PPC64_RelocationType
pattern R_PPC64_TPREL16_HIGHESTA = PPC64_RelocationType 100 -- #highesta(@tprel)

pattern R_PPC64_DTPREL16_DS :: PPC64_RelocationType
pattern R_PPC64_DTPREL16_DS = PPC64_RelocationType 101 -- @dtprel

pattern R_PPC64_DTPREL16_LO_DS :: PPC64_RelocationType
pattern R_PPC64_DTPREL16_LO_DS = PPC64_RelocationType 102 -- #lo(@dtprel)

pattern R_PPC64_DTPREL16_HIGHER :: PPC64_RelocationType
pattern R_PPC64_DTPREL16_HIGHER = PPC64_RelocationType 103 -- #higher(@dtprel)

pattern R_PPC64_DTPREL16_HIGHERA :: PPC64_RelocationType
pattern R_PPC64_DTPREL16_HIGHERA = PPC64_RelocationType 104 -- #highera(@dtprel)

pattern R_PPC64_DTPREL16_HIGHEST :: PPC64_RelocationType
pattern R_PPC64_DTPREL16_HIGHEST = PPC64_RelocationType 105 -- #highest(@dtprel)

pattern R_PPC64_DTPREL16_HIGHESTA :: PPC64_RelocationType
pattern R_PPC64_DTPREL16_HIGHESTA = PPC64_RelocationType 106 -- #highesta(@dtprel)

-- These values are derived from the ELFv2 relocation-types table:
-- https://github.com/OpenPOWERFoundation/ELFv2-ABI/blob/2c052b1ec5a5e2c51989eb109f8559a9df6d8202/specification/ch_3.xml.

pattern R_PPC64_TLSGD :: PPC64_RelocationType
pattern R_PPC64_TLSGD = PPC64_RelocationType 107
pattern R_PPC64_TLSLD :: PPC64_RelocationType
pattern R_PPC64_TLSLD = PPC64_RelocationType 108
pattern R_PPC64_TOCSAVE :: PPC64_RelocationType
pattern R_PPC64_TOCSAVE = PPC64_RelocationType 109
pattern R_PPC64_ADDR16_HIGH :: PPC64_RelocationType
pattern R_PPC64_ADDR16_HIGH = PPC64_RelocationType 110
pattern R_PPC64_ADDR16_HIGHA :: PPC64_RelocationType
pattern R_PPC64_ADDR16_HIGHA = PPC64_RelocationType 111
pattern R_PPC64_TPREL16_HIGH :: PPC64_RelocationType
pattern R_PPC64_TPREL16_HIGH = PPC64_RelocationType 112
pattern R_PPC64_TPREL16_HIGHA :: PPC64_RelocationType
pattern R_PPC64_TPREL16_HIGHA = PPC64_RelocationType 113
pattern R_PPC64_DTPREL16_HIGH :: PPC64_RelocationType
pattern R_PPC64_DTPREL16_HIGH = PPC64_RelocationType 114
pattern R_PPC64_DTPREL16_HIGHA :: PPC64_RelocationType
pattern R_PPC64_DTPREL16_HIGHA = PPC64_RelocationType 115
pattern R_PPC64_REL24_NOTOC :: PPC64_RelocationType
pattern R_PPC64_REL24_NOTOC = PPC64_RelocationType 116
pattern R_PPC64_ADDR64_LOCAL :: PPC64_RelocationType
pattern R_PPC64_ADDR64_LOCAL = PPC64_RelocationType 117
pattern R_PPC64_ENTRY :: PPC64_RelocationType
pattern R_PPC64_ENTRY = PPC64_RelocationType 118
pattern R_PPC64_PLTSEQ :: PPC64_RelocationType
pattern R_PPC64_PLTSEQ = PPC64_RelocationType 119
pattern R_PPC64_PLTCALL :: PPC64_RelocationType
pattern R_PPC64_PLTCALL = PPC64_RelocationType 120
pattern R_PPC64_PLTSEQ_NOTOC :: PPC64_RelocationType
pattern R_PPC64_PLTSEQ_NOTOC = PPC64_RelocationType 121
pattern R_PPC64_PLTCALL_NOTOC :: PPC64_RelocationType
pattern R_PPC64_PLTCALL_NOTOC = PPC64_RelocationType 122
pattern R_PPC64_PCREL_OPT :: PPC64_RelocationType
pattern R_PPC64_PCREL_OPT = PPC64_RelocationType 123
pattern R_PPC64_D34 :: PPC64_RelocationType
pattern R_PPC64_D34 = PPC64_RelocationType 128
pattern R_PPC64_D34_LO :: PPC64_RelocationType
pattern R_PPC64_D34_LO = PPC64_RelocationType 129
pattern R_PPC64_D34_HI30 :: PPC64_RelocationType
pattern R_PPC64_D34_HI30 = PPC64_RelocationType 130
pattern R_PPC64_D34_HA30 :: PPC64_RelocationType
pattern R_PPC64_D34_HA30 = PPC64_RelocationType 131
pattern R_PPC64_PCREL34 :: PPC64_RelocationType
pattern R_PPC64_PCREL34 = PPC64_RelocationType 132
pattern R_PPC64_GOT_PCREL34 :: PPC64_RelocationType
pattern R_PPC64_GOT_PCREL34 = PPC64_RelocationType 133
pattern R_PPC64_PLT_PCREL34 :: PPC64_RelocationType
pattern R_PPC64_PLT_PCREL34 = PPC64_RelocationType 134
pattern R_PPC64_PLT_PCREL34_NOTOC :: PPC64_RelocationType
pattern R_PPC64_PLT_PCREL34_NOTOC = PPC64_RelocationType 135
pattern R_PPC64_ADDR16_HIGHER34 :: PPC64_RelocationType
pattern R_PPC64_ADDR16_HIGHER34 = PPC64_RelocationType 136
pattern R_PPC64_ADDR16_HIGHERA34 :: PPC64_RelocationType
pattern R_PPC64_ADDR16_HIGHERA34 = PPC64_RelocationType 137
pattern R_PPC64_ADDR16_HIGHEST34 :: PPC64_RelocationType
pattern R_PPC64_ADDR16_HIGHEST34 = PPC64_RelocationType 138
pattern R_PPC64_ADDR16_HIGHESTA34 :: PPC64_RelocationType
pattern R_PPC64_ADDR16_HIGHESTA34 = PPC64_RelocationType 139
pattern R_PPC64_REL16_HIGHER34 :: PPC64_RelocationType
pattern R_PPC64_REL16_HIGHER34 = PPC64_RelocationType 140
pattern R_PPC64_REL16_HIGHERA34 :: PPC64_RelocationType
pattern R_PPC64_REL16_HIGHERA34 = PPC64_RelocationType 141
pattern R_PPC64_REL16_HIGHEST34 :: PPC64_RelocationType
pattern R_PPC64_REL16_HIGHEST34 = PPC64_RelocationType 142
pattern R_PPC64_REL16_HIGHESTA34 :: PPC64_RelocationType
pattern R_PPC64_REL16_HIGHESTA34 = PPC64_RelocationType 143
pattern R_PPC64_D28 :: PPC64_RelocationType
pattern R_PPC64_D28 = PPC64_RelocationType 144
pattern R_PPC64_PCREL28 :: PPC64_RelocationType
pattern R_PPC64_PCREL28 = PPC64_RelocationType 145
pattern R_PPC64_TPREL34 :: PPC64_RelocationType
pattern R_PPC64_TPREL34 = PPC64_RelocationType 146
pattern R_PPC64_DTPREL34 :: PPC64_RelocationType
pattern R_PPC64_DTPREL34 = PPC64_RelocationType 147
pattern R_PPC64_GOT_TLSGD_PCREL34 :: PPC64_RelocationType
pattern R_PPC64_GOT_TLSGD_PCREL34 = PPC64_RelocationType 148
pattern R_PPC64_GOT_TLSLD_PCREL34 :: PPC64_RelocationType
pattern R_PPC64_GOT_TLSLD_PCREL34 = PPC64_RelocationType 149
pattern R_PPC64_GOT_TPREL_PCREL34 :: PPC64_RelocationType
pattern R_PPC64_GOT_TPREL_PCREL34 = PPC64_RelocationType 150
pattern R_PPC64_GOT_DTPREL_PCREL34 :: PPC64_RelocationType
pattern R_PPC64_GOT_DTPREL_PCREL34 = PPC64_RelocationType 151
pattern R_PPC64_REL16_HIGH :: PPC64_RelocationType
pattern R_PPC64_REL16_HIGH = PPC64_RelocationType 240
pattern R_PPC64_REL16_HIGHA :: PPC64_RelocationType
pattern R_PPC64_REL16_HIGHA = PPC64_RelocationType 241
pattern R_PPC64_REL16_HIGHER :: PPC64_RelocationType
pattern R_PPC64_REL16_HIGHER = PPC64_RelocationType 242
pattern R_PPC64_REL16_HIGHERA :: PPC64_RelocationType
pattern R_PPC64_REL16_HIGHERA = PPC64_RelocationType 243
pattern R_PPC64_REL16_HIGHEST :: PPC64_RelocationType
pattern R_PPC64_REL16_HIGHEST = PPC64_RelocationType 244
pattern R_PPC64_REL16_HIGHESTA :: PPC64_RelocationType
pattern R_PPC64_REL16_HIGHESTA = PPC64_RelocationType 245
pattern R_PPC64_REL16DX_HA :: PPC64_RelocationType
pattern R_PPC64_REL16DX_HA = PPC64_RelocationType 246
pattern R_PPC64_IRELATIVE :: PPC64_RelocationType
pattern R_PPC64_IRELATIVE = PPC64_RelocationType 248
pattern R_PPC64_REL16 :: PPC64_RelocationType
pattern R_PPC64_REL16 = PPC64_RelocationType 249
pattern R_PPC64_REL16_LO :: PPC64_RelocationType
pattern R_PPC64_REL16_LO = PPC64_RelocationType 250
pattern R_PPC64_REL16_HI :: PPC64_RelocationType
pattern R_PPC64_REL16_HI = PPC64_RelocationType 251
pattern R_PPC64_REL16_HA :: PPC64_RelocationType
pattern R_PPC64_REL16_HA = PPC64_RelocationType 252
pattern R_PPC64_GNU_VTINHERIT :: PPC64_RelocationType
pattern R_PPC64_GNU_VTINHERIT = PPC64_RelocationType 253
pattern R_PPC64_GNU_VTENTRY :: PPC64_RelocationType
pattern R_PPC64_GNU_VTENTRY = PPC64_RelocationType 254

ppc64Reloc :: PPC64_RelocationType
           -> String
           -> Int
           -> (PPC64_RelocationType, (String,Maybe Int))
ppc64Reloc tp nm c = (tp, (nm, Just c))

none :: Int
none = 0

doubleword64 :: Int
doubleword64 = 64

word32 :: Int
word32 = 32

half16 :: Int
half16 = 16

half16ds :: Int
half16ds = 14

-- Branch relocation fields are not contiguous low-bit fields, so they are
-- represented as 'Nothing' by 'relocTargetBits'.
ppc64UnsupportedReloc :: PPC64_RelocationType
                     -> String
                     -> (PPC64_RelocationType, (String,Maybe Int))
ppc64UnsupportedReloc tp nm = (tp, (nm, Nothing))

-- The ELFv1 values are derived from Section 4.5.1 (Relocation Types) of
-- https://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf64abi-1.9.pdf.
--
-- Note that some of these values are not currently supported. See
-- https://github.com/GaloisInc/elf-edit/issues/39 for more information.
--
-- The ELFv1 portion of this map is derived from Figure 4-1 (Relocation Types) of
-- https://refspecs.linuxfoundation.org/ELF/ppc64/PPC-elf64abi-1.9.pdf.
-- The additional ELFv2 values are derived from
-- https://github.com/OpenPOWERFoundation/ELFv2-ABI/blob/2c052b1ec5a5e2c51989eb109f8559a9df6d8202/specification/ch_3.xml.

ppc64_RelocationTypes :: Map.Map PPC64_RelocationType (String, Maybe Int)
ppc64_RelocationTypes = Map.fromList
  [ ppc64Reloc R_PPC64_NONE "R_PPC64_NONE" none
  , ppc64Reloc R_PPC64_ADDR32 "R_PPC64_ADDR32" word32
  , ppc64UnsupportedReloc R_PPC64_ADDR24 "R_PPC64_ADDR24"
  , ppc64Reloc R_PPC64_ADDR16 "R_PPC64_ADDR16" half16
  , ppc64Reloc R_PPC64_ADDR16_LO "R_PPC64_ADDR16_LO" half16
  , ppc64Reloc R_PPC64_ADDR16_HI "R_PPC64_ADDR16_HI" half16
  , ppc64Reloc R_PPC64_ADDR16_HA "R_PPC64_ADDR16_HA" half16
  , ppc64UnsupportedReloc R_PPC64_ADDR14 "R_PPC64_ADDR14"
  , ppc64UnsupportedReloc R_PPC64_ADDR14_BRTAKEN "R_PPC64_ADDR14_BRTAKEN"
  , ppc64UnsupportedReloc R_PPC64_ADDR14_BRNTAKEN "R_PPC64_ADDR14_BRNTAKEN"
  , ppc64UnsupportedReloc R_PPC64_REL24 "R_PPC64_REL24"
  , ppc64UnsupportedReloc R_PPC64_REL14 "R_PPC64_REL14"
  , ppc64UnsupportedReloc R_PPC64_REL14_BRTAKEN "R_PPC64_REL14_BRTAKEN"
  , ppc64UnsupportedReloc R_PPC64_REL14_BRNTAKEN "R_PPC64_REL14_BRNTAKEN"
  , ppc64Reloc R_PPC64_GOT16 "R_PPC64_GOT16" half16
  , ppc64Reloc R_PPC64_GOT16_LO "R_PPC64_GOT16_LO" half16
  , ppc64Reloc R_PPC64_GOT16_HI "R_PPC64_GOT16_HI" half16
  , ppc64Reloc R_PPC64_GOT16_HA "R_PPC64_GOT16_HA" half16
  , ppc64Reloc R_PPC64_COPY "R_PPC64_COPY" none
  , ppc64Reloc R_PPC64_GLOB_DAT "R_PPC64_GLOB_DAT" doubleword64
  , ppc64Reloc R_PPC64_JMP_SLOT "R_PPC64_JMP_SLOT" doubleword64
  , ppc64Reloc R_PPC64_RELATIVE "R_PPC64_RELATIVE" doubleword64
  , ppc64Reloc R_PPC64_UADDR32 "R_PPC64_UADDR32" word32
  , ppc64Reloc R_PPC64_UADDR16 "R_PPC64_UADDR16" half16
  , ppc64Reloc R_PPC64_REL32 "R_PPC64_REL32" word32
  , ppc64Reloc R_PPC64_PLT32 "R_PPC64_PLT32" word32
  , ppc64Reloc R_PPC64_PLTREL32 "R_PPC64_PLTREL32" word32
  , ppc64Reloc R_PPC64_PLT16_LO "R_PPC64_PLT16_LO" half16
  , ppc64Reloc R_PPC64_PLT16_HI "R_PPC64_PLT16_HI" half16
  , ppc64Reloc R_PPC64_PLT16_HA "R_PPC64_PLT16_HA" half16
  , ppc64Reloc R_PPC64_SECTOFF "R_PPC64_SECTOFF" half16
  , ppc64Reloc R_PPC64_SECTOFF_LO "R_PPC64_SECTOFF_LO" half16
  , ppc64Reloc R_PPC64_SECTOFF_HI "R_PPC64_SECTOFF_HI" half16
  , ppc64Reloc R_PPC64_SECTOFF_HA "R_PPC64_SECTOFF_HA" half16
  , ppc64UnsupportedReloc R_PPC64_REL30 "R_PPC64_REL30"
  , ppc64Reloc R_PPC64_ADDR64 "R_PPC64_ADDR64" doubleword64
  , ppc64Reloc R_PPC64_ADDR16_HIGHER "R_PPC64_ADDR16_HIGHER" half16
  , ppc64Reloc R_PPC64_ADDR16_HIGHERA "R_PPC64_ADDR16_HIGHERA" half16
  , ppc64Reloc R_PPC64_ADDR16_HIGHEST "R_PPC64_ADDR16_HIGHEST" half16
  , ppc64Reloc R_PPC64_ADDR16_HIGHESTA "R_PPC64_ADDR16_HIGHESTA" half16
  , ppc64Reloc R_PPC64_UADDR64 "R_PPC64_UADDR64" doubleword64
  , ppc64Reloc R_PPC64_REL64 "R_PPC64_REL64" doubleword64
  , ppc64Reloc R_PPC64_PLT64 "R_PPC64_PLT64" doubleword64
  , ppc64Reloc R_PPC64_PLTREL64 "R_PPC64_PLTREL64" doubleword64
  , ppc64Reloc R_PPC64_TOC16 "R_PPC64_TOC16" half16
  , ppc64Reloc R_PPC64_TOC16_LO "R_PPC64_TOC16_LO" half16
  , ppc64Reloc R_PPC64_TOC16_HI "R_PPC64_TOC16_HI" half16
  , ppc64Reloc R_PPC64_TOC16_HA "R_PPC64_TOC16_HA" half16
  , ppc64Reloc R_PPC64_TOC "R_PPC64_TOC" doubleword64
  , ppc64Reloc R_PPC64_PLTGOT16 "R_PPC64_PLTGOT16" half16
  , ppc64Reloc R_PPC64_PLTGOT16_LO "R_PPC64_PLTGOT16_LO" half16
  , ppc64Reloc R_PPC64_PLTGOT16_HI "R_PPC64_PLTGOT16_HI" half16
  , ppc64Reloc R_PPC64_PLTGOT16_HA "R_PPC64_PLTGOT16_HA" half16
  , ppc64Reloc R_PPC64_ADDR16_DS "R_PPC64_ADDR16_DS" half16ds
  , ppc64Reloc R_PPC64_ADDR16_LO_DS "R_PPC64_ADDR16_LO_DS" half16ds
  , ppc64Reloc R_PPC64_GOT16_DS "R_PPC64_GOT16_DS" half16ds
  , ppc64Reloc R_PPC64_GOT16_LO_DS "R_PPC64_GOT16_LO_DS" half16ds
  , ppc64Reloc R_PPC64_PLT16_LO_DS "R_PPC64_PLT16_LO_DS" half16ds
  , ppc64Reloc R_PPC64_SECTOFF_DS "R_PPC64_SECTOFF_DS" half16ds
  , ppc64Reloc R_PPC64_SECTOFF_LO_DS "R_PPC64_SECTOFF_LO_DS" half16ds
  , ppc64Reloc R_PPC64_TOC16_DS "R_PPC64_TOC16_DS" half16ds
  , ppc64Reloc R_PPC64_TOC16_LO_DS "R_PPC64_TOC16_LO_DS" half16ds
  , ppc64Reloc R_PPC64_PLTGOT16_DS "R_PPC64_PLTGOT16_DS" half16ds
  , ppc64Reloc R_PPC64_PLTGOT16_LO_DS "R_PPC64_PLTGOT16_LO_DS" half16ds
  , ppc64Reloc R_PPC64_TLS "R_PPC64_TLS" none
  , ppc64Reloc R_PPC64_DTPMOD64 "R_PPC64_DTPMOD64" doubleword64
  , ppc64Reloc R_PPC64_TPREL16 "R_PPC64_TPREL16" half16
  , ppc64Reloc R_PPC64_TPREL16_LO "R_PPC64_TPREL16_LO" half16
  , ppc64Reloc R_PPC64_TPREL16_HI "R_PPC64_TPREL16_HI" half16
  , ppc64Reloc R_PPC64_TPREL16_HA "R_PPC64_TPREL16_HA" half16
  , ppc64Reloc R_PPC64_TPREL64 "R_PPC64_TPREL64" doubleword64
  , ppc64Reloc R_PPC64_DTPREL16 "R_PPC64_DTPREL16" half16
  , ppc64Reloc R_PPC64_DTPREL16_LO "R_PPC64_DTPREL16_LO" half16
  , ppc64Reloc R_PPC64_DTPREL16_HI "R_PPC64_DTPREL16_HI" half16
  , ppc64Reloc R_PPC64_DTPREL16_HA "R_PPC64_DTPREL16_HA" half16
  , ppc64Reloc R_PPC64_DTPREL64 "R_PPC64_DTPREL64" doubleword64
  , ppc64Reloc R_PPC64_GOT_TLSGD16 "R_PPC64_GOT_TLSGD16" half16
  , ppc64Reloc R_PPC64_GOT_TLSGD16_LO "R_PPC64_GOT_TLSGD16_LO" half16
  , ppc64Reloc R_PPC64_GOT_TLSGD16_HI "R_PPC64_GOT_TLSGD16_HI" half16
  , ppc64Reloc R_PPC64_GOT_TLSGD16_HA "R_PPC64_GOT_TLSGD16_HA" half16
  , ppc64Reloc R_PPC64_GOT_TLSLD16 "R_PPC64_GOT_TLSLD16" half16
  , ppc64Reloc R_PPC64_GOT_TLSLD16_LO "R_PPC64_GOT_TLSLD16_LO" half16
  , ppc64Reloc R_PPC64_GOT_TLSLD16_HI "R_PPC64_GOT_TLSLD16_HI" half16
  , ppc64Reloc R_PPC64_GOT_TLSLD16_HA "R_PPC64_GOT_TLSLD16_HA" half16
  , ppc64Reloc R_PPC64_GOT_TPREL16_DS "R_PPC64_GOT_TPREL16_DS" half16ds
  , ppc64Reloc R_PPC64_GOT_TPREL16_LO_DS "R_PPC64_GOT_TPREL16_LO_DS" half16ds
  , ppc64Reloc R_PPC64_GOT_TPREL16_HI "R_PPC64_GOT_TPREL16_HI" half16
  , ppc64Reloc R_PPC64_GOT_TPREL16_HA "R_PPC64_GOT_TPREL16_HA" half16
  , ppc64Reloc R_PPC64_GOT_DTPREL16_DS "R_PPC64_GOT_DTPREL16_DS" half16ds
  , ppc64Reloc R_PPC64_GOT_DTPREL16_LO_DS "R_PPC64_GOT_DTPREL16_LO_DS" half16ds
  , ppc64Reloc R_PPC64_GOT_DTPREL16_HI "R_PPC64_GOT_DTPREL16_HI" half16
  , ppc64Reloc R_PPC64_GOT_DTPREL16_HA "R_PPC64_GOT_DTPREL16_HA" half16
  , ppc64Reloc R_PPC64_TPREL16_DS "R_PPC64_TPREL16_DS" half16ds
  , ppc64Reloc R_PPC64_TPREL16_LO_DS "R_PPC64_TPREL16_LO_DS" half16ds
  , ppc64Reloc R_PPC64_TPREL16_HIGHER "R_PPC64_TPREL16_HIGHER" half16
  , ppc64Reloc R_PPC64_TPREL16_HIGHERA "R_PPC64_TPREL16_HIGHERA" half16
  , ppc64Reloc R_PPC64_TPREL16_HIGHEST "R_PPC64_TPREL16_HIGHEST" half16
  , ppc64Reloc R_PPC64_TPREL16_HIGHESTA "R_PPC64_TPREL16_HIGHESTA" half16
  , ppc64Reloc R_PPC64_DTPREL16_DS "R_PPC64_DTPREL16_DS" half16ds
  , ppc64Reloc R_PPC64_DTPREL16_LO_DS "R_PPC64_DTPREL16_LO_DS" half16ds
  , ppc64Reloc R_PPC64_DTPREL16_HIGHER "R_PPC64_DTPREL16_HIGHER" half16
  , ppc64Reloc R_PPC64_DTPREL16_HIGHERA "R_PPC64_DTPREL16_HIGHERA" half16
  , ppc64Reloc R_PPC64_DTPREL16_HIGHEST "R_PPC64_DTPREL16_HIGHEST" half16
  , ppc64Reloc R_PPC64_DTPREL16_HIGHESTA "R_PPC64_DTPREL16_HIGHESTA" half16
  , ppc64Reloc R_PPC64_TLSGD "R_PPC64_TLSGD" none
  , ppc64Reloc R_PPC64_TLSLD "R_PPC64_TLSLD" none
  , ppc64Reloc R_PPC64_TOCSAVE "R_PPC64_TOCSAVE" none
  , ppc64Reloc R_PPC64_ADDR16_HIGH "R_PPC64_ADDR16_HIGH" half16
  , ppc64Reloc R_PPC64_ADDR16_HIGHA "R_PPC64_ADDR16_HIGHA" half16
  , ppc64Reloc R_PPC64_TPREL16_HIGH "R_PPC64_TPREL16_HIGH" half16
  , ppc64Reloc R_PPC64_TPREL16_HIGHA "R_PPC64_TPREL16_HIGHA" half16
  , ppc64Reloc R_PPC64_DTPREL16_HIGH "R_PPC64_DTPREL16_HIGH" half16
  , ppc64Reloc R_PPC64_DTPREL16_HIGHA "R_PPC64_DTPREL16_HIGHA" half16
  , ppc64UnsupportedReloc R_PPC64_REL24_NOTOC "R_PPC64_REL24_NOTOC"
  , ppc64Reloc R_PPC64_ADDR64_LOCAL "R_PPC64_ADDR64_LOCAL" doubleword64
  , ppc64Reloc R_PPC64_ENTRY "R_PPC64_ENTRY" none
  , ppc64Reloc R_PPC64_PLTSEQ "R_PPC64_PLTSEQ" none
  , ppc64Reloc R_PPC64_PLTCALL "R_PPC64_PLTCALL" none
  , ppc64Reloc R_PPC64_PLTSEQ_NOTOC "R_PPC64_PLTSEQ_NOTOC" none
  , ppc64Reloc R_PPC64_PLTCALL_NOTOC "R_PPC64_PLTCALL_NOTOC" none
  , ppc64Reloc R_PPC64_PCREL_OPT "R_PPC64_PCREL_OPT" none
  , ppc64UnsupportedReloc R_PPC64_D34 "R_PPC64_D34"
  , ppc64UnsupportedReloc R_PPC64_D34_LO "R_PPC64_D34_LO"
  , ppc64UnsupportedReloc R_PPC64_D34_HI30 "R_PPC64_D34_HI30"
  , ppc64UnsupportedReloc R_PPC64_D34_HA30 "R_PPC64_D34_HA30"
  , ppc64UnsupportedReloc R_PPC64_PCREL34 "R_PPC64_PCREL34"
  , ppc64UnsupportedReloc R_PPC64_GOT_PCREL34 "R_PPC64_GOT_PCREL34"
  , ppc64UnsupportedReloc R_PPC64_PLT_PCREL34 "R_PPC64_PLT_PCREL34"
  , ppc64UnsupportedReloc R_PPC64_PLT_PCREL34_NOTOC "R_PPC64_PLT_PCREL34_NOTOC"
  , ppc64Reloc R_PPC64_ADDR16_HIGHER34 "R_PPC64_ADDR16_HIGHER34" half16
  , ppc64Reloc R_PPC64_ADDR16_HIGHERA34 "R_PPC64_ADDR16_HIGHERA34" half16
  , ppc64Reloc R_PPC64_ADDR16_HIGHEST34 "R_PPC64_ADDR16_HIGHEST34" half16
  , ppc64Reloc R_PPC64_ADDR16_HIGHESTA34 "R_PPC64_ADDR16_HIGHESTA34" half16
  , ppc64Reloc R_PPC64_REL16_HIGHER34 "R_PPC64_REL16_HIGHER34" half16
  , ppc64Reloc R_PPC64_REL16_HIGHERA34 "R_PPC64_REL16_HIGHERA34" half16
  , ppc64Reloc R_PPC64_REL16_HIGHEST34 "R_PPC64_REL16_HIGHEST34" half16
  , ppc64Reloc R_PPC64_REL16_HIGHESTA34 "R_PPC64_REL16_HIGHESTA34" half16
  , ppc64UnsupportedReloc R_PPC64_D28 "R_PPC64_D28"
  , ppc64UnsupportedReloc R_PPC64_PCREL28 "R_PPC64_PCREL28"
  , ppc64UnsupportedReloc R_PPC64_TPREL34 "R_PPC64_TPREL34"
  , ppc64UnsupportedReloc R_PPC64_DTPREL34 "R_PPC64_DTPREL34"
  , ppc64UnsupportedReloc R_PPC64_GOT_TLSGD_PCREL34 "R_PPC64_GOT_TLSGD_PCREL34"
  , ppc64UnsupportedReloc R_PPC64_GOT_TLSLD_PCREL34 "R_PPC64_GOT_TLSLD_PCREL34"
  , ppc64UnsupportedReloc R_PPC64_GOT_TPREL_PCREL34 "R_PPC64_GOT_TPREL_PCREL34"
  , ppc64UnsupportedReloc R_PPC64_GOT_DTPREL_PCREL34 "R_PPC64_GOT_DTPREL_PCREL34"
  , ppc64Reloc R_PPC64_REL16_HIGH "R_PPC64_REL16_HIGH" half16
  , ppc64Reloc R_PPC64_REL16_HIGHA "R_PPC64_REL16_HIGHA" half16
  , ppc64Reloc R_PPC64_REL16_HIGHER "R_PPC64_REL16_HIGHER" half16
  , ppc64Reloc R_PPC64_REL16_HIGHERA "R_PPC64_REL16_HIGHERA" half16
  , ppc64Reloc R_PPC64_REL16_HIGHEST "R_PPC64_REL16_HIGHEST" half16
  , ppc64Reloc R_PPC64_REL16_HIGHESTA "R_PPC64_REL16_HIGHESTA" half16
  , ppc64UnsupportedReloc R_PPC64_REL16DX_HA "R_PPC64_REL16DX_HA"
  , ppc64Reloc R_PPC64_IRELATIVE "R_PPC64_IRELATIVE" doubleword64
  , ppc64Reloc R_PPC64_REL16 "R_PPC64_REL16" half16
  , ppc64Reloc R_PPC64_REL16_LO "R_PPC64_REL16_LO" half16
  , ppc64Reloc R_PPC64_REL16_HI "R_PPC64_REL16_HI" half16
  , ppc64Reloc R_PPC64_REL16_HA "R_PPC64_REL16_HA" half16
  , ppc64Reloc R_PPC64_GNU_VTINHERIT "R_PPC64_GNU_VTINHERIT" none
  , ppc64Reloc R_PPC64_GNU_VTENTRY "R_PPC64_GNU_VTENTRY" none
  ]

instance Show PPC64_RelocationType where
  show i =
    case Map.lookup i ppc64_RelocationTypes of
      Just (s,_) -> s
      Nothing -> ppHex (fromPPC64_RelocationType i)

instance IsRelocationType PPC64_RelocationType where
  type RelocationWidth PPC64_RelocationType = 64

  relaWidth _ = ELFCLASS64

  toRelocType = PPC64_RelocationType . fromIntegral

  isRelative R_PPC64_RELATIVE = True
  isRelative _                = False

  relocTargetBits tp =
    case Map.lookup tp ppc64_RelocationTypes of
      Just (_,w) -> w
      Nothing -> Just 64
