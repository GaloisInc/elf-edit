{-
Copyright        : (c) Galois, Inc 2024
Maintainer       : Ryan Scott <rscott@galois.com>

RISC-V relocation types. The list of relocation types is taken from Table 3
(Relocation types) of
<https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/17038f12910bf6e0bc8bb12d3a2d09dce3f9152a/riscv-elf.adoc#relocations>.
-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}
module Data.ElfEdit.Relocations.RISCV
  ( RISCV_RelocationType(..)
  , pattern R_RISCV_NONE
  , pattern R_RISCV_32
  , pattern R_RISCV_64
  , pattern R_RISCV_RELATIVE
  , pattern R_RISCV_COPY
  , pattern R_RISCV_JUMP_SLOT
  , pattern R_RISCV_TLS_DTPMOD32
  , pattern R_RISCV_TLS_DTPMOD64
  , pattern R_RISCV_TLS_DTPREL32
  , pattern R_RISCV_TLS_DTPREL64
  , pattern R_RISCV_TLS_TPREL32
  , pattern R_RISCV_TLS_TPREL64
  , pattern R_RISCV_TLSDESC
  , pattern R_RISCV_BRANCH
  , pattern R_RISCV_JAL
  , pattern R_RISCV_CALL
  , pattern R_RISCV_CALL_PLT
  , pattern R_RISCV_GOT_HI20
  , pattern R_RISCV_TLS_GOT_HI20
  , pattern R_RISCV_TLS_GD_HI20
  , pattern R_RISCV_PCREL_HI20
  , pattern R_RISCV_PCREL_LO12_I
  , pattern R_RISCV_PCREL_LO12_S
  , pattern R_RISCV_HI20
  , pattern R_RISCV_LO12_I
  , pattern R_RISCV_LO12_S
  , pattern R_RISCV_TPREL_HI20
  , pattern R_RISCV_TPREL_LO12_I
  , pattern R_RISCV_TPREL_LO12_S
  , pattern R_RISCV_TPREL_ADD
  , pattern R_RISCV_ADD8
  , pattern R_RISCV_ADD16
  , pattern R_RISCV_ADD32
  , pattern R_RISCV_ADD64
  , pattern R_RISCV_SUB8
  , pattern R_RISCV_SUB16
  , pattern R_RISCV_SUB32
  , pattern R_RISCV_SUB64
  , pattern R_RISCV_GOT32_PCREL
  , pattern R_RISCV_ALIGN
  , pattern R_RISCV_RVC_BRANCH
  , pattern R_RISCV_RVC_JUMP
  , pattern R_RISCV_RELAX
  , pattern R_RISCV_SUB6
  , pattern R_RISCV_SET6
  , pattern R_RISCV_SET8
  , pattern R_RISCV_SET16
  , pattern R_RISCV_SET32
  , pattern R_RISCV_32_PCREL
  , pattern R_RISCV_IRELATIVE
  , pattern R_RISCV_PLT32
  , pattern R_RISCV_SET_ULEB128
  , pattern R_RISCV_SUB_ULEB128
  , pattern R_RISCV_TLSDESC_HI20
  , pattern R_RISCV_TLSDESC_LOAD_LO12
  , pattern R_RISCV_TLSDESC_ADD_LO12
  , pattern R_RISCV_TLSDESC_CALL
  , riscv_RelocationTypes
  ) where

import qualified Data.Map.Strict as Map
import           Data.Proxy (Proxy(..))
import           Data.Type.Equality ((:~:)(..))
import           GHC.TypeLits (KnownNat, natVal, sameNat)

import           Data.ElfEdit.Prim.Ehdr (ElfClass(..), ElfWidthConstraints, ElfWordType)
import           Data.ElfEdit.Relocations.Common
import           Data.ElfEdit.Utils (ppHex)

------------------------------------------------------------------------
-- RISCV_RelocationType

-- | Relocation types for RISC-V code. The @w@ type parameter represents the
-- word size (@32@ for ILP32 and @64@ for LP64).
newtype RISCV_RelocationType w = RISCV_RelocationType { fromRISCV_RelocationType :: ElfWordType w }
deriving instance Eq  (ElfWordType w) => Eq  (RISCV_RelocationType w)
deriving instance Ord (ElfWordType w) => Ord (RISCV_RelocationType w)

-- These values are derived from Table 3 (Relocation types) of
-- https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/17038f12910bf6e0bc8bb12d3a2d09dce3f9152a/riscv-elf.adoc#relocations.

pattern R_RISCV_NONE :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_NONE = RISCV_RelocationType 0

pattern R_RISCV_32 :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_32 = RISCV_RelocationType 1 -- S + A

pattern R_RISCV_64 :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_64 = RISCV_RelocationType 2 -- S + A

pattern R_RISCV_RELATIVE :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_RELATIVE = RISCV_RelocationType 3 -- B + A

pattern R_RISCV_COPY :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_COPY = RISCV_RelocationType 4

pattern R_RISCV_JUMP_SLOT :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_JUMP_SLOT = RISCV_RelocationType 5 -- S

pattern R_RISCV_TLS_DTPMOD32 :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_TLS_DTPMOD32 = RISCV_RelocationType 6 -- TLSMODULE

pattern R_RISCV_TLS_DTPMOD64 :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_TLS_DTPMOD64 = RISCV_RelocationType 7 -- TLSMODULE

pattern R_RISCV_TLS_DTPREL32 :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_TLS_DTPREL32 = RISCV_RelocationType 8 -- S + A - TLS_DTV_OFFSET

pattern R_RISCV_TLS_DTPREL64 :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_TLS_DTPREL64 = RISCV_RelocationType 9 -- S + A - TLS_DTV_OFFSET

pattern R_RISCV_TLS_TPREL32 :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_TLS_TPREL32 = RISCV_RelocationType 10 -- S + A + TLSOFFSET

pattern R_RISCV_TLS_TPREL64 :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_TLS_TPREL64 = RISCV_RelocationType 11 -- S + A + TLSOFFSET

pattern R_RISCV_TLSDESC :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_TLSDESC = RISCV_RelocationType 12 -- TLSDESC(S+A)

pattern R_RISCV_BRANCH :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_BRANCH = RISCV_RelocationType 16 -- S + A - P

pattern R_RISCV_JAL :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_JAL = RISCV_RelocationType 17 -- S + A - P

pattern R_RISCV_CALL :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_CALL = RISCV_RelocationType 18 -- S + A - P

pattern R_RISCV_CALL_PLT :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_CALL_PLT = RISCV_RelocationType 19 -- S + A - P

pattern R_RISCV_GOT_HI20 :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_GOT_HI20 = RISCV_RelocationType 20 -- G + GOT + A - P

pattern R_RISCV_TLS_GOT_HI20 :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_TLS_GOT_HI20 = RISCV_RelocationType 21

pattern R_RISCV_TLS_GD_HI20 :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_TLS_GD_HI20 = RISCV_RelocationType 22

pattern R_RISCV_PCREL_HI20 :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_PCREL_HI20 = RISCV_RelocationType 23 -- S + A - P

pattern R_RISCV_PCREL_LO12_I :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_PCREL_LO12_I = RISCV_RelocationType 24 -- S - P

pattern R_RISCV_PCREL_LO12_S :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_PCREL_LO12_S = RISCV_RelocationType 25 -- S - P

pattern R_RISCV_HI20 :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_HI20 = RISCV_RelocationType 26 -- S + A

pattern R_RISCV_LO12_I :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_LO12_I = RISCV_RelocationType 27 -- S + A

pattern R_RISCV_LO12_S :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_LO12_S = RISCV_RelocationType 28 -- S + A

pattern R_RISCV_TPREL_HI20 :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_TPREL_HI20 = RISCV_RelocationType 29

pattern R_RISCV_TPREL_LO12_I :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_TPREL_LO12_I = RISCV_RelocationType 30

pattern R_RISCV_TPREL_LO12_S :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_TPREL_LO12_S = RISCV_RelocationType 31

pattern R_RISCV_TPREL_ADD :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_TPREL_ADD = RISCV_RelocationType 32

pattern R_RISCV_ADD8 :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_ADD8 = RISCV_RelocationType 33 -- V + S + A

pattern R_RISCV_ADD16 :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_ADD16 = RISCV_RelocationType 34 -- V + S + A

pattern R_RISCV_ADD32 :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_ADD32 = RISCV_RelocationType 35 -- V + S + A

pattern R_RISCV_ADD64 :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_ADD64 = RISCV_RelocationType 36 -- V + S + A

pattern R_RISCV_SUB8 :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_SUB8 = RISCV_RelocationType 37 -- V - S - A

pattern R_RISCV_SUB16 :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_SUB16 = RISCV_RelocationType 38 -- V - S - A

pattern R_RISCV_SUB32 :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_SUB32 = RISCV_RelocationType 39 -- V - S - A

pattern R_RISCV_SUB64 :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_SUB64 = RISCV_RelocationType 40 -- V - S - A

pattern R_RISCV_GOT32_PCREL :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_GOT32_PCREL = RISCV_RelocationType 41 -- G + GOT + A - P

pattern R_RISCV_ALIGN :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_ALIGN = RISCV_RelocationType 43

pattern R_RISCV_RVC_BRANCH :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_RVC_BRANCH = RISCV_RelocationType 44 -- S + A - P

pattern R_RISCV_RVC_JUMP :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_RVC_JUMP = RISCV_RelocationType 45 -- S + A - P

pattern R_RISCV_RELAX :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_RELAX = RISCV_RelocationType 51

pattern R_RISCV_SUB6 :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_SUB6 = RISCV_RelocationType 52 -- V - S - A

pattern R_RISCV_SET6 :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_SET6 = RISCV_RelocationType 53 -- S + A

pattern R_RISCV_SET8 :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_SET8 = RISCV_RelocationType 54 -- S + A

pattern R_RISCV_SET16 :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_SET16 = RISCV_RelocationType 55 -- S + A

pattern R_RISCV_SET32 :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_SET32 = RISCV_RelocationType 56 -- S + A

pattern R_RISCV_32_PCREL :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_32_PCREL = RISCV_RelocationType 57 -- S + A - P

pattern R_RISCV_IRELATIVE :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_IRELATIVE = RISCV_RelocationType 58 -- `ifunc_resolver(B + A)`

pattern R_RISCV_PLT32 :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_PLT32 = RISCV_RelocationType 59 -- S + A - P

pattern R_RISCV_SET_ULEB128 :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_SET_ULEB128 = RISCV_RelocationType 60 -- S + A

pattern R_RISCV_SUB_ULEB128 :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_SUB_ULEB128 = RISCV_RelocationType 61 -- V - S - A

pattern R_RISCV_TLSDESC_HI20 :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_TLSDESC_HI20 = RISCV_RelocationType 62 -- S + A - P

pattern R_RISCV_TLSDESC_LOAD_LO12 :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_TLSDESC_LOAD_LO12 = RISCV_RelocationType 63 -- S - P

pattern R_RISCV_TLSDESC_ADD_LO12 :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_TLSDESC_ADD_LO12 = RISCV_RelocationType 64 -- S - P

pattern R_RISCV_TLSDESC_CALL :: (Eq (ElfWordType w), Num (ElfWordType w)) => RISCV_RelocationType w
pattern R_RISCV_TLSDESC_CALL = RISCV_RelocationType 65

riscvReloc :: RISCV_RelocationType w
           -> String
           -> Int
           -> (RISCV_RelocationType w, (String,Int))
riscvReloc tp nm c = (tp, (nm, c))

-- These values are derived from Table 5 (Variables used in relocation fields) of
-- https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/17038f12910bf6e0bc8bb12d3a2d09dce3f9152a/riscv-elf.adoc#relocations.

none :: Int
none = 0

word6 :: Int
word6 = 6

word8 :: Int
word8 = 8

word16 :: Int
word16 = 16

word32 :: Int
word32 = 32

word64 :: Int
word64 = 64

-- The following variable types are described in Figure 2.3 (RISC-V base
-- instruction formats showing immediate variants) and Table 12.1 (Compressed
-- 16-bit RVC instruction formats) of
-- https://riscv.org/wp-content/uploads/2017/05/riscv-spec-v2.2.pdf.
--
-- Note that these values are not currently supported. See
-- https://github.com/GaloisInc/elf-edit/issues/39 for more information.

bType :: Int
bType = error "B-Type fields not currently supported"

cbType :: Int
cbType = error "CB-Type fields not currently supported"

cjType :: Int
cjType = error "CJ-Type fields not currently supported"

iType :: Int
iType = error "I-Type fields not currently supported"

sType :: Int
sType = error "S-Type fields not currently supported"

uType :: Int
uType = error "U-Type fields not currently supported"

jType :: Int
jType = error "J-Type fields not currently supported"

uiType :: Int
uiType = error "U+I-Type fields not currently supported"

-- This is a variable-length encoding, and it's unclear how to support this at
-- the moment.
uleb128 :: Int
uleb128 = error "ULEB128-encoded variables not yet supported"

-- See https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/17038f12910bf6e0bc8bb12d3a2d09dce3f9152a/riscv-elf.adoc#tls-descriptors.
-- It's unclear how to support this at the moment.
tlsDescriptor :: Int
tlsDescriptor = error "TLS descriptor values not yet supported"

-- This map is derived from Table 3 (Relocation types) of
-- https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/17038f12910bf6e0bc8bb12d3a2d09dce3f9152a/riscv-elf.adoc#relocations.

riscv_RelocationTypes ::
  forall w.
  (ElfWidthConstraints w, KnownNat w) =>
  Map.Map (RISCV_RelocationType w) (String, Int)
riscv_RelocationTypes = Map.fromList
  [ riscvReloc R_RISCV_NONE "R_RISCV_NONE" none
  , riscvReloc R_RISCV_32 "R_RISCV_32" word32
  , riscvReloc R_RISCV_64 "R_RISCV_64" word64
  , riscvReloc R_RISCV_RELATIVE "R_RISCV_RELATIVE" wordclass
  , riscvReloc R_RISCV_COPY "R_RISCV_COPY" none
  , riscvReloc R_RISCV_JUMP_SLOT "R_RISCV_JUMP_SLOT" wordclass
  , riscvReloc R_RISCV_TLS_DTPMOD32 "R_RISCV_TLS_DTPMOD32" word32
  , riscvReloc R_RISCV_TLS_DTPMOD64 "R_RISCV_TLS_DTPMOD64" word64
  , riscvReloc R_RISCV_TLS_DTPREL32 "R_RISCV_TLS_DTPREL32" word32
  , riscvReloc R_RISCV_TLS_DTPREL64 "R_RISCV_TLS_DTPREL64" word64
  , riscvReloc R_RISCV_TLS_TPREL32 "R_RISCV_TLS_TPREL32" word32
  , riscvReloc R_RISCV_TLS_TPREL64 "R_RISCV_TLS_TPREL64" word64
  , riscvReloc R_RISCV_TLSDESC "R_RISCV_TLSDESC" tlsDescriptor
  , riscvReloc R_RISCV_BRANCH "R_RISCV_BRANCH" bType
  , riscvReloc R_RISCV_JAL "R_RISCV_JAL" jType
  , riscvReloc R_RISCV_CALL "R_RISCV_CALL" uiType
  , riscvReloc R_RISCV_CALL_PLT "R_RISCV_CALL_PLT" uiType
  , riscvReloc R_RISCV_GOT_HI20 "R_RISCV_GOT_HI20" uType
  , riscvReloc R_RISCV_TLS_GOT_HI20 "R_RISCV_TLS_GOT_HI20" uType
  , riscvReloc R_RISCV_TLS_GD_HI20 "R_RISCV_TLS_GD_HI20" uType
  , riscvReloc R_RISCV_PCREL_HI20 "R_RISCV_PCREL_HI20" uType
  , riscvReloc R_RISCV_PCREL_LO12_I "R_RISCV_PCREL_LO12_I" iType
  , riscvReloc R_RISCV_PCREL_LO12_S "R_RISCV_PCREL_LO12_S" sType
  , riscvReloc R_RISCV_HI20 "R_RISCV_HI20" uType
  , riscvReloc R_RISCV_LO12_I "R_RISCV_LO12_I" iType
  , riscvReloc R_RISCV_LO12_S "R_RISCV_LO12_S" sType
  , riscvReloc R_RISCV_TPREL_HI20 "R_RISCV_TPREL_HI20" uType
  , riscvReloc R_RISCV_TPREL_LO12_I "R_RISCV_TPREL_LO12_I" iType
  , riscvReloc R_RISCV_TPREL_LO12_S "R_RISCV_TPREL_LO12_S" sType
  , riscvReloc R_RISCV_TPREL_ADD "R_RISCV_TPREL_ADD" none
  , riscvReloc R_RISCV_ADD8 "R_RISCV_ADD8" word8
  , riscvReloc R_RISCV_ADD16 "R_RISCV_ADD16" word16
  , riscvReloc R_RISCV_ADD32 "R_RISCV_ADD32" word32
  , riscvReloc R_RISCV_ADD64 "R_RISCV_ADD64" word64
  , riscvReloc R_RISCV_SUB8 "R_RISCV_SUB8" word8
  , riscvReloc R_RISCV_SUB16 "R_RISCV_SUB16" word16
  , riscvReloc R_RISCV_SUB32 "R_RISCV_SUB32" word32
  , riscvReloc R_RISCV_SUB64 "R_RISCV_SUB64" word64
  , riscvReloc R_RISCV_GOT32_PCREL "R_RISCV_GOT32_PCREL" word32
  , riscvReloc R_RISCV_ALIGN "R_RISCV_ALIGN" none
  , riscvReloc R_RISCV_RVC_BRANCH "R_RISCV_RVC_BRANCH" cbType
  , riscvReloc R_RISCV_RVC_JUMP "R_RISCV_RVC_JUMP" cjType
  , riscvReloc R_RISCV_RELAX "R_RISCV_RELAX" none
  , riscvReloc R_RISCV_SUB6 "R_RISCV_SUB6" word6
  , riscvReloc R_RISCV_SET6 "R_RISCV_SET6" word6
  , riscvReloc R_RISCV_SET8 "R_RISCV_SET8" word8
  , riscvReloc R_RISCV_SET16 "R_RISCV_SET16" word16
  , riscvReloc R_RISCV_SET32 "R_RISCV_SET32" word32
  , riscvReloc R_RISCV_32_PCREL "R_RISCV_32_PCREL" word32
  , riscvReloc R_RISCV_IRELATIVE "R_RISCV_IRELATIVE" wordclass
  , riscvReloc R_RISCV_PLT32 "R_RISCV_PLT32" word32
  , riscvReloc R_RISCV_SET_ULEB128 "R_RISCV_SET_ULEB128" uleb128
  , riscvReloc R_RISCV_SUB_ULEB128 "R_RISCV_SUB_ULEB128" uleb128
  , riscvReloc R_RISCV_TLSDESC_HI20 "R_RISCV_TLSDESC_HI20" uType
  , riscvReloc R_RISCV_TLSDESC_LOAD_LO12 "R_RISCV_TLSDESC_LOAD_LO12" iType
  , riscvReloc R_RISCV_TLSDESC_ADD_LO12 "R_RISCV_TLSDESC_ADD_LO12" iType
  , riscvReloc R_RISCV_TLSDESC_CALL "R_RISCV_TLSDESC_CALL" none
  ]
  where
    wordclass :: Int
    wordclass = withRiscvWordSize (Proxy @w) word32 word64

instance (ElfWidthConstraints w, KnownNat w) => Show (RISCV_RelocationType w) where
  show i =
    case Map.lookup i riscv_RelocationTypes of
      Just (s,_) -> s
      Nothing -> ppHex (fromRISCV_RelocationType i)

instance (ElfWidthConstraints w, KnownNat w) => IsRelocationType (RISCV_RelocationType w) where
  type RelocationWidth (RISCV_RelocationType w) = w

  relaWidth _ = withRiscvWordSize (Proxy @w) ELFCLASS32 ELFCLASS64

  toRelocType = RISCV_RelocationType . fromIntegral

  isRelative R_RISCV_RELATIVE = True
  isRelative _                = False

  relocTargetBits tp =
    case Map.lookup tp riscv_RelocationTypes of
      Just (_,w) -> w
      Nothing -> fromInteger $ natVal $ Proxy @w

-- We only support 32-bit and 64-bit RISC-V. This is a helper function for
-- dispatching on the RISC-V word size, with each continuation having type-level
-- evidence that the word size is equal to either 32 or 64.
withRiscvWordSize :: KnownNat n => proxy n -> ((n ~ 32) => r) -> ((n ~ 64) => r) -> r
withRiscvWordSize proxy k32 k64
  | Just Refl <- sameNat proxy (Proxy @32)
  = k32
  | Just Refl <- sameNat proxy (Proxy @64)
  = k64
  | otherwise
  = error $ "Unsupported RISC-V word size: " ++ show (natVal proxy)
