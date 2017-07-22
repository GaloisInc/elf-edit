{-
Copyright        : (c) Galois, Inc 2016
Maintainer       : Joe Hendrix <jhendrix@galois.com>

X86_64 relocation type.
-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE TypeFamilies #-}
#if __GLASGOW_HASKELL__ >= 800
{-# OPTIONS_GHC -fno-warn-missing-pattern-synonym-signatures #-}
#endif
module Data.ElfEdit.Relocations.X86_64
  ( X86_64_RelocationType(..)
  , pattern R_X86_64_NONE
  , pattern R_X86_64_64
  , pattern R_X86_64_PC32
  , pattern R_X86_64_GOT32
  , pattern R_X86_64_PLT32
  , pattern R_X86_64_COPY
  , pattern R_X86_64_GLOB_DAT
  , pattern R_X86_64_JUMP_SLOT
  , pattern R_X86_64_RELATIVE
  , pattern R_X86_64_GOTPCREL
  , pattern R_X86_64_32
  , pattern R_X86_64_32S
  , pattern R_X86_64_16
  , pattern R_X86_64_PC16
  , pattern R_X86_64_8
  , pattern R_X86_64_PC8
  , pattern R_X86_64_DTPMOD64
  , pattern R_X86_64_DTPOFF64
  , pattern R_X86_64_TPOFF64
  , pattern R_X86_64_TLSGD
  , pattern R_X86_64_TLSLD
  , pattern R_X86_64_DTPOFF32
  , pattern R_X86_64_GOTTPOFF
  , pattern R_X86_64_TPOFF32
  , pattern R_X86_64_PC64
  , pattern R_X86_64_GOTOFF64
  , pattern R_X86_64_GOTPC32
  , pattern R_X86_64_SIZE32
  , pattern R_X86_64_SIZE64
  , pattern R_X86_64_GOTPC32_TLSDESC
  , pattern R_X86_64_TLSDESC_CALL
  , pattern R_X86_64_TLSDESC
  , pattern R_X86_64_IRELATIVE
  ) where

import qualified Data.Map.Strict as Map
import           Data.Word (Word32)
import           Numeric (showHex)

import           Data.ElfEdit.Relocations
import           Data.ElfEdit.Types (ElfClass(..))

------------------------------------------------------------------------
-- X86_64_RelocationType

-- | Relocation types for 64-bit x86 code.
newtype X86_64_RelocationType = X86_64_RelocationType { fromX86_64_RelocationType :: Word32 }
  deriving (Eq,Ord)

-- | No relocation
pattern R_X86_64_NONE            = X86_64_RelocationType  0
-- | Direct 64 bit
pattern R_X86_64_64              = X86_64_RelocationType  1
-- | PC relative 32 bit signed
pattern R_X86_64_PC32            = X86_64_RelocationType  2
-- | 32 bit GOT entry
pattern R_X86_64_GOT32           = X86_64_RelocationType  3
-- | 32 bit PLT address
pattern R_X86_64_PLT32           = X86_64_RelocationType  4
-- | Copy symbol at runtime
pattern R_X86_64_COPY            = X86_64_RelocationType  5
-- | Create GOT entry
pattern R_X86_64_GLOB_DAT        = X86_64_RelocationType  6
-- | Create PLT entry
pattern R_X86_64_JUMP_SLOT       = X86_64_RelocationType  7
-- | Adjust by program base
pattern R_X86_64_RELATIVE        = X86_64_RelocationType  8
-- | 32 bit signed pc relative offset to GOT
pattern R_X86_64_GOTPCREL        = X86_64_RelocationType  9
-- | Direct 32 bit zero extended
pattern R_X86_64_32              = X86_64_RelocationType 10

-- | Direct 32 bit sign extended
pattern R_X86_64_32S             = X86_64_RelocationType 11

-- | Direct 16 bit zero extended
pattern R_X86_64_16              = X86_64_RelocationType 12

-- | 16 bit sign extended pc relative
pattern R_X86_64_PC16            = X86_64_RelocationType 13

-- | Direct 8 bit sign extended
pattern R_X86_64_8               = X86_64_RelocationType 14

-- | 8 bit sign extended pc relative
pattern R_X86_64_PC8             = X86_64_RelocationType 15

pattern R_X86_64_DTPMOD64        = X86_64_RelocationType 16
pattern R_X86_64_DTPOFF64        = X86_64_RelocationType 17
pattern R_X86_64_TPOFF64         = X86_64_RelocationType 18
pattern R_X86_64_TLSGD           = X86_64_RelocationType 19
pattern R_X86_64_TLSLD           = X86_64_RelocationType 20
pattern R_X86_64_DTPOFF32        = X86_64_RelocationType 21
pattern R_X86_64_GOTTPOFF        = X86_64_RelocationType 22
pattern R_X86_64_TPOFF32         = X86_64_RelocationType 23

pattern R_X86_64_PC64            = X86_64_RelocationType 24
pattern R_X86_64_GOTOFF64        = X86_64_RelocationType 25
pattern R_X86_64_GOTPC32         = X86_64_RelocationType 26

pattern R_X86_64_SIZE32          = X86_64_RelocationType 32
pattern R_X86_64_SIZE64          = X86_64_RelocationType 33
pattern R_X86_64_GOTPC32_TLSDESC = X86_64_RelocationType 34
pattern R_X86_64_TLSDESC_CALL    = X86_64_RelocationType 35
pattern R_X86_64_TLSDESC         = X86_64_RelocationType 36
pattern R_X86_64_IRELATIVE       = X86_64_RelocationType 37

x86_64_RelocationTypes :: Map.Map X86_64_RelocationType String
x86_64_RelocationTypes = Map.fromList
  [ (,) R_X86_64_NONE            "R_X86_64_NONE"
  , (,) R_X86_64_64              "R_X86_64_64"
  , (,) R_X86_64_PC32            "R_X86_64_PC32"
  , (,) R_X86_64_GOT32           "R_X86_64_GOT32"
  , (,) R_X86_64_PLT32           "R_X86_64_PLT32"
  , (,) R_X86_64_COPY            "R_X86_64_COPY"
  , (,) R_X86_64_GLOB_DAT        "R_X86_64_GLOB_DAT"
  , (,) R_X86_64_JUMP_SLOT       "R_X86_64_JUMP_SLOT"

  , (,) R_X86_64_RELATIVE        "R_X86_64_RELATIVE"
  , (,) R_X86_64_GOTPCREL        "R_X86_64_GOTPCREL"
  , (,) R_X86_64_32              "R_X86_64_32"
  , (,) R_X86_64_32S             "R_X86_64_32S"
  , (,) R_X86_64_16              "R_X86_64_16"
  , (,) R_X86_64_PC16            "R_X86_64_PC16"
  , (,) R_X86_64_8               "R_X86_64_8"
  , (,) R_X86_64_PC8             "R_X86_64_PC8"

  , (,) R_X86_64_DTPMOD64        "R_X86_64_DTPMOD64"
  , (,) R_X86_64_DTPOFF64        "R_X86_64_DTPOFF64"
  , (,) R_X86_64_TPOFF64         "R_X86_64_TPOFF64"
  , (,) R_X86_64_TLSGD           "R_X86_64_TLSGD"
  , (,) R_X86_64_TLSLD           "R_X86_64_TLSLD"
  , (,) R_X86_64_DTPOFF32        "R_X86_64_DTPOFF32"
  , (,) R_X86_64_GOTTPOFF        "R_X86_64_GOTTPOFF"
  , (,) R_X86_64_TPOFF32         "R_X86_64_TPOFF32"

  , (,) R_X86_64_PC64            "R_X86_64_PC64"
  , (,) R_X86_64_GOTOFF64        "R_X86_64_GOTOFF64"
  , (,) R_X86_64_GOTPC32         "R_X86_64_GOTPC32"

  , (,) R_X86_64_SIZE32          "R_X86_64_SIZE32"
  , (,) R_X86_64_SIZE64          "R_X86_64_SIZE64"
  , (,) R_X86_64_GOTPC32_TLSDESC "R_X86_64_GOTPC32_TLSDESC"
  , (,) R_X86_64_TLSDESC_CALL    "R_X86_64_TLSDESC_CALL"
  , (,) R_X86_64_TLSDESC         "R_X86_64_TLSDESC"
  , (,) R_X86_64_IRELATIVE       "R_X86_64_IRELATIVE"
  ]

instance Show X86_64_RelocationType where
  show i =
    case Map.lookup i x86_64_RelocationTypes of
      Just s -> s
      Nothing -> "0x" ++ showHex (fromX86_64_RelocationType i) ""

instance IsRelocationType X86_64_RelocationType where
  type RelocationWidth X86_64_RelocationType = 64

  relaWidth _ = ELFCLASS64
  relaType = Just . X86_64_RelocationType . fromIntegral

  isRelative R_X86_64_RELATIVE = True
  isRelative _ = False
