{-
Copyright        : (c) Galois, Inc 2016
Maintainer       : Joe Hendrix <jhendrix@galois.com>

X86_64 relocation types. The list of relocation types is taken from
<https://gitlab.com/x86-psABIs/x86-64-ABI/-/blob/e1ce098331da5dbd66e1ffc74162380bcc213236/x86-64-ABI/object-files.tex>.
-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE TypeFamilies #-}
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
  , pattern R_X86_64_GOT64
  , pattern R_X86_64_GOTPCREL64
  , pattern R_X86_64_GOTPC64
  , pattern R_X86_64_PLTOFF64
  , pattern R_X86_64_SIZE32
  , pattern R_X86_64_SIZE64
  , pattern R_X86_64_GOTPC32_TLSDESC
  , pattern R_X86_64_TLSDESC_CALL
  , pattern R_X86_64_TLSDESC
  , pattern R_X86_64_IRELATIVE
  , pattern R_X86_64_RELATIVE64
  , pattern R_X86_64_GOTPCRELX
  , pattern R_X86_64_REX_GOTPCRELX
  , pattern R_X86_64_CODE_4_GOTPCRELX
  , pattern R_X86_64_CODE_4_GOTTPOFF
  , pattern R_X86_64_CODE_4_GOTPC32_TLSDESC
  , pattern R_X86_64_CODE_5_GOTPCRELX
  , pattern R_X86_64_CODE_5_GOTTPOFF
  , pattern R_X86_64_CODE_5_GOTPC32_TLSDESC
  , pattern R_X86_64_CODE_6_GOTPCRELX
  , pattern R_X86_64_CODE_6_GOTTPOFF
  , pattern R_X86_64_CODE_6_GOTPC32_TLSDESC
  ) where

import qualified Data.Map.Strict as Map
import           Data.Word (Word32)
import           Numeric (showHex)

import           Data.ElfEdit.Prim.Ehdr
import           Data.ElfEdit.Relocations.Common

------------------------------------------------------------------------
-- X86_64_RelocationType

-- | Relocation types for 64-bit x86 code.
newtype X86_64_RelocationType = X86_64_RelocationType { fromX86_64_RelocationType :: Word32 }
  deriving (Eq,Ord)

-- | No relocation
pattern R_X86_64_NONE :: X86_64_RelocationType
pattern R_X86_64_NONE            = X86_64_RelocationType  0
-- | Direct 64 bit
pattern R_X86_64_64 :: X86_64_RelocationType
pattern R_X86_64_64              = X86_64_RelocationType  1
-- | PC relative 32 bit signed
pattern R_X86_64_PC32 :: X86_64_RelocationType
pattern R_X86_64_PC32            = X86_64_RelocationType  2
-- | 32 bit GOT entry
pattern R_X86_64_GOT32 :: X86_64_RelocationType
pattern R_X86_64_GOT32           = X86_64_RelocationType  3
-- | 32 bit PLT address
pattern R_X86_64_PLT32 :: X86_64_RelocationType
pattern R_X86_64_PLT32           = X86_64_RelocationType  4
-- | Copy symbol at runtime
pattern R_X86_64_COPY :: X86_64_RelocationType
pattern R_X86_64_COPY            = X86_64_RelocationType  5
-- | Create GOT entry
pattern R_X86_64_GLOB_DAT :: X86_64_RelocationType
pattern R_X86_64_GLOB_DAT        = X86_64_RelocationType  6
-- | Create PLT entry
pattern R_X86_64_JUMP_SLOT :: X86_64_RelocationType
pattern R_X86_64_JUMP_SLOT       = X86_64_RelocationType  7
-- | Adjust by program base
pattern R_X86_64_RELATIVE :: X86_64_RelocationType
pattern R_X86_64_RELATIVE        = X86_64_RelocationType  8
-- | 32 bit signed pc relative offset to GOT
pattern R_X86_64_GOTPCREL :: X86_64_RelocationType
pattern R_X86_64_GOTPCREL        = X86_64_RelocationType  9
-- | Direct 32 bit zero extended
pattern R_X86_64_32 :: X86_64_RelocationType
pattern R_X86_64_32              = X86_64_RelocationType 10
-- | Direct 32 bit sign extended
pattern R_X86_64_32S :: X86_64_RelocationType
pattern R_X86_64_32S             = X86_64_RelocationType 11
-- | Direct 16 bit zero extended
pattern R_X86_64_16 :: X86_64_RelocationType
pattern R_X86_64_16              = X86_64_RelocationType 12
-- | 16 bit sign extended pc relative
pattern R_X86_64_PC16 :: X86_64_RelocationType
pattern R_X86_64_PC16            = X86_64_RelocationType 13
-- | Direct 8 bit sign extended
pattern R_X86_64_8 :: X86_64_RelocationType
pattern R_X86_64_8               = X86_64_RelocationType 14
-- | 8 bit sign extended pc relative
pattern R_X86_64_PC8 :: X86_64_RelocationType
pattern R_X86_64_PC8             = X86_64_RelocationType 15
pattern R_X86_64_DTPMOD64 :: X86_64_RelocationType
pattern R_X86_64_DTPMOD64        = X86_64_RelocationType 16
pattern R_X86_64_DTPOFF64 :: X86_64_RelocationType
pattern R_X86_64_DTPOFF64        = X86_64_RelocationType 17
pattern R_X86_64_TPOFF64 :: X86_64_RelocationType
pattern R_X86_64_TPOFF64         = X86_64_RelocationType 18
pattern R_X86_64_TLSGD :: X86_64_RelocationType
pattern R_X86_64_TLSGD           = X86_64_RelocationType 19
pattern R_X86_64_TLSLD :: X86_64_RelocationType
pattern R_X86_64_TLSLD           = X86_64_RelocationType 20
pattern R_X86_64_DTPOFF32 :: X86_64_RelocationType
pattern R_X86_64_DTPOFF32        = X86_64_RelocationType 21
pattern R_X86_64_GOTTPOFF :: X86_64_RelocationType
pattern R_X86_64_GOTTPOFF        = X86_64_RelocationType 22
pattern R_X86_64_TPOFF32 :: X86_64_RelocationType
pattern R_X86_64_TPOFF32         = X86_64_RelocationType 23

pattern R_X86_64_PC64 :: X86_64_RelocationType
pattern R_X86_64_PC64            = X86_64_RelocationType 24
pattern R_X86_64_GOTOFF64 :: X86_64_RelocationType
pattern R_X86_64_GOTOFF64        = X86_64_RelocationType 25
pattern R_X86_64_GOTPC32 :: X86_64_RelocationType
pattern R_X86_64_GOTPC32         = X86_64_RelocationType 26

-- These large-model relocation types are specified separately in the x86-64
-- psABI relocation tables.
pattern R_X86_64_GOT64 :: X86_64_RelocationType
pattern R_X86_64_GOT64            = X86_64_RelocationType 27
pattern R_X86_64_GOTPCREL64 :: X86_64_RelocationType
pattern R_X86_64_GOTPCREL64       = X86_64_RelocationType 28
pattern R_X86_64_GOTPC64 :: X86_64_RelocationType
pattern R_X86_64_GOTPC64          = X86_64_RelocationType 29
pattern R_X86_64_PLTOFF64 :: X86_64_RelocationType
pattern R_X86_64_PLTOFF64         = X86_64_RelocationType 31

pattern R_X86_64_SIZE32 :: X86_64_RelocationType
pattern R_X86_64_SIZE32          = X86_64_RelocationType 32
pattern R_X86_64_SIZE64 :: X86_64_RelocationType
pattern R_X86_64_SIZE64          = X86_64_RelocationType 33
pattern R_X86_64_GOTPC32_TLSDESC :: X86_64_RelocationType
pattern R_X86_64_GOTPC32_TLSDESC = X86_64_RelocationType 34
pattern R_X86_64_TLSDESC_CALL :: X86_64_RelocationType
pattern R_X86_64_TLSDESC_CALL    = X86_64_RelocationType 35
pattern R_X86_64_TLSDESC :: X86_64_RelocationType
pattern R_X86_64_TLSDESC         = X86_64_RelocationType 36
pattern R_X86_64_IRELATIVE :: X86_64_RelocationType
pattern R_X86_64_IRELATIVE       = X86_64_RelocationType 37
pattern R_X86_64_RELATIVE64 :: X86_64_RelocationType
pattern R_X86_64_RELATIVE64      = X86_64_RelocationType 38
pattern R_X86_64_GOTPCRELX :: X86_64_RelocationType
pattern R_X86_64_GOTPCRELX       = X86_64_RelocationType 41
pattern R_X86_64_REX_GOTPCRELX :: X86_64_RelocationType
pattern R_X86_64_REX_GOTPCRELX   = X86_64_RelocationType 42
pattern R_X86_64_CODE_4_GOTPCRELX :: X86_64_RelocationType
pattern R_X86_64_CODE_4_GOTPCRELX = X86_64_RelocationType 43
pattern R_X86_64_CODE_4_GOTTPOFF :: X86_64_RelocationType
pattern R_X86_64_CODE_4_GOTTPOFF = X86_64_RelocationType 44
pattern R_X86_64_CODE_4_GOTPC32_TLSDESC :: X86_64_RelocationType
pattern R_X86_64_CODE_4_GOTPC32_TLSDESC = X86_64_RelocationType 45
pattern R_X86_64_CODE_5_GOTPCRELX :: X86_64_RelocationType
pattern R_X86_64_CODE_5_GOTPCRELX = X86_64_RelocationType 46
pattern R_X86_64_CODE_5_GOTTPOFF :: X86_64_RelocationType
pattern R_X86_64_CODE_5_GOTTPOFF = X86_64_RelocationType 47
pattern R_X86_64_CODE_5_GOTPC32_TLSDESC :: X86_64_RelocationType
pattern R_X86_64_CODE_5_GOTPC32_TLSDESC = X86_64_RelocationType 48
pattern R_X86_64_CODE_6_GOTPCRELX :: X86_64_RelocationType
pattern R_X86_64_CODE_6_GOTPCRELX = X86_64_RelocationType 49
pattern R_X86_64_CODE_6_GOTTPOFF :: X86_64_RelocationType
pattern R_X86_64_CODE_6_GOTTPOFF = X86_64_RelocationType 50
pattern R_X86_64_CODE_6_GOTPC32_TLSDESC :: X86_64_RelocationType
pattern R_X86_64_CODE_6_GOTPC32_TLSDESC = X86_64_RelocationType 51

x86Reloc :: X86_64_RelocationType
         -> String
         -> Int
         -> (X86_64_RelocationType, (String,Int))
x86Reloc tp nm c = (tp, (nm, c))

-- | @wordclass@ is 64 on LP64 and 32 on LP32.
--
-- All our programs are currently LP64, but we use this
-- constant in case that needs to change.
wordclass :: Int
wordclass = 64


x86_64_RelocationTypes :: Map.Map X86_64_RelocationType (String,Int)
x86_64_RelocationTypes = Map.fromList
  [ x86Reloc R_X86_64_NONE            "R_X86_64_NONE"   0
  , x86Reloc R_X86_64_64              "R_X86_64_64"    64
  , x86Reloc R_X86_64_PC32            "R_X86_64_PC32"  32
  , x86Reloc R_X86_64_GOT32           "R_X86_64_GOT32" 32
  , x86Reloc R_X86_64_PLT32           "R_X86_64_PLT32" 32
  , x86Reloc R_X86_64_COPY            "R_X86_64_COPY"   0
  , x86Reloc R_X86_64_GLOB_DAT        "R_X86_64_GLOB_DAT"  wordclass
  , x86Reloc R_X86_64_JUMP_SLOT       "R_X86_64_JUMP_SLOT" wordclass

  , x86Reloc R_X86_64_RELATIVE        "R_X86_64_RELATIVE"  wordclass
  , x86Reloc R_X86_64_GOTPCREL        "R_X86_64_GOTPCREL"  32
  , x86Reloc R_X86_64_32              "R_X86_64_32"        32
  , x86Reloc R_X86_64_32S             "R_X86_64_32S"       32
  , x86Reloc R_X86_64_16              "R_X86_64_16"        16
  , x86Reloc R_X86_64_PC16            "R_X86_64_PC16"      16
  , x86Reloc R_X86_64_8               "R_X86_64_8"          8
  , x86Reloc R_X86_64_PC8             "R_X86_64_PC8"        8
  , x86Reloc R_X86_64_DTPMOD64        "R_X86_64_DTPMOD64"  64
  , x86Reloc R_X86_64_DTPOFF64        "R_X86_64_DTPOFF64"  64
  , x86Reloc R_X86_64_TPOFF64         "R_X86_64_TPOFF64"   64
  , x86Reloc R_X86_64_TLSGD           "R_X86_64_TLSGD"     32
  , x86Reloc R_X86_64_TLSLD           "R_X86_64_TLSLD"     32
  , x86Reloc R_X86_64_DTPOFF32        "R_X86_64_DTPOFF32"  32
  , x86Reloc R_X86_64_GOTTPOFF        "R_X86_64_GOTTPOFF"  32
  , x86Reloc R_X86_64_TPOFF32         "R_X86_64_TPOFF32"   32

  , x86Reloc R_X86_64_PC64            "R_X86_64_PC64"      64
  , x86Reloc R_X86_64_GOTOFF64        "R_X86_64_GOTOFF64"  64
  , x86Reloc R_X86_64_GOTPC32         "R_X86_64_GOTPC32"   32
  , x86Reloc R_X86_64_GOT64           "R_X86_64_GOT64"     64
  , x86Reloc R_X86_64_GOTPCREL64      "R_X86_64_GOTPCREL64" 64
  , x86Reloc R_X86_64_GOTPC64         "R_X86_64_GOTPC64"   64
  , x86Reloc R_X86_64_PLTOFF64        "R_X86_64_PLTOFF64"  64
  , x86Reloc R_X86_64_SIZE32          "R_X86_64_SIZE32"    32
  , x86Reloc R_X86_64_SIZE64          "R_X86_64_SIZE64"    64
  , x86Reloc R_X86_64_GOTPC32_TLSDESC "R_X86_64_GOTPC32_TLSDESC" 32
  , x86Reloc R_X86_64_TLSDESC_CALL    "R_X86_64_TLSDESC_CALL"     0
  , x86Reloc R_X86_64_TLSDESC         "R_X86_64_TLSDESC"        128
  , x86Reloc R_X86_64_IRELATIVE       "R_X86_64_IRELATIVE" wordclass
  , x86Reloc R_X86_64_RELATIVE64      "R_X86_64_RELATIVE64" 64
  , x86Reloc R_X86_64_GOTPCRELX       "R_X86_64_GOTPCRELX" 32
  , x86Reloc R_X86_64_REX_GOTPCRELX   "R_X86_64_REX_GOTPCRELX" 32
  , x86Reloc R_X86_64_CODE_4_GOTPCRELX "R_X86_64_CODE_4_GOTPCRELX" 32
  , x86Reloc R_X86_64_CODE_4_GOTTPOFF "R_X86_64_CODE_4_GOTTPOFF" 32
  , x86Reloc R_X86_64_CODE_4_GOTPC32_TLSDESC "R_X86_64_CODE_4_GOTPC32_TLSDESC" 32
  , x86Reloc R_X86_64_CODE_5_GOTPCRELX "R_X86_64_CODE_5_GOTPCRELX" 32
  , x86Reloc R_X86_64_CODE_5_GOTTPOFF "R_X86_64_CODE_5_GOTTPOFF" 32
  , x86Reloc R_X86_64_CODE_5_GOTPC32_TLSDESC "R_X86_64_CODE_5_GOTPC32_TLSDESC" 32
  , x86Reloc R_X86_64_CODE_6_GOTPCRELX "R_X86_64_CODE_6_GOTPCRELX" 32
  , x86Reloc R_X86_64_CODE_6_GOTTPOFF "R_X86_64_CODE_6_GOTTPOFF" 32
  , x86Reloc R_X86_64_CODE_6_GOTPC32_TLSDESC "R_X86_64_CODE_6_GOTPC32_TLSDESC" 32
  ]

instance Show X86_64_RelocationType where
  show i =
    case Map.lookup i x86_64_RelocationTypes of
      Just (s,_) -> s
      Nothing -> "0x" ++ showHex (fromX86_64_RelocationType i) ""

instance IsRelocationType X86_64_RelocationType where
  type RelocationWidth X86_64_RelocationType = 64

  relaWidth _ = ELFCLASS64
  toRelocType = X86_64_RelocationType . fromIntegral

  isRelative R_X86_64_RELATIVE = True
  isRelative R_X86_64_RELATIVE64 = True
  isRelative _ = False

  relocTargetBits tp =
    Just $ case Map.lookup tp x86_64_RelocationTypes of
      Just (_,w) -> w
      Nothing -> 64
