{-
AArch64 64bit relocation type.
-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE TypeFamilies #-}
module Data.ElfEdit.Relocations.AArch64
  ( AArch64_RelocationType(..)
  , pattern R_AARCH64_ABS64
  , pattern R_AARCH64_GLOB_DAT
  , pattern R_AARCH64_JUMP_SLOT
  , pattern R_AARCH64_RELATIVE
  , pattern R_AARCH64_TLS_DTPMOD64
  , aarch64RelocationTypeNameMap
  ) where

import qualified Data.Map.Strict          as Map
import           Data.Word

import           Data.ElfEdit.Relocations
import           Data.ElfEdit.Types       (ElfClass (..), ppHex)

------------------------------------------------------------------------
-- ARM_RelocationType

-- | Relocation types for AARCH64 code.
newtype AArch64_RelocationType = AArch64_RelocationType { fromARM_RelocationType :: Word32 }
  deriving (Eq,Ord)

pattern R_AARCH64_ABS64 :: AArch64_RelocationType
pattern R_AARCH64_ABS64 = AArch64_RelocationType 257

pattern R_AARCH64_GLOB_DAT :: AArch64_RelocationType
pattern R_AARCH64_GLOB_DAT = AArch64_RelocationType 1025

pattern R_AARCH64_JUMP_SLOT :: AArch64_RelocationType
pattern R_AARCH64_JUMP_SLOT = AArch64_RelocationType 1026

pattern R_AARCH64_RELATIVE :: AArch64_RelocationType
pattern R_AARCH64_RELATIVE = AArch64_RelocationType 1027

pattern R_AARCH64_TLS_DTPMOD64 :: AArch64_RelocationType
pattern R_AARCH64_TLS_DTPMOD64 = AArch64_RelocationType 1029

-- | Maps known AArch64 relocation types to their string representation.
aarch64RelocationTypeNameMap :: Map.Map AArch64_RelocationType String
aarch64RelocationTypeNameMap = Map.fromList
  [ (,) R_AARCH64_ABS64       "R_AARCH64_ABS64"
  , (,) R_AARCH64_GLOB_DAT     "R_AARCH64_GLOB_DAT"
  , (,) R_AARCH64_JUMP_SLOT    "R_AARCH64_JUMP_SLOT"
  , (,) R_AARCH64_RELATIVE     "R_AARCH64_RELATIVE"
  , (,) R_AARCH64_TLS_DTPMOD64 "R_AARCH64_TLS_DTPMOD64"
  ]

instance Show AArch64_RelocationType where
  show i =
    case Map.lookup i aarch64RelocationTypeNameMap of
      Just s  -> s
      Nothing -> ppHex (fromARM_RelocationType i)

instance IsRelocationType AArch64_RelocationType where
  type RelocationWidth AArch64_RelocationType = 64

  relaWidth _ = ELFCLASS64

  relocTargetBits _tp = 64
  toRelocType = AArch64_RelocationType . fromIntegral

  isRelative _tp = False
