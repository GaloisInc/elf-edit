{-
Copyright        : (c) Galois, Inc 2019
ARM 64bit relocation type.
-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE TypeFamilies #-}
module Data.ElfEdit.Relocations.ARM64
  ( ARM64_RelocationType(..)
  , pattern R_AARCH64_JUMP_SLOT
  ) where

import qualified Data.Map.Strict          as Map
import           Data.Word

import           Data.ElfEdit.Relocations
import           Data.ElfEdit.Types       (ElfClass (..), ppHex)

------------------------------------------------------------------------
-- ARM_RelocationType

-- | Relocation types for ARM64 code.
newtype ARM64_RelocationType = ARM64_RelocationType { fromARM_RelocationType :: Word32 }
  deriving (Eq,Ord)

pattern R_AARCH64_ABS64 :: ARM64_RelocationType
pattern R_AARCH64_ABS64 = ARM64_RelocationType 257

pattern R_AARCH64_GLOB_DAT :: ARM64_RelocationType
pattern R_AARCH64_GLOB_DAT = ARM64_RelocationType 1025

pattern R_AARCH64_JUMP_SLOT :: ARM64_RelocationType
pattern R_AARCH64_JUMP_SLOT = ARM64_RelocationType 1026

pattern R_AARCH64_RELATIVE :: ARM64_RelocationType
pattern R_AARCH64_RELATIVE = ARM64_RelocationType 1027

pattern R_AARCH64_TLS_DTPMOD64 :: ARM64_RelocationType
pattern R_AARCH64_TLS_DTPMOD64 = ARM64_RelocationType 1029

arm_RelocationTypes :: Map.Map ARM64_RelocationType String
arm_RelocationTypes = Map.fromList
  [ (,) R_AARCH64_ABS64     "R_AARCH64_ABS64"
  , (,) R_AARCH64_GLOB_DAT "R_AARCH64_GLOB_DAT"
  , (,) R_AARCH64_JUMP_SLOT "R_AARCH64_JUMP_SLOT"
  , (,) R_AARCH64_RELATIVE  "R_AARCH64_RELATIVE"
  , (,) R_AARCH64_TLS_DTPMOD64 "R_AARCH64_TLS_DTPMOD64"
  ]

instance Show ARM64_RelocationType where
  show i =
    case Map.lookup i arm_RelocationTypes of
      Just s  -> s
      Nothing -> ppHex (fromARM_RelocationType i)

instance IsRelocationType ARM64_RelocationType where
  type RelocationWidth ARM64_RelocationType = 64

  relaWidth _ = ELFCLASS64

  relocTargetBits _tp = 64
  toRelocType = ARM64_RelocationType . fromIntegral

  isRelative _tp = False
