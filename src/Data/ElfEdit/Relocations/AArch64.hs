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
  , pattern R_AARCH64_TLS_DTPREL64
  , pattern R_AARCH64_TLS_TPREL64
  , aarch64RelocationTypeNameMap
  ) where

import qualified Data.Map.Strict          as Map
import           Data.Word

import           Data.ElfEdit.Prim.Ehdr (ElfClass(..))
import           Data.ElfEdit.Relocations.Common
import           Data.ElfEdit.Utils (ppHex)

------------------------------------------------------------------------
-- ARM_RelocationType

-- | Relocation types for AARCH64 code.
--
-- N.B.  The type intentionally uses mixedcase for "AArch64" to match
-- ARM's names while the patterns use all capitals to match the
-- constants in `elf.h`
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
pattern R_AARCH64_TLS_DTPMOD64 = AArch64_RelocationType 1028

pattern R_AARCH64_TLS_DTPREL64 :: AArch64_RelocationType
pattern R_AARCH64_TLS_DTPREL64 = AArch64_RelocationType 1029

pattern R_AARCH64_TLS_TPREL64 :: AArch64_RelocationType
pattern R_AARCH64_TLS_TPREL64 = AArch64_RelocationType 1030

none :: Int
none = 0

word16 :: Int
word16 = 16

word32 :: Int
word32 = 32

word64 :: Int
word64 = 64

-- | An instruction-field or relaxation relocation has no contiguous low-bit
-- target field, so it is unsupported by 'relocTargetBits'.
instructionReloc :: Word32
                 -> String
                 -> (AArch64_RelocationType, (String, Maybe Int))
instructionReloc n nm = (AArch64_RelocationType n, (nm, Nothing))

dataReloc :: Word32
          -> String
          -> Int
          -> (AArch64_RelocationType, (String, Maybe Int))
dataReloc n nm bits = (AArch64_RelocationType n, (nm, Just bits))

-- These values are derived from the AArch64 ELF ABI:
-- https://github.com/ARM-software/abi-aa/blob/ee4b3c12d57c8424ff60c2ae56e10690d0604ab6/aaelf64/aaelf64.rst.
aarch64RelocationTypes :: Map.Map AArch64_RelocationType (String, Maybe Int)
aarch64RelocationTypes = Map.fromList
  [ dataReloc 0 "R_AARCH64_NONE" none
  , dataReloc 256 "R_AARCH64_NONE" none
  , dataReloc 1 "R_AARCH64_P32_ABS32" word32
  , dataReloc 180 "R_AARCH64_P32_COPY" none
  , dataReloc 181 "R_AARCH64_P32_GLOB_DAT" word32
  , dataReloc 182 "R_AARCH64_P32_JUMP_SLOT" word32
  , dataReloc 183 "R_AARCH64_P32_RELATIVE" word32
  , dataReloc 184 "R_AARCH64_P32_TLS_IMPDEF1" word32
  , dataReloc 185 "R_AARCH64_P32_TLS_IMPDEF2" word32
  , dataReloc 186 "R_AARCH64_P32_TLS_TPREL" word32
  , dataReloc 187 "R_AARCH64_P32_TLSDESC" word32
  , dataReloc 188 "R_AARCH64_P32_IRELATIVE" word32
  , dataReloc 257 "R_AARCH64_ABS64" word64
  , dataReloc 258 "R_AARCH64_ABS32" word32
  , dataReloc 259 "R_AARCH64_ABS16" word16
  , dataReloc 260 "R_AARCH64_PREL64" word64
  , dataReloc 261 "R_AARCH64_PREL32" word32
  , dataReloc 262 "R_AARCH64_PREL16" word16
  , instructionReloc 263 "R_AARCH64_MOVW_UABS_G0"
  , instructionReloc 264 "R_AARCH64_MOVW_UABS_G0_NC"
  , instructionReloc 265 "R_AARCH64_MOVW_UABS_G1"
  , instructionReloc 266 "R_AARCH64_MOVW_UABS_G1_NC"
  , instructionReloc 267 "R_AARCH64_MOVW_UABS_G2"
  , instructionReloc 268 "R_AARCH64_MOVW_UABS_G2_NC"
  , instructionReloc 269 "R_AARCH64_MOVW_UABS_G3"
  , instructionReloc 270 "R_AARCH64_MOVW_SABS_G0"
  , instructionReloc 271 "R_AARCH64_MOVW_SABS_G1"
  , instructionReloc 272 "R_AARCH64_MOVW_SABS_G2"
  , instructionReloc 273 "R_AARCH64_LD_PREL_LO19"
  , instructionReloc 274 "R_AARCH64_ADR_PREL_LO21"
  , instructionReloc 275 "R_AARCH64_ADR_PREL_PG_HI21"
  , instructionReloc 276 "R_AARCH64_ADR_PREL_PG_HI21_NC"
  , instructionReloc 277 "R_AARCH64_ADD_ABS_LO12_NC"
  , instructionReloc 278 "R_AARCH64_LDST8_ABS_LO12_NC"
  , instructionReloc 279 "R_AARCH64_TSTBR14"
  , instructionReloc 280 "R_AARCH64_CONDBR19"
  , instructionReloc 282 "R_AARCH64_JUMP26"
  , instructionReloc 283 "R_AARCH64_CALL26"
  , instructionReloc 284 "R_AARCH64_LDST16_ABS_LO12_NC"
  , instructionReloc 285 "R_AARCH64_LDST32_ABS_LO12_NC"
  , instructionReloc 286 "R_AARCH64_LDST64_ABS_LO12_NC"
  , instructionReloc 287 "R_AARCH64_MOVW_PREL_G0"
  , instructionReloc 288 "R_AARCH64_MOVW_PREL_G0_NC"
  , instructionReloc 289 "R_AARCH64_MOVW_PREL_G1"
  , instructionReloc 290 "R_AARCH64_MOVW_PREL_G1_NC"
  , instructionReloc 291 "R_AARCH64_MOVW_PREL_G2"
  , instructionReloc 292 "R_AARCH64_MOVW_PREL_G2_NC"
  , instructionReloc 293 "R_AARCH64_MOVW_PREL_G3"
  , instructionReloc 299 "R_AARCH64_LDST128_ABS_LO12_NC"
  , instructionReloc 300 "R_AARCH64_MOVW_GOTOFF_G0"
  , instructionReloc 301 "R_AARCH64_MOVW_GOTOFF_G0_NC"
  , instructionReloc 302 "R_AARCH64_MOVW_GOTOFF_G1"
  , instructionReloc 303 "R_AARCH64_MOVW_GOTOFF_G1_NC"
  , instructionReloc 304 "R_AARCH64_MOVW_GOTOFF_G2"
  , instructionReloc 305 "R_AARCH64_MOVW_GOTOFF_G2_NC"
  , instructionReloc 306 "R_AARCH64_MOVW_GOTOFF_G3"
  , dataReloc 307 "R_AARCH64_GOTREL64" word64
  , dataReloc 308 "R_AARCH64_GOTREL32" word32
  , instructionReloc 309 "R_AARCH64_GOT_LD_PREL19"
  , instructionReloc 310 "R_AARCH64_LD64_GOTOFF_LO15"
  , instructionReloc 311 "R_AARCH64_ADR_GOT_PAGE"
  , instructionReloc 312 "R_AARCH64_LD64_GOT_LO12_NC"
  , instructionReloc 313 "R_AARCH64_LD64_GOTPAGE_LO15"
  , dataReloc 314 "R_AARCH64_PLT32" word32
  , dataReloc 315 "R_AARCH64_GOTPCREL32" word32
  , instructionReloc 316 "R_AARCH64_PATCHINST"
  , dataReloc 317 "R_AARCH64_FUNCINIT64" word64
  , instructionReloc 512 "R_AARCH64_TLSGD_ADR_PREL21"
  , instructionReloc 513 "R_AARCH64_TLSGD_ADR_PAGE21"
  , instructionReloc 514 "R_AARCH64_TLSGD_ADD_LO12_NC"
  , instructionReloc 515 "R_AARCH64_TLSGD_MOVW_G1"
  , instructionReloc 516 "R_AARCH64_TLSGD_MOVW_G0_NC"
  , instructionReloc 517 "R_AARCH64_TLSLD_ADR_PREL21"
  , instructionReloc 518 "R_AARCH64_TLSLD_ADR_PAGE21"
  , instructionReloc 519 "R_AARCH64_TLSLD_ADD_LO12_NC"
  , instructionReloc 520 "R_AARCH64_TLSLD_MOVW_G1"
  , instructionReloc 521 "R_AARCH64_TLSLD_MOVW_G0_NC"
  , instructionReloc 522 "R_AARCH64_TLSLD_LD_PREL19"
  , instructionReloc 523 "R_AARCH64_TLSLD_MOVW_DTPREL_G2"
  , instructionReloc 524 "R_AARCH64_TLSLD_MOVW_DTPREL_G1"
  , instructionReloc 525 "R_AARCH64_TLSLD_MOVW_DTPREL_G1_NC"
  , instructionReloc 526 "R_AARCH64_TLSLD_MOVW_DTPREL_G0"
  , instructionReloc 527 "R_AARCH64_TLSLD_MOVW_DTPREL_G0_NC"
  , instructionReloc 528 "R_AARCH64_TLSLD_ADD_DTPREL_HI12"
  , instructionReloc 529 "R_AARCH64_TLSLD_ADD_DTPREL_LO12"
  , instructionReloc 530 "R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC"
  , instructionReloc 531 "R_AARCH64_TLSLD_LDST8_DTPREL_LO12"
  , instructionReloc 532 "R_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC"
  , instructionReloc 533 "R_AARCH64_TLSLD_LDST16_DTPREL_LO12"
  , instructionReloc 534 "R_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC"
  , instructionReloc 535 "R_AARCH64_TLSLD_LDST32_DTPREL_LO12"
  , instructionReloc 536 "R_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC"
  , instructionReloc 537 "R_AARCH64_TLSLD_LDST64_DTPREL_LO12"
  , instructionReloc 538 "R_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC"
  , instructionReloc 539 "R_AARCH64_TLSIE_MOVW_GOTTPREL_G1"
  , instructionReloc 540 "R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC"
  , instructionReloc 541 "R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21"
  , instructionReloc 542 "R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC"
  , instructionReloc 543 "R_AARCH64_TLSIE_LD_GOTTPREL_PREL19"
  , instructionReloc 544 "R_AARCH64_TLSLE_MOVW_TPREL_G2"
  , instructionReloc 545 "R_AARCH64_TLSLE_MOVW_TPREL_G1"
  , instructionReloc 546 "R_AARCH64_TLSLE_MOVW_TPREL_G1_NC"
  , instructionReloc 547 "R_AARCH64_TLSLE_MOVW_TPREL_G0"
  , instructionReloc 548 "R_AARCH64_TLSLE_MOVW_TPREL_G0_NC"
  , instructionReloc 549 "R_AARCH64_TLSLE_ADD_TPREL_HI12"
  , instructionReloc 550 "R_AARCH64_TLSLE_ADD_TPREL_LO12"
  , instructionReloc 551 "R_AARCH64_TLSLE_ADD_TPREL_LO12_NC"
  , instructionReloc 552 "R_AARCH64_TLSLE_LDST8_TPREL_LO12"
  , instructionReloc 553 "R_AARCH64_TLSLE_LDST8_TPREL_LO12_NC"
  , instructionReloc 554 "R_AARCH64_TLSLE_LDST16_TPREL_LO12"
  , instructionReloc 555 "R_AARCH64_TLSLE_LDST16_TPREL_LO12_NC"
  , instructionReloc 556 "R_AARCH64_TLSLE_LDST32_TPREL_LO12"
  , instructionReloc 557 "R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC"
  , instructionReloc 558 "R_AARCH64_TLSLE_LDST64_TPREL_LO12"
  , instructionReloc 559 "R_AARCH64_TLSLE_LDST64_TPREL_LO12_NC"
  , instructionReloc 560 "R_AARCH64_TLSDESC_LD_PREL19"
  , instructionReloc 561 "R_AARCH64_TLSDESC_ADR_PREL21"
  , instructionReloc 562 "R_AARCH64_TLSDESC_ADR_PAGE21"
  , instructionReloc 563 "R_AARCH64_TLSDESC_LD64_LO12"
  , instructionReloc 564 "R_AARCH64_TLSDESC_ADD_LO12"
  , instructionReloc 565 "R_AARCH64_TLSDESC_OFF_G1"
  , instructionReloc 566 "R_AARCH64_TLSDESC_OFF_G0_NC"
  , instructionReloc 567 "R_AARCH64_TLSDESC_LDR"
  , instructionReloc 568 "R_AARCH64_TLSDESC_ADD"
  , instructionReloc 569 "R_AARCH64_TLSDESC_CALL"
  , instructionReloc 570 "R_AARCH64_TLSLE_LDST128_TPREL_LO12"
  , instructionReloc 571 "R_AARCH64_TLSLE_LDST128_TPREL_LO12_NC"
  , instructionReloc 572 "R_AARCH64_TLSLD_LDST128_DTPREL_LO12"
  , instructionReloc 573 "R_AARCH64_TLSLD_LDST128_DTPREL_LO12_NC"
  , dataReloc 580 "R_AARCH64_AUTH_ABS64" word64
  , instructionReloc 581 "R_AARCH64_AUTH_MOVW_GOTOFF_G0"
  , instructionReloc 582 "R_AARCH64_AUTH_MOVW_GOTOFF_G0_NC"
  , instructionReloc 583 "R_AARCH64_AUTH_MOVW_GOTOFF_G1"
  , instructionReloc 584 "R_AARCH64_AUTH_MOVW_GOTOFF_G1_NC"
  , instructionReloc 585 "R_AARCH64_AUTH_MOVW_GOTOFF_G2"
  , instructionReloc 586 "R_AARCH64_AUTH_MOVW_GOTOFF_G2_NC"
  , instructionReloc 587 "R_AARCH64_AUTH_MOVW_GOTOFF_G3"
  , instructionReloc 588 "R_AARCH64_AUTH_GOT_LD_PREL19"
  , instructionReloc 589 "R_AARCH64_AUTH_LD64_GOTOFF_LO15"
  , instructionReloc 590 "R_AARCH64_AUTH_ADR_GOT_PAGE"
  , instructionReloc 591 "R_AARCH64_AUTH_LD64_GOT_LO12_NC"
  , instructionReloc 592 "R_AARCH64_AUTH_LD64_GOTPAGE_LO15"
  , instructionReloc 593 "R_AARCH64_AUTH_GOT_ADD_LO12_NC"
  , instructionReloc 594 "R_AARCH64_AUTH_GOT_ADR_PREL_LO21"
  , instructionReloc 595 "R_AARCH64_AUTH_TLSDESC_ADR_PAGE21"
  , instructionReloc 596 "R_AARCH64_AUTH_TLSDESC_LD64_LO12"
  , instructionReloc 597 "R_AARCH64_AUTH_TLSDESC_ADD_LO12"
  , instructionReloc 598 "R_AARCH64_AUTH_TLSDESC_CALL"
  , dataReloc 1024 "R_AARCH64_COPY" none
  , dataReloc 1025 "R_AARCH64_GLOB_DAT" word64
  , dataReloc 1026 "R_AARCH64_JUMP_SLOT" word64
  , dataReloc 1027 "R_AARCH64_RELATIVE" word64
  , dataReloc 1028 "R_AARCH64_TLS_IMPDEF1" word64
  , dataReloc 1029 "R_AARCH64_TLS_IMPDEF2" word64
  , dataReloc 1030 "R_AARCH64_TLS_TPREL" word64
  , dataReloc 1031 "R_AARCH64_TLSDESC" word64
  , dataReloc 1032 "R_AARCH64_IRELATIVE" word64
  , dataReloc 1041 "R_AARCH64_AUTH_RELATIVE" word64
  , dataReloc 1042 "R_AARCH64_AUTH_GLOB_DAT" word64
  , dataReloc 1043 "R_AARCH64_AUTH_TLSDESC" word64
  , dataReloc 1044 "R_AARCH64_AUTH_IRELATIVE" word64
  ]

-- | Maps known AArch64 relocation types to their string representation.
aarch64RelocationTypeNameMap :: Map.Map AArch64_RelocationType String
aarch64RelocationTypeNameMap = fmap fst aarch64RelocationTypes

instance Show AArch64_RelocationType where
  show i =
    case Map.lookup i aarch64RelocationTypeNameMap of
      Just s  -> s
      Nothing -> ppHex (fromARM_RelocationType i)

instance IsRelocationType AArch64_RelocationType where
  type RelocationWidth AArch64_RelocationType = 64

  relaWidth _ = ELFCLASS64

  relocTargetBits tp = Map.lookup tp aarch64RelocationTypes >>= snd
  toRelocType = AArch64_RelocationType . fromIntegral

  isRelative (AArch64_RelocationType 183) = True
  isRelative R_AARCH64_RELATIVE           = True
  isRelative (AArch64_RelocationType 1041) = True
  isRelative _                      = False
