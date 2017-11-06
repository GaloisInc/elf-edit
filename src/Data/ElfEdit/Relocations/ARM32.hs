{-
Copyright        : (c) Galois, Inc 2017
Maintainer       : Ben Davis <ben@galois.com>

ARM32 relocation type.
-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE TypeFamilies #-}
#if __GLASGOW_HASKELL__ >= 800
{-# OPTIONS_GHC -fno-warn-missing-pattern-synonym-signatures #-}
#endif
module Data.ElfEdit.Relocations.ARM32
  ( ARM_RelocationType(..)
  , pattern R_ARM_COPY
  , pattern R_ARM_GLOB_DAT
  , pattern R_ARM_JUMP_SLOT
  , pattern R_ARM_RELATIVE
 ) where

import qualified Data.Map.Strict          as Map
import           Data.Word                (Word32)
import           Numeric                  (showHex)

import           Data.ElfEdit.Relocations
import           Data.ElfEdit.Types       (ElfClass (..))

------------------------------------------------------------------------
-- ARM_RelocationType

-- | Relocation types for ARM32 code.
newtype ARM_RelocationType = ARM_RelocationType { fromARM_RelocationType :: Word32 }
  deriving (Eq,Ord)

pattern R_ARM_NONE               = ARM_RelocationType 0   -- Static Miscellaneous
pattern R_ARM_PC24               = ARM_RelocationType 1   -- Deprecated ARM ((S + A) | T) – P
pattern R_ARM_ABS32              = ARM_RelocationType 2   -- Static Data (S + A) | T
pattern R_ARM_REL32              = ARM_RelocationType 3   -- Static Data ((S + A) | T) – P
pattern R_ARM_LDR_PC_G0          = ARM_RelocationType 4   -- Static ARM S + A – P
pattern R_ARM_ABS16              = ARM_RelocationType 5   -- Static Data S + A
pattern R_ARM_ABS12              = ARM_RelocationType 6   -- Static ARM S + A
pattern R_ARM_THM_ABS5           = ARM_RelocationType 7   -- Static Thumb16 S + A
pattern R_ARM_ABS8               = ARM_RelocationType 8   -- Static Data S + A
pattern R_ARM_SBREL32            = ARM_RelocationType 9   -- Static Data ((S + A) | T) – B(S)
pattern R_ARM_THM_CALL           = ARM_RelocationType 10  -- Static Thumb32 ((S + A) | T) – P
pattern R_ARM_THM_PC8            = ARM_RelocationType 11  -- Static Thumb16 S + A – Pa
pattern R_ARM_BREL_ADJ           = ARM_RelocationType 12  -- Dynamic Data delta B(S) + A
pattern R_ARM_TLS_DESC           = ARM_RelocationType 13  -- Dynamic Data
pattern R_ARM_THM_SWI8           = ARM_RelocationType 14  -- Obsolete (reserved for future Dynamic relocations)
pattern R_ARM_XPC25              = ARM_RelocationType 15  -- Obsolete (reserved for future Dynamic relocations)
pattern R_ARM_THM_XPC22          = ARM_RelocationType 16  -- Obsolete (reserved for future Dynamic relocations)
pattern R_ARM_TLS_DTPMOD32       = ARM_RelocationType 17  -- Dynamic Data Module[S]
pattern R_ARM_TLS_DTPOFF32       = ARM_RelocationType 18  -- Dynamic Data S + A – TLS
pattern R_ARM_TLS_TPOFF32        = ARM_RelocationType 19  -- Dynamic Data S + A – tp
pattern R_ARM_COPY               = ARM_RelocationType 20  -- Dynamic Miscellaneous
pattern R_ARM_GLOB_DAT           = ARM_RelocationType 21  -- Dynamic Data (S + A) | T
pattern R_ARM_JUMP_SLOT          = ARM_RelocationType 22  -- Dynamic Data (S + A) | T
pattern R_ARM_RELATIVE           = ARM_RelocationType 23  -- Dynamic Data B(S) + A
pattern R_ARM_GOTOFF32           = ARM_RelocationType 24  -- Static Data ((S + A) | T) – GOT_ORG
pattern R_ARM_BASE_PREL          = ARM_RelocationType 25  -- Static Data B(S) + A – P
pattern R_ARM_GOT_BREL           = ARM_RelocationType 26  -- Static Data GOT(S) + A – GOT_ORG
pattern R_ARM_PLT32              = ARM_RelocationType 27  -- Deprecated ARM ((S + A) | T) – P
pattern R_ARM_CALL               = ARM_RelocationType 28  -- Static ARM ((S + A) | T) – P
pattern R_ARM_JUMP24             = ARM_RelocationType 29  -- Static ARM ((S + A) | T) – P
pattern R_ARM_THM_JUMP24         = ARM_RelocationType 30  -- Static Thumb32 ((S + A) | T) – P
pattern R_ARM_BASE_ABS           = ARM_RelocationType 31  -- Static Data B(S) + A
pattern R_ARM_ALU_PCREL_7_0      = ARM_RelocationType 32  -- Obsolete
pattern R_ARM_ALU_PCREL_15_8     = ARM_RelocationType 33  -- Obsolete
pattern R_ARM_ALU_PCREL_23_15    = ARM_RelocationType 34  -- Obsolete
pattern R_ARM_LDR_SBREL_11_0_NC  = ARM_RelocationType 35  -- Deprecated ARM S + A – B(S)
pattern R_ARM_ALU_SBREL_19_12_NC = ARM_RelocationType 36  -- Deprecated ARM S + A – B(S)
pattern R_ARM_ALU_SBREL_27_20_CK = ARM_RelocationType 37  -- Deprecated ARM S + A – B(S)
pattern R_ARM_TARGET1            = ARM_RelocationType 38  -- Static Miscellaneous (S + A) | T or ((S + A) | T) – P
pattern R_ARM_SBREL31            = ARM_RelocationType 39  -- Deprecated Data ((S + A) | T) – B(S)
pattern R_ARM_V4BX               = ARM_RelocationType 40  -- Static Miscellaneous
pattern R_ARM_TARGET2            = ARM_RelocationType 41  -- Static Miscellaneous
pattern R_ARM_PREL31             = ARM_RelocationType 42  -- Static Data ((S + A) | T) – P
pattern R_ARM_MOVW_ABS_NC        = ARM_RelocationType 43  -- Static ARM (S + A) | T
pattern R_ARM_MOVT_ABS           = ARM_RelocationType 44  -- Static ARM S + A
pattern R_ARM_MOVW_PREL_NC       = ARM_RelocationType 45  -- Static ARM ((S + A) | T) – P
pattern R_ARM_MOVT_PREL          = ARM_RelocationType 46  -- Static ARM S + A – P
pattern R_ARM_THM_MOVW_ABS_NC    = ARM_RelocationType 47  -- Static Thumb32 (S + A) | T
pattern R_ARM_THM_MOVT_ABS       = ARM_RelocationType 48  -- Static Thumb32 S + A
pattern R_ARM_THM_MOVW_PREL_NC   = ARM_RelocationType 49  -- Static Thumb32 ((S + A) | T) – P
pattern R_ARM_THM_MOVT_PREL      = ARM_RelocationType 50  -- Static Thumb32 S + A – P
pattern R_ARM_THM_JUMP19         = ARM_RelocationType 51  -- Static Thumb32 ((S + A) | T) – P
pattern R_ARM_THM_JUMP6          = ARM_RelocationType 52  -- Static Thumb16 S + A – P
pattern R_ARM_THM_ALU_PREL_11_0  = ARM_RelocationType 53  -- Static Thumb32 ((S + A) | T) – Pa
pattern R_ARM_THM_PC12           = ARM_RelocationType 54  -- Static Thumb32 S + A – Pa
pattern R_ARM_ABS32_NOI          = ARM_RelocationType 55  -- Static Data S + A
pattern R_ARM_REL32_NOI          = ARM_RelocationType 56  -- Static Data S + A – P
pattern R_ARM_ALU_PC_G0_NC       = ARM_RelocationType 57  -- Static ARM ((S + A) | T) – P
pattern R_ARM_ALU_PC_G0          = ARM_RelocationType 58  -- Static ARM ((S + A) | T) – P
pattern R_ARM_ALU_PC_G1_NC       = ARM_RelocationType 59  -- Static ARM ((S + A) | T) – P
pattern R_ARM_ALU_PC_G1          = ARM_RelocationType 60  -- Static ARM ((S + A) | T) – P
pattern R_ARM_ALU_PC_G2          = ARM_RelocationType 61  -- Static ARM ((S + A) | T) – P
pattern R_ARM_LDR_PC_G1          = ARM_RelocationType 62  -- Static ARM S + A – P
pattern R_ARM_LDR_PC_G2          = ARM_RelocationType 63  -- Static ARM S + A – P
pattern R_ARM_LDRS_PC_G0         = ARM_RelocationType 64  -- Static ARM S + A – P
pattern R_ARM_LDRS_PC_G1         = ARM_RelocationType 65  -- Static ARM S + A – P
pattern R_ARM_LDRS_PC_G2         = ARM_RelocationType 66  -- Static ARM S + A – P
pattern R_ARM_LDC_PC_G0          = ARM_RelocationType 67  -- Static ARM S + A – P
pattern R_ARM_LDC_PC_G1          = ARM_RelocationType 68  -- Static ARM S + A – P
pattern R_ARM_LDC_PC_G2          = ARM_RelocationType 69  -- Static ARM S + A – P
pattern R_ARM_ALU_SB_G0_NC       = ARM_RelocationType 70  -- Static ARM ((S + A) | T) – B(S)
pattern R_ARM_ALU_SB_G0          = ARM_RelocationType 71  -- Static ARM ((S + A) | T) – B(S)
pattern R_ARM_ALU_SB_G1_NC       = ARM_RelocationType 72  -- Static ARM ((S + A) | T) – B(S)
pattern R_ARM_ALU_SB_G1          = ARM_RelocationType 73  -- Static ARM ((S + A) | T) – B(S)
pattern R_ARM_ALU_SB_G2          = ARM_RelocationType 74  -- Static ARM ((S + A) | T) – B(S)
pattern R_ARM_LDR_SB_G0          = ARM_RelocationType 75  -- Static ARM S + A – B(S)
pattern R_ARM_LDR_SB_G1          = ARM_RelocationType 76  -- Static ARM S + A – B(S)
pattern R_ARM_LDR_SB_G2          = ARM_RelocationType 77  -- Static ARM S + A – B(S)
pattern R_ARM_LDRS_SB_G0         = ARM_RelocationType 78  -- Static ARM S + A – B(S)
pattern R_ARM_LDRS_SB_G1         = ARM_RelocationType 79  -- Static ARM S + A – B(S)
pattern R_ARM_LDRS_SB_G2         = ARM_RelocationType 80  -- Static ARM S + A – B(S)
pattern R_ARM_LDC_SB_G0          = ARM_RelocationType 81  -- Static ARM S + A – B(S)
pattern R_ARM_LDC_SB_G1          = ARM_RelocationType 82  -- Static ARM S + A – B(S)
pattern R_ARM_LDC_SB_G2          = ARM_RelocationType 83  -- Static ARM S + A – B(S)
pattern R_ARM_MOVW_BREL_NC       = ARM_RelocationType 84  -- Static ARM ((S + A) | T) – B(S)
pattern R_ARM_MOVT_BREL          = ARM_RelocationType 85  -- Static ARM S + A – B(S)
pattern R_ARM_MOVW_BREL          = ARM_RelocationType 86  -- Static ARM ((S + A) | T) – B(S)
pattern R_ARM_THM_MOVW_BREL_NC   = ARM_RelocationType 87  -- Static Thumb32 ((S + A) | T) – B(S)
pattern R_ARM_THM_MOVT_BREL      = ARM_RelocationType 88  -- Static Thumb32 S + A – B(S)
pattern R_ARM_THM_MOVW_BREL      = ARM_RelocationType 89  -- Static Thumb32 ((S + A) | T) – B(S)
pattern R_ARM_TLS_GOTDESC        = ARM_RelocationType 90  -- Static Data
pattern R_ARM_TLS_CALL           = ARM_RelocationType 91  -- Static ARM
pattern R_ARM_TLS_DESCSEQ        = ARM_RelocationType 92  -- Static ARM TLS relaxation
pattern R_ARM_THM_TLS_CALL       = ARM_RelocationType 93  -- Static Thumb32
pattern R_ARM_PLT32_ABS          = ARM_RelocationType 94  -- Static Data PLT(S) + A
pattern R_ARM_GOT_ABS            = ARM_RelocationType 95  -- Static Data GOT(S) + A
pattern R_ARM_GOT_PREL           = ARM_RelocationType 96  -- Static Data GOT(S) + A – P
pattern R_ARM_GOT_BREL12         = ARM_RelocationType 97  -- Static ARM GOT(S) + A – GOT_ORG
pattern R_ARM_GOTOFF12           = ARM_RelocationType 98  -- Static ARM S + A – GOT_ORG
pattern R_ARM_GOTRELAX           = ARM_RelocationType 99  -- Static Miscellaneous
pattern R_ARM_GNU_VTENTRY        = ARM_RelocationType 100 -- Deprecated Data ???
pattern R_ARM_GNU_VTINHERIT      = ARM_RelocationType 101 -- Deprecated Data ???
pattern R_ARM_THM_JUMP11         = ARM_RelocationType 102 -- Static Thumb16 S + A – P
pattern R_ARM_THM_JUMP8          = ARM_RelocationType 103 -- Static Thumb16 S + A – P
pattern R_ARM_TLS_GD32           = ARM_RelocationType 104 -- Static Data GOT(S) + A – P
pattern R_ARM_TLS_LDM32          = ARM_RelocationType 105 -- Static Data GOT(S) + A – P
pattern R_ARM_TLS_LDO32          = ARM_RelocationType 106 -- Static Data S + A – TLS
pattern R_ARM_TLS_IE32           = ARM_RelocationType 107 -- Static Data GOT(S) + A – P
pattern R_ARM_TLS_LE32           = ARM_RelocationType 108 -- Static Data S + A – tp
pattern R_ARM_TLS_LDO12          = ARM_RelocationType 109 -- Static ARM S + A – TLS
pattern R_ARM_TLS_LE12           = ARM_RelocationType 110 -- Static ARM S + A – tp
pattern R_ARM_TLS_IE12GP         = ARM_RelocationType 111 -- Static ARM GOT(S) + A – GOT_ORG
pattern R_ARM_PRIVATE_0          = ARM_RelocationType 112 -- Private
pattern R_ARM_PRIVATE_1          = ARM_RelocationType 113 -- Private
pattern R_ARM_PRIVATE_2          = ARM_RelocationType 114 -- Private
pattern R_ARM_PRIVATE_3          = ARM_RelocationType 115 -- Private
pattern R_ARM_PRIVATE_4          = ARM_RelocationType 116 -- Private
pattern R_ARM_PRIVATE_5          = ARM_RelocationType 117 -- Private
pattern R_ARM_PRIVATE_6          = ARM_RelocationType 118 -- Private
pattern R_ARM_PRIVATE_7          = ARM_RelocationType 119 -- Private
pattern R_ARM_PRIVATE_8          = ARM_RelocationType 120 -- Private
pattern R_ARM_PRIVATE_9          = ARM_RelocationType 121 -- Private
pattern R_ARM_PRIVATE_10         = ARM_RelocationType 122 -- Private
pattern R_ARM_PRIVATE_11         = ARM_RelocationType 123 -- Private
pattern R_ARM_PRIVATE_12         = ARM_RelocationType 124 -- Private
pattern R_ARM_PRIVATE_13         = ARM_RelocationType 125 -- Private
pattern R_ARM_PRIVATE_14         = ARM_RelocationType 126 -- Private
pattern R_ARM_PRIVATE_15         = ARM_RelocationType 127 -- Private
pattern R_ARM_ME_TOO             = ARM_RelocationType 128 -- Obsolete
pattern R_ARM_THM_TLS_DESCSEQ16  = ARM_RelocationType 129 -- Static Thumb16
pattern R_ARM_THM_TLS_DESCSEQ32  = ARM_RelocationType 130 -- Static Thumb32
pattern R_ARM_THM_GOT_BREL12     = ARM_RelocationType 131 -- Static Thumb32 GOT(S) + A – GOT_ORG
pattern R_ARM_THM_ALU_ABS_G0_NC  = ARM_RelocationType 132 -- Static Thumb16 (S + A) | T
pattern R_ARM_THM_ALU_ABS_G1_NC  = ARM_RelocationType 133 -- Static Thumb16 S + A
pattern R_ARM_THM_ALU_ABS_G2_NC  = ARM_RelocationType 134 -- Static Thumb16 S + A
pattern R_ARM_THM_ALU_ABS_G3     = ARM_RelocationType 135 -- Static Thumb16 S + A
pattern R_ARM_IRELATIVE          = ARM_RelocationType 160 -- Dynamic Reserved for future functionality

arm_RelocationTypes :: Map.Map ARM_RelocationType String
arm_RelocationTypes = Map.fromList
  [ (,) R_ARM_NONE               "R_ARM_NONE"
  , (,) R_ARM_PC24               "R_ARM_PC24"
  , (,) R_ARM_ABS32              "R_ARM_ABS32"
  , (,) R_ARM_REL32              "R_ARM_REL32"
  , (,) R_ARM_LDR_PC_G0          "R_ARM_LDR_PC_G0"
  , (,) R_ARM_ABS16              "R_ARM_ABS16"
  , (,) R_ARM_ABS12              "R_ARM_ABS12"
  , (,) R_ARM_THM_ABS5           "R_ARM_THM_ABS5"
  , (,) R_ARM_ABS8               "R_ARM_ABS8"
  , (,) R_ARM_SBREL32            "R_ARM_SBREL32"
  , (,) R_ARM_THM_CALL           "R_ARM_THM_CALL"
  , (,) R_ARM_THM_PC8            "R_ARM_THM_PC8"
  , (,) R_ARM_BREL_ADJ           "R_ARM_BREL_ADJ"
  , (,) R_ARM_TLS_DESC           "R_ARM_TLS_DESC"
  , (,) R_ARM_THM_SWI8           "R_ARM_THM_SWI8"
  , (,) R_ARM_XPC25              "R_ARM_XPC25"
  , (,) R_ARM_THM_XPC22          "R_ARM_THM_XPC22"
  , (,) R_ARM_TLS_DTPMOD32       "R_ARM_TLS_DTPMOD32"
  , (,) R_ARM_TLS_DTPOFF32       "R_ARM_TLS_DTPOFF32"
  , (,) R_ARM_TLS_TPOFF32        "R_ARM_TLS_TPOFF32"
  , (,) R_ARM_COPY               "R_ARM_COPY"
  , (,) R_ARM_GLOB_DAT           "R_ARM_GLOB_DAT"
  , (,) R_ARM_JUMP_SLOT          "R_ARM_JUMP_SLOT"
  , (,) R_ARM_RELATIVE           "R_ARM_RELATIVE"
  , (,) R_ARM_GOTOFF32           "R_ARM_GOTOFF32"
  , (,) R_ARM_BASE_PREL          "R_ARM_BASE_PREL"
  , (,) R_ARM_GOT_BREL           "R_ARM_GOT_BREL"
  , (,) R_ARM_PLT32              "R_ARM_PLT32"
  , (,) R_ARM_CALL               "R_ARM_CALL"
  , (,) R_ARM_JUMP24             "R_ARM_JUMP24"
  , (,) R_ARM_THM_JUMP24         "R_ARM_THM_JUMP24"
  , (,) R_ARM_BASE_ABS           "R_ARM_BASE_ABS"
  , (,) R_ARM_ALU_PCREL_7_0      "R_ARM_ALU_PCREL_7_0"
  , (,) R_ARM_ALU_PCREL_15_8     "R_ARM_ALU_PCREL_15_8"
  , (,) R_ARM_ALU_PCREL_23_15    "R_ARM_ALU_PCREL_23_15"
  , (,) R_ARM_LDR_SBREL_11_0_NC  "R_ARM_LDR_SBREL_11_0_NC"
  , (,) R_ARM_ALU_SBREL_19_12_NC "R_ARM_ALU_SBREL_19_12_NC"
  , (,) R_ARM_ALU_SBREL_27_20_CK "R_ARM_ALU_SBREL_27_20_CK"
  , (,) R_ARM_TARGET1            "R_ARM_TARGET1"
  , (,) R_ARM_SBREL31            "R_ARM_SBREL31"
  , (,) R_ARM_V4BX               "R_ARM_V4BX"
  , (,) R_ARM_TARGET2            "R_ARM_TARGET2"
  , (,) R_ARM_PREL31             "R_ARM_PREL31"
  , (,) R_ARM_MOVW_ABS_NC        "R_ARM_MOVW_ABS_NC"
  , (,) R_ARM_MOVT_ABS           "R_ARM_MOVT_ABS"
  , (,) R_ARM_MOVW_PREL_NC       "R_ARM_MOVW_PREL_NC"
  , (,) R_ARM_MOVT_PREL          "R_ARM_MOVT_PREL"
  , (,) R_ARM_THM_MOVW_ABS_NC    "R_ARM_THM_MOVW_ABS_NC"
  , (,) R_ARM_THM_MOVT_ABS       "R_ARM_THM_MOVT_ABS"
  , (,) R_ARM_THM_MOVW_PREL_NC   "R_ARM_THM_MOVW_PREL_NC"
  , (,) R_ARM_THM_MOVT_PREL      "R_ARM_THM_MOVT_PREL"
  , (,) R_ARM_THM_JUMP19         "R_ARM_THM_JUMP19"
  , (,) R_ARM_THM_JUMP6          "R_ARM_THM_JUMP6"
  , (,) R_ARM_THM_ALU_PREL_11_0  "R_ARM_THM_ALU_PREL_11_0"
  , (,) R_ARM_THM_PC12           "R_ARM_THM_PC12"
  , (,) R_ARM_ABS32_NOI          "R_ARM_ABS32_NOI"
  , (,) R_ARM_REL32_NOI          "R_ARM_REL32_NOI"
  , (,) R_ARM_ALU_PC_G0_NC       "R_ARM_ALU_PC_G0_NC"
  , (,) R_ARM_ALU_PC_G0          "R_ARM_ALU_PC_G0"
  , (,) R_ARM_ALU_PC_G1_NC       "R_ARM_ALU_PC_G1_NC"
  , (,) R_ARM_ALU_PC_G1          "R_ARM_ALU_PC_G1"
  , (,) R_ARM_ALU_PC_G2          "R_ARM_ALU_PC_G2"
  , (,) R_ARM_LDR_PC_G1          "R_ARM_LDR_PC_G1"
  , (,) R_ARM_LDR_PC_G2          "R_ARM_LDR_PC_G2"
  , (,) R_ARM_LDRS_PC_G0         "R_ARM_LDRS_PC_G0"
  , (,) R_ARM_LDRS_PC_G1         "R_ARM_LDRS_PC_G1"
  , (,) R_ARM_LDRS_PC_G2         "R_ARM_LDRS_PC_G2"
  , (,) R_ARM_LDC_PC_G0          "R_ARM_LDC_PC_G0"
  , (,) R_ARM_LDC_PC_G1          "R_ARM_LDC_PC_G1"
  , (,) R_ARM_LDC_PC_G2          "R_ARM_LDC_PC_G2"
  , (,) R_ARM_ALU_SB_G0_NC       "R_ARM_ALU_SB_G0_NC"
  , (,) R_ARM_ALU_SB_G0          "R_ARM_ALU_SB_G0"
  , (,) R_ARM_ALU_SB_G1_NC       "R_ARM_ALU_SB_G1_NC"
  , (,) R_ARM_ALU_SB_G1          "R_ARM_ALU_SB_G1"
  , (,) R_ARM_ALU_SB_G2          "R_ARM_ALU_SB_G2"
  , (,) R_ARM_LDR_SB_G0          "R_ARM_LDR_SB_G0"
  , (,) R_ARM_LDR_SB_G1          "R_ARM_LDR_SB_G1"
  , (,) R_ARM_LDR_SB_G2          "R_ARM_LDR_SB_G2"
  , (,) R_ARM_LDRS_SB_G0         "R_ARM_LDRS_SB_G0"
  , (,) R_ARM_LDRS_SB_G1         "R_ARM_LDRS_SB_G1"
  , (,) R_ARM_LDRS_SB_G2         "R_ARM_LDRS_SB_G2"
  , (,) R_ARM_LDC_SB_G0          "R_ARM_LDC_SB_G0"
  , (,) R_ARM_LDC_SB_G1          "R_ARM_LDC_SB_G1"
  , (,) R_ARM_LDC_SB_G2          "R_ARM_LDC_SB_G2"
  , (,) R_ARM_MOVW_BREL_NC       "R_ARM_MOVW_BREL_NC"
  , (,) R_ARM_MOVT_BREL          "R_ARM_MOVT_BREL"
  , (,) R_ARM_MOVW_BREL          "R_ARM_MOVW_BREL"
  , (,) R_ARM_THM_MOVW_BREL_NC   "R_ARM_THM_MOVW_BREL_NC"
  , (,) R_ARM_THM_MOVT_BREL      "R_ARM_THM_MOVT_BREL"
  , (,) R_ARM_THM_MOVW_BREL      "R_ARM_THM_MOVW_BREL"
  , (,) R_ARM_TLS_GOTDESC        "R_ARM_TLS_GOTDESC"
  , (,) R_ARM_TLS_CALL           "R_ARM_TLS_CALL"
  , (,) R_ARM_TLS_DESCSEQ        "R_ARM_TLS_DESCSEQ"
  , (,) R_ARM_THM_TLS_CALL       "R_ARM_THM_TLS_CALL"
  , (,) R_ARM_PLT32_ABS          "R_ARM_PLT32_ABS"
  , (,) R_ARM_GOT_ABS            "R_ARM_GOT_ABS"
  , (,) R_ARM_GOT_PREL           "R_ARM_GOT_PREL"
  , (,) R_ARM_GOT_BREL12         "R_ARM_GOT_BREL12"
  , (,) R_ARM_GOTOFF12           "R_ARM_GOTOFF12"
  , (,) R_ARM_GOTRELAX           "R_ARM_GOTRELAX"
  , (,) R_ARM_GNU_VTENTRY        "R_ARM_GNU_VTENTRY"
  , (,) R_ARM_GNU_VTINHERIT      "R_ARM_GNU_VTINHERIT"
  , (,) R_ARM_THM_JUMP11         "R_ARM_THM_JUMP11"
  , (,) R_ARM_THM_JUMP8          "R_ARM_THM_JUMP8"
  , (,) R_ARM_TLS_GD32           "R_ARM_TLS_GD32"
  , (,) R_ARM_TLS_LDM32          "R_ARM_TLS_LDM32"
  , (,) R_ARM_TLS_LDO32          "R_ARM_TLS_LDO32"
  , (,) R_ARM_TLS_IE32           "R_ARM_TLS_IE32"
  , (,) R_ARM_TLS_LE32           "R_ARM_TLS_LE32"
  , (,) R_ARM_TLS_LDO12          "R_ARM_TLS_LDO12"
  , (,) R_ARM_TLS_LE12           "R_ARM_TLS_LE12"
  , (,) R_ARM_TLS_IE12GP         "R_ARM_TLS_IE12GP"
  , (,) R_ARM_PRIVATE_0          "R_ARM_PRIVATE_0"
  , (,) R_ARM_PRIVATE_1          "R_ARM_PRIVATE_1"
  , (,) R_ARM_PRIVATE_2          "R_ARM_PRIVATE_2"
  , (,) R_ARM_PRIVATE_3          "R_ARM_PRIVATE_3"
  , (,) R_ARM_PRIVATE_4          "R_ARM_PRIVATE_4"
  , (,) R_ARM_PRIVATE_5          "R_ARM_PRIVATE_5"
  , (,) R_ARM_PRIVATE_6          "R_ARM_PRIVATE_6"
  , (,) R_ARM_PRIVATE_7          "R_ARM_PRIVATE_7"
  , (,) R_ARM_PRIVATE_8          "R_ARM_PRIVATE_8"
  , (,) R_ARM_PRIVATE_9          "R_ARM_PRIVATE_9"
  , (,) R_ARM_PRIVATE_10         "R_ARM_PRIVATE_10"
  , (,) R_ARM_PRIVATE_11         "R_ARM_PRIVATE_11"
  , (,) R_ARM_PRIVATE_12         "R_ARM_PRIVATE_12"
  , (,) R_ARM_PRIVATE_13         "R_ARM_PRIVATE_13"
  , (,) R_ARM_PRIVATE_14         "R_ARM_PRIVATE_14"
  , (,) R_ARM_PRIVATE_15         "R_ARM_PRIVATE_15"
  , (,) R_ARM_ME_TOO             "R_ARM_ME_TOO"
  , (,) R_ARM_THM_TLS_DESCSEQ16  "R_ARM_THM_TLS_DESCSEQ16"
  , (,) R_ARM_THM_TLS_DESCSEQ32  "R_ARM_THM_TLS_DESCSEQ32"
  , (,) R_ARM_THM_GOT_BREL12     "R_ARM_THM_GOT_BREL12"
  , (,) R_ARM_THM_ALU_ABS_G0_NC  "R_ARM_THM_ALU_ABS_G0_NC"
  , (,) R_ARM_THM_ALU_ABS_G1_NC  "R_ARM_THM_ALU_ABS_G1_NC"
  , (,) R_ARM_THM_ALU_ABS_G2_NC  "R_ARM_THM_ALU_ABS_G2_NC"
  , (,) R_ARM_THM_ALU_ABS_G3     "R_ARM_THM_ALU_ABS_G3"
  , (,) R_ARM_IRELATIVE          "R_ARM_IRELATIVE"
  ]

instance Show ARM_RelocationType where
  show i =
    case Map.lookup i arm_RelocationTypes of
      Just s  -> s
      Nothing -> "0x" ++ showHex (fromARM_RelocationType i) ""

instance IsRelocationType ARM_RelocationType where
  type RelocationWidth ARM_RelocationType = 32

  relaWidth _ = ELFCLASS32

  relaType = Just . ARM_RelocationType . fromIntegral

  isRelative R_ARM_RELATIVE = True
  isRelative _              = False
