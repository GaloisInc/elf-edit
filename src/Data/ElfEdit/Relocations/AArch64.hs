{-
AArch64 64bit relocation type.
-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE TypeFamilies #-}
module Data.ElfEdit.Relocations.AArch64
  ( AArch64_RelocationType(..)
  , pattern R_AARCH64_NONE
  , pattern R_AARCH64_NONE_withdrawn
  , pattern R_AARCH64_P32_NONE
  , pattern R_AARCH64_P32_ABS32
  , pattern R_AARCH64_P32_ABS16
  , pattern R_AARCH64_P32_PREL32
  , pattern R_AARCH64_P32_PREL16
  , pattern R_AARCH64_P32_MOVW_UABS_G0
  , pattern R_AARCH64_P32_MOVW_UABS_G0_NC
  , pattern R_AARCH64_P32_MOVW_UABS_G1
  , pattern R_AARCH64_P32_MOVW_SABS_G0
  , pattern R_AARCH64_P32_LD_PREL_LO19
  , pattern R_AARCH64_P32_ADR_PREL_LO21
  , pattern R_AARCH64_P32_ADR_PREL_PG_HI21
  , pattern R_AARCH64_P32_ADD_ABS_LO12_NC
  , pattern R_AARCH64_P32_LDST8_ABS_LO12_NC
  , pattern R_AARCH64_P32_LDST16_ABS_LO12_NC
  , pattern R_AARCH64_P32_LDST32_ABS_LO12_NC
  , pattern R_AARCH64_P32_LDST64_ABS_LO12_NC
  , pattern R_AARCH64_P32_LDST128_ABS_LO12_NC
  , pattern R_AARCH64_P32_TSTBR14
  , pattern R_AARCH64_P32_CONDBR19
  , pattern R_AARCH64_P32_JUMP26
  , pattern R_AARCH64_P32_CALL26
  , pattern R_AARCH64_P32_MOVW_PREL_G0
  , pattern R_AARCH64_P32_MOVW_PREL_G0_NC
  , pattern R_AARCH64_P32_MOVW_PREL_G1
  , pattern R_AARCH64_P32_GOT_LD_PREL19
  , pattern R_AARCH64_P32_ADR_GOT_PAGE
  , pattern R_AARCH64_P32_LD32_GOT_LO12_NC
  , pattern R_AARCH64_P32_LD32_GOTPAGE_LO14
  , pattern R_AARCH64_P32_PLT32
  , pattern R_AARCH64_P32_TLSGD_ADR_PREL21
  , pattern R_AARCH64_P32_TLSGD_ADR_PAGE21
  , pattern R_AARCH64_P32_TLSGD_ADD_LO12_NC
  , pattern R_AARCH64_P32_TLSLD_ADR_PREL21
  , pattern R_AARCH64_P32_TLSLD_ADR_PAGE21
  , pattern R_AARCH64_P32_TLSLD_ADD_LO12_NC
  , pattern R_AARCH64_P32_TLSLD_LD_PREL19
  , pattern R_AARCH64_P32_TLSLD_MOVW_DTPREL_G1
  , pattern R_AARCH64_P32_TLSLD_MOVW_DTPREL_G0
  , pattern R_AARCH64_P32_TLSLD_MOVW_DTPREL_G0_NC
  , pattern R_AARCH64_P32_TLSLD_ADD_DTPREL_HI12
  , pattern R_AARCH64_P32_TLSLD_ADD_DTPREL_LO12
  , pattern R_AARCH64_P32_TLSLD_ADD_DTPREL_LO12_NC
  , pattern R_AARCH64_P32_TLSLD_LDST8_DTPREL_LO12
  , pattern R_AARCH64_P32_TLSLD_LDST8_DTPREL_LO12_NC
  , pattern R_AARCH64_P32_TLSLD_LDST16_DTPREL_LO12
  , pattern R_AARCH64_P32_TLSLD_LDST16_DTPREL_LO12_NC
  , pattern R_AARCH64_P32_TLSLD_LDST32_DTPREL_LO12
  , pattern R_AARCH64_P32_TLSLD_LDST32_DTPREL_LO12_NC
  , pattern R_AARCH64_P32_TLSLD_LDST64_DTPREL_LO12
  , pattern R_AARCH64_P32_TLSLD_LDST64_DTPREL_LO12_NC
  , pattern R_AARCH64_P32_TLSLD_LDST128_DTPREL_LO12
  , pattern R_AARCH64_P32_TLSLD_LDST128_DTPREL_LO12_NC
  , pattern R_AARCH64_P32_TLSIE_ADR_GOTTPREL_PAGE21
  , pattern R_AARCH64_P32_TLSIE_LD32_GOTTPREL_LO12_NC
  , pattern R_AARCH64_P32_TLSIE_LD_GOTTPREL_PREL19
  , pattern R_AARCH64_P32_TLSLE_MOVW_TPREL_G1
  , pattern R_AARCH64_P32_TLSLE_MOVW_TPREL_G0
  , pattern R_AARCH64_P32_TLSLE_MOVW_TPREL_G0_NC
  , pattern R_AARCH64_P32_TLSLE_ADD_TPREL_HI12
  , pattern R_AARCH64_P32_TLSLE_ADD_TPREL_LO12
  , pattern R_AARCH64_P32_TLSLE_ADD_TPREL_LO12_NC
  , pattern R_AARCH64_P32_TLSLE_LDST8_TPREL_LO12
  , pattern R_AARCH64_P32_TLSLE_LDST8_TPREL_LO12_NC
  , pattern R_AARCH64_P32_TLSLE_LDST16_TPREL_LO12
  , pattern R_AARCH64_P32_TLSLE_LDST16_TPREL_LO12_NC
  , pattern R_AARCH64_P32_TLSLE_LDST32_TPREL_LO12
  , pattern R_AARCH64_P32_TLSLE_LDST32_TPREL_LO12_NC
  , pattern R_AARCH64_P32_TLSLE_LDST64_TPREL_LO12
  , pattern R_AARCH64_P32_TLSLE_LDST64_TPREL_LO12_NC
  , pattern R_AARCH64_P32_TLSLE_LDST128_TPREL_LO12
  , pattern R_AARCH64_P32_TLSLE_LDST128_TPREL_LO12_NC
  , pattern R_AARCH64_P32_TLSDESC_LD_PREL19
  , pattern R_AARCH64_P32_TLSDESC_ADR_PREL21
  , pattern R_AARCH64_P32_TLSDESC_ADR_PAGE21
  , pattern R_AARCH64_P32_TLSDESC_LD32_LO12
  , pattern R_AARCH64_P32_TLSDESC_ADD_LO12
  , pattern R_AARCH64_P32_TLSDESC_CALL
  , pattern R_AARCH64_P32_COPY
  , pattern R_AARCH64_P32_GLOB_DAT
  , pattern R_AARCH64_P32_JUMP_SLOT
  , pattern R_AARCH64_P32_RELATIVE
  , pattern R_AARCH64_P32_TLS_IMPDEF1
  , pattern R_AARCH64_P32_TLS_DTPMOD
  , pattern R_AARCH64_P32_TLS_IMPDEF2
  , pattern R_AARCH64_P32_TLS_DTPREL
  , pattern R_AARCH64_P32_TLS_TPREL
  , pattern R_AARCH64_P32_TLSDESC
  , pattern R_AARCH64_P32_IRELATIVE
  , pattern R_AARCH64_ABS64
  , pattern R_AARCH64_ABS32
  , pattern R_AARCH64_ABS16
  , pattern R_AARCH64_PREL64
  , pattern R_AARCH64_PREL32
  , pattern R_AARCH64_PREL16
  , pattern R_AARCH64_MOVW_UABS_G0
  , pattern R_AARCH64_MOVW_UABS_G0_NC
  , pattern R_AARCH64_MOVW_UABS_G1
  , pattern R_AARCH64_MOVW_UABS_G1_NC
  , pattern R_AARCH64_MOVW_UABS_G2
  , pattern R_AARCH64_MOVW_UABS_G2_NC
  , pattern R_AARCH64_MOVW_UABS_G3
  , pattern R_AARCH64_MOVW_SABS_G0
  , pattern R_AARCH64_MOVW_SABS_G1
  , pattern R_AARCH64_MOVW_SABS_G2
  , pattern R_AARCH64_LD_PREL_LO19
  , pattern R_AARCH64_ADR_PREL_LO21
  , pattern R_AARCH64_ADR_PREL_PG_HI21
  , pattern R_AARCH64_ADR_PREL_PG_HI21_NC
  , pattern R_AARCH64_ADD_ABS_LO12_NC
  , pattern R_AARCH64_LDST8_ABS_LO12_NC
  , pattern R_AARCH64_TSTBR14
  , pattern R_AARCH64_CONDBR19
  , pattern R_AARCH64_JUMP26
  , pattern R_AARCH64_CALL26
  , pattern R_AARCH64_LDST16_ABS_LO12_NC
  , pattern R_AARCH64_LDST32_ABS_LO12_NC
  , pattern R_AARCH64_LDST64_ABS_LO12_NC
  , pattern R_AARCH64_MOVW_PREL_G0
  , pattern R_AARCH64_MOVW_PREL_G0_NC
  , pattern R_AARCH64_MOVW_PREL_G1
  , pattern R_AARCH64_MOVW_PREL_G1_NC
  , pattern R_AARCH64_MOVW_PREL_G2
  , pattern R_AARCH64_MOVW_PREL_G2_NC
  , pattern R_AARCH64_MOVW_PREL_G3
  , pattern R_AARCH64_LDST128_ABS_LO12_NC
  , pattern R_AARCH64_MOVW_GOTOFF_G0
  , pattern R_AARCH64_MOVW_GOTOFF_G0_NC
  , pattern R_AARCH64_MOVW_GOTOFF_G1
  , pattern R_AARCH64_MOVW_GOTOFF_G1_NC
  , pattern R_AARCH64_MOVW_GOTOFF_G2
  , pattern R_AARCH64_MOVW_GOTOFF_G2_NC
  , pattern R_AARCH64_MOVW_GOTOFF_G3
  , pattern R_AARCH64_GOTREL64
  , pattern R_AARCH64_GOTREL32
  , pattern R_AARCH64_GOT_LD_PREL19
  , pattern R_AARCH64_LD64_GOTOFF_LO15
  , pattern R_AARCH64_ADR_GOT_PAGE
  , pattern R_AARCH64_LD64_GOT_LO12_NC
  , pattern R_AARCH64_LD64_GOTPAGE_LO15
  , pattern R_AARCH64_PLT32
  , pattern R_AARCH64_GOTPCREL32
  , pattern R_AARCH64_PATCHINST
  , pattern R_AARCH64_FUNCINIT64
  , pattern R_AARCH64_TLSGD_ADR_PREL21
  , pattern R_AARCH64_TLSGD_ADR_PAGE21
  , pattern R_AARCH64_TLSGD_ADD_LO12_NC
  , pattern R_AARCH64_TLSGD_MOVW_G1
  , pattern R_AARCH64_TLSGD_MOVW_G0_NC
  , pattern R_AARCH64_TLSLD_ADR_PREL21
  , pattern R_AARCH64_TLSLD_ADR_PAGE21
  , pattern R_AARCH64_TLSLD_ADD_LO12_NC
  , pattern R_AARCH64_TLSLD_MOVW_G1
  , pattern R_AARCH64_TLSLD_MOVW_G0_NC
  , pattern R_AARCH64_TLSLD_LD_PREL19
  , pattern R_AARCH64_TLSLD_MOVW_DTPREL_G2
  , pattern R_AARCH64_TLSLD_MOVW_DTPREL_G1
  , pattern R_AARCH64_TLSLD_MOVW_DTPREL_G1_NC
  , pattern R_AARCH64_TLSLD_MOVW_DTPREL_G0
  , pattern R_AARCH64_TLSLD_MOVW_DTPREL_G0_NC
  , pattern R_AARCH64_TLSLD_ADD_DTPREL_HI12
  , pattern R_AARCH64_TLSLD_ADD_DTPREL_LO12
  , pattern R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC
  , pattern R_AARCH64_TLSLD_LDST8_DTPREL_LO12
  , pattern R_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC
  , pattern R_AARCH64_TLSLD_LDST16_DTPREL_LO12
  , pattern R_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC
  , pattern R_AARCH64_TLSLD_LDST32_DTPREL_LO12
  , pattern R_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC
  , pattern R_AARCH64_TLSLD_LDST64_DTPREL_LO12
  , pattern R_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC
  , pattern R_AARCH64_TLSIE_MOVW_GOTTPREL_G1
  , pattern R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC
  , pattern R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21
  , pattern R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC
  , pattern R_AARCH64_TLSIE_LD_GOTTPREL_PREL19
  , pattern R_AARCH64_TLSLE_MOVW_TPREL_G2
  , pattern R_AARCH64_TLSLE_MOVW_TPREL_G1
  , pattern R_AARCH64_TLSLE_MOVW_TPREL_G1_NC
  , pattern R_AARCH64_TLSLE_MOVW_TPREL_G0
  , pattern R_AARCH64_TLSLE_MOVW_TPREL_G0_NC
  , pattern R_AARCH64_TLSLE_ADD_TPREL_HI12
  , pattern R_AARCH64_TLSLE_ADD_TPREL_LO12
  , pattern R_AARCH64_TLSLE_ADD_TPREL_LO12_NC
  , pattern R_AARCH64_TLSLE_LDST8_TPREL_LO12
  , pattern R_AARCH64_TLSLE_LDST8_TPREL_LO12_NC
  , pattern R_AARCH64_TLSLE_LDST16_TPREL_LO12
  , pattern R_AARCH64_TLSLE_LDST16_TPREL_LO12_NC
  , pattern R_AARCH64_TLSLE_LDST32_TPREL_LO12
  , pattern R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC
  , pattern R_AARCH64_TLSLE_LDST64_TPREL_LO12
  , pattern R_AARCH64_TLSLE_LDST64_TPREL_LO12_NC
  , pattern R_AARCH64_TLSDESC_LD_PREL19
  , pattern R_AARCH64_TLSDESC_ADR_PREL21
  , pattern R_AARCH64_TLSDESC_ADR_PAGE21
  , pattern R_AARCH64_TLSDESC_LD64_LO12
  , pattern R_AARCH64_TLSDESC_ADD_LO12
  , pattern R_AARCH64_TLSDESC_OFF_G1
  , pattern R_AARCH64_TLSDESC_OFF_G0_NC
  , pattern R_AARCH64_TLSDESC_LDR
  , pattern R_AARCH64_TLSDESC_ADD
  , pattern R_AARCH64_TLSDESC_CALL
  , pattern R_AARCH64_TLSLE_LDST128_TPREL_LO12
  , pattern R_AARCH64_TLSLE_LDST128_TPREL_LO12_NC
  , pattern R_AARCH64_TLSLD_LDST128_DTPREL_LO12
  , pattern R_AARCH64_TLSLD_LDST128_DTPREL_LO12_NC
  , pattern R_AARCH64_AUTH_ABS64
  , pattern R_AARCH64_AUTH_MOVW_GOTOFF_G0
  , pattern R_AARCH64_AUTH_MOVW_GOTOFF_G0_NC
  , pattern R_AARCH64_AUTH_MOVW_GOTOFF_G1
  , pattern R_AARCH64_AUTH_MOVW_GOTOFF_G1_NC
  , pattern R_AARCH64_AUTH_MOVW_GOTOFF_G2
  , pattern R_AARCH64_AUTH_MOVW_GOTOFF_G2_NC
  , pattern R_AARCH64_AUTH_MOVW_GOTOFF_G3
  , pattern R_AARCH64_AUTH_GOT_LD_PREL19
  , pattern R_AARCH64_AUTH_LD64_GOTOFF_LO15
  , pattern R_AARCH64_AUTH_ADR_GOT_PAGE
  , pattern R_AARCH64_AUTH_LD64_GOT_LO12_NC
  , pattern R_AARCH64_AUTH_LD64_GOTPAGE_LO15
  , pattern R_AARCH64_AUTH_GOT_ADD_LO12_NC
  , pattern R_AARCH64_AUTH_GOT_ADR_PREL_LO21
  , pattern R_AARCH64_AUTH_TLSDESC_ADR_PAGE21
  , pattern R_AARCH64_AUTH_TLSDESC_LD64_LO12
  , pattern R_AARCH64_AUTH_TLSDESC_ADD_LO12
  , pattern R_AARCH64_AUTH_TLSDESC_CALL
  , pattern R_AARCH64_COPY
  , pattern R_AARCH64_GLOB_DAT
  , pattern R_AARCH64_JUMP_SLOT
  , pattern R_AARCH64_RELATIVE
  , pattern R_AARCH64_TLS_IMPDEF1
  , pattern R_AARCH64_TLS_DTPMOD
  , pattern R_AARCH64_TLS_DTPMOD64
  , pattern R_AARCH64_TLS_IMPDEF2
  , pattern R_AARCH64_TLS_DTPREL
  , pattern R_AARCH64_TLS_DTPREL64
  , pattern R_AARCH64_TLS_TPREL
  , pattern R_AARCH64_TLS_TPREL64
  , pattern R_AARCH64_TLSDESC
  , pattern R_AARCH64_IRELATIVE
  , pattern R_AARCH64_AUTH_RELATIVE
  , pattern R_AARCH64_AUTH_GLOB_DAT
  , pattern R_AARCH64_AUTH_TLSDESC
  , pattern R_AARCH64_AUTH_IRELATIVE
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

pattern R_AARCH64_NONE :: AArch64_RelocationType
pattern R_AARCH64_NONE = AArch64_RelocationType 0 -- None

-- | A withdrawn relocation code. Although its value is distinct from
-- 'R_AARCH64_NONE', the AArch64 ELF ABI says to treat this relocation the same
-- as 'R_AARCH64_NONE'.
pattern R_AARCH64_NONE_withdrawn :: AArch64_RelocationType
pattern R_AARCH64_NONE_withdrawn = AArch64_RelocationType 256 -- None

pattern R_AARCH64_P32_NONE :: AArch64_RelocationType
pattern R_AARCH64_P32_NONE = AArch64_RelocationType 0 -- None

pattern R_AARCH64_P32_ABS32 :: AArch64_RelocationType
pattern R_AARCH64_P32_ABS32 = AArch64_RelocationType 1 -- S + A

pattern R_AARCH64_P32_ABS16 :: AArch64_RelocationType
pattern R_AARCH64_P32_ABS16 = AArch64_RelocationType 2 -- S + A

pattern R_AARCH64_P32_PREL32 :: AArch64_RelocationType
pattern R_AARCH64_P32_PREL32 = AArch64_RelocationType 3 -- S + A - P

pattern R_AARCH64_P32_PREL16 :: AArch64_RelocationType
pattern R_AARCH64_P32_PREL16 = AArch64_RelocationType 4 -- S + A - P

pattern R_AARCH64_P32_MOVW_UABS_G0 :: AArch64_RelocationType
pattern R_AARCH64_P32_MOVW_UABS_G0 = AArch64_RelocationType 5 -- S + A

pattern R_AARCH64_P32_MOVW_UABS_G0_NC :: AArch64_RelocationType
pattern R_AARCH64_P32_MOVW_UABS_G0_NC = AArch64_RelocationType 6 -- S + A

pattern R_AARCH64_P32_MOVW_UABS_G1 :: AArch64_RelocationType
pattern R_AARCH64_P32_MOVW_UABS_G1 = AArch64_RelocationType 7 -- S + A

pattern R_AARCH64_P32_MOVW_SABS_G0 :: AArch64_RelocationType
pattern R_AARCH64_P32_MOVW_SABS_G0 = AArch64_RelocationType 8 -- S + A

pattern R_AARCH64_P32_LD_PREL_LO19 :: AArch64_RelocationType
pattern R_AARCH64_P32_LD_PREL_LO19 = AArch64_RelocationType 9 -- S + A - P

pattern R_AARCH64_P32_ADR_PREL_LO21 :: AArch64_RelocationType
pattern R_AARCH64_P32_ADR_PREL_LO21 = AArch64_RelocationType 10 -- S + A - P

pattern R_AARCH64_P32_ADR_PREL_PG_HI21 :: AArch64_RelocationType
pattern R_AARCH64_P32_ADR_PREL_PG_HI21 = AArch64_RelocationType 11 -- Page(S+A)-Page(P)

pattern R_AARCH64_P32_ADD_ABS_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_P32_ADD_ABS_LO12_NC = AArch64_RelocationType 12 -- S + A

pattern R_AARCH64_P32_LDST8_ABS_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_P32_LDST8_ABS_LO12_NC = AArch64_RelocationType 13 -- S + A

pattern R_AARCH64_P32_LDST16_ABS_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_P32_LDST16_ABS_LO12_NC = AArch64_RelocationType 14 -- S + A

pattern R_AARCH64_P32_LDST32_ABS_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_P32_LDST32_ABS_LO12_NC = AArch64_RelocationType 15 -- S + A

pattern R_AARCH64_P32_LDST64_ABS_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_P32_LDST64_ABS_LO12_NC = AArch64_RelocationType 16 -- S + A

pattern R_AARCH64_P32_LDST128_ABS_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_P32_LDST128_ABS_LO12_NC = AArch64_RelocationType 17 -- S + A

pattern R_AARCH64_P32_TSTBR14 :: AArch64_RelocationType
pattern R_AARCH64_P32_TSTBR14 = AArch64_RelocationType 18 -- S+A-P

pattern R_AARCH64_P32_CONDBR19 :: AArch64_RelocationType
pattern R_AARCH64_P32_CONDBR19 = AArch64_RelocationType 19 -- S+A-P

pattern R_AARCH64_P32_JUMP26 :: AArch64_RelocationType
pattern R_AARCH64_P32_JUMP26 = AArch64_RelocationType 20 -- S+A-P

pattern R_AARCH64_P32_CALL26 :: AArch64_RelocationType
pattern R_AARCH64_P32_CALL26 = AArch64_RelocationType 21 -- S+A-P

pattern R_AARCH64_P32_MOVW_PREL_G0 :: AArch64_RelocationType
pattern R_AARCH64_P32_MOVW_PREL_G0 = AArch64_RelocationType 22 -- S+A-P

pattern R_AARCH64_P32_MOVW_PREL_G0_NC :: AArch64_RelocationType
pattern R_AARCH64_P32_MOVW_PREL_G0_NC = AArch64_RelocationType 23 -- S+A-P

pattern R_AARCH64_P32_MOVW_PREL_G1 :: AArch64_RelocationType
pattern R_AARCH64_P32_MOVW_PREL_G1 = AArch64_RelocationType 24 -- S+A-P

pattern R_AARCH64_P32_GOT_LD_PREL19 :: AArch64_RelocationType
pattern R_AARCH64_P32_GOT_LD_PREL19 = AArch64_RelocationType 25 -- G(GDAT(S))- P

pattern R_AARCH64_P32_ADR_GOT_PAGE :: AArch64_RelocationType
pattern R_AARCH64_P32_ADR_GOT_PAGE = AArch64_RelocationType 26 -- Page(G(GDAT(S)))-Page(P)

pattern R_AARCH64_P32_LD32_GOT_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_P32_LD32_GOT_LO12_NC = AArch64_RelocationType 27 -- G(GDAT(S))

pattern R_AARCH64_P32_LD32_GOTPAGE_LO14 :: AArch64_RelocationType
pattern R_AARCH64_P32_LD32_GOTPAGE_LO14 = AArch64_RelocationType 28 -- G(GDAT(S))-Page(GOT)

pattern R_AARCH64_P32_PLT32 :: AArch64_RelocationType
pattern R_AARCH64_P32_PLT32 = AArch64_RelocationType 29 -- S + A - P

pattern R_AARCH64_P32_TLSGD_ADR_PREL21 :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSGD_ADR_PREL21 = AArch64_RelocationType 80 -- G(GTLSIDX(S)) - P

pattern R_AARCH64_P32_TLSGD_ADR_PAGE21 :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSGD_ADR_PAGE21 = AArch64_RelocationType 81 -- Page(G(GTLSIDX(S)) - Page(P)

pattern R_AARCH64_P32_TLSGD_ADD_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSGD_ADD_LO12_NC = AArch64_RelocationType 82 -- G(GTLSIDX(S))

pattern R_AARCH64_P32_TLSLD_ADR_PREL21 :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSLD_ADR_PREL21 = AArch64_RelocationType 83 -- G(GLDM(S))) - P

pattern R_AARCH64_P32_TLSLD_ADR_PAGE21 :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSLD_ADR_PAGE21 = AArch64_RelocationType 84 -- Page(G(GLDM(S)))-Page(P)

pattern R_AARCH64_P32_TLSLD_ADD_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSLD_ADD_LO12_NC = AArch64_RelocationType 85 -- G(GLDM(S))

pattern R_AARCH64_P32_TLSLD_LD_PREL19 :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSLD_LD_PREL19 = AArch64_RelocationType 86 -- G(GLDM(S)) - P

pattern R_AARCH64_P32_TLSLD_MOVW_DTPREL_G1 :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSLD_MOVW_DTPREL_G1 = AArch64_RelocationType 87 -- DTPREL(S+A)

pattern R_AARCH64_P32_TLSLD_MOVW_DTPREL_G0 :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSLD_MOVW_DTPREL_G0 = AArch64_RelocationType 88 -- DTPREL(S+A)

pattern R_AARCH64_P32_TLSLD_MOVW_DTPREL_G0_NC :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSLD_MOVW_DTPREL_G0_NC = AArch64_RelocationType 89 -- DTPREL(S+A)

pattern R_AARCH64_P32_TLSLD_ADD_DTPREL_HI12 :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSLD_ADD_DTPREL_HI12 = AArch64_RelocationType 90 -- DTPREL(S+A)

pattern R_AARCH64_P32_TLSLD_ADD_DTPREL_LO12 :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSLD_ADD_DTPREL_LO12 = AArch64_RelocationType 91 -- DTPREL(S+A)

pattern R_AARCH64_P32_TLSLD_ADD_DTPREL_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSLD_ADD_DTPREL_LO12_NC = AArch64_RelocationType 92 -- DTPREL(S+A)

pattern R_AARCH64_P32_TLSLD_LDST8_DTPREL_LO12 :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSLD_LDST8_DTPREL_LO12 = AArch64_RelocationType 93 -- DTPREL(S+A)

pattern R_AARCH64_P32_TLSLD_LDST8_DTPREL_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSLD_LDST8_DTPREL_LO12_NC = AArch64_RelocationType 94 -- DTPREL(S+A)

pattern R_AARCH64_P32_TLSLD_LDST16_DTPREL_LO12 :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSLD_LDST16_DTPREL_LO12 = AArch64_RelocationType 95 -- DTPREL(S+A)

pattern R_AARCH64_P32_TLSLD_LDST16_DTPREL_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSLD_LDST16_DTPREL_LO12_NC = AArch64_RelocationType 96 -- DTPREL(S+A)

pattern R_AARCH64_P32_TLSLD_LDST32_DTPREL_LO12 :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSLD_LDST32_DTPREL_LO12 = AArch64_RelocationType 97 -- DTPREL(S+A)

pattern R_AARCH64_P32_TLSLD_LDST32_DTPREL_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSLD_LDST32_DTPREL_LO12_NC = AArch64_RelocationType 98 -- DTPREL(S+A)

pattern R_AARCH64_P32_TLSLD_LDST64_DTPREL_LO12 :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSLD_LDST64_DTPREL_LO12 = AArch64_RelocationType 99 -- DTPREL(S+A)

pattern R_AARCH64_P32_TLSLD_LDST64_DTPREL_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSLD_LDST64_DTPREL_LO12_NC = AArch64_RelocationType 100 -- DTPREL(S+A)

pattern R_AARCH64_P32_TLSLD_LDST128_DTPREL_LO12 :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSLD_LDST128_DTPREL_LO12 = AArch64_RelocationType 101 -- DTPREL(S+A)

pattern R_AARCH64_P32_TLSLD_LDST128_DTPREL_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSLD_LDST128_DTPREL_LO12_NC = AArch64_RelocationType 102 -- DTPREL(S+A)

pattern R_AARCH64_P32_TLSIE_ADR_GOTTPREL_PAGE21 :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSIE_ADR_GOTTPREL_PAGE21 = AArch64_RelocationType 103 -- Page(G(GTPREL(S))) - Page(P)

pattern R_AARCH64_P32_TLSIE_LD32_GOTTPREL_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSIE_LD32_GOTTPREL_LO12_NC = AArch64_RelocationType 104 -- G(GTPREL(S))

pattern R_AARCH64_P32_TLSIE_LD_GOTTPREL_PREL19 :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSIE_LD_GOTTPREL_PREL19 = AArch64_RelocationType 105 -- G(GTPREL(S)) – P

pattern R_AARCH64_P32_TLSLE_MOVW_TPREL_G1 :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSLE_MOVW_TPREL_G1 = AArch64_RelocationType 106 -- TPREL(S+A)

pattern R_AARCH64_P32_TLSLE_MOVW_TPREL_G0 :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSLE_MOVW_TPREL_G0 = AArch64_RelocationType 107 -- TPREL(S+A)

pattern R_AARCH64_P32_TLSLE_MOVW_TPREL_G0_NC :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSLE_MOVW_TPREL_G0_NC = AArch64_RelocationType 108 -- TPREL(S+A)

pattern R_AARCH64_P32_TLSLE_ADD_TPREL_HI12 :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSLE_ADD_TPREL_HI12 = AArch64_RelocationType 109 -- TPREL(S+A)

pattern R_AARCH64_P32_TLSLE_ADD_TPREL_LO12 :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSLE_ADD_TPREL_LO12 = AArch64_RelocationType 110 -- TPREL(S+A)

pattern R_AARCH64_P32_TLSLE_ADD_TPREL_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSLE_ADD_TPREL_LO12_NC = AArch64_RelocationType 111 -- TPREL(S+A)

pattern R_AARCH64_P32_TLSLE_LDST8_TPREL_LO12 :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSLE_LDST8_TPREL_LO12 = AArch64_RelocationType 112 -- TPREL(S+A)

pattern R_AARCH64_P32_TLSLE_LDST8_TPREL_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSLE_LDST8_TPREL_LO12_NC = AArch64_RelocationType 113 -- TPREL(S+A)

pattern R_AARCH64_P32_TLSLE_LDST16_TPREL_LO12 :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSLE_LDST16_TPREL_LO12 = AArch64_RelocationType 114 -- TPREL(S+A)

pattern R_AARCH64_P32_TLSLE_LDST16_TPREL_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSLE_LDST16_TPREL_LO12_NC = AArch64_RelocationType 115 -- TPREL(S+A)

pattern R_AARCH64_P32_TLSLE_LDST32_TPREL_LO12 :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSLE_LDST32_TPREL_LO12 = AArch64_RelocationType 116 -- TPREL(S+A)

pattern R_AARCH64_P32_TLSLE_LDST32_TPREL_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSLE_LDST32_TPREL_LO12_NC = AArch64_RelocationType 117 -- TPREL(S+A)

pattern R_AARCH64_P32_TLSLE_LDST64_TPREL_LO12 :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSLE_LDST64_TPREL_LO12 = AArch64_RelocationType 118 -- TPREL(S+A)

pattern R_AARCH64_P32_TLSLE_LDST64_TPREL_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSLE_LDST64_TPREL_LO12_NC = AArch64_RelocationType 119 -- TPREL(S+A)

pattern R_AARCH64_P32_TLSLE_LDST128_TPREL_LO12 :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSLE_LDST128_TPREL_LO12 = AArch64_RelocationType 120 -- TPREL(S+A)

pattern R_AARCH64_P32_TLSLE_LDST128_TPREL_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSLE_LDST128_TPREL_LO12_NC = AArch64_RelocationType 121 -- TPREL(S+A)

pattern R_AARCH64_P32_TLSDESC_LD_PREL19 :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSDESC_LD_PREL19 = AArch64_RelocationType 122 -- G(GTLSDESC(S)) - P

pattern R_AARCH64_P32_TLSDESC_ADR_PREL21 :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSDESC_ADR_PREL21 = AArch64_RelocationType 123 -- G(GTLSDESC(S)) - P

pattern R_AARCH64_P32_TLSDESC_ADR_PAGE21 :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSDESC_ADR_PAGE21 = AArch64_RelocationType 124 -- Page(G(GTLSDESC(S))) - Page(P)

pattern R_AARCH64_P32_TLSDESC_LD32_LO12 :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSDESC_LD32_LO12 = AArch64_RelocationType 125 -- G(GTLSDESC(S))

pattern R_AARCH64_P32_TLSDESC_ADD_LO12 :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSDESC_ADD_LO12 = AArch64_RelocationType 126 -- G(GTLSDESC(S))

pattern R_AARCH64_P32_TLSDESC_CALL :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSDESC_CALL = AArch64_RelocationType 127 -- None

pattern R_AARCH64_P32_COPY :: AArch64_RelocationType
pattern R_AARCH64_P32_COPY = AArch64_RelocationType 180

pattern R_AARCH64_P32_GLOB_DAT :: AArch64_RelocationType
pattern R_AARCH64_P32_GLOB_DAT = AArch64_RelocationType 181 -- S + A

pattern R_AARCH64_P32_JUMP_SLOT :: AArch64_RelocationType
pattern R_AARCH64_P32_JUMP_SLOT = AArch64_RelocationType 182 -- S + A

pattern R_AARCH64_P32_RELATIVE :: AArch64_RelocationType
pattern R_AARCH64_P32_RELATIVE = AArch64_RelocationType 183 -- Delta + A

-- | See also 'R_AARCH64_P32_TLS_DTPMOD' and 'R_AARCH64_P32_TLS_DTPREL'.
pattern R_AARCH64_P32_TLS_IMPDEF1 :: AArch64_RelocationType
pattern R_AARCH64_P32_TLS_IMPDEF1 = AArch64_RelocationType 184

-- | According to the AArch64 ELF ABI, it is implementation-defined whether
-- 'R_AARCH64_P32_TLS_DTPMOD' refers to 'R_AARCH64_P32_TLS_IMPDEF1' or
-- 'R_AARCH64_P32_TLS_IMPDEF2'. In practice, the Linux platform ABI always had
-- 'R_AARCH64_P32_TLS_DTPMOD' refer to 'R_AARCH64_P32_TLS_IMPDEF1', and the AArch64 ELF
-- ABI recommends that new platforms follow the Linux platform specification,
-- as this is the most widely adopted. As such, @elf-edit@ follows the same
-- convention.
pattern R_AARCH64_P32_TLS_DTPMOD :: AArch64_RelocationType
pattern R_AARCH64_P32_TLS_DTPMOD = R_AARCH64_P32_TLS_IMPDEF1 -- LDM(S)

-- | See also 'R_AARCH64_P32_TLS_DTPMOD' and 'R_AARCH64_P32_TLS_DTPREL'.
pattern R_AARCH64_P32_TLS_IMPDEF2 :: AArch64_RelocationType
pattern R_AARCH64_P32_TLS_IMPDEF2 = AArch64_RelocationType 185

-- | According to the AArch64 ELF ABI, it is implementation-defined whether
-- 'R_AARCH64_P32_TLS_DTPREL' refers to 'R_AARCH64_P32_TLS_IMPDEF1' or
-- 'R_AARCH64_P32_TLS_IMPDEF2'. In practice, the Linux platform ABI always had
-- 'R_AARCH64_P32_TLS_DTPREL' refer to 'R_AARCH64_P32_TLS_IMPDEF2', and the AArch64 ELF
-- ABI recommends that new platforms follow the Linux platform specification,
-- as this is the most widely adopted. As such, @elf-edit@ follows the same
-- convention.
pattern R_AARCH64_P32_TLS_DTPREL :: AArch64_RelocationType
pattern R_AARCH64_P32_TLS_DTPREL = R_AARCH64_P32_TLS_IMPDEF2 -- DTPREL(S+A)

pattern R_AARCH64_P32_TLS_TPREL :: AArch64_RelocationType
pattern R_AARCH64_P32_TLS_TPREL = AArch64_RelocationType 186 -- TPREL(S+A)

pattern R_AARCH64_P32_TLSDESC :: AArch64_RelocationType
pattern R_AARCH64_P32_TLSDESC = AArch64_RelocationType 187 -- TLSDESC(S+A)

pattern R_AARCH64_P32_IRELATIVE :: AArch64_RelocationType
pattern R_AARCH64_P32_IRELATIVE = AArch64_RelocationType 188 -- Indirect(Delta + A)

pattern R_AARCH64_ABS64 :: AArch64_RelocationType
pattern R_AARCH64_ABS64 = AArch64_RelocationType 257 -- S + A

pattern R_AARCH64_ABS32 :: AArch64_RelocationType
pattern R_AARCH64_ABS32 = AArch64_RelocationType 258 -- S + A

pattern R_AARCH64_ABS16 :: AArch64_RelocationType
pattern R_AARCH64_ABS16 = AArch64_RelocationType 259 -- S + A

pattern R_AARCH64_PREL64 :: AArch64_RelocationType
pattern R_AARCH64_PREL64 = AArch64_RelocationType 260 -- S + A - P

pattern R_AARCH64_PREL32 :: AArch64_RelocationType
pattern R_AARCH64_PREL32 = AArch64_RelocationType 261 -- S + A - P

pattern R_AARCH64_PREL16 :: AArch64_RelocationType
pattern R_AARCH64_PREL16 = AArch64_RelocationType 262 -- S + A - P

pattern R_AARCH64_MOVW_UABS_G0 :: AArch64_RelocationType
pattern R_AARCH64_MOVW_UABS_G0 = AArch64_RelocationType 263 -- S + A

pattern R_AARCH64_MOVW_UABS_G0_NC :: AArch64_RelocationType
pattern R_AARCH64_MOVW_UABS_G0_NC = AArch64_RelocationType 264 -- S + A

pattern R_AARCH64_MOVW_UABS_G1 :: AArch64_RelocationType
pattern R_AARCH64_MOVW_UABS_G1 = AArch64_RelocationType 265 -- S + A

pattern R_AARCH64_MOVW_UABS_G1_NC :: AArch64_RelocationType
pattern R_AARCH64_MOVW_UABS_G1_NC = AArch64_RelocationType 266 -- S + A

pattern R_AARCH64_MOVW_UABS_G2 :: AArch64_RelocationType
pattern R_AARCH64_MOVW_UABS_G2 = AArch64_RelocationType 267 -- S + A

pattern R_AARCH64_MOVW_UABS_G2_NC :: AArch64_RelocationType
pattern R_AARCH64_MOVW_UABS_G2_NC = AArch64_RelocationType 268 -- S + A

pattern R_AARCH64_MOVW_UABS_G3 :: AArch64_RelocationType
pattern R_AARCH64_MOVW_UABS_G3 = AArch64_RelocationType 269 -- S + A

pattern R_AARCH64_MOVW_SABS_G0 :: AArch64_RelocationType
pattern R_AARCH64_MOVW_SABS_G0 = AArch64_RelocationType 270 -- S + A

pattern R_AARCH64_MOVW_SABS_G1 :: AArch64_RelocationType
pattern R_AARCH64_MOVW_SABS_G1 = AArch64_RelocationType 271 -- S + A

pattern R_AARCH64_MOVW_SABS_G2 :: AArch64_RelocationType
pattern R_AARCH64_MOVW_SABS_G2 = AArch64_RelocationType 272 -- S + A

pattern R_AARCH64_LD_PREL_LO19 :: AArch64_RelocationType
pattern R_AARCH64_LD_PREL_LO19 = AArch64_RelocationType 273 -- S + A - P

pattern R_AARCH64_ADR_PREL_LO21 :: AArch64_RelocationType
pattern R_AARCH64_ADR_PREL_LO21 = AArch64_RelocationType 274 -- S + A - P

pattern R_AARCH64_ADR_PREL_PG_HI21 :: AArch64_RelocationType
pattern R_AARCH64_ADR_PREL_PG_HI21 = AArch64_RelocationType 275 -- Page(S+A)-Page(P)

pattern R_AARCH64_ADR_PREL_PG_HI21_NC :: AArch64_RelocationType
pattern R_AARCH64_ADR_PREL_PG_HI21_NC = AArch64_RelocationType 276 -- Page(S+A)-Page(P)

pattern R_AARCH64_ADD_ABS_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_ADD_ABS_LO12_NC = AArch64_RelocationType 277 -- S + A

pattern R_AARCH64_LDST8_ABS_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_LDST8_ABS_LO12_NC = AArch64_RelocationType 278 -- S + A

pattern R_AARCH64_TSTBR14 :: AArch64_RelocationType
pattern R_AARCH64_TSTBR14 = AArch64_RelocationType 279 -- S+A-P

pattern R_AARCH64_CONDBR19 :: AArch64_RelocationType
pattern R_AARCH64_CONDBR19 = AArch64_RelocationType 280 -- S+A-P

pattern R_AARCH64_JUMP26 :: AArch64_RelocationType
pattern R_AARCH64_JUMP26 = AArch64_RelocationType 282 -- S+A-P

pattern R_AARCH64_CALL26 :: AArch64_RelocationType
pattern R_AARCH64_CALL26 = AArch64_RelocationType 283 -- S+A-P

pattern R_AARCH64_LDST16_ABS_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_LDST16_ABS_LO12_NC = AArch64_RelocationType 284 -- S + A

pattern R_AARCH64_LDST32_ABS_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_LDST32_ABS_LO12_NC = AArch64_RelocationType 285 -- S + A

pattern R_AARCH64_LDST64_ABS_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_LDST64_ABS_LO12_NC = AArch64_RelocationType 286 -- S + A

pattern R_AARCH64_MOVW_PREL_G0 :: AArch64_RelocationType
pattern R_AARCH64_MOVW_PREL_G0 = AArch64_RelocationType 287 -- S+A-P

pattern R_AARCH64_MOVW_PREL_G0_NC :: AArch64_RelocationType
pattern R_AARCH64_MOVW_PREL_G0_NC = AArch64_RelocationType 288 -- S+A-P

pattern R_AARCH64_MOVW_PREL_G1 :: AArch64_RelocationType
pattern R_AARCH64_MOVW_PREL_G1 = AArch64_RelocationType 289 -- S+A-P

pattern R_AARCH64_MOVW_PREL_G1_NC :: AArch64_RelocationType
pattern R_AARCH64_MOVW_PREL_G1_NC = AArch64_RelocationType 290 -- S+A-P

pattern R_AARCH64_MOVW_PREL_G2 :: AArch64_RelocationType
pattern R_AARCH64_MOVW_PREL_G2 = AArch64_RelocationType 291 -- S+A-P

pattern R_AARCH64_MOVW_PREL_G2_NC :: AArch64_RelocationType
pattern R_AARCH64_MOVW_PREL_G2_NC = AArch64_RelocationType 292 -- S+A-P

pattern R_AARCH64_MOVW_PREL_G3 :: AArch64_RelocationType
pattern R_AARCH64_MOVW_PREL_G3 = AArch64_RelocationType 293 -- S+A-P

pattern R_AARCH64_LDST128_ABS_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_LDST128_ABS_LO12_NC = AArch64_RelocationType 299 -- S + A

pattern R_AARCH64_MOVW_GOTOFF_G0 :: AArch64_RelocationType
pattern R_AARCH64_MOVW_GOTOFF_G0 = AArch64_RelocationType 300 -- G(GDAT(S)) -GOT

pattern R_AARCH64_MOVW_GOTOFF_G0_NC :: AArch64_RelocationType
pattern R_AARCH64_MOVW_GOTOFF_G0_NC = AArch64_RelocationType 301 -- G(GDAT(S)) -GOT

pattern R_AARCH64_MOVW_GOTOFF_G1 :: AArch64_RelocationType
pattern R_AARCH64_MOVW_GOTOFF_G1 = AArch64_RelocationType 302 -- G(GDAT(S)) -GOT

pattern R_AARCH64_MOVW_GOTOFF_G1_NC :: AArch64_RelocationType
pattern R_AARCH64_MOVW_GOTOFF_G1_NC = AArch64_RelocationType 303 -- G(GDAT(S)) -GOT

pattern R_AARCH64_MOVW_GOTOFF_G2 :: AArch64_RelocationType
pattern R_AARCH64_MOVW_GOTOFF_G2 = AArch64_RelocationType 304 -- G(GDAT(S)) -GOT

pattern R_AARCH64_MOVW_GOTOFF_G2_NC :: AArch64_RelocationType
pattern R_AARCH64_MOVW_GOTOFF_G2_NC = AArch64_RelocationType 305 -- G(GDAT(S)) -GOT

pattern R_AARCH64_MOVW_GOTOFF_G3 :: AArch64_RelocationType
pattern R_AARCH64_MOVW_GOTOFF_G3 = AArch64_RelocationType 306 -- G(GDAT(S)) -GOT

pattern R_AARCH64_GOTREL64 :: AArch64_RelocationType
pattern R_AARCH64_GOTREL64 = AArch64_RelocationType 307 -- S+A-GOT

pattern R_AARCH64_GOTREL32 :: AArch64_RelocationType
pattern R_AARCH64_GOTREL32 = AArch64_RelocationType 308 -- S+A-GOT

pattern R_AARCH64_GOT_LD_PREL19 :: AArch64_RelocationType
pattern R_AARCH64_GOT_LD_PREL19 = AArch64_RelocationType 309 -- G(GDAT(S))- P

pattern R_AARCH64_LD64_GOTOFF_LO15 :: AArch64_RelocationType
pattern R_AARCH64_LD64_GOTOFF_LO15 = AArch64_RelocationType 310 -- G(GDAT(S))- GOT

pattern R_AARCH64_ADR_GOT_PAGE :: AArch64_RelocationType
pattern R_AARCH64_ADR_GOT_PAGE = AArch64_RelocationType 311 -- Page(G(GDAT(S)))-Page(P)

pattern R_AARCH64_LD64_GOT_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_LD64_GOT_LO12_NC = AArch64_RelocationType 312 -- G(GDAT(S))

pattern R_AARCH64_LD64_GOTPAGE_LO15 :: AArch64_RelocationType
pattern R_AARCH64_LD64_GOTPAGE_LO15 = AArch64_RelocationType 313 -- G(GDAT(S))-Page(GOT)

pattern R_AARCH64_PLT32 :: AArch64_RelocationType
pattern R_AARCH64_PLT32 = AArch64_RelocationType 314 -- S + A - P

pattern R_AARCH64_GOTPCREL32 :: AArch64_RelocationType
pattern R_AARCH64_GOTPCREL32 = AArch64_RelocationType 315 -- G(GDAT(S))-P+A

pattern R_AARCH64_PATCHINST :: AArch64_RelocationType
pattern R_AARCH64_PATCHINST = AArch64_RelocationType 316 -- S + A

pattern R_AARCH64_FUNCINIT64 :: AArch64_RelocationType
pattern R_AARCH64_FUNCINIT64 = AArch64_RelocationType 317 -- FUNCINIT(S + A)

pattern R_AARCH64_TLSGD_ADR_PREL21 :: AArch64_RelocationType
pattern R_AARCH64_TLSGD_ADR_PREL21 = AArch64_RelocationType 512 -- G(GTLSIDX(S)) - P

pattern R_AARCH64_TLSGD_ADR_PAGE21 :: AArch64_RelocationType
pattern R_AARCH64_TLSGD_ADR_PAGE21 = AArch64_RelocationType 513 -- Page(G(GTLSIDX(S)) - Page(P)

pattern R_AARCH64_TLSGD_ADD_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_TLSGD_ADD_LO12_NC = AArch64_RelocationType 514 -- G(GTLSIDX(S))

pattern R_AARCH64_TLSGD_MOVW_G1 :: AArch64_RelocationType
pattern R_AARCH64_TLSGD_MOVW_G1 = AArch64_RelocationType 515 -- G(GTLSIDX(S)) - GOT

pattern R_AARCH64_TLSGD_MOVW_G0_NC :: AArch64_RelocationType
pattern R_AARCH64_TLSGD_MOVW_G0_NC = AArch64_RelocationType 516 -- G(GTLSIDX(S)) - GOT

pattern R_AARCH64_TLSLD_ADR_PREL21 :: AArch64_RelocationType
pattern R_AARCH64_TLSLD_ADR_PREL21 = AArch64_RelocationType 517 -- G(GLDM(S))) - P

pattern R_AARCH64_TLSLD_ADR_PAGE21 :: AArch64_RelocationType
pattern R_AARCH64_TLSLD_ADR_PAGE21 = AArch64_RelocationType 518 -- Page(G(GLDM(S)))-Page(P)

pattern R_AARCH64_TLSLD_ADD_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_TLSLD_ADD_LO12_NC = AArch64_RelocationType 519 -- G(GLDM(S))

pattern R_AARCH64_TLSLD_MOVW_G1 :: AArch64_RelocationType
pattern R_AARCH64_TLSLD_MOVW_G1 = AArch64_RelocationType 520 -- G(GLDM(S)) - GOT

pattern R_AARCH64_TLSLD_MOVW_G0_NC :: AArch64_RelocationType
pattern R_AARCH64_TLSLD_MOVW_G0_NC = AArch64_RelocationType 521 -- G(GLDM(S)) - GOT

pattern R_AARCH64_TLSLD_LD_PREL19 :: AArch64_RelocationType
pattern R_AARCH64_TLSLD_LD_PREL19 = AArch64_RelocationType 522 -- G(GLDM(S)) - P

pattern R_AARCH64_TLSLD_MOVW_DTPREL_G2 :: AArch64_RelocationType
pattern R_AARCH64_TLSLD_MOVW_DTPREL_G2 = AArch64_RelocationType 523 -- DTPREL(S+A)

pattern R_AARCH64_TLSLD_MOVW_DTPREL_G1 :: AArch64_RelocationType
pattern R_AARCH64_TLSLD_MOVW_DTPREL_G1 = AArch64_RelocationType 524 -- DTPREL(S+A)

pattern R_AARCH64_TLSLD_MOVW_DTPREL_G1_NC :: AArch64_RelocationType
pattern R_AARCH64_TLSLD_MOVW_DTPREL_G1_NC = AArch64_RelocationType 525 -- DTPREL(S+A)

pattern R_AARCH64_TLSLD_MOVW_DTPREL_G0 :: AArch64_RelocationType
pattern R_AARCH64_TLSLD_MOVW_DTPREL_G0 = AArch64_RelocationType 526 -- DTPREL(S+A)

pattern R_AARCH64_TLSLD_MOVW_DTPREL_G0_NC :: AArch64_RelocationType
pattern R_AARCH64_TLSLD_MOVW_DTPREL_G0_NC = AArch64_RelocationType 527 -- DTPREL(S+A)

pattern R_AARCH64_TLSLD_ADD_DTPREL_HI12 :: AArch64_RelocationType
pattern R_AARCH64_TLSLD_ADD_DTPREL_HI12 = AArch64_RelocationType 528 -- DTPREL(S+A)

pattern R_AARCH64_TLSLD_ADD_DTPREL_LO12 :: AArch64_RelocationType
pattern R_AARCH64_TLSLD_ADD_DTPREL_LO12 = AArch64_RelocationType 529 -- DTPREL(S+A)

pattern R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC = AArch64_RelocationType 530 -- DTPREL(S+A)

pattern R_AARCH64_TLSLD_LDST8_DTPREL_LO12 :: AArch64_RelocationType
pattern R_AARCH64_TLSLD_LDST8_DTPREL_LO12 = AArch64_RelocationType 531 -- DTPREL(S+A)

pattern R_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC = AArch64_RelocationType 532 -- DTPREL(S+A)

pattern R_AARCH64_TLSLD_LDST16_DTPREL_LO12 :: AArch64_RelocationType
pattern R_AARCH64_TLSLD_LDST16_DTPREL_LO12 = AArch64_RelocationType 533 -- DTPREL(S+A)

pattern R_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC = AArch64_RelocationType 534 -- DTPREL(S+A)

pattern R_AARCH64_TLSLD_LDST32_DTPREL_LO12 :: AArch64_RelocationType
pattern R_AARCH64_TLSLD_LDST32_DTPREL_LO12 = AArch64_RelocationType 535 -- DTPREL(S+A)

pattern R_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC = AArch64_RelocationType 536 -- DTPREL(S+A)

pattern R_AARCH64_TLSLD_LDST64_DTPREL_LO12 :: AArch64_RelocationType
pattern R_AARCH64_TLSLD_LDST64_DTPREL_LO12 = AArch64_RelocationType 537 -- DTPREL(S+A)

pattern R_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC = AArch64_RelocationType 538 -- DTPREL(S+A)

pattern R_AARCH64_TLSIE_MOVW_GOTTPREL_G1 :: AArch64_RelocationType
pattern R_AARCH64_TLSIE_MOVW_GOTTPREL_G1 = AArch64_RelocationType 539 -- G(GTPREL(S)) - GOT

pattern R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC :: AArch64_RelocationType
pattern R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC = AArch64_RelocationType 540 -- G(GTPREL(S)) - GOT

pattern R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21 :: AArch64_RelocationType
pattern R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21 = AArch64_RelocationType 541 -- Page(G(GTPREL(S))) - Page(P)

pattern R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC = AArch64_RelocationType 542 -- G(GTPREL(S))

pattern R_AARCH64_TLSIE_LD_GOTTPREL_PREL19 :: AArch64_RelocationType
pattern R_AARCH64_TLSIE_LD_GOTTPREL_PREL19 = AArch64_RelocationType 543 -- G(GTPREL(S)) – P

pattern R_AARCH64_TLSLE_MOVW_TPREL_G2 :: AArch64_RelocationType
pattern R_AARCH64_TLSLE_MOVW_TPREL_G2 = AArch64_RelocationType 544 -- TPREL(S+A)

pattern R_AARCH64_TLSLE_MOVW_TPREL_G1 :: AArch64_RelocationType
pattern R_AARCH64_TLSLE_MOVW_TPREL_G1 = AArch64_RelocationType 545 -- TPREL(S+A)

pattern R_AARCH64_TLSLE_MOVW_TPREL_G1_NC :: AArch64_RelocationType
pattern R_AARCH64_TLSLE_MOVW_TPREL_G1_NC = AArch64_RelocationType 546 -- TPREL(S+A)

pattern R_AARCH64_TLSLE_MOVW_TPREL_G0 :: AArch64_RelocationType
pattern R_AARCH64_TLSLE_MOVW_TPREL_G0 = AArch64_RelocationType 547 -- TPREL(S+A)

pattern R_AARCH64_TLSLE_MOVW_TPREL_G0_NC :: AArch64_RelocationType
pattern R_AARCH64_TLSLE_MOVW_TPREL_G0_NC = AArch64_RelocationType 548 -- TPREL(S+A)

pattern R_AARCH64_TLSLE_ADD_TPREL_HI12 :: AArch64_RelocationType
pattern R_AARCH64_TLSLE_ADD_TPREL_HI12 = AArch64_RelocationType 549 -- TPREL(S+A)

pattern R_AARCH64_TLSLE_ADD_TPREL_LO12 :: AArch64_RelocationType
pattern R_AARCH64_TLSLE_ADD_TPREL_LO12 = AArch64_RelocationType 550 -- TPREL(S+A)

pattern R_AARCH64_TLSLE_ADD_TPREL_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_TLSLE_ADD_TPREL_LO12_NC = AArch64_RelocationType 551 -- TPREL(S+A)

pattern R_AARCH64_TLSLE_LDST8_TPREL_LO12 :: AArch64_RelocationType
pattern R_AARCH64_TLSLE_LDST8_TPREL_LO12 = AArch64_RelocationType 552 -- TPREL(S+A)

pattern R_AARCH64_TLSLE_LDST8_TPREL_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_TLSLE_LDST8_TPREL_LO12_NC = AArch64_RelocationType 553 -- TPREL(S+A)

pattern R_AARCH64_TLSLE_LDST16_TPREL_LO12 :: AArch64_RelocationType
pattern R_AARCH64_TLSLE_LDST16_TPREL_LO12 = AArch64_RelocationType 554 -- TPREL(S+A)

pattern R_AARCH64_TLSLE_LDST16_TPREL_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_TLSLE_LDST16_TPREL_LO12_NC = AArch64_RelocationType 555 -- TPREL(S+A)

pattern R_AARCH64_TLSLE_LDST32_TPREL_LO12 :: AArch64_RelocationType
pattern R_AARCH64_TLSLE_LDST32_TPREL_LO12 = AArch64_RelocationType 556 -- TPREL(S+A)

pattern R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC = AArch64_RelocationType 557 -- TPREL(S+A)

pattern R_AARCH64_TLSLE_LDST64_TPREL_LO12 :: AArch64_RelocationType
pattern R_AARCH64_TLSLE_LDST64_TPREL_LO12 = AArch64_RelocationType 558 -- TPREL(S+A)

pattern R_AARCH64_TLSLE_LDST64_TPREL_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_TLSLE_LDST64_TPREL_LO12_NC = AArch64_RelocationType 559 -- TPREL(S+A)

pattern R_AARCH64_TLSDESC_LD_PREL19 :: AArch64_RelocationType
pattern R_AARCH64_TLSDESC_LD_PREL19 = AArch64_RelocationType 560 -- G(GTLSDESC(S)) - P

pattern R_AARCH64_TLSDESC_ADR_PREL21 :: AArch64_RelocationType
pattern R_AARCH64_TLSDESC_ADR_PREL21 = AArch64_RelocationType 561 -- G(GTLSDESC(S)) - P

pattern R_AARCH64_TLSDESC_ADR_PAGE21 :: AArch64_RelocationType
pattern R_AARCH64_TLSDESC_ADR_PAGE21 = AArch64_RelocationType 562 -- Page(G(GTLSDESC(S))) - Page(P)

pattern R_AARCH64_TLSDESC_LD64_LO12 :: AArch64_RelocationType
pattern R_AARCH64_TLSDESC_LD64_LO12 = AArch64_RelocationType 563 -- G(GTLSDESC(S))

pattern R_AARCH64_TLSDESC_ADD_LO12 :: AArch64_RelocationType
pattern R_AARCH64_TLSDESC_ADD_LO12 = AArch64_RelocationType 564 -- G(GTLSDESC(S))

pattern R_AARCH64_TLSDESC_OFF_G1 :: AArch64_RelocationType
pattern R_AARCH64_TLSDESC_OFF_G1 = AArch64_RelocationType 565 -- G(GTLSDESC(S)) - GOT

pattern R_AARCH64_TLSDESC_OFF_G0_NC :: AArch64_RelocationType
pattern R_AARCH64_TLSDESC_OFF_G0_NC = AArch64_RelocationType 566 -- G(GTLSDESC(S)) - GOT

pattern R_AARCH64_TLSDESC_LDR :: AArch64_RelocationType
pattern R_AARCH64_TLSDESC_LDR = AArch64_RelocationType 567 -- None

pattern R_AARCH64_TLSDESC_ADD :: AArch64_RelocationType
pattern R_AARCH64_TLSDESC_ADD = AArch64_RelocationType 568 -- None

pattern R_AARCH64_TLSDESC_CALL :: AArch64_RelocationType
pattern R_AARCH64_TLSDESC_CALL = AArch64_RelocationType 569 -- None

pattern R_AARCH64_TLSLE_LDST128_TPREL_LO12 :: AArch64_RelocationType
pattern R_AARCH64_TLSLE_LDST128_TPREL_LO12 = AArch64_RelocationType 570 -- TPREL(S+A)

pattern R_AARCH64_TLSLE_LDST128_TPREL_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_TLSLE_LDST128_TPREL_LO12_NC = AArch64_RelocationType 571 -- TPREL(S+A)

pattern R_AARCH64_TLSLD_LDST128_DTPREL_LO12 :: AArch64_RelocationType
pattern R_AARCH64_TLSLD_LDST128_DTPREL_LO12 = AArch64_RelocationType 572 -- DTPREL(S+A)

pattern R_AARCH64_TLSLD_LDST128_DTPREL_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_TLSLD_LDST128_DTPREL_LO12_NC = AArch64_RelocationType 573 -- DTPREL(S+A)

pattern R_AARCH64_AUTH_ABS64 :: AArch64_RelocationType
pattern R_AARCH64_AUTH_ABS64 = AArch64_RelocationType 580 -- PAUTH(S+A)

pattern R_AARCH64_AUTH_MOVW_GOTOFF_G0 :: AArch64_RelocationType
pattern R_AARCH64_AUTH_MOVW_GOTOFF_G0 = AArch64_RelocationType 581 -- G(ENCD(GDAT(S))) - GOT

pattern R_AARCH64_AUTH_MOVW_GOTOFF_G0_NC :: AArch64_RelocationType
pattern R_AARCH64_AUTH_MOVW_GOTOFF_G0_NC = AArch64_RelocationType 582 -- G(ENCD(GDAT(S))) - GOT

pattern R_AARCH64_AUTH_MOVW_GOTOFF_G1 :: AArch64_RelocationType
pattern R_AARCH64_AUTH_MOVW_GOTOFF_G1 = AArch64_RelocationType 583 -- G(ENCD(GDAT(S))) - GOT

pattern R_AARCH64_AUTH_MOVW_GOTOFF_G1_NC :: AArch64_RelocationType
pattern R_AARCH64_AUTH_MOVW_GOTOFF_G1_NC = AArch64_RelocationType 584 -- G(ENCD(GDAT(S))) - GOT

pattern R_AARCH64_AUTH_MOVW_GOTOFF_G2 :: AArch64_RelocationType
pattern R_AARCH64_AUTH_MOVW_GOTOFF_G2 = AArch64_RelocationType 585 -- G(ENCD(GDAT(S))) - GOT

pattern R_AARCH64_AUTH_MOVW_GOTOFF_G2_NC :: AArch64_RelocationType
pattern R_AARCH64_AUTH_MOVW_GOTOFF_G2_NC = AArch64_RelocationType 586 -- G(ENCD(GDAT(S))) - GOT

pattern R_AARCH64_AUTH_MOVW_GOTOFF_G3 :: AArch64_RelocationType
pattern R_AARCH64_AUTH_MOVW_GOTOFF_G3 = AArch64_RelocationType 587 -- G(ENCD(GDAT(S))) - GOT

pattern R_AARCH64_AUTH_GOT_LD_PREL19 :: AArch64_RelocationType
pattern R_AARCH64_AUTH_GOT_LD_PREL19 = AArch64_RelocationType 588 -- G(ENCD(GDAT(S))) - P

pattern R_AARCH64_AUTH_LD64_GOTOFF_LO15 :: AArch64_RelocationType
pattern R_AARCH64_AUTH_LD64_GOTOFF_LO15 = AArch64_RelocationType 589 -- G(ENCD(GDAT(S))) - GOT

pattern R_AARCH64_AUTH_ADR_GOT_PAGE :: AArch64_RelocationType
pattern R_AARCH64_AUTH_ADR_GOT_PAGE = AArch64_RelocationType 590 -- G(ENCD(GDAT(S))) - Page(P)

pattern R_AARCH64_AUTH_LD64_GOT_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_AUTH_LD64_GOT_LO12_NC = AArch64_RelocationType 591 -- G(ENCD(GDAT(S)))

pattern R_AARCH64_AUTH_LD64_GOTPAGE_LO15 :: AArch64_RelocationType
pattern R_AARCH64_AUTH_LD64_GOTPAGE_LO15 = AArch64_RelocationType 592 -- G(ENCD(GDAT(S))) - Page(GOT)

pattern R_AARCH64_AUTH_GOT_ADD_LO12_NC :: AArch64_RelocationType
pattern R_AARCH64_AUTH_GOT_ADD_LO12_NC = AArch64_RelocationType 593 -- G(ENCD(GDAT(S)))

pattern R_AARCH64_AUTH_GOT_ADR_PREL_LO21 :: AArch64_RelocationType
pattern R_AARCH64_AUTH_GOT_ADR_PREL_LO21 = AArch64_RelocationType 594 -- G(ENCD(GDAT(S))) - P

pattern R_AARCH64_AUTH_TLSDESC_ADR_PAGE21 :: AArch64_RelocationType
pattern R_AARCH64_AUTH_TLSDESC_ADR_PAGE21 = AArch64_RelocationType 595 -- Page(G(ENCD(GTLSDESC(S)))) - Page(P)

pattern R_AARCH64_AUTH_TLSDESC_LD64_LO12 :: AArch64_RelocationType
pattern R_AARCH64_AUTH_TLSDESC_LD64_LO12 = AArch64_RelocationType 596 -- G(ENCD(GTLSDESC(S)))

pattern R_AARCH64_AUTH_TLSDESC_ADD_LO12 :: AArch64_RelocationType
pattern R_AARCH64_AUTH_TLSDESC_ADD_LO12 = AArch64_RelocationType 597 -- G(ENCD(GTLSDESC(S)))

pattern R_AARCH64_AUTH_TLSDESC_CALL :: AArch64_RelocationType
pattern R_AARCH64_AUTH_TLSDESC_CALL = AArch64_RelocationType 598 -- None

pattern R_AARCH64_COPY :: AArch64_RelocationType
pattern R_AARCH64_COPY = AArch64_RelocationType 1024

pattern R_AARCH64_GLOB_DAT :: AArch64_RelocationType
pattern R_AARCH64_GLOB_DAT = AArch64_RelocationType 1025 -- S + A

pattern R_AARCH64_JUMP_SLOT :: AArch64_RelocationType
pattern R_AARCH64_JUMP_SLOT = AArch64_RelocationType 1026 -- S + A

pattern R_AARCH64_RELATIVE :: AArch64_RelocationType
pattern R_AARCH64_RELATIVE = AArch64_RelocationType 1027 -- Delta + A

-- | See also 'R_AARCH64_TLS_DTPMOD' and 'R_AARCH64_TLS_DTPREL'.
pattern R_AARCH64_TLS_IMPDEF1 :: AArch64_RelocationType
pattern R_AARCH64_TLS_IMPDEF1 = AArch64_RelocationType 1028

-- | According to the AArch64 ELF ABI, it is implementation-defined whether
-- 'R_AARCH64_TLS_DTPMOD' refers to 'R_AARCH64_TLS_IMPDEF1' or
-- 'R_AARCH64_TLS_IMPDEF2'. In practice, the Linux platform ABI always had
-- 'R_AARCH64_TLS_DTPMOD' refer to 'R_AARCH64_TLS_IMPDEF1', and the AArch64 ELF
-- ABI recommends that new platforms follow the Linux platform specification,
-- as this is the most widely adopted. As such, @elf-edit@ follows the same
-- convention.
pattern R_AARCH64_TLS_DTPMOD :: AArch64_RelocationType
pattern R_AARCH64_TLS_DTPMOD = R_AARCH64_TLS_IMPDEF1 -- LDM(S)

-- | An old name for 'R_AARCH64_TLS_DTPMOD' used for backwards compatibility
pattern R_AARCH64_TLS_DTPMOD64 :: AArch64_RelocationType
pattern R_AARCH64_TLS_DTPMOD64 = R_AARCH64_TLS_DTPMOD -- LDM(S)

-- | See also 'R_AARCH64_TLS_DTPMOD' and 'R_AARCH64_TLS_DTPREL'.
pattern R_AARCH64_TLS_IMPDEF2 :: AArch64_RelocationType
pattern R_AARCH64_TLS_IMPDEF2 = AArch64_RelocationType 1029

-- | According to the AArch64 ELF ABI, it is implementation-defined whether
-- 'R_AARCH64_TLS_DTPREL' refers to 'R_AARCH64_TLS_IMPDEF1' or
-- 'R_AARCH64_TLS_IMPDEF2'. In practice, the Linux platform ABI always had
-- 'R_AARCH64_TLS_DTPREL' refer to 'R_AARCH64_TLS_IMPDEF2', and the AArch64 ELF
-- ABI recommends that new platforms follow the Linux platform specification,
-- as this is the most widely adopted. As such, @elf-edit@ follows the same
-- convention.
pattern R_AARCH64_TLS_DTPREL :: AArch64_RelocationType
pattern R_AARCH64_TLS_DTPREL = R_AARCH64_TLS_IMPDEF2 -- DTPREL(S+A)

-- | An old name for 'R_AARCH64_TLS_DTPREL' used for backwards compatibility
pattern R_AARCH64_TLS_DTPREL64 :: AArch64_RelocationType
pattern R_AARCH64_TLS_DTPREL64 = R_AARCH64_TLS_DTPREL -- DTPREL(S+A)

pattern R_AARCH64_TLS_TPREL :: AArch64_RelocationType
pattern R_AARCH64_TLS_TPREL = AArch64_RelocationType 1030 -- TPREL(S+A)

-- | An old name for 'R_AARCH64_TLS_TPREL' used for backwards compatibility.
pattern R_AARCH64_TLS_TPREL64 :: AArch64_RelocationType
pattern R_AARCH64_TLS_TPREL64 = R_AARCH64_TLS_TPREL -- TPREL(S+A)

pattern R_AARCH64_TLSDESC :: AArch64_RelocationType
pattern R_AARCH64_TLSDESC = AArch64_RelocationType 1031 -- TLSDESC(S+A)

pattern R_AARCH64_IRELATIVE :: AArch64_RelocationType
pattern R_AARCH64_IRELATIVE = AArch64_RelocationType 1032 -- Indirect(Delta + A)

pattern R_AARCH64_AUTH_RELATIVE :: AArch64_RelocationType
pattern R_AARCH64_AUTH_RELATIVE = AArch64_RelocationType 1041 -- SIGN(Delta + A, SCHEMA(*P))

pattern R_AARCH64_AUTH_GLOB_DAT :: AArch64_RelocationType
pattern R_AARCH64_AUTH_GLOB_DAT = AArch64_RelocationType 1042 -- SIGN((S + A), SCHEMA(*P))

pattern R_AARCH64_AUTH_TLSDESC :: AArch64_RelocationType
pattern R_AARCH64_AUTH_TLSDESC = AArch64_RelocationType 1043 -- SIGN(TLSDESC(S + A), SCHEMA(*P))

pattern R_AARCH64_AUTH_IRELATIVE :: AArch64_RelocationType
pattern R_AARCH64_AUTH_IRELATIVE = AArch64_RelocationType 1044 -- SIGN(Indirect(S + A), SCHEMA(*P))

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
instructionReloc :: AArch64_RelocationType
                 -> String
                 -> (AArch64_RelocationType, (String, Maybe Int))
instructionReloc tp nm = (tp, (nm, Nothing))

dataReloc :: AArch64_RelocationType
          -> String
          -> Int
          -> (AArch64_RelocationType, (String, Maybe Int))
dataReloc tp nm bits = (tp, (nm, Just bits))

-- These values are derived from the AArch64 ELF ABI:
-- https://github.com/ARM-software/abi-aa/blob/ee4b3c12d57c8424ff60c2ae56e10690d0604ab6/aaelf64/aaelf64.rst.
aarch64RelocationTypes :: Map.Map AArch64_RelocationType (String, Maybe Int)
aarch64RelocationTypes = Map.fromList
  [ dataReloc R_AARCH64_NONE "R_AARCH64_NONE" none
  , dataReloc R_AARCH64_NONE_withdrawn "R_AARCH64_NONE" none
  , dataReloc R_AARCH64_P32_ABS32 "R_AARCH64_P32_ABS32" word32
  , dataReloc R_AARCH64_P32_ABS16 "R_AARCH64_P32_ABS16" word16
  , dataReloc R_AARCH64_P32_PREL32 "R_AARCH64_P32_PREL32" word32
  , dataReloc R_AARCH64_P32_PREL16 "R_AARCH64_P32_PREL16" word16
  , instructionReloc R_AARCH64_P32_MOVW_UABS_G0 "R_AARCH64_P32_MOVW_UABS_G0"
  , instructionReloc R_AARCH64_P32_MOVW_UABS_G0_NC "R_AARCH64_P32_MOVW_UABS_G0_NC"
  , instructionReloc R_AARCH64_P32_MOVW_UABS_G1 "R_AARCH64_P32_MOVW_UABS_G1"
  , instructionReloc R_AARCH64_P32_MOVW_SABS_G0 "R_AARCH64_P32_MOVW_SABS_G0"
  , instructionReloc R_AARCH64_P32_LD_PREL_LO19 "R_AARCH64_P32_LD_PREL_LO19"
  , instructionReloc R_AARCH64_P32_ADR_PREL_LO21 "R_AARCH64_P32_ADR_PREL_LO21"
  , instructionReloc R_AARCH64_P32_ADR_PREL_PG_HI21 "R_AARCH64_P32_ADR_PREL_PG_HI21"
  , instructionReloc R_AARCH64_P32_ADD_ABS_LO12_NC "R_AARCH64_P32_ADD_ABS_LO12_NC"
  , instructionReloc R_AARCH64_P32_LDST8_ABS_LO12_NC "R_AARCH64_P32_LDST8_ABS_LO12_NC"
  , instructionReloc R_AARCH64_P32_LDST16_ABS_LO12_NC "R_AARCH64_P32_LDST16_ABS_LO12_NC"
  , instructionReloc R_AARCH64_P32_LDST32_ABS_LO12_NC "R_AARCH64_P32_LDST32_ABS_LO12_NC"
  , instructionReloc R_AARCH64_P32_LDST64_ABS_LO12_NC "R_AARCH64_P32_LDST64_ABS_LO12_NC"
  , instructionReloc R_AARCH64_P32_LDST128_ABS_LO12_NC "R_AARCH64_P32_LDST128_ABS_LO12_NC"
  , instructionReloc R_AARCH64_P32_TSTBR14 "R_AARCH64_P32_TSTBR14"
  , instructionReloc R_AARCH64_P32_CONDBR19 "R_AARCH64_P32_CONDBR19"
  , instructionReloc R_AARCH64_P32_JUMP26 "R_AARCH64_P32_JUMP26"
  , instructionReloc R_AARCH64_P32_CALL26 "R_AARCH64_P32_CALL26"
  , instructionReloc R_AARCH64_P32_MOVW_PREL_G0 "R_AARCH64_P32_MOVW_PREL_G0"
  , instructionReloc R_AARCH64_P32_MOVW_PREL_G0_NC "R_AARCH64_P32_MOVW_PREL_G0_NC"
  , instructionReloc R_AARCH64_P32_MOVW_PREL_G1 "R_AARCH64_P32_MOVW_PREL_G1"
  , instructionReloc R_AARCH64_P32_GOT_LD_PREL19 "R_AARCH64_P32_GOT_LD_PREL19"
  , instructionReloc R_AARCH64_P32_ADR_GOT_PAGE "R_AARCH64_P32_ADR_GOT_PAGE"
  , instructionReloc R_AARCH64_P32_LD32_GOT_LO12_NC "R_AARCH64_P32_LD32_GOT_LO12_NC"
  , instructionReloc R_AARCH64_P32_LD32_GOTPAGE_LO14 "R_AARCH64_P32_LD32_GOTPAGE_LO14"
  , dataReloc R_AARCH64_P32_PLT32 "R_AARCH64_P32_PLT32" word32
  , instructionReloc R_AARCH64_P32_TLSGD_ADR_PREL21 "R_AARCH64_P32_TLSGD_ADR_PREL21"
  , instructionReloc R_AARCH64_P32_TLSGD_ADR_PAGE21 "R_AARCH64_P32_TLSGD_ADR_PAGE21"
  , instructionReloc R_AARCH64_P32_TLSGD_ADD_LO12_NC "R_AARCH64_P32_TLSGD_ADD_LO12_NC"
  , instructionReloc R_AARCH64_P32_TLSLD_ADR_PREL21 "R_AARCH64_P32_TLSLD_ADR_PREL21"
  , instructionReloc R_AARCH64_P32_TLSLD_ADR_PAGE21 "R_AARCH64_P32_TLSLD_ADR_PAGE21"
  , instructionReloc R_AARCH64_P32_TLSLD_ADD_LO12_NC "R_AARCH64_P32_TLSLD_ADD_LO12_NC"
  , instructionReloc R_AARCH64_P32_TLSLD_LD_PREL19 "R_AARCH64_P32_TLSLD_LD_PREL19"
  , instructionReloc R_AARCH64_P32_TLSLD_MOVW_DTPREL_G1 "R_AARCH64_P32_TLSLD_MOVW_DTPREL_G1"
  , instructionReloc R_AARCH64_P32_TLSLD_MOVW_DTPREL_G0 "R_AARCH64_P32_TLSLD_MOVW_DTPREL_G0"
  , instructionReloc R_AARCH64_P32_TLSLD_MOVW_DTPREL_G0_NC "R_AARCH64_P32_TLSLD_MOVW_DTPREL_G0_NC"
  , instructionReloc R_AARCH64_P32_TLSLD_ADD_DTPREL_HI12 "R_AARCH64_P32_TLSLD_ADD_DTPREL_HI12"
  , instructionReloc R_AARCH64_P32_TLSLD_ADD_DTPREL_LO12 "R_AARCH64_P32_TLSLD_ADD_DTPREL_LO12"
  , instructionReloc R_AARCH64_P32_TLSLD_ADD_DTPREL_LO12_NC "R_AARCH64_P32_TLSLD_ADD_DTPREL_LO12_NC"
  , instructionReloc R_AARCH64_P32_TLSLD_LDST8_DTPREL_LO12 "R_AARCH64_P32_TLSLD_LDST8_DTPREL_LO12"
  , instructionReloc R_AARCH64_P32_TLSLD_LDST8_DTPREL_LO12_NC "R_AARCH64_P32_TLSLD_LDST8_DTPREL_LO12_NC"
  , instructionReloc R_AARCH64_P32_TLSLD_LDST16_DTPREL_LO12 "R_AARCH64_P32_TLSLD_LDST16_DTPREL_LO12"
  , instructionReloc R_AARCH64_P32_TLSLD_LDST16_DTPREL_LO12_NC "R_AARCH64_P32_TLSLD_LDST16_DTPREL_LO12_NC"
  , instructionReloc R_AARCH64_P32_TLSLD_LDST32_DTPREL_LO12 "R_AARCH64_P32_TLSLD_LDST32_DTPREL_LO12"
  , instructionReloc R_AARCH64_P32_TLSLD_LDST32_DTPREL_LO12_NC "R_AARCH64_P32_TLSLD_LDST32_DTPREL_LO12_NC"
  , instructionReloc R_AARCH64_P32_TLSLD_LDST64_DTPREL_LO12 "R_AARCH64_P32_TLSLD_LDST64_DTPREL_LO12"
  , instructionReloc R_AARCH64_P32_TLSLD_LDST64_DTPREL_LO12_NC "R_AARCH64_P32_TLSLD_LDST64_DTPREL_LO12_NC"
  , instructionReloc R_AARCH64_P32_TLSLD_LDST128_DTPREL_LO12 "R_AARCH64_P32_TLSLD_LDST128_DTPREL_LO12"
  , instructionReloc R_AARCH64_P32_TLSLD_LDST128_DTPREL_LO12_NC "R_AARCH64_P32_TLSLD_LDST128_DTPREL_LO12_NC"
  , instructionReloc R_AARCH64_P32_TLSIE_ADR_GOTTPREL_PAGE21 "R_AARCH64_P32_TLSIE_ADR_GOTTPREL_PAGE21"
  , instructionReloc R_AARCH64_P32_TLSIE_LD32_GOTTPREL_LO12_NC "R_AARCH64_P32_TLSIE_LD32_GOTTPREL_LO12_NC"
  , instructionReloc R_AARCH64_P32_TLSIE_LD_GOTTPREL_PREL19 "R_AARCH64_P32_TLSIE_LD_GOTTPREL_PREL19"
  , instructionReloc R_AARCH64_P32_TLSLE_MOVW_TPREL_G1 "R_AARCH64_P32_TLSLE_MOVW_TPREL_G1"
  , instructionReloc R_AARCH64_P32_TLSLE_MOVW_TPREL_G0 "R_AARCH64_P32_TLSLE_MOVW_TPREL_G0"
  , instructionReloc R_AARCH64_P32_TLSLE_MOVW_TPREL_G0_NC "R_AARCH64_P32_TLSLE_MOVW_TPREL_G0_NC"
  , instructionReloc R_AARCH64_P32_TLSLE_ADD_TPREL_HI12 "R_AARCH64_P32_TLSLE_ADD_TPREL_HI12"
  , instructionReloc R_AARCH64_P32_TLSLE_ADD_TPREL_LO12 "R_AARCH64_P32_TLSLE_ADD_TPREL_LO12"
  , instructionReloc R_AARCH64_P32_TLSLE_ADD_TPREL_LO12_NC "R_AARCH64_P32_TLSLE_ADD_TPREL_LO12_NC"
  , instructionReloc R_AARCH64_P32_TLSLE_LDST8_TPREL_LO12 "R_AARCH64_P32_TLSLE_LDST8_TPREL_LO12"
  , instructionReloc R_AARCH64_P32_TLSLE_LDST8_TPREL_LO12_NC "R_AARCH64_P32_TLSLE_LDST8_TPREL_LO12_NC"
  , instructionReloc R_AARCH64_P32_TLSLE_LDST16_TPREL_LO12 "R_AARCH64_P32_TLSLE_LDST16_TPREL_LO12"
  , instructionReloc R_AARCH64_P32_TLSLE_LDST16_TPREL_LO12_NC "R_AARCH64_P32_TLSLE_LDST16_TPREL_LO12_NC"
  , instructionReloc R_AARCH64_P32_TLSLE_LDST32_TPREL_LO12 "R_AARCH64_P32_TLSLE_LDST32_TPREL_LO12"
  , instructionReloc R_AARCH64_P32_TLSLE_LDST32_TPREL_LO12_NC "R_AARCH64_P32_TLSLE_LDST32_TPREL_LO12_NC"
  , instructionReloc R_AARCH64_P32_TLSLE_LDST64_TPREL_LO12 "R_AARCH64_P32_TLSLE_LDST64_TPREL_LO12"
  , instructionReloc R_AARCH64_P32_TLSLE_LDST64_TPREL_LO12_NC "R_AARCH64_P32_TLSLE_LDST64_TPREL_LO12_NC"
  , instructionReloc R_AARCH64_P32_TLSLE_LDST128_TPREL_LO12 "R_AARCH64_P32_TLSLE_LDST128_TPREL_LO12"
  , instructionReloc R_AARCH64_P32_TLSLE_LDST128_TPREL_LO12_NC "R_AARCH64_P32_TLSLE_LDST128_TPREL_LO12_NC"
  , instructionReloc R_AARCH64_P32_TLSDESC_LD_PREL19 "R_AARCH64_P32_TLSDESC_LD_PREL19"
  , instructionReloc R_AARCH64_P32_TLSDESC_ADR_PREL21 "R_AARCH64_P32_TLSDESC_ADR_PREL21"
  , instructionReloc R_AARCH64_P32_TLSDESC_ADR_PAGE21 "R_AARCH64_P32_TLSDESC_ADR_PAGE21"
  , instructionReloc R_AARCH64_P32_TLSDESC_LD32_LO12 "R_AARCH64_P32_TLSDESC_LD32_LO12"
  , instructionReloc R_AARCH64_P32_TLSDESC_ADD_LO12 "R_AARCH64_P32_TLSDESC_ADD_LO12"
  , instructionReloc R_AARCH64_P32_TLSDESC_CALL "R_AARCH64_P32_TLSDESC_CALL"
  , dataReloc R_AARCH64_P32_COPY "R_AARCH64_P32_COPY" none
  , dataReloc R_AARCH64_P32_GLOB_DAT "R_AARCH64_P32_GLOB_DAT" word32
  , dataReloc R_AARCH64_P32_JUMP_SLOT "R_AARCH64_P32_JUMP_SLOT" word32
  , dataReloc R_AARCH64_P32_RELATIVE "R_AARCH64_P32_RELATIVE" word32
  , dataReloc R_AARCH64_P32_TLS_IMPDEF1 "R_AARCH64_P32_TLS_IMPDEF1" word32
  , dataReloc R_AARCH64_P32_TLS_IMPDEF2 "R_AARCH64_P32_TLS_IMPDEF2" word32
  , dataReloc R_AARCH64_P32_TLS_TPREL "R_AARCH64_P32_TLS_TPREL" word32
  , dataReloc R_AARCH64_P32_TLSDESC "R_AARCH64_P32_TLSDESC" word32
  , dataReloc R_AARCH64_P32_IRELATIVE "R_AARCH64_P32_IRELATIVE" word32
  , dataReloc R_AARCH64_ABS64 "R_AARCH64_ABS64" word64
  , dataReloc R_AARCH64_ABS32 "R_AARCH64_ABS32" word32
  , dataReloc R_AARCH64_ABS16 "R_AARCH64_ABS16" word16
  , dataReloc R_AARCH64_PREL64 "R_AARCH64_PREL64" word64
  , dataReloc R_AARCH64_PREL32 "R_AARCH64_PREL32" word32
  , dataReloc R_AARCH64_PREL16 "R_AARCH64_PREL16" word16
  , instructionReloc R_AARCH64_MOVW_UABS_G0 "R_AARCH64_MOVW_UABS_G0"
  , instructionReloc R_AARCH64_MOVW_UABS_G0_NC "R_AARCH64_MOVW_UABS_G0_NC"
  , instructionReloc R_AARCH64_MOVW_UABS_G1 "R_AARCH64_MOVW_UABS_G1"
  , instructionReloc R_AARCH64_MOVW_UABS_G1_NC "R_AARCH64_MOVW_UABS_G1_NC"
  , instructionReloc R_AARCH64_MOVW_UABS_G2 "R_AARCH64_MOVW_UABS_G2"
  , instructionReloc R_AARCH64_MOVW_UABS_G2_NC "R_AARCH64_MOVW_UABS_G2_NC"
  , instructionReloc R_AARCH64_MOVW_UABS_G3 "R_AARCH64_MOVW_UABS_G3"
  , instructionReloc R_AARCH64_MOVW_SABS_G0 "R_AARCH64_MOVW_SABS_G0"
  , instructionReloc R_AARCH64_MOVW_SABS_G1 "R_AARCH64_MOVW_SABS_G1"
  , instructionReloc R_AARCH64_MOVW_SABS_G2 "R_AARCH64_MOVW_SABS_G2"
  , instructionReloc R_AARCH64_LD_PREL_LO19 "R_AARCH64_LD_PREL_LO19"
  , instructionReloc R_AARCH64_ADR_PREL_LO21 "R_AARCH64_ADR_PREL_LO21"
  , instructionReloc R_AARCH64_ADR_PREL_PG_HI21 "R_AARCH64_ADR_PREL_PG_HI21"
  , instructionReloc R_AARCH64_ADR_PREL_PG_HI21_NC "R_AARCH64_ADR_PREL_PG_HI21_NC"
  , instructionReloc R_AARCH64_ADD_ABS_LO12_NC "R_AARCH64_ADD_ABS_LO12_NC"
  , instructionReloc R_AARCH64_LDST8_ABS_LO12_NC "R_AARCH64_LDST8_ABS_LO12_NC"
  , instructionReloc R_AARCH64_TSTBR14 "R_AARCH64_TSTBR14"
  , instructionReloc R_AARCH64_CONDBR19 "R_AARCH64_CONDBR19"
  , instructionReloc R_AARCH64_JUMP26 "R_AARCH64_JUMP26"
  , instructionReloc R_AARCH64_CALL26 "R_AARCH64_CALL26"
  , instructionReloc R_AARCH64_LDST16_ABS_LO12_NC "R_AARCH64_LDST16_ABS_LO12_NC"
  , instructionReloc R_AARCH64_LDST32_ABS_LO12_NC "R_AARCH64_LDST32_ABS_LO12_NC"
  , instructionReloc R_AARCH64_LDST64_ABS_LO12_NC "R_AARCH64_LDST64_ABS_LO12_NC"
  , instructionReloc R_AARCH64_MOVW_PREL_G0 "R_AARCH64_MOVW_PREL_G0"
  , instructionReloc R_AARCH64_MOVW_PREL_G0_NC "R_AARCH64_MOVW_PREL_G0_NC"
  , instructionReloc R_AARCH64_MOVW_PREL_G1 "R_AARCH64_MOVW_PREL_G1"
  , instructionReloc R_AARCH64_MOVW_PREL_G1_NC "R_AARCH64_MOVW_PREL_G1_NC"
  , instructionReloc R_AARCH64_MOVW_PREL_G2 "R_AARCH64_MOVW_PREL_G2"
  , instructionReloc R_AARCH64_MOVW_PREL_G2_NC "R_AARCH64_MOVW_PREL_G2_NC"
  , instructionReloc R_AARCH64_MOVW_PREL_G3 "R_AARCH64_MOVW_PREL_G3"
  , instructionReloc R_AARCH64_LDST128_ABS_LO12_NC "R_AARCH64_LDST128_ABS_LO12_NC"
  , instructionReloc R_AARCH64_MOVW_GOTOFF_G0 "R_AARCH64_MOVW_GOTOFF_G0"
  , instructionReloc R_AARCH64_MOVW_GOTOFF_G0_NC "R_AARCH64_MOVW_GOTOFF_G0_NC"
  , instructionReloc R_AARCH64_MOVW_GOTOFF_G1 "R_AARCH64_MOVW_GOTOFF_G1"
  , instructionReloc R_AARCH64_MOVW_GOTOFF_G1_NC "R_AARCH64_MOVW_GOTOFF_G1_NC"
  , instructionReloc R_AARCH64_MOVW_GOTOFF_G2 "R_AARCH64_MOVW_GOTOFF_G2"
  , instructionReloc R_AARCH64_MOVW_GOTOFF_G2_NC "R_AARCH64_MOVW_GOTOFF_G2_NC"
  , instructionReloc R_AARCH64_MOVW_GOTOFF_G3 "R_AARCH64_MOVW_GOTOFF_G3"
  , dataReloc R_AARCH64_GOTREL64 "R_AARCH64_GOTREL64" word64
  , dataReloc R_AARCH64_GOTREL32 "R_AARCH64_GOTREL32" word32
  , instructionReloc R_AARCH64_GOT_LD_PREL19 "R_AARCH64_GOT_LD_PREL19"
  , instructionReloc R_AARCH64_LD64_GOTOFF_LO15 "R_AARCH64_LD64_GOTOFF_LO15"
  , instructionReloc R_AARCH64_ADR_GOT_PAGE "R_AARCH64_ADR_GOT_PAGE"
  , instructionReloc R_AARCH64_LD64_GOT_LO12_NC "R_AARCH64_LD64_GOT_LO12_NC"
  , instructionReloc R_AARCH64_LD64_GOTPAGE_LO15 "R_AARCH64_LD64_GOTPAGE_LO15"
  , dataReloc R_AARCH64_PLT32 "R_AARCH64_PLT32" word32
  , dataReloc R_AARCH64_GOTPCREL32 "R_AARCH64_GOTPCREL32" word32
  , instructionReloc R_AARCH64_PATCHINST "R_AARCH64_PATCHINST"
  , dataReloc R_AARCH64_FUNCINIT64 "R_AARCH64_FUNCINIT64" word64
  , instructionReloc R_AARCH64_TLSGD_ADR_PREL21 "R_AARCH64_TLSGD_ADR_PREL21"
  , instructionReloc R_AARCH64_TLSGD_ADR_PAGE21 "R_AARCH64_TLSGD_ADR_PAGE21"
  , instructionReloc R_AARCH64_TLSGD_ADD_LO12_NC "R_AARCH64_TLSGD_ADD_LO12_NC"
  , instructionReloc R_AARCH64_TLSGD_MOVW_G1 "R_AARCH64_TLSGD_MOVW_G1"
  , instructionReloc R_AARCH64_TLSGD_MOVW_G0_NC "R_AARCH64_TLSGD_MOVW_G0_NC"
  , instructionReloc R_AARCH64_TLSLD_ADR_PREL21 "R_AARCH64_TLSLD_ADR_PREL21"
  , instructionReloc R_AARCH64_TLSLD_ADR_PAGE21 "R_AARCH64_TLSLD_ADR_PAGE21"
  , instructionReloc R_AARCH64_TLSLD_ADD_LO12_NC "R_AARCH64_TLSLD_ADD_LO12_NC"
  , instructionReloc R_AARCH64_TLSLD_MOVW_G1 "R_AARCH64_TLSLD_MOVW_G1"
  , instructionReloc R_AARCH64_TLSLD_MOVW_G0_NC "R_AARCH64_TLSLD_MOVW_G0_NC"
  , instructionReloc R_AARCH64_TLSLD_LD_PREL19 "R_AARCH64_TLSLD_LD_PREL19"
  , instructionReloc R_AARCH64_TLSLD_MOVW_DTPREL_G2 "R_AARCH64_TLSLD_MOVW_DTPREL_G2"
  , instructionReloc R_AARCH64_TLSLD_MOVW_DTPREL_G1 "R_AARCH64_TLSLD_MOVW_DTPREL_G1"
  , instructionReloc R_AARCH64_TLSLD_MOVW_DTPREL_G1_NC "R_AARCH64_TLSLD_MOVW_DTPREL_G1_NC"
  , instructionReloc R_AARCH64_TLSLD_MOVW_DTPREL_G0 "R_AARCH64_TLSLD_MOVW_DTPREL_G0"
  , instructionReloc R_AARCH64_TLSLD_MOVW_DTPREL_G0_NC "R_AARCH64_TLSLD_MOVW_DTPREL_G0_NC"
  , instructionReloc R_AARCH64_TLSLD_ADD_DTPREL_HI12 "R_AARCH64_TLSLD_ADD_DTPREL_HI12"
  , instructionReloc R_AARCH64_TLSLD_ADD_DTPREL_LO12 "R_AARCH64_TLSLD_ADD_DTPREL_LO12"
  , instructionReloc R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC "R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC"
  , instructionReloc R_AARCH64_TLSLD_LDST8_DTPREL_LO12 "R_AARCH64_TLSLD_LDST8_DTPREL_LO12"
  , instructionReloc R_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC "R_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC"
  , instructionReloc R_AARCH64_TLSLD_LDST16_DTPREL_LO12 "R_AARCH64_TLSLD_LDST16_DTPREL_LO12"
  , instructionReloc R_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC "R_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC"
  , instructionReloc R_AARCH64_TLSLD_LDST32_DTPREL_LO12 "R_AARCH64_TLSLD_LDST32_DTPREL_LO12"
  , instructionReloc R_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC "R_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC"
  , instructionReloc R_AARCH64_TLSLD_LDST64_DTPREL_LO12 "R_AARCH64_TLSLD_LDST64_DTPREL_LO12"
  , instructionReloc R_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC "R_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC"
  , instructionReloc R_AARCH64_TLSIE_MOVW_GOTTPREL_G1 "R_AARCH64_TLSIE_MOVW_GOTTPREL_G1"
  , instructionReloc R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC "R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC"
  , instructionReloc R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21 "R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21"
  , instructionReloc R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC "R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC"
  , instructionReloc R_AARCH64_TLSIE_LD_GOTTPREL_PREL19 "R_AARCH64_TLSIE_LD_GOTTPREL_PREL19"
  , instructionReloc R_AARCH64_TLSLE_MOVW_TPREL_G2 "R_AARCH64_TLSLE_MOVW_TPREL_G2"
  , instructionReloc R_AARCH64_TLSLE_MOVW_TPREL_G1 "R_AARCH64_TLSLE_MOVW_TPREL_G1"
  , instructionReloc R_AARCH64_TLSLE_MOVW_TPREL_G1_NC "R_AARCH64_TLSLE_MOVW_TPREL_G1_NC"
  , instructionReloc R_AARCH64_TLSLE_MOVW_TPREL_G0 "R_AARCH64_TLSLE_MOVW_TPREL_G0"
  , instructionReloc R_AARCH64_TLSLE_MOVW_TPREL_G0_NC "R_AARCH64_TLSLE_MOVW_TPREL_G0_NC"
  , instructionReloc R_AARCH64_TLSLE_ADD_TPREL_HI12 "R_AARCH64_TLSLE_ADD_TPREL_HI12"
  , instructionReloc R_AARCH64_TLSLE_ADD_TPREL_LO12 "R_AARCH64_TLSLE_ADD_TPREL_LO12"
  , instructionReloc R_AARCH64_TLSLE_ADD_TPREL_LO12_NC "R_AARCH64_TLSLE_ADD_TPREL_LO12_NC"
  , instructionReloc R_AARCH64_TLSLE_LDST8_TPREL_LO12 "R_AARCH64_TLSLE_LDST8_TPREL_LO12"
  , instructionReloc R_AARCH64_TLSLE_LDST8_TPREL_LO12_NC "R_AARCH64_TLSLE_LDST8_TPREL_LO12_NC"
  , instructionReloc R_AARCH64_TLSLE_LDST16_TPREL_LO12 "R_AARCH64_TLSLE_LDST16_TPREL_LO12"
  , instructionReloc R_AARCH64_TLSLE_LDST16_TPREL_LO12_NC "R_AARCH64_TLSLE_LDST16_TPREL_LO12_NC"
  , instructionReloc R_AARCH64_TLSLE_LDST32_TPREL_LO12 "R_AARCH64_TLSLE_LDST32_TPREL_LO12"
  , instructionReloc R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC "R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC"
  , instructionReloc R_AARCH64_TLSLE_LDST64_TPREL_LO12 "R_AARCH64_TLSLE_LDST64_TPREL_LO12"
  , instructionReloc R_AARCH64_TLSLE_LDST64_TPREL_LO12_NC "R_AARCH64_TLSLE_LDST64_TPREL_LO12_NC"
  , instructionReloc R_AARCH64_TLSDESC_LD_PREL19 "R_AARCH64_TLSDESC_LD_PREL19"
  , instructionReloc R_AARCH64_TLSDESC_ADR_PREL21 "R_AARCH64_TLSDESC_ADR_PREL21"
  , instructionReloc R_AARCH64_TLSDESC_ADR_PAGE21 "R_AARCH64_TLSDESC_ADR_PAGE21"
  , instructionReloc R_AARCH64_TLSDESC_LD64_LO12 "R_AARCH64_TLSDESC_LD64_LO12"
  , instructionReloc R_AARCH64_TLSDESC_ADD_LO12 "R_AARCH64_TLSDESC_ADD_LO12"
  , instructionReloc R_AARCH64_TLSDESC_OFF_G1 "R_AARCH64_TLSDESC_OFF_G1"
  , instructionReloc R_AARCH64_TLSDESC_OFF_G0_NC "R_AARCH64_TLSDESC_OFF_G0_NC"
  , instructionReloc R_AARCH64_TLSDESC_LDR "R_AARCH64_TLSDESC_LDR"
  , instructionReloc R_AARCH64_TLSDESC_ADD "R_AARCH64_TLSDESC_ADD"
  , instructionReloc R_AARCH64_TLSDESC_CALL "R_AARCH64_TLSDESC_CALL"
  , instructionReloc R_AARCH64_TLSLE_LDST128_TPREL_LO12 "R_AARCH64_TLSLE_LDST128_TPREL_LO12"
  , instructionReloc R_AARCH64_TLSLE_LDST128_TPREL_LO12_NC "R_AARCH64_TLSLE_LDST128_TPREL_LO12_NC"
  , instructionReloc R_AARCH64_TLSLD_LDST128_DTPREL_LO12 "R_AARCH64_TLSLD_LDST128_DTPREL_LO12"
  , instructionReloc R_AARCH64_TLSLD_LDST128_DTPREL_LO12_NC "R_AARCH64_TLSLD_LDST128_DTPREL_LO12_NC"
  , instructionReloc R_AARCH64_AUTH_ABS64 "R_AARCH64_AUTH_ABS64"
  , instructionReloc R_AARCH64_AUTH_MOVW_GOTOFF_G0 "R_AARCH64_AUTH_MOVW_GOTOFF_G0"
  , instructionReloc R_AARCH64_AUTH_MOVW_GOTOFF_G0_NC "R_AARCH64_AUTH_MOVW_GOTOFF_G0_NC"
  , instructionReloc R_AARCH64_AUTH_MOVW_GOTOFF_G1 "R_AARCH64_AUTH_MOVW_GOTOFF_G1"
  , instructionReloc R_AARCH64_AUTH_MOVW_GOTOFF_G1_NC "R_AARCH64_AUTH_MOVW_GOTOFF_G1_NC"
  , instructionReloc R_AARCH64_AUTH_MOVW_GOTOFF_G2 "R_AARCH64_AUTH_MOVW_GOTOFF_G2"
  , instructionReloc R_AARCH64_AUTH_MOVW_GOTOFF_G2_NC "R_AARCH64_AUTH_MOVW_GOTOFF_G2_NC"
  , instructionReloc R_AARCH64_AUTH_MOVW_GOTOFF_G3 "R_AARCH64_AUTH_MOVW_GOTOFF_G3"
  , instructionReloc R_AARCH64_AUTH_GOT_LD_PREL19 "R_AARCH64_AUTH_GOT_LD_PREL19"
  , instructionReloc R_AARCH64_AUTH_LD64_GOTOFF_LO15 "R_AARCH64_AUTH_LD64_GOTOFF_LO15"
  , instructionReloc R_AARCH64_AUTH_ADR_GOT_PAGE "R_AARCH64_AUTH_ADR_GOT_PAGE"
  , instructionReloc R_AARCH64_AUTH_LD64_GOT_LO12_NC "R_AARCH64_AUTH_LD64_GOT_LO12_NC"
  , instructionReloc R_AARCH64_AUTH_LD64_GOTPAGE_LO15 "R_AARCH64_AUTH_LD64_GOTPAGE_LO15"
  , instructionReloc R_AARCH64_AUTH_GOT_ADD_LO12_NC "R_AARCH64_AUTH_GOT_ADD_LO12_NC"
  , instructionReloc R_AARCH64_AUTH_GOT_ADR_PREL_LO21 "R_AARCH64_AUTH_GOT_ADR_PREL_LO21"
  , instructionReloc R_AARCH64_AUTH_TLSDESC_ADR_PAGE21 "R_AARCH64_AUTH_TLSDESC_ADR_PAGE21"
  , instructionReloc R_AARCH64_AUTH_TLSDESC_LD64_LO12 "R_AARCH64_AUTH_TLSDESC_LD64_LO12"
  , instructionReloc R_AARCH64_AUTH_TLSDESC_ADD_LO12 "R_AARCH64_AUTH_TLSDESC_ADD_LO12"
  , instructionReloc R_AARCH64_AUTH_TLSDESC_CALL "R_AARCH64_AUTH_TLSDESC_CALL"
  , dataReloc R_AARCH64_COPY "R_AARCH64_COPY" none
  , dataReloc R_AARCH64_GLOB_DAT "R_AARCH64_GLOB_DAT" word64
  , dataReloc R_AARCH64_JUMP_SLOT "R_AARCH64_JUMP_SLOT" word64
  , dataReloc R_AARCH64_RELATIVE "R_AARCH64_RELATIVE" word64
  , dataReloc R_AARCH64_TLS_IMPDEF1 "R_AARCH64_TLS_IMPDEF1" word64
  , dataReloc R_AARCH64_TLS_IMPDEF2 "R_AARCH64_TLS_IMPDEF2" word64
  , dataReloc R_AARCH64_TLS_TPREL "R_AARCH64_TLS_TPREL" word64
  , dataReloc R_AARCH64_TLSDESC "R_AARCH64_TLSDESC" word64
  , dataReloc R_AARCH64_IRELATIVE "R_AARCH64_IRELATIVE" word64
  , dataReloc R_AARCH64_AUTH_RELATIVE "R_AARCH64_AUTH_RELATIVE" word64
  , dataReloc R_AARCH64_AUTH_GLOB_DAT "R_AARCH64_AUTH_GLOB_DAT" word64
  , dataReloc R_AARCH64_AUTH_TLSDESC "R_AARCH64_AUTH_TLSDESC" word64
  , dataReloc R_AARCH64_AUTH_IRELATIVE "R_AARCH64_AUTH_IRELATIVE" word64
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
