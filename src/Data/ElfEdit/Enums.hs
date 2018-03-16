{-
Module           : Data.ElfEdit.Enums
Copyright        : (c) Galois, Inc 2016
Maintainer       : Joe Hendrix <jhendrix@galois.com>

Defines a large collection of constants used in defining elf values.
-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE PatternSynonyms #-}
#if __GLASGOW_HASKELL__ >= 800
{-# OPTIONS_GHC -fno-warn-missing-pattern-synonym-signatures #-}
#endif
module Data.ElfEdit.Enums
  (  -- * ElfOSABI
    ElfOSABI(..)
  , pattern ELFOSABI_SYSV
  , pattern ELFOSABI_HPUX
  , pattern ELFOSABI_NETBSD
  , pattern ELFOSABI_LINUX
  , pattern ELFOSABI_SOLARIS
  , pattern ELFOSABI_AIX
  , pattern ELFOSABI_IRIS
  , pattern ELFOSABI_FREEBSD
  , pattern ELFOSABI_TRU64
  , pattern ELFOSABI_MODESTO
  , pattern ELFOSABI_OPENBSD
  , pattern ELFOSABI_OPENVMS
  , pattern ELFOSABI_NSK
  , pattern ELFOSABI_AROS
  , pattern ELFOSABI_ARM
  , pattern ELFOSABI_STANDALONE
    -- * ElfType
  , ElfType(..)
  , pattern ET_NONE
  , pattern ET_REL
  , pattern ET_EXEC
  , pattern ET_DYN
  , pattern ET_CORE
    -- * ElfMachine
  , ElfMachine(..)
  , pattern EM_NONE
  , pattern EM_M32
  , pattern EM_SPARC
  , pattern EM_386
  , pattern EM_68K
  , pattern EM_88K
  , pattern EM_486
  , pattern EM_860
  , pattern EM_MIPS
  , pattern EM_S370
  , pattern EM_MIPS_RS3_LE
  , pattern EM_SPARC64
  , pattern EM_PARISC
  , pattern EM_VPP500
  , pattern EM_SPARC32PLUS
  , pattern EM_960
  , pattern EM_PPC
  , pattern EM_PPC64
  , pattern EM_S390
  , pattern EM_SPU
  , pattern EM_V800
  , pattern EM_FR20
  , pattern EM_RH32
  , pattern EM_RCE
  , pattern EM_ARM
  , pattern EM_ALPHA
  , pattern EM_SH
  , pattern EM_SPARCV9
  , pattern EM_TRICORE
  , pattern EM_ARC
  , pattern EM_H8_300
  , pattern EM_H8_300H
  , pattern EM_H8S
  , pattern EM_H8_500
  , pattern EM_IA_64
  , pattern EM_MIPS_X
  , pattern EM_COLDFIRE
  , pattern EM_68HC12
  , pattern EM_MMA
  , pattern EM_PCP
  , pattern EM_NCPU
  , pattern EM_NDR1
  , pattern EM_STARCORE
  , pattern EM_ME16
  , pattern EM_ST100
  , pattern EM_TINYJ
  , pattern EM_X86_64
  , pattern EM_PDSP
  , pattern EM_FX66
  , pattern EM_ST9PLUS
  , pattern EM_ST7
  , pattern EM_68HC16
  , pattern EM_68HC11
  , pattern EM_68HC08
  , pattern EM_68HC05
  , pattern EM_SVX
  , pattern EM_ST19
  , pattern EM_VAX
  , pattern EM_CRIS
  , pattern EM_JAVELIN
  , pattern EM_FIREPATH
  , pattern EM_ZSP
  , pattern EM_MMIX
  , pattern EM_HUANY
  , pattern EM_PRISM
  , pattern EM_AVR
  , pattern EM_FR30
  , pattern EM_D10V
  , pattern EM_D30V
  , pattern EM_V850
  , pattern EM_M32R
  , pattern EM_MN10300
  , pattern EM_MN10200
  , pattern EM_PJ
  , pattern EM_OPENRISC
  , pattern EM_ARC_A5
  , pattern EM_XTENSA
  , pattern EM_VIDEOCORE
  , pattern EM_TMM_GPP
  , pattern EM_NS32K
  , pattern EM_TPC
  , pattern EM_SNP1K
  , pattern EM_ST200
  , pattern EM_IP2K
  , pattern EM_MAX
  , pattern EM_CR
  , pattern EM_F2MC16
  , pattern EM_MSP430
  , pattern EM_BLACKFIN
  , pattern EM_SE_C33
  , pattern EM_SEP
  , pattern EM_ARCA
  , pattern EM_UNICORE
  , pattern EM_TI_C6000
  , pattern EM_L1OM
  , pattern EM_K1OM
  , pattern EM_RISCV
    -- * ElfSectionIndex
  , ElfSectionIndex(..)
  , pattern SHN_UNDEF
  , pattern SHN_ABS
  , pattern SHN_COMMON
  , pattern SHN_LORESERVE
  , pattern SHN_LOPROC
  , pattern SHN_X86_64_LCOMMON
  , pattern SHN_IA_64_ANSI_COMMON
  , pattern SHN_MIPS_SCOMMON
  , pattern SHN_MIPS_SUNDEFINED
  , pattern SHN_TIC6X_SCOMMON
  , pattern SHN_HIPROC
  , pattern SHN_LOOS
  , pattern SHN_HIOS
  , ppElfSectionIndex
    -- * Elf symbol type
  , ElfSymbolType(..)
  , pattern STT_NOTYPE
  , pattern STT_OBJECT
  , pattern STT_FUNC
  , pattern STT_SECTION
  , pattern STT_FILE
  , pattern STT_COMMON
  , pattern STT_TLS
  , pattern STT_RELC
  , pattern STT_SRELC
  , pattern STT_GNU_IFUNC
    -- * Elf symbol binding
  , ElfSymbolBinding(..)
  , pattern STB_LOCAL
  , pattern STB_GLOBAL
  , pattern STB_WEAK
  , pattern STB_NUM
  , pattern STB_LOOS
  , pattern STB_HIOS
  , pattern STB_GNU_UNIQUE
  , pattern STB_LOPROC
  , pattern STB_HIPROC
  ) where

import qualified Data.Map.Strict as Map
import           Data.Word
import           Numeric (showHex)

------------------------------------------------------------------------
-- ElfOSABI

-- | A flag identifying the OS or ABI specific Elf extensions used.
newtype ElfOSABI = ElfOSABI { fromElfOSABI :: Word8 }
  deriving (Eq, Ord)

-- | No extensions or unspecified
pattern ELFOSABI_SYSV = ElfOSABI 0

-- | Hewlett-Packard HP-UX
pattern ELFOSABI_HPUX = ElfOSABI 1

-- | NetBSD
pattern ELFOSABI_NETBSD = ElfOSABI 2

-- | Linux
pattern ELFOSABI_LINUX = ElfOSABI 3

-- | Sun Solaris
pattern ELFOSABI_SOLARIS = ElfOSABI 6

-- | AIX
pattern ELFOSABI_AIX = ElfOSABI 7

-- | IRIX
pattern ELFOSABI_IRIS = ElfOSABI 8

-- | FreeBSD
pattern ELFOSABI_FREEBSD = ElfOSABI 9

-- | Compat TRU64 Unix
pattern ELFOSABI_TRU64 = ElfOSABI 10

-- | Novell Modesto
pattern ELFOSABI_MODESTO = ElfOSABI 11

-- | Open BSD
pattern ELFOSABI_OPENBSD = ElfOSABI 12

-- | Open VMS
pattern ELFOSABI_OPENVMS = ElfOSABI 13

-- | Hewlett-Packard Non-Stop Kernel
pattern ELFOSABI_NSK = ElfOSABI 14

-- | Amiga Research OS
pattern ELFOSABI_AROS = ElfOSABI 15

-- | ARM
pattern ELFOSABI_ARM = ElfOSABI 97

-- | Standalone (embedded) application
pattern ELFOSABI_STANDALONE = ElfOSABI 255

osabiNames :: Map.Map ElfOSABI String
osabiNames = Map.fromList
  [ (,) ELFOSABI_SYSV "SYSV"
  , (,) ELFOSABI_HPUX "HPUX"
  , (,) ELFOSABI_NETBSD "NETBSD"
  , (,) ELFOSABI_LINUX "LINUX"
  , (,) ELFOSABI_SOLARIS "SOLARIS"
  , (,) ELFOSABI_AIX "AIX"
  , (,) ELFOSABI_IRIS "IRIS"
  , (,) ELFOSABI_FREEBSD "FREEBSD"
  , (,) ELFOSABI_TRU64 "TRU64"
  , (,) ELFOSABI_MODESTO "MODESTO"
  , (,) ELFOSABI_OPENBSD "OPENBSD"
  , (,) ELFOSABI_OPENVMS "OPENVMS"
  , (,) ELFOSABI_NSK "NSK"
  , (,) ELFOSABI_AROS "AROS"
  , (,) ELFOSABI_ARM "ARM"
  , (,) ELFOSABI_STANDALONE "STANDALONE"
  ]

-- This pretty prints the ABI in a user-friendly format.
instance Show ElfOSABI where
  show e =
    case Map.lookup e osabiNames of
      Nothing -> "unknown_" ++ show (fromElfOSABI e)
      Just nm -> nm

------------------------------------------------------------------------
-- ElfType

-- | The type of information stored in the Elf file.
newtype ElfType = ElfType { fromElfType :: Word16 }
  deriving (Eq, Ord)

-- | Unspecified elf type.
pattern ET_NONE = ElfType 0
-- | Relocatable object file such as assembler output
pattern ET_REL  = ElfType 1
-- | Executable
pattern ET_EXEC = ElfType 2
-- | Shared object
pattern ET_DYN  = ElfType 3
-- | Core dump
pattern ET_CORE = ElfType 4

instance Show ElfType where
  show ET_NONE = "ET_NONE"
  show ET_REL  = "ET_REL"
  show ET_EXEC = "ET_EXEC"
  show ET_DYN  = "ET_DYN"
  show ET_CORE = "ET_CORE"
  show (ElfType w) = "ElfType " ++ show w

------------------------------------------------------------------------
-- ElfMachine

newtype ElfMachine = ElfMachine { fromElfMachine :: Word16 }
  deriving (Eq, Ord)

pattern EM_NONE = ElfMachine 0
-- ^ No machine

pattern EM_M32 = ElfMachine 1
-- ^ AT&T WE 32100

pattern EM_SPARC = ElfMachine 2
-- ^ SPARC
pattern EM_386 = ElfMachine 3
-- ^ Intel 80386
pattern EM_68K = ElfMachine 4
-- ^ Motorola 68000
pattern EM_88K = ElfMachine 5
-- ^ Motorola 88000
pattern EM_486 = ElfMachine 6
-- ^ Intel i486 (DO NOT USE THIS ONE)
pattern EM_860 = ElfMachine 7
-- ^ Intel 80860
pattern EM_MIPS = ElfMachine 8
-- ^ MIPS I Architecture
pattern EM_S370 = ElfMachine 9
-- ^ IBM System/370 Processor
pattern EM_MIPS_RS3_LE = ElfMachine 10
-- ^ MIPS RS3000 Little-endian
pattern EM_SPARC64 = ElfMachine 11
-- ^ SPARC 64-bit
pattern EM_PARISC = ElfMachine 15
-- ^ Hewlett-Packard PA-RISC
pattern EM_VPP500 = ElfMachine 17
-- ^ Fujitsu VPP500
pattern EM_SPARC32PLUS = ElfMachine 18
-- ^ Enhanced instruction set SPARC
pattern EM_960 = ElfMachine 19
-- ^ Intel 80960
pattern EM_PPC = ElfMachine 20
-- ^ PowerPC
pattern EM_PPC64 = ElfMachine 21
-- ^ 64-bit PowerPC
pattern EM_S390  = ElfMachine 22
-- ^ IBM System/390 Processor
pattern EM_SPU   = ElfMachine 23
-- ^ Cell SPU
pattern EM_V800  = ElfMachine 36
-- ^ NEC V800
pattern EM_FR20  = ElfMachine 37
-- ^ Fujitsu FR20
pattern EM_RH32  = ElfMachine 38
-- ^ TRW RH-32
pattern EM_RCE   = ElfMachine 39
-- ^ Motorola RCE
pattern EM_ARM   = ElfMachine 40
-- ^ Advanced RISC Machines ARM
pattern EM_ALPHA = ElfMachine 41
-- ^ Digital Alpha
pattern EM_SH    = ElfMachine 42
-- ^ Hitachi SH
pattern EM_SPARCV9  = ElfMachine 43
-- ^ SPARC Version 9
pattern EM_TRICORE  = ElfMachine 44
-- ^ Siemens TriCore embedded processor
pattern EM_ARC      = ElfMachine 45
-- ^ Argonaut RISC Core, Argonaut Technologies Inc.
pattern EM_H8_300   = ElfMachine 46
-- ^ Hitachi H8/300
pattern EM_H8_300H  = ElfMachine 47
-- ^ Hitachi H8/300H
pattern EM_H8S      = ElfMachine 48
-- ^ Hitachi H8S
pattern EM_H8_500   = ElfMachine 49
-- ^ Hitachi H8/500
pattern EM_IA_64    = ElfMachine 50
-- ^ Intel IA-64 processor architecture
pattern EM_MIPS_X   = ElfMachine 51
-- ^ Stanford MIPS-X
pattern EM_COLDFIRE = ElfMachine 52
-- ^ Motorola ColdFire
pattern EM_68HC12   = ElfMachine 53
-- ^ Motorola M68HC12
pattern EM_MMA      = ElfMachine 54
-- ^ Fujitsu MMA Multimedia Accelerator
pattern EM_PCP      = ElfMachine 55
-- ^ Siemens PCP
pattern EM_NCPU     = ElfMachine 56
-- ^ Sony nCPU embedded RISC processor
pattern EM_NDR1     = ElfMachine 57
-- ^ Denso NDR1 microprocessor
pattern EM_STARCORE = ElfMachine 58
-- ^ Motorola Star*Core processor
pattern EM_ME16     = ElfMachine 59
-- ^ Toyota ME16 processor
pattern EM_ST100    = ElfMachine 60
-- ^ STMicroelectronics ST100 processor
pattern EM_TINYJ    = ElfMachine 61
-- ^ Advanced Logic Corp. TinyJ embedded processor family
pattern EM_X86_64   = ElfMachine 62
-- ^ AMD x86-64 architecture
pattern EM_PDSP     = ElfMachine 63
-- ^ Sony DSP Processor
pattern EM_FX66     = ElfMachine 66
-- ^ Siemens FX66 microcontroller
pattern EM_ST9PLUS  = ElfMachine 67
-- ^ STMicroelectronics ST9+ 8/16 bit microcontroller
pattern EM_ST7      = ElfMachine 68
-- ^ STMicroelectronics ST7 8-bit microcontroller
pattern EM_68HC16   = ElfMachine 69
-- ^ Motorola MC68HC16 Microcontroller
pattern EM_68HC11      = ElfMachine 70
-- ^ Motorola MC68HC11 Microcontroller
pattern EM_68HC08      = ElfMachine 71
-- ^ Motorola MC68HC08 Microcontroller
pattern EM_68HC05      = ElfMachine 72
-- ^ Motorola MC68HC05 Microcontroller
pattern EM_SVX         = ElfMachine 73
-- ^ Silicon Graphics SVx
pattern EM_ST19        = ElfMachine 74
-- ^ STMicroelectronics ST19 8-bit microcontroller
pattern EM_VAX         = ElfMachine 75
-- ^ Digital VAX
pattern EM_CRIS        = ElfMachine 76
-- ^ Axis Communications 32-bit embedded processor
pattern EM_JAVELIN     = ElfMachine 77
-- ^ Infineon Technologies 32-bit embedded processor
pattern EM_FIREPATH    = ElfMachine 78
-- ^ Element 14 64-bit DSP Processor
pattern EM_ZSP         = ElfMachine 79
-- ^ LSI Logic 16-bit DSP Processor
pattern EM_MMIX        = ElfMachine 80
-- ^ Donald Knuth's educational 64-bit processor
pattern EM_HUANY       = ElfMachine 81
-- ^ Harvard University machine-independent object files
pattern EM_PRISM       = ElfMachine 82
-- ^ SiTera Prism
pattern EM_AVR         = ElfMachine 83
-- ^ Atmel AVR 8-bit microcontroller
pattern EM_FR30        = ElfMachine 84
-- ^ Fujitsu FR30
pattern EM_D10V        = ElfMachine 85
-- ^ Mitsubishi D10V
pattern EM_D30V        = ElfMachine 86
-- ^ Mitsubishi D30V
pattern EM_V850        = ElfMachine 87
-- ^ NEC v850
pattern EM_M32R        = ElfMachine 88
-- ^ Mitsubishi M32R
pattern EM_MN10300     = ElfMachine 89
-- ^ Matsushita MN10300
pattern EM_MN10200     = ElfMachine 90
-- ^ Matsushita MN10200
pattern EM_PJ          = ElfMachine 91
-- ^ picoJava
pattern EM_OPENRISC    = ElfMachine 92
-- ^ OpenRISC 32-bit embedded processor
pattern EM_ARC_A5      = ElfMachine 93
-- ^ ARC Cores Tangent-A5
pattern EM_XTENSA      = ElfMachine 94
-- ^ Tensilica Xtensa Architecture
pattern EM_VIDEOCORE   = ElfMachine 95
-- ^ Alphamosaic VideoCore processor
pattern EM_TMM_GPP     = ElfMachine 96
-- ^ Thompson Multimedia General Purpose Processor
pattern EM_NS32K       = ElfMachine 97
-- ^ National Semiconductor 32000 series
pattern EM_TPC         = ElfMachine 98
-- ^ Tenor Network TPC processor
pattern EM_SNP1K       = ElfMachine 99
-- ^ Trebia SNP 1000 processor
pattern EM_ST200       = ElfMachine 100
-- ^ STMicroelectronics (www.st.com) ST200 microcontroller
pattern EM_IP2K        = ElfMachine 101
-- ^ Ubicom IP2xxx microcontroller family
pattern EM_MAX         = ElfMachine 102
-- ^ MAX Processor
pattern EM_CR          = ElfMachine 103
-- ^ National Semiconductor CompactRISC microprocessor
pattern EM_F2MC16      = ElfMachine 104
-- ^ Fujitsu F2MC16
pattern EM_MSP430      = ElfMachine 105
-- ^ Texas Instruments embedded microcontroller msp430
pattern EM_BLACKFIN    = ElfMachine 106
-- ^ Analog Devices Blackfin (DSP) processor
pattern EM_SE_C33      = ElfMachine 107
-- ^ S1C33 Family of Seiko Epson processors
pattern EM_SEP         = ElfMachine 108
-- ^ Sharp embedded microprocessor
pattern EM_ARCA        = ElfMachine 109
-- ^ Arca RISC Microprocessor
pattern EM_UNICORE     = ElfMachine 110
-- ^ Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University
pattern EM_TI_C6000    = ElfMachine 140
-- ^ Texas Instruments TMS320C6000 DSP family
pattern EM_L1OM        = ElfMachine 180
-- ^ Intel L10M
pattern EM_K1OM        = ElfMachine 181
-- ^ Intel K10M
pattern EM_RISCV       = ElfMachine 243
-- ^ RISC-V

instance Show ElfMachine where
  show m =
    case Map.lookup m elfMachineNameMap of
      Just nm -> nm
      Nothing -> "ElfMachine " ++ show (fromElfMachine m)

elfMachineNameMap :: Map.Map ElfMachine String
elfMachineNameMap = Map.fromList
  [ (,) EM_NONE "EM_NONE"
  , (,) EM_M32  "EM_M32"
  , (,) EM_SPARC "EM_SPARC"
  , (,) EM_386 "EM_386"
  , (,) EM_68K "EM_68K"
  , (,) EM_88K "EM_88K"
  , (,) EM_486 "EM_486"
  , (,) EM_860 "EM_860"
  , (,) EM_MIPS "EM_MIPS"
  , (,) EM_S370 "EM_S370"
  , (,) EM_MIPS_RS3_LE "EM_MIPS_RS3_LE"
  , (,) EM_SPARC64 "EM_SPARC64"
  , (,) EM_PARISC "EM_PARISC"
  , (,) EM_VPP500 "EM_VPP500"
  , (,) EM_SPARC32PLUS "EM_SPARC32PLUS"
  , (,) EM_960 "EM_960"
  , (,) EM_PPC "EM_PPC"
  , (,) EM_PPC64 "EM_PPC64"
  , (,) EM_S390 "EM_S390"
  , (,) EM_SPU "EM_SPU"
  , (,) EM_V800 "EM_V800"
  , (,) EM_FR20 "EM_FR20"
  , (,) EM_RH32 "EM_RH32"
  , (,) EM_RCE "EM_RCE"
  , (,) EM_ARM "EM_ARM"
  , (,) EM_ALPHA "EM_ALPHA"
  , (,) EM_SH "EM_SH"
  , (,) EM_SPARCV9 "EM_SPARCV9"
  , (,) EM_TRICORE "EM_TRICORE"
  , (,) EM_ARC "EM_ARC"
  , (,) EM_H8_300 "EM_H8_300"
  , (,) EM_H8_300H "EM_H8_300H"
  , (,) EM_H8S "EM_H8S"
  , (,) EM_H8_500 "EM_H8_500"
  , (,) EM_IA_64 "EM_IA_64"
  , (,) EM_MIPS_X "EM_MIPS_X"
  , (,) EM_COLDFIRE "EM_COLDFIRE"
  , (,) EM_68HC12 "EM_68HC12"
  , (,) EM_MMA "EM_MMA"
  , (,) EM_PCP "EM_PCP"
  , (,) EM_NCPU "EM_NCPU"
  , (,) EM_NDR1 "EM_NDR1"
  , (,) EM_STARCORE "EM_STARCORE"
  , (,) EM_ME16 "EM_ME16"
  , (,) EM_ST100 "EM_ST100"
  , (,) EM_TINYJ "EM_TINYJ"
  , (,) EM_X86_64 "EM_X86_64"
  , (,) EM_PDSP "EM_PDSP"
  , (,) EM_FX66 "EM_FX66"
  , (,) EM_ST9PLUS "EM_ST9PLUS"
  , (,) EM_ST7 "EM_ST7"
  , (,) EM_68HC16 "EM_68HC16"
  , (,) EM_68HC11 "EM_68HC11"
  , (,) EM_68HC08 "EM_68HC08"
  , (,) EM_68HC05 "EM_68HC05"
  , (,) EM_SVX "EM_SVX"
  , (,) EM_ST19 "EM_ST19"
  , (,) EM_VAX "EM_VAX"
  , (,) EM_CRIS "EM_CRIS"
  , (,) EM_JAVELIN "EM_JAVELIN"
  , (,) EM_FIREPATH "EM_FIREPATH"
  , (,) EM_ZSP "EM_ZSP"
  , (,) EM_MMIX "EM_MMIX"
  , (,) EM_HUANY "EM_HUANY"
  , (,) EM_PRISM "EM_PRISM"
  , (,) EM_AVR "EM_AVR"
  , (,) EM_FR30 "EM_FR30"
  , (,) EM_D10V "EM_D10V"
  , (,) EM_D30V "EM_D30V"
  , (,) EM_V850 "EM_V850"
  , (,) EM_M32R "EM_M32R"
  , (,) EM_MN10300 "EM_MN10300"
  , (,) EM_MN10200 "EM_MN10200"
  , (,) EM_PJ "EM_PJ"
  , (,) EM_OPENRISC "EM_OPENRISC"
  , (,) EM_ARC_A5 "EM_ARC_A5"
  , (,) EM_XTENSA "EM_XTENSA"
  , (,) EM_VIDEOCORE "EM_VIDEOCORE"
  , (,) EM_TMM_GPP "EM_TMM_GPP"
  , (,) EM_NS32K "EM_NS32K"
  , (,) EM_TPC "EM_TPC"
  , (,) EM_SNP1K "EM_SNP1K"
  , (,) EM_ST200 "EM_ST200"
  , (,) EM_IP2K "EM_IP2K"
  , (,) EM_MAX "EM_MAX"
  , (,) EM_CR "EM_CR"
  , (,) EM_F2MC16 "EM_F2MC16"
  , (,) EM_MSP430 "EM_MSP430"
  , (,) EM_BLACKFIN "EM_BLACKFIN"
  , (,) EM_SE_C33 "EM_SE_C33"
  , (,) EM_SEP "EM_SEP"
  , (,) EM_ARCA "EM_ARCA"
  , (,) EM_UNICORE "EM_UNICORE"
  , (,) EM_TI_C6000 "EM_TI_C6000"
  , (,) EM_L1OM "EM_L1OM"
  , (,) EM_K1OM "EM_K1OM"
  ]

------------------------------------------------------------------------
-- ElfSectionIndex

newtype ElfSectionIndex = ElfSectionIndex { fromElfSectionIndex :: Word16 }
  deriving (Eq, Ord, Enum, Num, Real, Integral)

-- | Undefined section
pattern SHN_UNDEF = ElfSectionIndex 0

-- | Associated symbol is absolute.
pattern SHN_ABS = ElfSectionIndex 0xfff1

-- | This identifies a symbol in a relocatable file that is not yet allocated.
--
-- The linker should allocate space for this symbol at an address that is a
-- aligned to the symbol value ('steValue').
pattern SHN_COMMON = ElfSectionIndex 0xfff2

-- | Start of reserved indices.
pattern SHN_LORESERVE  = ElfSectionIndex 0xff00

-- | Start of processor specific.
pattern SHN_LOPROC = SHN_LORESERVE

-- | Like SHN_COMMON but symbol in .lbss
pattern SHN_X86_64_LCOMMON = ElfSectionIndex 0xff02

-- | Only used by HP-UX, because HP linker gives
-- weak symbols precdence over regular common symbols.
pattern SHN_IA_64_ANSI_COMMON = SHN_LORESERVE

-- | Small common symbols
pattern SHN_MIPS_SCOMMON = ElfSectionIndex 0xff03

-- | Small undefined symbols
pattern SHN_MIPS_SUNDEFINED = ElfSectionIndex 0xff04

-- | Small data area common symbol.
pattern SHN_TIC6X_SCOMMON = SHN_LORESERVE

-- | End of processor specific.
pattern SHN_HIPROC = ElfSectionIndex 0xff1f

-- | Start of OS-specific.
pattern SHN_LOOS = ElfSectionIndex 0xff20

-- | End of OS-specific.
pattern SHN_HIOS = ElfSectionIndex 0xff3f

instance Show ElfSectionIndex where
  show i = ppElfSectionIndex EM_NONE ELFOSABI_SYSV maxBound "SHN_" i

-- | Pretty print an elf section index
ppElfSectionIndex :: ElfMachine
                  -> ElfOSABI
                  -> Word16 -- ^ Number of sections.
                  -> String -- ^ Prefix for names
                  -> ElfSectionIndex
                  -> String
ppElfSectionIndex m abi this_shnum pre tp =
  case tp of
    SHN_UNDEF -> pre ++ "UND"
    SHN_ABS   -> pre ++ "ABS"
    SHN_COMMON -> pre ++ "COM"
    SHN_IA_64_ANSI_COMMON | m == EM_IA_64, abi == ELFOSABI_HPUX     -> pre ++ "ANSI_COM"
    SHN_X86_64_LCOMMON    | m `elem` [ EM_X86_64, EM_L1OM, EM_K1OM] -> pre ++ "LARGE_COM"
    SHN_MIPS_SCOMMON      | m == EM_MIPS                            -> pre ++ "SCOM"
    SHN_MIPS_SUNDEFINED   | m == EM_MIPS                            -> pre ++ "SUND"
    SHN_TIC6X_SCOMMON     | m == EM_TI_C6000                        -> pre ++ "SCOM"

    ElfSectionIndex w
      | tp >= SHN_LOPROC, tp <= SHN_HIPROC   -> pre ++ "PRC[0x" ++ showHex w "]"
      | tp >= SHN_LOOS,   tp <= SHN_HIOS     -> pre ++ "OS [0x" ++ showHex w "]"
      | tp >= SHN_LORESERVE                  -> pre ++ "RSV[0x" ++ showHex w "]"
      | w >= this_shnum                      -> "bad section index[" ++ show w ++ "]"
      | otherwise                            -> show w

------------------------------------------------------------------------
-- ElfSymbolType

-- | The type of an elf symbol table entry
newtype ElfSymbolType = ElfSymbolType Word8
  deriving (Eq, Ord)

-- | Symbol type is unspecified
pattern STT_NOTYPE = ElfSymbolType 0

-- | Symbol is a data object
pattern STT_OBJECT = ElfSymbolType 1

-- | Symbol is a code object
pattern STT_FUNC   = ElfSymbolType 2

-- | Symbol associated with a section.
pattern STT_SECTION = ElfSymbolType 3

-- | Symbol gives a file name.
pattern STT_FILE = ElfSymbolType 4

-- | An uninitialised common block.
pattern STT_COMMON = ElfSymbolType 5

-- | Thread local data object.
pattern STT_TLS = ElfSymbolType 6

-- | Complex relocation expression.
pattern STT_RELC = ElfSymbolType 8

-- | Signed Complex relocation expression.
pattern STT_SRELC = ElfSymbolType 9

-- | Symbol is an indirect code object.
pattern STT_GNU_IFUNC = ElfSymbolType 10

-- | Returns true if this is an OF specififc symbol type.
isOSSpecificSymbolType :: ElfSymbolType -> Bool
isOSSpecificSymbolType (ElfSymbolType w) = 10 <= w && w <= 12

isProcSpecificSymbolType :: ElfSymbolType -> Bool
isProcSpecificSymbolType (ElfSymbolType w) = 13 <= w && w <= 15

instance Show ElfSymbolType where
   show = ppElfSymbolType

ppElfSymbolType :: ElfSymbolType -> String
ppElfSymbolType tp =
  case tp of
    STT_NOTYPE  -> "NOTYPE"
    STT_OBJECT  -> "OBJECT"
    STT_FUNC    -> "FUNC"
    STT_SECTION -> "SECTION"
    STT_FILE    -> "FILE"
    STT_COMMON  -> "COMMON"
    STT_TLS     -> "TLS"
    STT_RELC    -> "RELC"
    STT_SRELC   -> "SRELC"
    STT_GNU_IFUNC -> "IFUNC"
    ElfSymbolType w
      | isOSSpecificSymbolType tp   -> "<OS specific>: " ++ show w
      | isProcSpecificSymbolType tp -> "<processor specific>: " ++ show w
      | otherwise -> "<unknown>: " ++ show w

------------------------------------------------------------------------
-- ElfSymbolBinding

-- | Symbol binding type
newtype ElfSymbolBinding = ElfSymbolBinding { fromElfSymbolBinding :: Word8 }
  deriving (Eq, Ord)

pattern STB_LOCAL  = ElfSymbolBinding  0
pattern STB_GLOBAL = ElfSymbolBinding  1
pattern STB_WEAK   = ElfSymbolBinding  2
pattern STB_NUM    = ElfSymbolBinding  3

-- | Lower bound for OS specific symbol bindings.
pattern STB_LOOS   = ElfSymbolBinding 10
-- | Upper bound for OS specific symbol bindings.
pattern STB_HIOS   = ElfSymbolBinding 12
-- | GNU-specific override that makes symbol unique even with local
-- dynamic loading.
pattern STB_GNU_UNIQUE = ElfSymbolBinding 10

pattern STB_LOPROC = ElfSymbolBinding 13
pattern STB_HIPROC = ElfSymbolBinding 15

instance Show ElfSymbolBinding where
  show STB_LOCAL  = "STB_LOCAL"
  show STB_GLOBAL = "STB_GLOBAL"
  show STB_WEAK   = "STB_WEAK"
  show STB_NUM    = "STB_NUM"
  show STB_GNU_UNIQUE = "STB_GNU_UNIQUE"
  show b | STB_LOOS   <= b && b <= STB_HIOS   = "<OS specific>: " ++ show w
         | STB_LOPROC <= b && b <= STB_HIPROC = "<processor specific>: " ++ show w
         | otherwise = "<unknown>: " ++ show w
   where w = fromElfSymbolBinding b
