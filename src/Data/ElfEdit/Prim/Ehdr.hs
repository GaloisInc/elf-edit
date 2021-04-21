{-|
Header for start of elf file and utilities functions
-}
{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE TypeFamilies #-}
module Data.ElfEdit.Prim.Ehdr
  ( -- * EHdr
    Ehdr(..)
  , decodeEhdr
  , encodeEhdr
    -- ** Core header
  , ElfHeader(..)
    -- ** Class
  , ElfClass(..)
  , SomeElf(..)
  , elfClassInstances
  , elfClassByteWidth
  , elfClassBitWidth
  , ElfWordType
  , ElfIntType
  , ElfWidthConstraints
    -- ** Sizes
  , ehdrSize
  , phdrEntrySize
  , shdrEntrySize
    -- ** Data
  , ElfData(..)
  , decodeWord32
  , decodeWord64
  , getWord16
  , getWord32
  , getWord64
  , putWord16
  , putWord32
  , putWord64
    -- ** Elf Constants
  , elfMagic
  , expectedElfVersion
    -- ** ElfOSABI
  , ElfOSABI(..)
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
    -- ** ElfType
  , ElfType(..)
  , pattern ET_NONE
  , pattern ET_REL
  , pattern ET_EXEC
  , pattern ET_DYN
  , pattern ET_CORE
    -- ** ElfMachine
  , ElfMachine(..)
  , elfMachineNameMap
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
  , pattern EM_QDSP6
  , pattern EM_L1OM
  , pattern EM_K1OM
  , pattern EM_AARCH64
  , pattern EM_AVR32
  , pattern EM_STM8
  , pattern EM_RISCV
  ) where

import           Control.Monad
import           Data.Binary.Get (Get)
import qualified Data.Binary.Get as Get
import           Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Builder as Bld
import qualified Data.Map.Strict as Map
import           Data.Int
import qualified Data.Type.Equality as TE
import           Data.Word
import           GHC.Stack
import           GHC.TypeLits

import           Data.ElfEdit.ByteString
import           Data.ElfEdit.Prim.File
import           Data.ElfEdit.Utils

-- | The version of elf files supported by this parser
expectedElfVersion :: Word8
expectedElfVersion = 1

------------------------------------------------------------------------
-- ElfClass

-- | A flag indicating whether Elf is 32 or 64-bit.
data ElfClass (w :: Nat) where
  ELFCLASS32 :: ElfClass 32
  ELFCLASS64 :: ElfClass 64

instance Show (ElfClass w) where
  show ELFCLASS32 = "ELFCLASS32"
  show ELFCLASS64 = "ELFCLASS64"

instance TE.TestEquality ElfClass where
  testEquality ELFCLASS32 ELFCLASS32 = Just TE.Refl
  testEquality ELFCLASS64 ELFCLASS64 = Just TE.Refl
  testEquality _ _ = Nothing

-- | Return the number of bytes in an address with this elf class.
elfClassByteWidth :: ElfClass w -> Int
elfClassByteWidth ELFCLASS32 = 4
elfClassByteWidth ELFCLASS64 = 8

-- | Return the number of bits in an address with this elf class.
elfClassBitWidth :: ElfClass w -> Int
elfClassBitWidth ELFCLASS32 = 32
elfClassBitWidth ELFCLASS64 = 64

-- | Wraps a either a 32-bit or 64-bit typed value.
data SomeElf f = forall (w::Nat) . SomeElf (f w)

fromElfClass :: ElfClass w -> Word8
fromElfClass ELFCLASS32 = 1
fromElfClass ELFCLASS64 = 2

-- | An unsigned value of a given width
type family ElfWordType (w::Nat) :: * where
  ElfWordType 32 = Word32
  ElfWordType 64 = Word64

-- | A signed value of a given width
type family ElfIntType (w::Nat) :: * where
  ElfIntType 32 = Int32
  ElfIntType 64 = Int64

type ElfWidthConstraints w
   = (Bits (ElfWordType w), Integral (ElfWordType w), Show (ElfWordType w), Bounded (ElfWordType w))

-- | Given a provides a way to access 'Bits', 'Integral' and 'Show' instances
-- of underlying word types associated with an 'ElfClass'.
elfClassInstances :: ElfClass w
                  -> (ElfWidthConstraints w => a)
                  -> a
elfClassInstances ELFCLASS32 a = a
elfClassInstances ELFCLASS64 a = a

------------------------------------------------------------------------
-- Sizes

-- | Size of the main elf header table for given width.
ehdrSize :: ElfClass w -> Word16
ehdrSize ELFCLASS32 = 52
ehdrSize ELFCLASS64 = 64

-- | Size of entry in Elf program header table for given width.
phdrEntrySize :: ElfClass w -> Word16
phdrEntrySize ELFCLASS32 = 32
phdrEntrySize ELFCLASS64 = 56

-- | Size of entry in Elf section header table for given width.
shdrEntrySize :: ElfClass w -> Word16
shdrEntrySize ELFCLASS32 = 40
shdrEntrySize ELFCLASS64 = 64

------------------------------------------------------------------------
-- ElfData

-- | A flag indicating byte order used to encode data.
data ElfData = ELFDATA2LSB -- ^ Least significant byte first
             | ELFDATA2MSB -- ^ Most significant byte first.
  deriving (Eq, Ord, Show)

fromElfData :: ElfData -> Word8
fromElfData ELFDATA2LSB = 1
fromElfData ELFDATA2MSB = 2

-- | Decode a 32-bit word using elf data for endianess.
--
-- Argument must contain at least 4 bytes.
decodeWord32 :: HasCallStack => ElfData -> B.ByteString -> Word32
decodeWord32 ELFDATA2LSB = bsWord32le
decodeWord32 ELFDATA2MSB = bsWord32be

-- | Decode a 64-bit word using elf data for endianess.
--
-- Argument must contain at least 8 bytes.
decodeWord64 :: HasCallStack => ElfData -> B.ByteString -> Word64
decodeWord64 ELFDATA2LSB = bsWord64le
decodeWord64 ELFDATA2MSB = bsWord64be

getWord16 :: ElfData -> Get.Get Word16
getWord16 ELFDATA2LSB = Get.getWord16le
getWord16 ELFDATA2MSB = Get.getWord16be

getWord32 :: ElfData -> Get.Get Word32
getWord32 ELFDATA2LSB = Get.getWord32le
getWord32 ELFDATA2MSB = Get.getWord32be

getWord64 :: ElfData -> Get.Get Word64
getWord64 ELFDATA2LSB = Get.getWord64le
getWord64 ELFDATA2MSB = Get.getWord64be

-- | Convert 'Word16' to data using appropriate endianess.
putWord16 :: ElfData -> Word16 -> Bld.Builder
putWord16 ELFDATA2LSB = Bld.word16LE
putWord16 ELFDATA2MSB = Bld.word16BE

-- | Convert 'Word32' to data using appropriate endianess.
putWord32 :: ElfData -> Word32 -> Bld.Builder
putWord32 ELFDATA2LSB = Bld.word32LE
putWord32 ELFDATA2MSB = Bld.word32BE

-- | Convert 'Word64' to data using appropriate endianess.
putWord64 :: ElfData -> Word64 -> Bld.Builder
putWord64 ELFDATA2LSB = Bld.word64LE
putWord64 ELFDATA2MSB = Bld.word64BE

------------------------------------------------------------------------
-- ElfOSABI

-- | A flag identifying the OS or ABI specific Elf extensions used.
newtype ElfOSABI = ElfOSABI { fromElfOSABI :: Word8 }
  deriving (Eq, Ord)

-- | No extensions or unspecified
pattern ELFOSABI_SYSV :: ElfOSABI
pattern ELFOSABI_SYSV = ElfOSABI 0

-- | Hewlett-Packard HP-UX
pattern ELFOSABI_HPUX :: ElfOSABI
pattern ELFOSABI_HPUX = ElfOSABI 1

-- | NetBSD
pattern ELFOSABI_NETBSD :: ElfOSABI
pattern ELFOSABI_NETBSD = ElfOSABI 2

-- | Linux
pattern ELFOSABI_LINUX :: ElfOSABI
pattern ELFOSABI_LINUX = ElfOSABI 3

-- | Sun Solaris
pattern ELFOSABI_SOLARIS :: ElfOSABI
pattern ELFOSABI_SOLARIS = ElfOSABI 6

-- | AIX
pattern ELFOSABI_AIX :: ElfOSABI
pattern ELFOSABI_AIX = ElfOSABI 7

-- | IRIX
pattern ELFOSABI_IRIS :: ElfOSABI
pattern ELFOSABI_IRIS = ElfOSABI 8

-- | FreeBSD
pattern ELFOSABI_FREEBSD :: ElfOSABI
pattern ELFOSABI_FREEBSD = ElfOSABI 9

-- | Compat TRU64 Unix
pattern ELFOSABI_TRU64 :: ElfOSABI
pattern ELFOSABI_TRU64 = ElfOSABI 10

-- | Novell Modesto
pattern ELFOSABI_MODESTO :: ElfOSABI
pattern ELFOSABI_MODESTO = ElfOSABI 11

-- | Open BSD
pattern ELFOSABI_OPENBSD :: ElfOSABI
pattern ELFOSABI_OPENBSD = ElfOSABI 12

-- | Open VMS
pattern ELFOSABI_OPENVMS :: ElfOSABI
pattern ELFOSABI_OPENVMS = ElfOSABI 13

-- | Hewlett-Packard Non-Stop Kernel
pattern ELFOSABI_NSK :: ElfOSABI
pattern ELFOSABI_NSK = ElfOSABI 14

-- | Amiga Research OS
pattern ELFOSABI_AROS :: ElfOSABI
pattern ELFOSABI_AROS = ElfOSABI 15

-- | ARM
pattern ELFOSABI_ARM :: ElfOSABI
pattern ELFOSABI_ARM = ElfOSABI 97

-- | Standalone (embedded) application
pattern ELFOSABI_STANDALONE :: ElfOSABI
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
pattern ET_NONE :: ElfType
pattern ET_NONE = ElfType 0

-- | Relocatable object file such as assembler output
pattern ET_REL :: ElfType
pattern ET_REL  = ElfType 1

-- | Executable
pattern ET_EXEC :: ElfType
pattern ET_EXEC = ElfType 2

-- | Shared object
pattern ET_DYN :: ElfType
pattern ET_DYN  = ElfType 3

-- | Core dump
pattern ET_CORE :: ElfType
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

pattern EM_NONE :: ElfMachine
pattern EM_NONE = ElfMachine 0
-- ^ No machine

pattern EM_M32 :: ElfMachine
pattern EM_M32 = ElfMachine 1
-- ^ AT&T WE 32100

pattern EM_SPARC :: ElfMachine
pattern EM_SPARC = ElfMachine 2
-- ^ SPARC
pattern EM_386 :: ElfMachine
pattern EM_386 = ElfMachine 3
-- ^ Intel 80386
pattern EM_68K :: ElfMachine
pattern EM_68K = ElfMachine 4
-- ^ Motorola 68000
pattern EM_88K :: ElfMachine
pattern EM_88K = ElfMachine 5
-- ^ Motorola 88000
pattern EM_486 :: ElfMachine
pattern EM_486 = ElfMachine 6
-- ^ Intel i486 (DO NOT USE THIS ONE)
pattern EM_860 :: ElfMachine
pattern EM_860 = ElfMachine 7
-- ^ Intel 80860
pattern EM_MIPS :: ElfMachine
pattern EM_MIPS = ElfMachine 8
-- ^ MIPS I Architecture
pattern EM_S370 :: ElfMachine
pattern EM_S370 = ElfMachine 9
-- ^ IBM System/370 Processor
pattern EM_MIPS_RS3_LE :: ElfMachine
pattern EM_MIPS_RS3_LE = ElfMachine 10
-- ^ MIPS RS3000 Little-endian
pattern EM_SPARC64 :: ElfMachine
pattern EM_SPARC64 = ElfMachine 11
-- ^ SPARC 64-bit
pattern EM_PARISC :: ElfMachine
pattern EM_PARISC = ElfMachine 15
-- ^ Hewlett-Packard PA-RISC
pattern EM_VPP500 :: ElfMachine
pattern EM_VPP500 = ElfMachine 17
-- ^ Fujitsu VPP500
pattern EM_SPARC32PLUS :: ElfMachine
pattern EM_SPARC32PLUS = ElfMachine 18
-- ^ Enhanced instruction set SPARC
pattern EM_960 :: ElfMachine
pattern EM_960 = ElfMachine 19
-- ^ Intel 80960
pattern EM_PPC :: ElfMachine
pattern EM_PPC = ElfMachine 20
-- ^ PowerPC
pattern EM_PPC64 :: ElfMachine
pattern EM_PPC64 = ElfMachine 21
-- ^ 64-bit PowerPC
pattern EM_S390 :: ElfMachine
pattern EM_S390  = ElfMachine 22
-- ^ IBM System/390 Processor
pattern EM_SPU :: ElfMachine
pattern EM_SPU   = ElfMachine 23
-- ^ Cell SPU
pattern EM_V800 :: ElfMachine
pattern EM_V800  = ElfMachine 36
-- ^ NEC V800
pattern EM_FR20 :: ElfMachine
pattern EM_FR20  = ElfMachine 37
-- ^ Fujitsu FR20
pattern EM_RH32 :: ElfMachine
pattern EM_RH32  = ElfMachine 38
-- ^ TRW RH-32
pattern EM_RCE :: ElfMachine
pattern EM_RCE   = ElfMachine 39
-- ^ Motorola RCE
pattern EM_ARM :: ElfMachine
pattern EM_ARM   = ElfMachine 40
-- ^ Advanced RISC Machines ARM
pattern EM_ALPHA :: ElfMachine
pattern EM_ALPHA = ElfMachine 41
-- ^ Digital Alpha
pattern EM_SH :: ElfMachine
pattern EM_SH    = ElfMachine 42
-- ^ Hitachi SH
pattern EM_SPARCV9 :: ElfMachine
pattern EM_SPARCV9  = ElfMachine 43
-- ^ SPARC Version 9
pattern EM_TRICORE :: ElfMachine
pattern EM_TRICORE  = ElfMachine 44
-- ^ Siemens TriCore embedded processor
pattern EM_ARC :: ElfMachine
pattern EM_ARC      = ElfMachine 45
-- ^ Argonaut RISC Core, Argonaut Technologies Inc.
pattern EM_H8_300 :: ElfMachine
pattern EM_H8_300   = ElfMachine 46
-- ^ Hitachi H8/300
pattern EM_H8_300H :: ElfMachine
pattern EM_H8_300H  = ElfMachine 47
-- ^ Hitachi H8/300H
pattern EM_H8S :: ElfMachine
pattern EM_H8S      = ElfMachine 48
-- ^ Hitachi H8S
pattern EM_H8_500 :: ElfMachine
pattern EM_H8_500   = ElfMachine 49
-- ^ Hitachi H8/500
pattern EM_IA_64 :: ElfMachine
pattern EM_IA_64    = ElfMachine 50
-- ^ Intel IA-64 processor architecture
pattern EM_MIPS_X :: ElfMachine
pattern EM_MIPS_X   = ElfMachine 51
-- ^ Stanford MIPS-X
pattern EM_COLDFIRE :: ElfMachine
pattern EM_COLDFIRE = ElfMachine 52
-- ^ Motorola ColdFire
pattern EM_68HC12 :: ElfMachine
pattern EM_68HC12   = ElfMachine 53
-- ^ Motorola M68HC12
pattern EM_MMA :: ElfMachine
pattern EM_MMA      = ElfMachine 54
-- ^ Fujitsu MMA Multimedia Accelerator
pattern EM_PCP :: ElfMachine
pattern EM_PCP      = ElfMachine 55
-- ^ Siemens PCP
pattern EM_NCPU :: ElfMachine
pattern EM_NCPU     = ElfMachine 56
-- ^ Sony nCPU embedded RISC processor
pattern EM_NDR1 :: ElfMachine
pattern EM_NDR1     = ElfMachine 57
-- ^ Denso NDR1 microprocessor
pattern EM_STARCORE :: ElfMachine
pattern EM_STARCORE = ElfMachine 58
-- ^ Motorola Star*Core processor
pattern EM_ME16 :: ElfMachine
pattern EM_ME16     = ElfMachine 59
-- ^ Toyota ME16 processor
pattern EM_ST100 :: ElfMachine
pattern EM_ST100    = ElfMachine 60
-- ^ STMicroelectronics ST100 processor
pattern EM_TINYJ :: ElfMachine
pattern EM_TINYJ    = ElfMachine 61
-- ^ Advanced Logic Corp. TinyJ embedded processor family
pattern EM_X86_64 :: ElfMachine
pattern EM_X86_64   = ElfMachine 62
-- ^ AMD x86-64 architecture
pattern EM_PDSP :: ElfMachine
pattern EM_PDSP     = ElfMachine 63
-- ^ Sony DSP Processor
pattern EM_FX66 :: ElfMachine
pattern EM_FX66     = ElfMachine 66
-- ^ Siemens FX66 microcontroller
pattern EM_ST9PLUS :: ElfMachine
pattern EM_ST9PLUS  = ElfMachine 67
-- ^ STMicroelectronics ST9+ 8/16 bit microcontroller
pattern EM_ST7 :: ElfMachine
pattern EM_ST7      = ElfMachine 68
-- ^ STMicroelectronics ST7 8-bit microcontroller
pattern EM_68HC16 :: ElfMachine
pattern EM_68HC16   = ElfMachine 69
-- ^ Motorola MC68HC16 Microcontroller
pattern EM_68HC11 :: ElfMachine
pattern EM_68HC11      = ElfMachine 70
-- ^ Motorola MC68HC11 Microcontroller
pattern EM_68HC08 :: ElfMachine
pattern EM_68HC08      = ElfMachine 71
-- ^ Motorola MC68HC08 Microcontroller
pattern EM_68HC05 :: ElfMachine
pattern EM_68HC05      = ElfMachine 72
-- ^ Motorola MC68HC05 Microcontroller
pattern EM_SVX :: ElfMachine
pattern EM_SVX         = ElfMachine 73
-- ^ Silicon Graphics SVx
pattern EM_ST19 :: ElfMachine
pattern EM_ST19        = ElfMachine 74
-- ^ STMicroelectronics ST19 8-bit microcontroller
pattern EM_VAX :: ElfMachine
pattern EM_VAX         = ElfMachine 75
-- ^ Digital VAX
pattern EM_CRIS :: ElfMachine
pattern EM_CRIS        = ElfMachine 76
-- ^ Axis Communications 32-bit embedded processor
pattern EM_JAVELIN :: ElfMachine
pattern EM_JAVELIN     = ElfMachine 77
-- ^ Infineon Technologies 32-bit embedded processor
pattern EM_FIREPATH :: ElfMachine
pattern EM_FIREPATH    = ElfMachine 78
-- ^ Element 14 64-bit DSP Processor
pattern EM_ZSP :: ElfMachine
pattern EM_ZSP         = ElfMachine 79
-- ^ LSI Logic 16-bit DSP Processor
pattern EM_MMIX :: ElfMachine
pattern EM_MMIX        = ElfMachine 80
-- ^ Donald Knuth's educational 64-bit processor
pattern EM_HUANY :: ElfMachine
pattern EM_HUANY       = ElfMachine 81
-- ^ Harvard University machine-independent object files
pattern EM_PRISM :: ElfMachine
pattern EM_PRISM       = ElfMachine 82
-- ^ SiTera Prism
pattern EM_AVR :: ElfMachine
pattern EM_AVR         = ElfMachine 83
-- ^ Atmel AVR 8-bit microcontroller
pattern EM_FR30 :: ElfMachine
pattern EM_FR30        = ElfMachine 84
-- ^ Fujitsu FR30
pattern EM_D10V :: ElfMachine
pattern EM_D10V        = ElfMachine 85
-- ^ Mitsubishi D10V
pattern EM_D30V :: ElfMachine
pattern EM_D30V        = ElfMachine 86
-- ^ Mitsubishi D30V
pattern EM_V850 :: ElfMachine
pattern EM_V850        = ElfMachine 87
-- ^ NEC v850
pattern EM_M32R :: ElfMachine
pattern EM_M32R        = ElfMachine 88
-- ^ Mitsubishi M32R
pattern EM_MN10300 :: ElfMachine
pattern EM_MN10300     = ElfMachine 89
-- ^ Matsushita MN10300
pattern EM_MN10200 :: ElfMachine
pattern EM_MN10200     = ElfMachine 90
-- ^ Matsushita MN10200
pattern EM_PJ :: ElfMachine
pattern EM_PJ          = ElfMachine 91
-- ^ picoJava
pattern EM_OPENRISC :: ElfMachine
pattern EM_OPENRISC    = ElfMachine 92
-- ^ OpenRISC 32-bit embedded processor
pattern EM_ARC_A5 :: ElfMachine
pattern EM_ARC_A5      = ElfMachine 93
-- ^ ARC Cores Tangent-A5
pattern EM_XTENSA :: ElfMachine
pattern EM_XTENSA      = ElfMachine 94
-- ^ Tensilica Xtensa Architecture
pattern EM_VIDEOCORE :: ElfMachine
pattern EM_VIDEOCORE   = ElfMachine 95
-- ^ Alphamosaic VideoCore processor
pattern EM_TMM_GPP :: ElfMachine
pattern EM_TMM_GPP     = ElfMachine 96
-- ^ Thompson Multimedia General Purpose Processor
pattern EM_NS32K :: ElfMachine
pattern EM_NS32K       = ElfMachine 97
-- ^ National Semiconductor 32000 series
pattern EM_TPC :: ElfMachine
pattern EM_TPC         = ElfMachine 98
-- ^ Tenor Network TPC processor
pattern EM_SNP1K :: ElfMachine
pattern EM_SNP1K       = ElfMachine 99
-- ^ Trebia SNP 1000 processor
pattern EM_ST200 :: ElfMachine
pattern EM_ST200       = ElfMachine 100
-- ^ STMicroelectronics (www.st.com) ST200 microcontroller
pattern EM_IP2K :: ElfMachine
pattern EM_IP2K        = ElfMachine 101
-- ^ Ubicom IP2xxx microcontroller family
pattern EM_MAX :: ElfMachine
pattern EM_MAX         = ElfMachine 102
-- ^ MAX Processor
pattern EM_CR :: ElfMachine
pattern EM_CR          = ElfMachine 103
-- ^ National Semiconductor CompactRISC microprocessor
pattern EM_F2MC16 :: ElfMachine
pattern EM_F2MC16      = ElfMachine 104
-- ^ Fujitsu F2MC16
pattern EM_MSP430 :: ElfMachine
pattern EM_MSP430      = ElfMachine 105
-- ^ Texas Instruments embedded microcontroller msp430
pattern EM_BLACKFIN :: ElfMachine
pattern EM_BLACKFIN    = ElfMachine 106
-- ^ Analog Devices Blackfin (DSP) processor
pattern EM_SE_C33 :: ElfMachine
pattern EM_SE_C33      = ElfMachine 107
-- ^ S1C33 Family of Seiko Epson processors
pattern EM_SEP :: ElfMachine
pattern EM_SEP         = ElfMachine 108
-- ^ Sharp embedded microprocessor
pattern EM_ARCA :: ElfMachine
pattern EM_ARCA        = ElfMachine 109
-- ^ Arca RISC Microprocessor
pattern EM_UNICORE :: ElfMachine
pattern EM_UNICORE     = ElfMachine 110
-- ^ Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University
pattern EM_TI_C6000 :: ElfMachine
pattern EM_TI_C6000    = ElfMachine 140
-- ^ Texas Instruments TMS320C6000 DSP family
pattern EM_QDSP6 :: ElfMachine
pattern EM_QDSP6 = ElfMachine 164

pattern EM_L1OM :: ElfMachine
pattern EM_L1OM = ElfMachine 180
-- ^ Intel L10M
pattern EM_K1OM :: ElfMachine
pattern EM_K1OM = ElfMachine 181
-- ^ Intel K10M
pattern EM_AARCH64 :: ElfMachine
pattern EM_AARCH64 = ElfMachine 183
-- ^ ARM 64-bit architecture (AARCH64)
pattern EM_AVR32 :: ElfMachine
pattern EM_AVR32 = ElfMachine 185
-- ^ Atmel Corporation 32-bit microprocessor family
pattern EM_STM8 :: ElfMachine
pattern EM_STM8 = ElfMachine 186
-- ^ STMicroeletronics STM8 8-bit microcontroller
pattern EM_RISCV :: ElfMachine
pattern EM_RISCV = ElfMachine 243
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
  , (,) EM_QDSP6 "EM_QDSP6"
  , (,) EM_L1OM "EM_L1OM"
  , (,) EM_K1OM "EM_K1OM"
  , (,) EM_AARCH64 "EM_AARCH64"
  , (,) EM_AVR32   "EM_AVR32"
  , (,) EM_STM8    "EM_STM8"
  , (,) EM_RISCV "EM_RISCV"
  ]

------------------------------------------------------------------------
-- ElfHeader

-- | Core information in the header of an elf file.
--
-- This is reused in high-level implementation.
data ElfHeader w = ElfHeader { headerData       :: !ElfData
                             , headerClass      :: !(ElfClass w)
                             , headerOSABI      :: !ElfOSABI
                             , headerABIVersion :: !Word8
                             , headerType       :: !ElfType
                             , headerMachine    :: !ElfMachine
                             , headerEntry      :: !(ElfWordType w)
                             , headerFlags      :: !Word32
                             }

------------------------------------------------------------------------
-- Ehdr

-- | Information to be rendered into Elf header record at start of file.
data Ehdr w = Ehdr { ehdrHeader :: !(ElfHeader w)
                   , ehdrPhoff :: !(FileOffset (ElfWordType w))
                   , ehdrShoff :: !(FileOffset (ElfWordType w))
                   , ehdrPhnum :: !Word16
                   , ehdrShnum :: !Word16
                   , ehdrShstrndx :: !Word16
                   }

------------------------------------------------------------------------
-- Encoding

-- | The 4-byte strict expected at the start of an Elf file @"(0x7f)ELF"@
elfMagic :: B.ByteString
elfMagic = "\DELELF"

-- | Create the 16-byte header that sits at the start of an elf file.
elfIdentBuilder :: ElfHeader w -> Bld.Builder
elfIdentBuilder e =
  mconcat [ Bld.byteString elfMagic
          , Bld.word8 (fromElfClass (headerClass e))
          , Bld.word8 (fromElfData  (headerData e))
          , Bld.word8 expectedElfVersion
          , Bld.word8 (fromElfOSABI (headerOSABI e))
          , Bld.word8 (fromIntegral (headerABIVersion e))
          , mconcat (replicate 7 (Bld.word8 0))
          ]

-- | Encode 32-bit ELF header in a builder
encodeEhdr32 :: Ehdr 32 -> Bld.Builder
encodeEhdr32 e = do
  let hdr = ehdrHeader e
  let d = headerData hdr
  elfIdentBuilder hdr
    <> putWord16 d (fromElfType (headerType hdr))
    <> putWord16 d (fromElfMachine (headerMachine hdr))

    <> putWord32 d (fromIntegral expectedElfVersion)
    <> putWord32 d (headerEntry hdr)
    <> putWord32 d (fromFileOffset (ehdrPhoff e))
    <> putWord32 d (fromFileOffset (ehdrShoff e))
    <> putWord32 d (headerFlags hdr)

    <> putWord16 d (ehdrSize      ELFCLASS32)
    <> putWord16 d (phdrEntrySize ELFCLASS32)
    <> putWord16 d (ehdrPhnum e)
    <> putWord16 d (shdrEntrySize ELFCLASS32)
    <> putWord16 d (ehdrShnum e)
    <> putWord16 d (ehdrShstrndx e)

-- | Encode 64-bit ELF header in a builder
encodeEhdr64 :: Ehdr 64 -> Bld.Builder
encodeEhdr64 e = do
  let hdr = ehdrHeader e
  let d = headerData hdr
  elfIdentBuilder hdr
    <> putWord16 d (fromElfType (headerType hdr))
    <> putWord16 d (fromElfMachine (headerMachine hdr))
    <> putWord32 d (fromIntegral expectedElfVersion)
    <> putWord64 d (headerEntry hdr)
    <> putWord64 d (fromFileOffset (ehdrPhoff e))
    <> putWord64 d (fromFileOffset (ehdrShoff e))
    <> putWord32 d (headerFlags hdr)
    <> putWord16 d (ehdrSize ELFCLASS64)
    <> putWord16 d (phdrEntrySize ELFCLASS64)
    <> putWord16 d (ehdrPhnum e)
    <> putWord16 d (shdrEntrySize ELFCLASS64)
    <> putWord16 d (ehdrShnum e)
    <> putWord16 d (ehdrShstrndx e)

-- | Encode the main ELF header in a builder
encodeEhdr :: Ehdr w -> Bld.Builder
encodeEhdr e =
  case headerClass (ehdrHeader e) of
    ELFCLASS32 -> encodeEhdr32 e
    ELFCLASS64 -> encodeEhdr64 e

------------------------------------------------------------------------
-- Decoding

-- | Parse a 32-bit elf.
decodeEhdr32 :: ElfData
             -> ElfOSABI
             -> Word8 -- ^ ABI Version
             -> B.ByteString -- ^ Full Elf contents
             -> Get (Ehdr 32)
decodeEhdr32 d ei_osabi ei_abiver b = do
  e_type      <- ElfType      <$> getWord16 d
  e_machine   <- ElfMachine   <$> getWord16 d
  e_version   <- getWord32 d
  when (fromIntegral expectedElfVersion /= e_version) $
    fail "ELF Version mismatch"
  e_entry     <- getWord32 d
  e_phoff     <- FileOffset <$> getWord32 d
  e_shoff     <- FileOffset <$> getWord32 d
  e_flags     <- getWord32 d
  e_ehsize    <- getWord16 d
  e_phentsize <- getWord16 d
  e_phnum     <- getWord16 d
  e_shentsize <- getWord16 d
  e_shnum     <- getWord16 d
  e_shstrndx  <- getWord16 d
  when (e_ehsize /= ehdrSize ELFCLASS32) $ do
    fail $ "Unexpected ehdr size."
  let expected_phdr_entry_size = phdrEntrySize ELFCLASS32
  let expected_shdr_entry_size = shdrEntrySize ELFCLASS32
  when (e_phnum /= 0 && e_phentsize /= expected_phdr_entry_size) $ do
    fail $ "Expected segment entry size of " ++ show expected_phdr_entry_size
      ++ " and found size of " ++ show e_phentsize ++ " instead."
  when (e_shnum /= 0 && e_shentsize /= expected_shdr_entry_size) $ do
    fail $ "Invalid section entry size"
  -- Check end of program header table is in file bounds.
  let phdrEnd = toInteger e_phoff + toInteger expected_phdr_entry_size * toInteger e_phnum
  when (e_phnum /= 0 && phdrEnd > toInteger (B.length b)) $ do
    fail $ "Program header table out of bounds."
  -- Check end of section header table is in file bounds.
  let shdrEnd = toInteger e_shoff + toInteger expected_shdr_entry_size * toInteger e_shnum
  when (e_shnum /= 0 && shdrEnd > toInteger (B.length b)) $ do
    fail $ "Section header table out of bounds."
  -- Check string table index
  when (e_shnum /= 0 && e_shstrndx >= e_shnum) $ do
    fail $ "Section name index exceeds section count."
  let hdr = ElfHeader { headerData       = d
                      , headerClass      = ELFCLASS32
                      , headerOSABI      = ei_osabi
                      , headerABIVersion = ei_abiver
                      , headerType       = e_type
                      , headerMachine    = e_machine
                      , headerFlags      = e_flags
                      , headerEntry      = e_entry
                      }
  return $! Ehdr { ehdrHeader = hdr
                 , ehdrPhoff = e_phoff
                 , ehdrShoff = e_shoff
                 , ehdrPhnum = e_phnum
                 , ehdrShnum = e_shnum
                 , ehdrShstrndx = e_shstrndx
                 }

-- | Parse a 64-bit elf header.
decodeEhdr64 :: ElfData
             -> ElfOSABI
             -> Word8 -- ^ ABI Version
             -> B.ByteString -- ^ Full Elf contents
             -> Get (Ehdr 64)
decodeEhdr64 d ei_osabi ei_abiver b = do
  e_type      <- ElfType    <$> getWord16 d
  e_machine   <- ElfMachine <$> getWord16 d
  e_version   <- getWord32 d
  when (fromIntegral expectedElfVersion /= e_version) $
    fail "ELF Version mismatch"
  e_entry     <- getWord64 d
  e_phoff     <- FileOffset <$> getWord64 d
  e_shoff     <- FileOffset <$> getWord64 d
  e_flags     <- getWord32 d
  e_ehsize    <- getWord16 d
  e_phentsize <- getWord16 d
  e_phnum     <- getWord16 d
  e_shentsize <- getWord16 d
  e_shnum     <- getWord16 d
  e_shstrndx  <- getWord16 d
  let expected_phdr_entry_size = phdrEntrySize ELFCLASS64
  let expected_shdr_entry_size = shdrEntrySize ELFCLASS64

  when (e_ehsize /= ehdrSize ELFCLASS64) $ do
    fail $ "Unexpected ehdr size."
  when (e_phnum /= 0 && e_phentsize /= expected_phdr_entry_size) $ do
    fail $ "Invalid segment entry size"
  when (e_shnum /= 0 && e_shentsize /= expected_shdr_entry_size) $ do
    fail $ "Invalid section entry size"
  -- Check end of program header table is in file bounds.
  let phdrEnd = toInteger e_phoff + toInteger expected_phdr_entry_size * toInteger e_phnum
  when (e_phnum /= 0 && phdrEnd > toInteger (B.length b)) $ do
    fail $ "Program header table out of bounds."
  -- Check end of section header table is in file bounds.
  let shdrEnd = toInteger e_shoff + toInteger expected_shdr_entry_size * toInteger e_shnum
  when (e_shnum /= 0 && shdrEnd > toInteger (B.length b)) $ do
    fail $ "Section header table out of bounds."
  -- Check string table index
  when (e_shnum /= 0 && e_shstrndx >= e_shnum) $ do
    fail $ "Section name index exceeds section count."
  let hdr = ElfHeader { headerData       = d
                      , headerClass      = ELFCLASS64
                      , headerOSABI      = ei_osabi
                      , headerABIVersion = ei_abiver
                      , headerType       = e_type
                      , headerMachine    = e_machine
                      , headerFlags      = e_flags
                      , headerEntry      = e_entry
                      }
  return $! Ehdr { ehdrHeader = hdr
                 , ehdrPhoff = e_phoff
                 , ehdrShoff = e_shoff
                 , ehdrPhnum = e_phnum
                 , ehdrShnum = e_shnum
                 , ehdrShstrndx = e_shstrndx
                 }

-- | Creates a `ElfHeaderInfo` from a bytestring with data in the Elf format.
-- their fields promoted to 64-bit so that the 32- and 64-bit ELF records can be the same.
decodeEhdr :: B.ByteString -> Either (Get.ByteOffset, String) (SomeElf Ehdr)
decodeEhdr b = do
  when (B.length b <= 16) $ do
    Left (0, "Buffer too short.")
  let ei_magic = B.take 4 b
  unless (ei_magic == elfMagic) $
    Left (0, "Invalid magic number for ELF: " ++ show (ei_magic, elfMagic))
  cl <- case B.index b 4 of
          1 -> Right (SomeElf ELFCLASS32)
          2 -> Right (SomeElf ELFCLASS64)
          clb -> Left (4, "Invalid class: " <> show clb)
  d <- case B.index b 5 of
         1 -> Right ELFDATA2LSB
         2 -> Right ELFDATA2MSB
         db -> Left (5, "Invalid ata: " <> show db)
  let version = B.index b 6
  unless (version == expectedElfVersion) $
     Left (6, "Invalid version number for ELF")
  let osabi = ElfOSABI (B.index b 7)
  let abiver = B.index b 8
  let m =
        case cl of
          SomeElf ELFCLASS32 -> do
            SomeElf <$> decodeEhdr32 d osabi abiver b
          SomeElf ELFCLASS64 -> do
            SomeElf <$> decodeEhdr64 d osabi abiver b
  case strictRunGetOrFail m (B.drop 16 b) of
    Left (_, o, e) -> Left (o, e)
    Right (_,_, r) -> Right r
