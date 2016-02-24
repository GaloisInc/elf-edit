{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE RankNTypes #-}
module Data.Elf.Types
  ( -- * Top leve ldeclaration
    Elf(..)
  , emptyElf
  , elfFileData
    -- ** ElfClass
  , ElfClass(..)
  , fromElfClass
  , SomeElfClass(..)
  , toSomeElfClass
  , elfClassInstances
    -- **  ElfData
  , ElfData(..)
  , fromElfData
  , toElfData
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
  , fromElfOSABI
    -- ** ElfType
  , ElfType(..)
  , pattern ET_NONE
  , pattern ET_REL
  , pattern ET_EXEC
  , pattern ET_DYN
  , pattern ET_CORE
    -- ** ElfMachine
  , ElfMachine(..)
  , fromElfMachine
  , toElfMachine
    -- * ElfDataRegion
  , ElfDataRegion(..)
    -- * ElfSection
  , ElfSection(..)
    -- ** Elf section type
  , ElfSectionType(..)
  , pattern SHT_NULL
  , pattern SHT_PROGBITS
  , pattern SHT_SYMTAB
  , pattern SHT_STRTAB
  , pattern SHT_RELA
  , pattern SHT_HASH
  , pattern SHT_DYNAMIC
  , pattern SHT_NOTE
  , pattern SHT_NOBITS
  , pattern SHT_REL
  , pattern SHT_SHLIB
  , pattern SHT_DYNSYM
    -- ** Elf section flags
  , ElfSectionFlags(..)
  , shf_none
  , shf_write
  , shf_alloc
  , shf_execinstr
  , shf_merge
  , shf_tls
    -- ** ElfGOT
  , ElfGOT(..)
  , elfGotSize
  , elfGotSection
  , elfGotSectionFlags
    --  * Memory size
  , ElfMemSize(..)
    -- * ElfSegment
  , ElfSegment(..)
  , ppSegment
    -- ** Elf segment type
  , ElfSegmentType(..)
  , pattern PT_NULL
  , pattern PT_LOAD
  , pattern PT_DYNAMIC
  , pattern PT_INTERP
  , pattern PT_NOTE
  , pattern PT_SHLIB
  , pattern PT_PHDR
  , pattern PT_TLS
  , pattern PT_NUM
  , pattern PT_LOOS
  , pattern PT_GNU_EH_FRAME
  , pattern PT_GNU_STACK
  , pattern PT_GNU_RELRO
  , pattern PT_HIOS
  , pattern PT_LOPROC
  , pattern PT_HIPROC
    -- ** Elf segment flags
  , ElfSegmentFlags(..)
  , pf_none, pf_x, pf_w, pf_r
    -- * ElfHeader
  , ElfHeader(..)
  , elfHeader
  , expectedElfVersion
    -- * Range
  ,  Range
  , inRange
  , slice
  , sliceL
    -- * Utilities
  , enumCnt
  , hasPermissions
  , ppHex
  ) where

import           Control.Lens hiding (enum)
import           Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import qualified Data.Foldable as F
import           Data.List (intercalate)
import qualified Data.Map as Map
import qualified Data.Sequence as Seq
import qualified Data.Vector as V
import           Data.Word
import           Numeric (showHex)
import           Text.PrettyPrint.ANSI.Leijen hiding ((<>), (<$>))

import           Data.Elf.TH

-- | @p `hasPermissions` req@ returns true if all bits set in 'req' are set in 'p'.
hasPermissions :: Bits b => b -> b -> Bool
hasPermissions p req = (p .&. req) == req
{-# INLINE hasPermissions #-}

------------------------------------------------------------------------
-- Range

-- | A range contains a starting index and a byte count.
type Range w = (w,w)

inRange :: (Ord w, Num w) => w -> Range w -> Bool
inRange w (s,c) = s <= w && (w-s) < c

slice :: Integral w => Range w -> B.ByteString -> B.ByteString
slice (i,c) = B.take (fromIntegral c) . B.drop (fromIntegral i)

sliceL :: Integral w => Range w -> L.ByteString -> L.ByteString
sliceL (i,c) = L.take (fromIntegral c) . L.drop (fromIntegral i)

------------------------------------------------------------------------
-- Utilities

-- | 'enumCnt b c' returns a list with c enum values starting from 'b'.
enumCnt :: (Enum e, Real r) => e -> r -> [e]
enumCnt e x = if x > 0 then e : enumCnt (succ e) (x-1) else []

-- | Shows a bitwise combination of flags
showFlags :: (Bits w, Integral w, Show w) => V.Vector String -> Int -> w -> ShowS
showFlags names d w =
  case l of
        [] -> showString "pf_none"
        [e] -> showString e
        _ -> showParen (d > orPrec) $ showString $ intercalate " .|. " l
  where orPrec = 5
        nl = V.length names
        unknown = w .&. complement (1 `shiftR` nl - 1)
        l = map (names V.!) (filter (testBit w) (enumCnt 0 nl))
              ++ (if unknown /= 0 then ["0x" ++ showHex unknown ""] else [])


ppShow :: Show v => v -> Doc
ppShow = text . show

ppHex :: (Bits a, Integral a, Show a) => a -> String
ppHex v = "0x" ++ fixLength (bitSizeMaybe v) (showHex v "")
  where fixLength (Just n) s | r == 0 && w > l = replicate (w - l) '0' ++ s
          where (w,r) = n `quotRem` 4
                l = length s
        fixLength _ s = s

------------------------------------------------------------------------
-- ElfClass

-- | A flag indicating whether Elf is 32 or 64-bit.
data ElfClass w where
  ELFCLASS32 :: ElfClass Word32
  ELFCLASS64 :: ElfClass Word64

instance Show (ElfClass w) where
  show ELFCLASS32 = "ELFCLASS32"
  show ELFCLASS64 = "ELFCLASS64"

fromElfClass :: ElfClass w -> Word8
fromElfClass ELFCLASS32 = 1
fromElfClass ELFCLASS64 = 2

-- | A flag indicating this is either 32 or 64 bit.
data SomeElfClass = forall w . SomeElfClass !(ElfClass w)

toSomeElfClass :: Word8 -> Maybe SomeElfClass
toSomeElfClass 1 = Just (SomeElfClass ELFCLASS32)
toSomeElfClass 2 = Just (SomeElfClass ELFCLASS64)
toSomeElfClass _ = Nothing

-- | Given a provides a way to access 'Bits', 'Integral' and 'Show' instances
-- of underlying word types associated with an 'ElfClass'.
elfClassInstances :: ElfClass w -> ((Bits w, Integral w, Show w) => a) -> a
elfClassInstances ELFCLASS32 a = a
elfClassInstances ELFCLASS64 a = a

------------------------------------------------------------------------
-- ElfData

-- | A flag indicating byte order used to encode data.
data ElfData = ELFDATA2LSB -- ^ Least significant byte first
             | ELFDATA2MSB -- ^ Most significant byte first.
  deriving (Eq, Ord, Show)

toElfData :: Word8 -> Maybe ElfData
toElfData 1 = Just $ ELFDATA2LSB
toElfData 2 = Just $ ELFDATA2MSB
toElfData _ = Nothing

fromElfData :: ElfData -> Word8
fromElfData ELFDATA2LSB = 1
fromElfData ELFDATA2MSB = 2

------------------------------------------------------------------------
-- ElfOSABI

-- | A flag identifying the OS or ABI specific Elf extensions used.
newtype ElfOSABI = ElfOSABI { fromElfOSABI :: Word8 }
  deriving (Eq, Ord, Show)

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

------------------------------------------------------------------------
-- ElfType

-- | The type of information stored in the Elf file.
newtype ElfType = ElfType { fromElfType :: Word16 }
  deriving (Eq, Ord)

-- | Unspecified elf type.
pattern ET_NONE = ElfType 0
-- | Relocatable object file
pattern ET_REL  = ElfType 1
-- | Executable object file
pattern ET_EXEC = ElfType 2
-- | Shared object file
pattern ET_DYN  = ElfType 3
-- | Core dump object file
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

[enum|
 ElfMachine :: Word16
 EM_NONE          0 -- ^ No machine
 EM_M32           1 -- ^ AT&T WE 32100
 EM_SPARC         2 -- ^ SPARC
 EM_386           3 -- ^ Intel 80386
 EM_68K           4 -- ^ Motorola 68000
 EM_88K           5  -- ^ Motorola 88000
 EM_486           6 -- ^ Intel i486 (DO NOT USE THIS ONE)
 EM_860           7 -- ^ Intel 80860
 EM_MIPS          8 -- ^ MIPS I Architecture
 EM_S370          9 -- ^ IBM System/370 Processor
 EM_MIPS_RS3_LE  10 -- ^ MIPS RS3000 Little-endian
 EM_SPARC64      11 -- ^ SPARC 64-bit
 EM_PARISC       15 -- ^ Hewlett-Packard PA-RISC
 EM_VPP500       17 -- ^ Fujitsu VPP500
 EM_SPARC32PLUS  18 -- ^ Enhanced instruction set SPARC
 EM_960          19 -- ^ Intel 80960
 EM_PPC          20 -- ^ PowerPC
 EM_PPC64        21 -- ^ 64-bit PowerPC
 EM_S390         22 -- ^ IBM System/390 Processor
 EM_SPU          23 -- ^ Cell SPU
 EM_V800         36 -- ^ NEC V800
 EM_FR20         37 -- ^ Fujitsu FR20
 EM_RH32         38 -- ^ TRW RH-32
 EM_RCE          39 -- ^ Motorola RCE
 EM_ARM          40 -- ^ Advanced RISC Machines ARM
 EM_ALPHA        41 -- ^ Digital Alpha
 EM_SH           42 -- ^ Hitachi SH
 EM_SPARCV9      43 -- ^ SPARC Version 9
 EM_TRICORE      44 -- ^ Siemens TriCore embedded processor
 EM_ARC          45 -- ^ Argonaut RISC Core, Argonaut Technologies Inc.
 EM_H8_300       46 -- ^ Hitachi H8/300
 EM_H8_300H      47 -- ^ Hitachi H8/300H
 EM_H8S          48 -- ^ Hitachi H8S
 EM_H8_500       49 -- ^ Hitachi H8/500
 EM_IA_64        50 -- ^ Intel IA-64 processor architecture
 EM_MIPS_X       51 -- ^ Stanford MIPS-X
 EM_COLDFIRE     52 -- ^ Motorola ColdFire
 EM_68HC12       53 -- ^ Motorola M68HC12
 EM_MMA          54 -- ^ Fujitsu MMA Multimedia Accelerator
 EM_PCP          55 -- ^ Siemens PCP
 EM_NCPU         56 -- ^ Sony nCPU embedded RISC processor
 EM_NDR1         57 -- ^ Denso NDR1 microprocessor
 EM_STARCORE     58 -- ^ Motorola Star*Core processor
 EM_ME16         59 -- ^ Toyota ME16 processor
 EM_ST100        60 -- ^ STMicroelectronics ST100 processor
 EM_TINYJ        61 -- ^ Advanced Logic Corp. TinyJ embedded processor family
 EM_X86_64       62 -- ^ AMD x86-64 architecture
 EM_PDSP         63 -- ^ Sony DSP Processor
 EM_FX66         66 -- ^ Siemens FX66 microcontroller
 EM_ST9PLUS      67 -- ^ STMicroelectronics ST9+ 8/16 bit microcontroller
 EM_ST7          68 -- ^ STMicroelectronics ST7 8-bit microcontroller
 EM_68HC16       69 -- ^ Motorola MC68HC16 Microcontroller
 EM_68HC11       70 -- ^ Motorola MC68HC11 Microcontroller
 EM_68HC08       71 -- ^ Motorola MC68HC08 Microcontroller
 EM_68HC05       72 -- ^ Motorola MC68HC05 Microcontroller
 EM_SVX          73 -- ^ Silicon Graphics SVx
 EM_ST19         74 -- ^ STMicroelectronics ST19 8-bit microcontroller
 EM_VAX          75 -- ^ Digital VAX
 EM_CRIS         76 -- ^ Axis Communications 32-bit embedded processor
 EM_JAVELIN      77 -- ^ Infineon Technologies 32-bit embedded processor
 EM_FIREPATH     78 -- ^ Element 14 64-bit DSP Processor
 EM_ZSP          79 -- ^ LSI Logic 16-bit DSP Processor
 EM_MMIX         80 -- ^ Donald Knuth's educational 64-bit processor
 EM_HUANY        81 -- ^ Harvard University machine-independent object files
 EM_PRISM        82 -- ^ SiTera Prism
 EM_AVR          83 -- ^ Atmel AVR 8-bit microcontroller
 EM_FR30         84 -- ^ Fujitsu FR30
 EM_D10V         85 -- ^ Mitsubishi D10V
 EM_D30V         86 -- ^ Mitsubishi D30V
 EM_V850         87  -- ^ NEC v850
 EM_M32R         88 -- ^ Mitsubishi M32R
 EM_MN10300      89 -- ^ Matsushita MN10300
 EM_MN10200      90 -- ^ Matsushita MN10200
 EM_PJ           91 -- ^ picoJava
 EM_OPENRISC     92 -- ^ OpenRISC 32-bit embedded processor
 EM_ARC_A5       93 -- ^ ARC Cores Tangent-A5
 EM_XTENSA       94 -- ^ Tensilica Xtensa Architecture
 EM_VIDEOCORE    95 -- ^ Alphamosaic VideoCore processor
 EM_TMM_GPP      96 -- ^ Thompson Multimedia General Purpose Processor
 EM_NS32K        97 -- ^ National Semiconductor 32000 series
 EM_TPC          98 -- ^ Tenor Network TPC processor
 EM_SNP1K        99 -- ^ Trebia SNP 1000 processor
 EM_ST200       100 -- ^ STMicroelectronics (www.st.com) ST200 microcontroller
 EM_IP2K        101 -- ^ Ubicom IP2xxx microcontroller family
 EM_MAX         102 -- ^ MAX Processor
 EM_CR          103 -- ^ National Semiconductor CompactRISC microprocessor
 EM_F2MC16      104 -- ^ Fujitsu F2MC16
 EM_MSP430      105 -- ^ Texas Instruments embedded microcontroller msp430
 EM_BLACKFIN    106 -- ^ Analog Devices Blackfin (DSP) processor
 EM_SE_C33      107 -- ^ S1C33 Family of Seiko Epson processors
 EM_SEP         108 -- ^ Sharp embedded microprocessor
 EM_ARCA        109 -- ^ Arca RISC Microprocessor
 EM_UNICORE     110 -- ^ Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University
 EM_TI_C6000	140 -- Texas Instruments TMS320C6000 DSP family
 EM_L1OM        180 -- Intel L10M
 EM_K1OM        181 -- Intel K10M
 EM_EXT           _  -- ^ Other
|]

------------------------------------------------------------------------
-- ElfSectionType

-- | The type associated with an Elf file.
newtype ElfSectionType = ElfSectionType { fromElfSectionType :: Word32 }
  deriving (Eq, Ord)

-- | Identifies an empty section header.
pattern SHT_NULL     = ElfSectionType  0
-- | Contains information defined by the program
pattern SHT_PROGBITS = ElfSectionType  1
-- | Contains a linker symbol table
pattern SHT_SYMTAB   = ElfSectionType  2
-- | Contains a string table
pattern SHT_STRTAB   = ElfSectionType  3
-- | Contains "Rela" type relocation entries
pattern SHT_RELA     = ElfSectionType  4
-- | Contains a symbol hash table
pattern SHT_HASH     = ElfSectionType  5
-- | Contains dynamic linking tables
pattern SHT_DYNAMIC  = ElfSectionType  6
-- | Contains note information
pattern SHT_NOTE     = ElfSectionType  7
-- | Contains uninitialized space; does not occupy any space in the file
pattern SHT_NOBITS   = ElfSectionType  8
-- | Contains "Rel" type relocation entries
pattern SHT_REL      = ElfSectionType  9
-- | Reserved
pattern SHT_SHLIB    = ElfSectionType 10
-- | Contains a dynamic loader symbol table
pattern SHT_DYNSYM   = ElfSectionType 11

instance Show ElfSectionType where
  show tp =
    case tp of
      SHT_NULL     -> "SHT_NULL"
      SHT_PROGBITS -> "SHT_PROGBITS"
      SHT_SYMTAB   -> "SHT_SYMTAB"
      SHT_STRTAB   -> "SHT_STRTAB"
      SHT_RELA     -> "SHT_RELA"
      SHT_HASH     -> "SHT_HASH"
      SHT_DYNAMIC  -> "SHT_DYNAMIC"
      SHT_NOTE     -> "SHT_NOTE"
      SHT_NOBITS   -> "SHT_NOBITS"
      SHT_REL      -> "SHT_REL"
      SHT_SHLIB    -> "SHT_SHLIB"
      SHT_DYNSYM   -> "SHT_DYNSYM"
      ElfSectionType w -> "(Unknown type " ++ show w ++ ")"

------------------------------------------------------------------------
-- ElfSectionFlags

-- | Flags for sections
newtype ElfSectionFlags w = ElfSectionFlags { fromElfSectionFlags :: w }
  deriving (Eq, Bits)

instance (Bits w, Integral w, Show w) => Show (ElfSectionFlags w) where
  showsPrec d (ElfSectionFlags w) = showFlags names d w
    where names = V.fromList ["shf_write", "shf_alloc", "shf_execinstr"]

-- | Empty set of flags
shf_none :: Num w => ElfSectionFlags w
shf_none = ElfSectionFlags 0x0

-- | Section contains writable data
shf_write :: Num w => ElfSectionFlags w
shf_write = ElfSectionFlags 0x1

-- | Section is allocated in memory image of program
shf_alloc :: Num w => ElfSectionFlags w
shf_alloc = ElfSectionFlags 0x2

-- | Section contains executable instructions
shf_execinstr :: Num w => ElfSectionFlags w
shf_execinstr = ElfSectionFlags 0x4

-- | The contents of this section can be merged with elements in
-- sections of the same name, type, and flags.
shf_merge :: Num w => ElfSectionFlags w
shf_merge = ElfSectionFlags 0x10

-- | Section contains TLS data (".tdata" or ".tbss")
--
-- Information in it may be modified by the dynamic linker, but is only copied
-- once the binary is linked.
shf_tls :: Num w => ElfSectionFlags w
shf_tls = ElfSectionFlags 0x400

------------------------------------------------------------------------
-- ElfSection

-- | A section in the Elf file.
data ElfSection w = ElfSection
    { elfSectionName      :: !String
      -- ^ Identifies the name of the section.
    , elfSectionType      :: !ElfSectionType
      -- ^ Identifies the type of the section.
    , elfSectionFlags     :: !(ElfSectionFlags w)
      -- ^ Identifies the attributes of the section.
    , elfSectionAddr      :: !w
      -- ^ The virtual address of the beginning of the section in memory.
      --
      -- This should be 0 for sections that are not loaded into target memory.
    , elfSectionSize      :: !w
      -- ^ The size of the section. Except for SHT_NOBITS sections, this is the
      -- size of elfSectionData.
    , elfSectionLink      :: !Word32
      -- ^ Contains a section index of an associated section, depending on section type.
    , elfSectionInfo      :: !Word32
      -- ^ Contains extra information for the index, depending on type.
    , elfSectionAddrAlign :: !w
      -- ^ Contains the required alignment of the section.  This should be a power of
      -- two, and the address of the section should be a multiple of the alignment.
      --
      -- Note that when writing files, no effort is made to add padding so that the
      -- alignment constraint is correct.  It is up to the user to insert raw data segments
      -- as needed for padding.  We considered inserting padding automatically, but this
      -- can result in extra bytes inadvertently appearing in loadable segments, thus
      -- breaking layout constraints.  In particular, 'ld' sometimes generates files where
      -- the '.bss' section address is not a multiple of the alignment.
    , elfSectionEntSize   :: !w
      -- ^ Size of entries if section has a table.
    , elfSectionData      :: !B.ByteString
      -- ^ Data in section.
    } deriving (Eq, Show)

------------------------------------------------------------------------
-- ElfGOT

-- | A global offset table section.
data ElfGOT w = ElfGOT
    { elfGotName      :: !String -- ^ Name of section.
    , elfGotAddr      :: !w
    , elfGotAddrAlign :: !w
    , elfGotEntSize   :: !w
    , elfGotData      :: !B.ByteString
    } deriving (Show)

elfGotSize :: Num w => ElfGOT w -> w
elfGotSize g = fromIntegral (B.length (elfGotData g))

elfGotSectionFlags :: (Bits w, Num w) => ElfSectionFlags w
elfGotSectionFlags = shf_write .|. shf_alloc

-- | Convert a GOT section to a standard section.
elfGotSection :: (Bits w, Num w) => ElfGOT w -> ElfSection w
elfGotSection g =
  ElfSection { elfSectionName = elfGotName g
             , elfSectionType = SHT_PROGBITS
             , elfSectionFlags = elfGotSectionFlags
             , elfSectionAddr = elfGotAddr g
             , elfSectionSize = elfGotSize g
             , elfSectionLink = 0
             , elfSectionInfo = 0
             , elfSectionAddrAlign = elfGotAddrAlign g
             , elfSectionEntSize = elfGotEntSize g
             , elfSectionData = elfGotData g
             }

------------------------------------------------------------------------
-- ElfSegmentType

-- | The type of an elf segment
newtype ElfSegmentType = ElfSegmentType { fromElfSegmentType :: Word32 }
  deriving (Eq,Ord)

-- | Unused entry
pattern PT_NULL    = ElfSegmentType 0
-- | Loadable program segment
pattern PT_LOAD    = ElfSegmentType 1
-- | Dynamic linking information
pattern PT_DYNAMIC = ElfSegmentType 2
-- | Program interpreter path name
pattern PT_INTERP  = ElfSegmentType 3
-- | Note sections
pattern PT_NOTE    = ElfSegmentType 4
-- | Reserved
pattern PT_SHLIB   = ElfSegmentType 5
-- | Program header table
pattern PT_PHDR    = ElfSegmentType 6
-- | A thread local storage segment
--
-- See 'https://www.akkadia.org/drepper/tls.pdf'
pattern PT_TLS     = ElfSegmentType 7
-- | A number of defined types.
pattern PT_NUM     = ElfSegmentType 8

-- | Start of OS-specific
pattern PT_LOOS    = ElfSegmentType 0x60000000

-- | The GCC '.eh_frame_hdr' segment
pattern PT_GNU_EH_FRAME = ElfSegmentType 0x6474e550
-- | Indicates if stack should be executable.
pattern PT_GNU_STACK    = ElfSegmentType 0x6474e551
-- | GNU segment with relocation that may be read-only.
pattern PT_GNU_RELRO    = ElfSegmentType 0x6474e552

-- | End of OS-specific
pattern PT_HIOS    = ElfSegmentType 0x6fffffff

-- | Start of OS-specific
pattern PT_LOPROC  = ElfSegmentType 0x70000000
-- | End of OS-specific
pattern PT_HIPROC  = ElfSegmentType 0x7fffffff

elfSegmentTypeNameMap :: Map.Map ElfSegmentType String
elfSegmentTypeNameMap = Map.fromList $
  [ (,) PT_NULL         "NULL"
  , (,) PT_LOAD         "LOAD"
  , (,) PT_DYNAMIC      "DYNAMIC"
  , (,) PT_INTERP       "INTERP"
  , (,) PT_NOTE         "NOTE"
  , (,) PT_SHLIB        "SHLIB"
  , (,) PT_PHDR         "PHDR"
  , (,) PT_TLS          "TLS"
  , (,) PT_GNU_EH_FRAME "GNU_EH_FRAME"
  , (,) PT_GNU_STACK    "GNU_STACK"
  , (,) PT_GNU_RELRO    "GNU_RELRO"
  ]

instance Show ElfSegmentType where
  show tp =
    case Map.lookup tp elfSegmentTypeNameMap of
      Just s -> "PT_" ++ s
      Nothing -> "ElfSegmentType " ++ show (fromElfSegmentType tp)

------------------------------------------------------------------------
-- ElfSegmentFlags

-- | The flags (permission bits on an elf segment.
newtype ElfSegmentFlags  = ElfSegmentFlags { fromElfSegmentFlags :: Word32 }
  deriving (Eq, Num, Bits)

instance Show ElfSegmentFlags where
  showsPrec d (ElfSegmentFlags w) = showFlags names d w
    where names = V.fromList [ "pf_x", "pf_w", "pf_r" ]

-- | No permissions
pf_none :: ElfSegmentFlags
pf_none = ElfSegmentFlags 0

-- | Execute permission
pf_x :: ElfSegmentFlags
pf_x = ElfSegmentFlags 1

-- | Write permission
pf_w :: ElfSegmentFlags
pf_w = ElfSegmentFlags 2

-- | Read permission
pf_r :: ElfSegmentFlags
pf_r = ElfSegmentFlags 4

------------------------------------------------------------------------
-- ElfMemSize

-- | This describes the size of a elf section or segment memory size.
data ElfMemSize w
   = ElfAbsoluteSize !w
     -- ^ The region  has the given absolute size
   | ElfRelativeSize !w
     -- ^ The given offset should be added to the computed size.
  deriving (Show)

------------------------------------------------------------------------
-- ElfSegment and ElfDataRegion

-- | Information about an elf segment
--
-- The parameter should be a 'Word32' or 'Word64' depending on whether this
-- is a 32 or 64-bit elf file.
data ElfSegment w = ElfSegment
  { elfSegmentType      :: !ElfSegmentType
    -- ^ Segment type
  , elfSegmentFlags     :: !ElfSegmentFlags
    -- ^ Segment flags
  , elfSegmentIndex     :: !Word16
    -- ^ A 0-based index indicating the position of the segment in the Phdr table
    --
    -- The index of a segment should be unique and range from '0' to one less than
    -- the number of segemnts in the Elf file.
    -- Since the phdr table is typically stored in a loaded segment, the number of
    -- entries affects the layout of binaries.
  , elfSegmentVirtAddr  :: !w
    -- ^ Virtual address for the segment
  , elfSegmentPhysAddr  :: !w
    -- ^ Physical address for the segment.
    --
    -- This contents are typically not used on executables and shared libraries
    -- as they are not loaded at fixed physical addresses.  The convention
    -- seems to be to set 'eltSegmentPhysAddr' to 'elfSegmentVirtAddr'
  , elfSegmentAlign     :: !w
    -- ^ The value to which this segment is aligned in memory and the file.
    -- This field is called @p_align@ in Elf documentation.
    --
    -- A value of 0 or 1 means no alignment is required.  This gives the
    -- value to which segments are loaded in the file.  If it is not 0 or 1,
    -- then is hould be a positve power of two.  'elfSegmentVirtAddr' should
    -- be congruent to the segment offset in the file modulo 'elfSegmentAlign'.
    -- e.g., if file offset is 'o', alignment is 'n', and virtual address is 'a',
    -- then 'o mod n = a mod n'
    --
    -- Note that when writing files, no effort is made to add padding so that the
    -- alignment property is expected.  It is up to the user to insert raw data segments
    -- as needed for padding.  We considered inserting padding automatically, but this
    -- can result in extra bytes inadvertently appearing in loadable segments, thus
    -- breaking layout constraints.
  , elfSegmentMemSize   :: !(ElfMemSize w)
    -- ^ Size in memory (may be larger then segment data)
  , elfSegmentData     :: !(Seq.Seq (ElfDataRegion w))
    -- ^ Regions contained in segment.
  }

-- | A region of data in the file.
data ElfDataRegion w
   = ElfDataElfHeader
     -- ^ Identifies the elf header
     --
     -- This should appear 1st in an in-order traversal of the file.
     -- This is represented explicitly as an elf data region as it may be part of
     -- an elf segment, and thus we need to know whether a segment contains it.
   | ElfDataSegmentHeaders
     -- ^ Identifies the program header table.
     --
     -- This is represented explicitly as an elf data region as it may be part of
     -- an elf segment, and thus we need to know whether a segment contains it.
   | ElfDataSegment (ElfSegment w)
     -- ^ A segment that contains other segments.
   | ElfDataSectionHeaders
     -- ^ Identifies the section header table.
     --
     -- This is represented explicitly as an elf data region as it may be part of
     -- an elf segment, and thus we need to know whether a segment contains it.
   | ElfDataSectionNameTable
     -- ^ The section for storing the section names.
   | ElfDataGOT (ElfGOT w)
     -- ^ A global offset table.
   | ElfDataSection (ElfSection w)
     -- ^ A section that has no special interpretation.
   | ElfDataRaw B.ByteString
     -- ^ Identifies an uninterpreted array of bytes.
  deriving Show

ppSegment :: (Bits w, Integral w, Show w) => ElfSegment w -> Doc
ppSegment s =
  text "type: " <+> ppShow (elfSegmentType s) <$$>
  text "flags:" <+> ppShow (elfSegmentFlags s) <$$>
  text "index:" <+> ppShow (elfSegmentIndex s) <$$>
  text "vaddr:" <+> text (ppHex (elfSegmentVirtAddr s)) <$$>
  text "paddr:" <+> text (ppHex (elfSegmentPhysAddr s)) <$$>
  text "align:" <+> ppShow (elfSegmentAlign s) <$$>
  text "msize:" <+> ppShow (elfSegmentMemSize s) <$$>
  text "data:"  <$$>
  indent 2 (ppShow (F.toList (elfSegmentData s)))

instance (Bits w, Integral w, Show w) => Show (ElfSegment w) where
  show s = show (ppSegment s)

------------------------------------------------------------------------
-- Elf

-- | The version of elf files supported by this parser
expectedElfVersion :: Word8
expectedElfVersion = 1

-- | The contents of an Elf file.  Many operations require that the
-- width parameter is either @Word32@ or @Word64@ dependings on whether
-- this is a 32-bit or 64-bit file.
data Elf w = Elf
    { elfData       :: !ElfData       -- ^ Identifies the data encoding of the object file.
    , elfClass      :: !(ElfClass w)  -- ^ Identifies width of elf class.
    , elfOSABI      :: !ElfOSABI
      -- ^ Identifies the operating system and ABI for which the object is prepared.
    , elfABIVersion :: !Word8
      -- ^ Identifies the ABI version for which the object is prepared.
    , elfType       :: !ElfType       -- ^ Identifies the object file type.
    , elfMachine    :: !ElfMachine    -- ^ Identifies the target architecture.
    , elfEntry      :: !w
      -- ^ Virtual address of the program entry point.
      --
      -- 0 for non-executable Elfs.
    , elfFlags      :: !Word32
      -- ^ Machine specific flags
    , _elfFileData  :: Seq.Seq (ElfDataRegion w)
      -- ^ Data to be stored in elf file.
    , elfRelroRange :: !(Maybe (Range w))
      -- ^ Range for Elf read-only relocation section.
    } deriving Show

-- | Create an empty elf file.
emptyElf :: ElfData -> ElfClass w -> ElfType -> ElfMachine -> Elf w
emptyElf d c tp m = elfClassInstances c $
  Elf { elfData       = d
      , elfClass      = c
      , elfOSABI      = ELFOSABI_SYSV
      , elfABIVersion = 0
      , elfType       = tp
      , elfMachine    = m
      , elfEntry      = 0
      , elfFlags      = 0
      , _elfFileData  = Seq.empty
      , elfRelroRange = Nothing
      }

-- | Lens to access top-level regions in Elf file.
elfFileData :: Simple Lens (Elf w) (Seq.Seq (ElfDataRegion w))
elfFileData = lens _elfFileData (\s v -> s { _elfFileData = v })

------------------------------------------------------------------------
-- ElfHeader

-- | This contain entry for the Elf header.
data ElfHeader w = ElfHeader { headerData       :: !ElfData
                             , headerClass      :: !(ElfClass w)
                             , headerOSABI      :: !ElfOSABI
                             , headerABIVersion :: !Word8
                             , headerType       :: !ElfType
                             , headerMachine    :: !ElfMachine
                             , headerEntry      :: !w
                             , headerFlags      :: !Word32
                             }

-- | Return the header information about the elf
elfHeader :: Elf w -> ElfHeader w
elfHeader e = ElfHeader { headerData       = elfData e
                        , headerClass      = elfClass e
                        , headerOSABI      = elfOSABI e
                        , headerABIVersion = elfABIVersion e
                        , headerType       = elfType e
                        , headerMachine    = elfMachine e
                        , headerEntry      = elfEntry e
                        , headerFlags      = elfFlags e
                        }
