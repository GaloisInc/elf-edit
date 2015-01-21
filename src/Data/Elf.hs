{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE DoAndIfThenElse #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE Rank2Types #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
-- | Data.Elf provides an interface for querying and manipulating Elf files.
module Data.Elf ( SomeElf(..)
                , ElfWidth
                , Elf(..)
                , ElfClass(..)
                , ElfData(..)
                , ElfOSABI(..)
                , ElfType(..)
                , ElfMachine(..)
                , ElfDataRegion(..)
                , hasElfMagic
                , parseElf

                , renderElf

                , elfSections
                , updateSections
                , findSectionByName
                , removeSectionByName

                , elfSegments
                , ElfSection(..)
                , ElfSectionType(..)
                , ElfSectionFlags
                , shf_none, shf_write, shf_alloc, shf_execinstr

                  -- * Segment operations.
                , ElfSegment
                , ElfSegmentF

                , ElfSegmentType(..)
                , elfSegmentType

                , ElfSegmentFlags
                , pf_none, pf_x, pf_w, pf_r
                , hasPermissions

                , elfSegmentFlags

                , elfSegmentVirtAddr
                , elfSegmentPhysAddr
                , elfSegmentAlign
                , elfSegmentMemSize
                , elfSegmentData

                , RenderedElfSegment
                , renderedElfSegments

                , ElfSymbolTableEntry(..)
                , ppSymbolTableEntries
                , ElfSymbolType(..)
                , fromElfSymbolType
                , toElfSymbolType
                , ElfSymbolBinding(..)
                , ElfSectionIndex(..)
                , parseSymbolTables
                , findSymbolDefinition
                , elfInterpreter
                , RelaEntry
                , ppRelaEntries
                , I386_RelocationType
                , X86_64_RelocationType
                , DynamicSection(..)
                , dynamicEntries
                ) where

import Control.Applicative
import Control.Exception ( assert )
import Control.Lens hiding (enum)
import Control.Monad
import Control.Monad.Error
import Data.Binary
import Data.Binary.Builder.Sized (Builder)
import qualified Data.Binary.Builder.Sized as U
import Data.Binary.Get as G
import Data.Bits
import qualified Data.ByteString      as B
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Lazy.UTF8 as L (toString)
import qualified Data.ByteString.UTF8 as B (fromString, toString)
import qualified Data.Foldable as F
import Data.Int
import Data.List (genericDrop, foldl', intercalate, sort, transpose)
import qualified Data.Map as Map
import Data.Maybe
import Data.Monoid
import qualified Data.Sequence as Seq
import qualified Data.Vector as V
import Numeric
import Text.PrettyPrint.Leijen hiding ((<>), (<$>))

import Data.Elf.TH

import Debug.Trace

------------------------------------------------------------------------
-- Utilities

enumCnt :: (Enum e, Real r) => e -> r -> [e]
enumCnt e x = if x > 0 then e : enumCnt (succ e) (x-1) else []

ppShow :: Show v => v -> Doc
ppShow = text . show

ppHex :: (Bits a, Integral a, Show a) => a -> String
ppHex v = "0x" ++ fixLength (bitSizeMaybe v) (showHex v "")
  where fixLength (Just n) s | r == 0 && w > l = replicate (w - l) '0' ++ s
          where (w,r) = n `quotRem` 4
                l = length s
        fixLength _ s = s

-- | @fixAlignment v a@ returns the smallest multiple of @a@
-- that is not less than @v@.
fixAlignment :: Integral w => w -> w -> w
fixAlignment v 0 = v
fixAlignment v 1 = v
fixAlignment v a0
    | m == 0 = c * a
    | otherwise = (c + 1) * a
  where a = fromIntegral a0
        (c,m) = v `divMod` a

-- | Shows a bitwise combination of flags
showFlags :: (Show w, Bits w, Integral w) => V.Vector String -> Int -> w -> ShowS
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

-- | @tryParse msg f v@ returns @fromJust (f v)@ is @f v@ returns a value,
-- and calls @fail@ otherwise.
tryParse :: Monad m => String -> (a -> Maybe b) -> a -> m b
tryParse desc toFn = maybe (fail ("Invalid " ++ desc)) return . toFn

runGetMany :: Get a -> L.ByteString -> [a]
runGetMany g0 bs0 = start g0 (L.toChunks bs0)
  where go :: Get a -> [B.ByteString] -> Decoder a -> [a]
        go _ _ (Fail _ _ msg)  = error $ "runGetMany: " ++ msg
        go g [] (Partial f)    = go g [] (f Nothing)
        go g (h:r) (Partial f) = go g r (f (Just h))
        go g l (Done bs _ v)   = v : start g (bs:l)

        start _ [] = []
        start g (h:r) | B.null h = start g r
        start g l = go g l (runGetIncremental g)

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
-- Elf

data Elf w = Elf
    { elfData       :: ElfData       -- ^ Identifies the data encoding of the object file.
    , elfVersion    :: Word8         -- ^ Identifies the version of the object file format.
    , elfOSABI      :: ElfOSABI      -- ^ Identifies the operating system and ABI for which the object is prepared.
    , elfABIVersion :: Word8         -- ^ Identifies the ABI version for which the object is prepared.
    , elfType       :: ElfType       -- ^ Identifies the object file type.
    , elfMachine    :: ElfMachine    -- ^ Identifies the target architecture.
    , elfEntry      :: w              -- ^ Virtual address of the program entry point. 0 for non-executable Elfs.
    , elfFlags      :: Word32          -- ^ Machine specific flags
    , _elfFileData  :: [ElfDataRegion w]
      -- ^ Data to be stored in elf file.
    , elfRelroRange :: !(Maybe (Range w))
      -- ^ Range for Elf read-only relocation section.
    } deriving (Show)

elfFileData :: Simple Lens (Elf w) [ElfDataRegion w]
elfFileData = lens _elfFileData (\s v -> s { _elfFileData = v })

[enum|
 ElfClass :: Word8
 ELFCLASS32  1
 ELFCLASS64  2
|]

[enum|
 ElfData :: Word8
 ELFDATA2LSB 1
 ELFDATA2MSB 2
|]

[enum|
 ElfOSABI :: Word8
 ELFOSABI_SYSV         0 -- ^ No extensions or unspecified
 ELFOSABI_HPUX         1 -- ^ Hewlett-Packard HP-UX
 ELFOSABI_NETBSD       2 -- ^ NetBSD
 ELFOSABI_LINUX        3 -- ^ Linux
 ELFOSABI_SOLARIS      6 -- ^ Sun Solaris
 ELFOSABI_AIX          7 -- ^ AIX
 ELFOSABI_IRIX         8 -- ^ IRIX
 ELFOSABI_FREEBSD      9 -- ^ FreeBSD
 ELFOSABI_TRU64       10 -- ^ Compaq TRU64 UNIX
 ELFOSABI_MODESTO     11 -- ^ Novell Modesto
 ELFOSABI_OPENBSD     12 -- ^ Open BSD
 ELFOSABI_OPENVMS     13 -- ^ Open VMS
 ELFOSABI_NSK         14 -- ^ Hewlett-Packard Non-Stop Kernel
 ELFOSABI_AROS        15 -- ^ Amiga Research OS
 ELFOSABI_ARM         97 -- ^ ARM
 ELFOSABI_STANDALONE 255 -- ^ Standalone (embedded) application
 ELFOSABI_EXT          _ -- ^ Other
|]

[enum|
 ElfType :: Word16
 ET_NONE 0 -- ^ Unspecified type
 ET_REL  1 -- ^ Relocatable object file
 ET_EXEC 2 -- ^ Executable object file
 ET_DYN  3 -- ^ Shared object file
 ET_CORE 4 -- ^ Core dump object file
 ET_EXT  _ -- ^ Other
|]

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

-- | Describes a block of data in the file.
data ElfDataRegion w
    -- | Identifies the elf header (should appear 1st in an in-order traversal of the file).
  = ElfDataElfHeader
    -- | Identifies the program header table.
  | ElfDataSegmentHeaders
    -- | A segment that contains other segments.
  | ElfDataSegment (ElfSegment w)
    -- | Identifies the section header table.
  | ElfDataSectionHeaders
    -- | The section for storing the section names.
  | ElfDataSectionNameTable
    -- | A global offset table.
  | ElfDataGOT (ElfGOT w)
    -- | Uninterpreted sections.
  | ElfDataSection (ElfSection w)
    -- | Identifies an uninterpreted array of bytes.
  | ElfDataRaw B.ByteString
  deriving (Show)

[enum|
 ElfSectionType :: Word32
 SHT_NULL           0 -- ^ Identifies an empty section header.
 SHT_PROGBITS       1 -- ^ Contains information defined by the program
 SHT_SYMTAB         2 -- ^ Contains a linker symbol table
 SHT_STRTAB         3 -- ^ Contains a string table
 SHT_RELA           4 -- ^ Contains "Rela" type relocation entries
 SHT_HASH           5 -- ^ Contains a symbol hash table
 SHT_DYNAMIC        6 -- ^ Contains dynamic linking tables
 SHT_NOTE           7 -- ^ Contains note information
 SHT_NOBITS         8 -- ^ Contains uninitialized space; does not occupy any space in the file
 SHT_REL            9 -- ^ Contains "Rel" type relocation entries
 SHT_SHLIB         10 -- ^ Reserved
 SHT_DYNSYM        11 -- ^ Contains a dynamic loader symbol table
 SHT_EXT            _ -- ^ Processor- or environment-specific type
|]

newtype ElfSectionFlags w = ElfSectionFlags { fromElfSectionFlags :: w }
  deriving (Eq, Num, Bits)

instance (Bits w, Integral w, Show w) => Show (ElfSectionFlags w) where
  showsPrec d (ElfSectionFlags w) = showFlags names d w
    where names = V.fromList ["shf_write", "shf_alloc", "shf_execinstr"]

-- | Empty set of flags
shf_none :: Num w => ElfSectionFlags w
shf_none = 0

-- | Section contains writable data
shf_write :: Num w => ElfSectionFlags w
shf_write = 1

-- | Section is allocated in memory image of program
shf_alloc :: Num w => ElfSectionFlags w
shf_alloc = 2

-- | Section contains executable instructions
shf_execinstr :: Num w => ElfSectionFlags w
shf_execinstr = 4

-- | A section in the Elf file.
data ElfSection w = ElfSection
    { elfSectionName      :: String            -- ^ Identifies the name of the section.
    , elfSectionType      :: ElfSectionType    -- ^ Identifies the type of the section.
    , elfSectionFlags     :: ElfSectionFlags w -- ^ Identifies the attributes of the section.
    , elfSectionAddr      :: w
      -- ^ The virtual address of the beginning of the section in memory.
      -- 0 for sections that are not loaded into target memory.
    , elfSectionSize      :: w                 -- ^ The size of the section. Except for SHT_NOBITS sections, this is the size of elfSectionData.
    , elfSectionLink      :: Word32            -- ^ Contains a section index of an associated section, depending on section type.
    , elfSectionInfo      :: Word32            -- ^ Contains extra information for the index, depending on type.
    , elfSectionAddrAlign :: w                 -- ^ Contains the required alignment of the section. Must be a power of two.
    , elfSectionEntSize   :: w                 -- ^ Size of entries if section has a table.
    , elfSectionData      :: B.ByteString      -- ^ Data in section.
    } deriving (Eq, Show)

-- | A global offset table section.
data ElfGOT w = ElfGOT
    { elfGotName      :: !String -- ^ Name of section.
    , elfGotAddr      :: !w
    , elfGotAddrAlign :: !w
    , elfGotEntSize   :: !w
    , elfGotData      :: !B.ByteString
    } deriving (Show)

elfGotSectionFlags :: (Bits w, Num w) => ElfSectionFlags w
elfGotSectionFlags = shf_write .|. shf_alloc

elfGotSize :: Num w => ElfGOT w -> w
elfGotSize g = fromIntegral (B.length (elfGotData g))

-- | Convert a GOT section to a standard section.
elfGotSection :: ElfWidth w => ElfGOT w -> ElfSection w
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

-- | Attempt to convert a section to a GOT.
elfSectionAsGOT :: (Monad m, Bits w, Num w)
                => ElfSection w
                -> m (ElfGOT w)
elfSectionAsGOT s = do
  -- TODO: Perform checks
  when (elfSectionType s /= SHT_PROGBITS) $ do
    fail "Unexpected type"
  when (elfSectionFlags s /= elfGotSectionFlags) $ do
    fail "Unexpected type"
  let d = elfSectionData s
  when (elfSectionSize s /= fromIntegral (B.length d)) $ do
    fail "Section size does not match data length."
  when (elfSectionLink s /= 0) $ do
    fail "Unexpected section length"
  when (elfSectionInfo s /= 0) $ do
    fail "Unexpected section info"
  return ElfGOT { elfGotName = elfSectionName s
                , elfGotAddr = elfSectionAddr s
                , elfGotAddrAlign = elfSectionAddrAlign s
                , elfGotEntSize = elfSectionEntSize s
                , elfGotData = d
                }

-- | Information about an elf segment (parameter is for type of data).
data ElfSegmentF w v = ElfSegment
  { elfSegmentType      :: ElfSegmentType  -- ^ Segment type
  , elfSegmentFlags     :: ElfSegmentFlags -- ^ Segment flags
  , elfSegmentVirtAddr  :: w               -- ^ Virtual address for the segment
  , elfSegmentPhysAddr  :: w               -- ^ Physical address for the segment
  , elfSegmentAlign     :: w               -- ^ Segment alignment
  , elfSegmentMemSize   :: w               -- ^ Size in memory (may be larger then segment data)
  , _elfSegmentData     :: v               -- ^ Identifies data in the segment.
  } deriving (Functor)

-- | Return true if segment has given type.
hasSegmentType :: ElfSegmentType -> ElfSegmentF w v -> Bool
hasSegmentType tp s = elfSegmentType s == tp

ppSegment :: (Bits w, Integral w, Show w, Show v) => ElfSegmentF w v -> Doc
ppSegment s =
    text "type: " <+> ppShow (elfSegmentType s) <$$>
    text "flags:" <+> ppShow (elfSegmentFlags s) <$$>
    text "vaddr:" <+> text (ppHex (elfSegmentVirtAddr s)) <$$>
    text "paddr:" <+> text (ppHex (elfSegmentPhysAddr s)) <$$>
    text "align:" <+> ppShow (elfSegmentAlign s) <$$>
    text "msize:" <+> ppShow (elfSegmentMemSize s) <$$>
    text "data:" <+> ppShow (elfSegmentMemSize s)

instance (Bits w, Integral w, Show w, Show v) => Show (ElfSegmentF w v) where
  show s = show (ppSegment s)

type ElfSegment w = ElfSegmentF w [ElfDataRegion w]

elfSegmentData :: Lens (ElfSegmentF w u) (ElfSegmentF w v) u v
elfSegmentData = lens _elfSegmentData (\s v -> s { _elfSegmentData = v })

[enum|
 ElfSegmentType :: Word32
 PT_NULL    0 -- ^ Unused entry
 PT_LOAD    1 -- ^ Loadable segment
 PT_DYNAMIC 2 -- ^ Dynamic linking tables
 PT_INTERP  3 -- ^ Program interpreter path name
 PT_NOTE    4 -- ^ Note sections
 PT_SHLIB   5 -- ^ Reserved
 PT_PHDR    6 -- ^ Program header table
 PT_GNU_EH_FRAME 0x6474e550 -- ^ Exception handling information.
 PT_GNU_STACK    0x6474e551 -- ^ Indicates if stack should be executable.
 PT_GNU_RELRO    0x6474e552 -- ^ GNU segment with relocation that may be read-only.
 PT_Other   _ -- ^ Some other type
 |]

newtype ElfSegmentFlags  = ElfSegmentFlags { fromElfSegmentFlags :: Word32 }
  deriving (Eq, Num, Bits)

instance Show ElfSegmentFlags where
  showsPrec d (ElfSegmentFlags w) = showFlags names d w
    where names = V.fromList [ "pf_x", "pf_w", "pf_r" ]

-- | No permissions
pf_none :: ElfSegmentFlags
pf_none = 0

-- | Execute permission
pf_x :: ElfSegmentFlags
pf_x = 1

-- | Write permission
pf_w :: ElfSegmentFlags
pf_w = 2

-- | Read permission
pf_r :: ElfSegmentFlags
pf_r = 4

-- | @hasPermissions p req@ returns @True@ if @p@ has permissions @req@.
hasPermissions :: ElfSegmentFlags -> ElfSegmentFlags -> Bool
hasPermissions p req = (p .&. req) == req

-- | Name of shstrtab (used to reduce spelling errors).
shstrtab :: String
shstrtab = ".shstrtab"

type StringTable = (Map.Map B.ByteString Word32, Builder)

-- | Insert bytestring in list of strings.
insertString :: StringTable -> B.ByteString -> StringTable
insertString a@(m,b) bs
    | Map.member bs m = a
    | otherwise = (m', b')
  where insertTail i = Map.insertWith (\_n o -> o) (B.drop i bs) offset
          where offset  = fromIntegral (U.length b) + fromIntegral i
        m' = foldr insertTail m (enumCnt 0 (B.length bs + 1))
        b' = b `mappend` U.fromByteString bs `mappend` U.singleton 0

-- | Create a string table from the list of strings, and return list of offsets.
stringTable :: [String] -> (B.ByteString, Map.Map String Word32)
stringTable strings = (res, stringMap)
  where res = B.concat $ L.toChunks (U.toLazyByteString b)
        empty_table = (Map.empty, mempty)
        -- Get list of strings as bytestrings.
        bsl = map B.fromString strings
        -- | Reverses individual bytestrings in list.
        revl = map B.reverse
        -- Compress entries by removing a string if it is the suffix of
        -- another string.
        compress (f:r@(s:_)) | B.isPrefixOf f s = compress r
        compress (f:r) = f:compress r
        compress [] = []
        entries = revl $ compress $ sort $ revl bsl
        -- Insert strings into map (first string must be empty string)
        empty_string = B.fromString ""
        (m,b) = foldl insertString empty_table (empty_string : entries)
        myFind bs =
          case Map.lookup bs m of
            Just v -> v
            Nothing -> error $ "internal: stringTable missing entry."
        stringMap = Map.fromList $ strings `zip` map myFind bsl

-- | Returns null-terminated string at given index in bytestring.
lookupString :: Word32 -> B.ByteString -> B.ByteString
lookupString o b = B.takeWhile (/= 0) $ B.drop (fromIntegral o) b

-- | Returns null-terminated string at given index in bytestring.
lookupStringL :: Int64 -> L.ByteString -> L.ByteString
lookupStringL o b = L.takeWhile (/= 0) $ L.drop o b

-- | Create a section for the section name table from the data.
elfNameTableSection :: Num w => B.ByteString -> ElfSection w
elfNameTableSection name_data =
  ElfSection {
      elfSectionName = shstrtab
    , elfSectionType = SHT_STRTAB
    , elfSectionFlags = shf_none
    , elfSectionAddr = 0
    , elfSectionSize = fromIntegral (B.length name_data)
    , elfSectionLink = 0
    , elfSectionInfo = 0
    , elfSectionAddrAlign = 1
    , elfSectionEntSize = 0
    , elfSectionData = name_data
    }

-- | Given a section name, extract the ElfSection.
findSectionByName :: ElfWidth w => String -> Elf w -> Maybe (ElfSection w)
findSectionByName name  = findOf elfSections byName
  where byName section  = elfSectionName section == name

-- | Traverse elements in a list and modify or delete them.
updateList :: Traversal [a] [b] a (Maybe b)
updateList _ [] = pure []
updateList f (h:l) = compose <$> f h <*> updateList f l
  where compose Nothing  r = r
        compose (Just e) r = e:r

-- | Traverse sections in Elf file and modify or delete them.
updateSections :: ElfWidth w
               => Traversal (Elf w) (Elf w) (ElfSection w) (Maybe (ElfSection w))
updateSections fn e0 = elfFileData (updateList impl) e0
  where (t,_) = stringTable $ map elfSectionName (toListOf elfSections e0)
        norm s
          | elfSectionName s == shstrtab = ElfDataSectionNameTable
          | elfSectionName s `elem` [".got", ".got.plt"] =
            case runIdentity (runErrorT (elfSectionAsGOT s)) of
              Left e -> error $ "Error in Data.Elf.updateSections: " ++ e
              Right v -> ElfDataGOT v
          | otherwise = ElfDataSection s
        impl (ElfDataSegment s) = Just . ElfDataSegment <$> s'
          where s' = s & elfSegmentData (updateList impl)
        impl ElfDataSectionNameTable = fmap norm <$> fn (elfNameTableSection t)
        impl (ElfDataGOT g) = fmap norm <$> fn (elfGotSection g)
        impl (ElfDataSection s) = fmap norm <$> fn s
        impl d = pure (Just d)

-- | Traverse elf sections
elfSections :: ElfWidth w => Simple Traversal (Elf w) (ElfSection w)
elfSections f = updateSections (fmap Just . f)

-- | Remove section with given name.
removeSectionByName :: ElfWidth w => String -> Elf w -> Elf w
removeSectionByName nm = over updateSections fn
  where fn s | elfSectionName s == nm = Nothing
             | otherwise = Just s

-- | List of segments in the file.
elfSegments :: Elf w -> [ElfSegment w]
elfSegments e = concatMap impl (e^.elfFileData)
  where impl (ElfDataSegment s) = s : concatMap impl (s^.elfSegmentData)
        impl _ = []

getWord16 :: ElfData -> Get Word16
getWord16 ELFDATA2LSB = getWord16le
getWord16 ELFDATA2MSB = getWord16be

getWord32 :: ElfData -> Get Word32
getWord32 ELFDATA2LSB = getWord32le
getWord32 ELFDATA2MSB = getWord32be

getWord64 :: ElfData -> Get Word64
getWord64 ELFDATA2LSB = getWord64le
getWord64 ELFDATA2MSB = getWord64be

-- | Returns length of section in file.
sectionFileLen :: Num w => ElfSectionType -> w -> w
sectionFileLen SHT_NOBITS _ = 0
sectionFileLen _ s = s

sectionData :: Integral w => ElfSectionType -> w -> w -> B.ByteString -> B.ByteString
sectionData SHT_NOBITS _ _ _ = B.empty
sectionData _ o s b = slice (o,s) b

type GetShdrFn w = B.ByteString
                 -> B.ByteString
                 -> Get (Range w, ElfSection w)

getShdr32 :: ElfData -> GetShdrFn Word32
getShdr32 d file string_section = do
  sh_name      <- getWord32 d
  sh_type      <- toElfSectionType <$> getWord32 d
  sh_flags     <- ElfSectionFlags  <$> getWord32 d
  sh_addr      <- getWord32 d
  sh_offset    <- getWord32 d
  sh_size      <- getWord32 d
  sh_link      <- getWord32 d
  sh_info      <- getWord32 d
  sh_addralign <- getWord32 d
  sh_entsize   <- getWord32 d
  let s = ElfSection
           { elfSectionName      = B.toString $ lookupString sh_name string_section
           , elfSectionType      = sh_type
           , elfSectionFlags     = sh_flags
           , elfSectionAddr      = sh_addr
           , elfSectionSize      = sh_size
           , elfSectionLink      = sh_link
           , elfSectionInfo      = sh_info
           , elfSectionAddrAlign = sh_addralign
           , elfSectionEntSize   = sh_entsize
           , elfSectionData      = sectionData sh_type sh_offset sh_size file
           }
  return ((sh_offset, sectionFileLen sh_type sh_size), s)

getShdr64 :: ElfData -> GetShdrFn Word64
getShdr64 er file string_section = do
  sh_name      <- getWord32 er
  sh_type      <- toElfSectionType <$> getWord32 er
  sh_flags     <- ElfSectionFlags  <$> getWord64 er
  sh_addr      <- getWord64 er
  sh_offset    <- getWord64 er
  sh_size      <- getWord64 er
  sh_link      <- getWord32 er
  sh_info      <- getWord32 er
  sh_addralign <- getWord64 er
  sh_entsize   <- getWord64 er
  let s = ElfSection
           { elfSectionName      = B.toString $ lookupString sh_name string_section
           , elfSectionType      = sh_type
           , elfSectionFlags     = sh_flags
           , elfSectionAddr      = sh_addr
           , elfSectionSize      = sh_size
           , elfSectionLink      = sh_link
           , elfSectionInfo      = sh_info
           , elfSectionAddrAlign = sh_addralign
           , elfSectionEntSize   = sh_entsize
           , elfSectionData = sectionData sh_type sh_offset sh_size file
    }
  return ((sh_offset, sectionFileLen sh_type sh_size), s)

type GetPhdrFn w = Get (ElfSegmentF w (Range w))

getPhdr32 :: ElfData -> GetPhdrFn Word32
getPhdr32 d = do
  p_type   <- toElfSegmentType  <$> getWord32 d
  p_offset <- getWord32 d
  p_vaddr  <- getWord32 d
  p_paddr  <- getWord32 d
  p_filesz <- getWord32 d
  p_memsz  <- getWord32 d
  p_flags  <- ElfSegmentFlags <$> getWord32 d
  p_align  <- getWord32 d
  return ElfSegment
       { elfSegmentType      = p_type
       , elfSegmentFlags     = p_flags
       , elfSegmentVirtAddr  = p_vaddr
       , elfSegmentPhysAddr  = p_paddr
       , elfSegmentAlign     = p_align
       , elfSegmentMemSize   = p_memsz
       , _elfSegmentData      = (p_offset, p_filesz)
       }

getPhdr64 :: ElfData -> GetPhdrFn Word64
getPhdr64 d = do
  p_type   <- toElfSegmentType  <$> getWord32 d
  p_flags  <- ElfSegmentFlags <$> getWord32 d
  p_offset <- getWord64 d
  p_vaddr  <- getWord64 d
  p_paddr  <- getWord64 d
  p_filesz <- getWord64 d
  p_memsz  <- getWord64 d
  p_align  <- getWord64 d
  return ElfSegment
         { elfSegmentType     = p_type
         , elfSegmentFlags    = p_flags
         , elfSegmentVirtAddr = p_vaddr
         , elfSegmentPhysAddr = p_paddr
         , elfSegmentAlign    = p_align
         , elfSegmentMemSize  = p_memsz
         , _elfSegmentData     = (p_offset,p_filesz)
         }

-- | Defines the layout of a table with elements of a fixed size.
data TableLayout w =
  TableLayout { tableOffset :: w
                -- ^ Offset where table starts relative to start of file.
              , entrySize :: Word16
                -- ^ Size of entries in bytes.
              , entryNum :: Word16
                -- ^ Number of entries in bytes.
              }

mkTableLayout :: w -> Word16 -> Word16 -> TableLayout w
mkTableLayout o s n = TableLayout o s n

-- | Returns offset of entry in table.
tableEntry :: Integral w => TableLayout w -> Word16 -> B.ByteString -> L.ByteString
tableEntry l i b = L.fromChunks [B.drop (fromIntegral o) b]
  where sz = fromIntegral (entrySize l)
        o = tableOffset l + fromIntegral i * sz

-- | Returns size of table.
tableSize :: Integral w => TableLayout w -> w
tableSize l = fromIntegral (entryNum l) * fromIntegral (entrySize l)

-- | Returns range in memory of table.
tableRange :: Integral w => TableLayout w -> Range w
tableRange l = (tableOffset l, tableSize l)

-- | Returns size of region.
type RegionSizeFn w = ElfDataRegion w -> w

-- | Function that transforms list of regions into new list.
type RegionPrefixFn w = [ElfDataRegion w] -> [ElfDataRegion w]

-- | Create a singleton list with a raw data region if one exists
insertRawRegion :: B.ByteString -> RegionPrefixFn w
insertRawRegion b r | B.length b == 0 = r
                    | otherwise = ElfDataRaw b : r

-- | Insert an elf data region at a given offset.
insertAtOffset :: Integral w
               => RegionSizeFn w   -- ^ Function for getting size of a region.
               -> Range w          -- ^ Range to insert in.
               -> RegionPrefixFn w -- ^ Insert function
               -> RegionPrefixFn w
insertAtOffset sizeOf (o,c) fn (p:r)
    -- Go to next segment if offset to insert is after p.
  | o >= sz = p:insertAtOffset sizeOf (o-sz,c) fn r
    -- Recurse inside segment if p is a segment that contains region to insert.
  | o + c <= sz
  , ElfDataSegment s <- p = -- New region ends before p ends and p is a segment.
      let s' = s & elfSegmentData %~ insertAtOffset sizeOf (o,c) fn
       in ElfDataSegment s' : r
    -- Insert into current region is offset is 0.
  | o == 0 = fn (p:r)
    -- Split a raw segment into prefix and post.
  | ElfDataRaw b <- p =
      -- We know offset is less than length of bytestring as otherwise we would
      -- have gone to next segment
      assert (fromIntegral o < B.length b) $ do
        let (pref,post) = B.splitAt (fromIntegral o) b
        insertRawRegion pref $ fn $ insertRawRegion post r
  | otherwise = error "Attempt to insert overlapping Elf region"
  where sz = sizeOf p
insertAtOffset _ (0,0) fn [] = fn []
insertAtOffset _ _ _ [] = error "Invalid region"

-- | Insert a leaf region into the region.
insertSpecialRegion :: Integral w
                    => RegionSizeFn w -- ^ Returns size of region.
                    -> Range w
                    -> ElfDataRegion w -- ^ New region
                    -> RegionPrefixFn w
insertSpecialRegion sizeOf r n = insertAtOffset sizeOf r fn
  where c = snd r
        fn l | c == 0 = n : l
        fn (ElfDataRaw b:l)
          | fromIntegral c <= B.length b
          = n : insertRawRegion (B.drop (fromIntegral c) b) l
        fn _ = error $ "Elf file contained a non-empty header that overlapped with another.\n"
                       ++ "  This is not supported by the Elf parser"

insertSegment :: forall w
               . (Bits w, Integral w, Show w)
              => RegionSizeFn w
              -> ElfSegmentF w (Range w)
              -> RegionPrefixFn w
insertSegment sizeOf d = insertAtOffset sizeOf rng (gather szd [])
  where rng@(_,szd) = d^.elfSegmentData
        -- | @gather@ inserts new segment into head of list after collecting existings
        -- data it contains.
        gather :: w -- ^ Number of bytes to insert.
               -> [ElfDataRegion w]
                  -- ^ Subsegments to insert into this segment.
                  -- Stored in reverse order.
               -> [ElfDataRegion w]
                  -- ^ Segments after insertion point.
               -> [ElfDataRegion w]
        -- Insert segment if there are 0 bytes left to process.
        gather 0 l r = ElfDataSegment (d & elfSegmentData .~ reverse l):r
        -- Collect p if it is contained within segment we are inserting.
        gather cnt l (p:r)
          | sizeOf p <= cnt
          = gather (cnt - sizeOf p) (p:l) r
        -- Split raw bytes into contiguous segments.
        gather cnt l (ElfDataRaw b:r) =
            ElfDataSegment d' : insertRawRegion post r
          where pref = B.take (fromIntegral cnt) b
                post = B.drop (fromIntegral cnt) b
                newData = reverse l ++ insertRawRegion pref []
                d' = d & elfSegmentData .~ newData
        gather cnt _ (p:_) =
          error $ "insertSegment: Inserted segments overlaps a previous segment.\n"
                ++ "  Previous segment: " ++ show p ++ "\n"
                ++ "  Previous segment size: " ++ show (sizeOf p) ++ "\n"
                ++ "  New segment:\n" ++ show (indent 2 (ppSegment d)) ++ "\n"
                ++ "  Remaining bytes: " ++ show cnt
        gather _ _ []    = error "insertSegment: Data ended before completion"

-- | Contains information needed to parse elf files.
data ElfParseInfo w = ElfParseInfo {
       -- | Size of ehdr table
       ehdrSize :: !Word16
       -- | Layout of segment header table.
     , phdrTable :: !(TableLayout w)
     , getPhdr :: !(GetPhdrFn w)
       -- | Index of section for storing section names.
     , shdrNameIdx :: !Word16
       -- | Layout of section header table.
     , shdrTable :: !(TableLayout w)
     , getShdr   :: !(GetShdrFn w)
     , fileContents :: !B.ByteString
     }

-- | Return size of region given parse information.
regionSize :: Integral w
           => ElfParseInfo w
           -> w -- ^ Contains size of name table
           -> RegionSizeFn w
regionSize epi nameSize = sizeOf
  where sizeOf ElfDataElfHeader        = fromIntegral $ ehdrSize epi
        sizeOf ElfDataSegmentHeaders   = tableSize $ phdrTable epi
        sizeOf (ElfDataSegment s)      = sum $ map sizeOf (s^.elfSegmentData)
        sizeOf ElfDataSectionHeaders   = tableSize $ shdrTable epi
        sizeOf ElfDataSectionNameTable = nameSize
        sizeOf (ElfDataGOT g)          = elfGotSize g
        sizeOf (ElfDataSection s)      = fromIntegral $ B.length (elfSectionData s)
        sizeOf (ElfDataRaw b)          = fromIntegral $ B.length b

elfMagic :: B.ByteString
elfMagic = B.fromString "\DELELF"

-- | Parse segment at given index.
segmentByIndex :: Integral w
               => ElfParseInfo w -- ^ Information for parsing
               -> Word16 -- ^ Index
               -> ElfSegmentF w (Range w)
segmentByIndex epi i =
  runGet (getPhdr epi) (tableEntry (phdrTable epi) i (fileContents epi))

-- | Return list of segments with contents.
rawSegments :: Integral w => ElfParseInfo w -> [ElfSegmentF w (Range w)]
rawSegments epi = segmentByIndex epi <$> enumCnt 0 (entryNum (phdrTable epi))

isRelroSegment :: ElfSegmentF w r -> Bool
isRelroSegment s = elfSegmentType s == PT_GNU_RELRO

-- | Extract relro information.
asRelroInfo :: [ElfSegmentF w (Range w)] -> Maybe (Range w)
asRelroInfo l =
  case filter isRelroSegment l of
    [] -> Nothing
    [s] -> Just (s^.elfSegmentData)
    _ -> error "Multiple relro segments."

-- | Parse elf region.
parseElfRegions :: ElfWidth w
                => ElfParseInfo w -- ^ Information for parsing.
                -> [ElfSegmentF w (Range w)]
                -> [ElfDataRegion w]
parseElfRegions epi segments = final
  where file = fileContents epi
        getSection i = runGet (getShdr epi file names)
                              (tableEntry (shdrTable epi) i file)
        nameRange = fst $ getSection (shdrNameIdx epi)
        sizeOf = regionSize epi (snd nameRange)
        names = slice nameRange file
        -- Define table with special data regions.
        headers = [ ((0, fromIntegral (ehdrSize epi)), ElfDataElfHeader)
                  , (tableRange (phdrTable epi), ElfDataSegmentHeaders)
                  , (tableRange (shdrTable epi), ElfDataSectionHeaders)
                  , (nameRange, ElfDataSectionNameTable)
                  ]
        -- Define table with regions for sections.
        dataSection (r,s) = (r, ElfDataSection s)
        sections = map (dataSection . getSection)
                 $ filter (/= shdrNameIdx epi)
                 $ enumCnt 0 (entryNum (shdrTable epi))
        -- Define initial region list without segments.
        initial  = foldr (uncurry (insertSpecialRegion sizeOf))
                         (insertRawRegion file [])
                         (headers ++ sections)
        final = foldr (insertSegment sizeOf) initial
              $ filter (not . isRelroSegment) segments

-- | Either a 32-bit or 64-bit elf file.
data SomeElf
   = Elf32 (Elf Word32)
   | Elf64 (Elf Word64)

parseElfResult :: Either (L.ByteString, ByteOffset, String) (L.ByteString, ByteOffset, a)
               -> Either (ByteOffset,String) a
parseElfResult (Left (_,o,e)) = Left (o,e)
parseElfResult (Right (_,_,v)) = Right v

-- | Return true if this bytestring has the 4 bytes "\DELELF" at the start.
hasElfMagic :: L.ByteString -> Bool
hasElfMagic l = either (const False) (const True) $ flip runGetOrFail l $ do
  ei_magic    <- getByteString 4
  unless (ei_magic == elfMagic) $
    fail "Invalid magic number for ELF"

-- | Parses a ByteString into an Elf record. Parse failures call error. 32-bit ELF objects hav
-- their fields promoted to 64-bit so that the 32- and 64-bit ELF records can be the same.
parseElf :: B.ByteString -> Either (ByteOffset,String) SomeElf
parseElf b = parseElfResult $ flip runGetOrFail (L.fromChunks [b]) $ do
  ei_magic    <- getByteString 4
  unless (ei_magic == elfMagic) $
    fail $ "Invalid magic number for ELF: " ++ show (ei_magic, elfMagic)
  ei_class   <- tryParse "ELF class" toElfClass =<< getWord8
  d          <- tryParse "ELF data"  toElfData =<< getWord8
  ei_version <- getWord8
  unless (ei_version == 1) $
    fail "Invalid version number for ELF"
  ei_osabi    <- toElfOSABI <$> getWord8
  ei_abiver   <- getWord8
  skip 7
  case ei_class of
    ELFCLASS32 -> Elf32 <$> parseElf32 d ei_version ei_osabi ei_abiver b
    ELFCLASS64 -> Elf64 <$> parseElf64 d ei_version ei_osabi ei_abiver b

-- | Parse a 32-bit elf.
parseElf32 :: ElfData -> Word8 -> ElfOSABI -> Word8 -> B.ByteString -> Get (Elf Word32)
parseElf32 d ei_version ei_osabi ei_abiver b = do
  e_type      <- toElfType    <$> getWord16 d
  e_machine   <- toElfMachine <$> getWord16 d
  e_version   <- getWord32 d
  unless (fromIntegral ei_version == e_version) $
    fail "ELF Version mismatch"
  e_entry     <- getWord32 d
  e_phoff     <- getWord32 d
  e_shoff     <- getWord32 d
  e_flags     <- getWord32 d
  e_ehsize    <- getWord16 d
  e_phentsize <- getWord16 d
  unless (e_phentsize == sizeOfPhdr32) $
    fail $ "Invalid segment entry size"
  e_phnum     <- getWord16 d
  e_shentsize <- getWord16 d
  unless (e_shentsize == sizeOfShdr32) $
    fail $ "Invalid section entry size"
  e_shnum     <- getWord16 d
  e_shstrndx  <- getWord16 d
  let epi = ElfParseInfo
                  { ehdrSize = e_ehsize
                  , phdrTable = mkTableLayout e_phoff e_phentsize e_phnum
                  , getPhdr = getPhdr32 d
                  , shdrNameIdx = e_shstrndx
                  , shdrTable = mkTableLayout e_shoff e_shentsize e_shnum
                  , getShdr = getShdr32 d
                  , fileContents = b
                  }
  let segments = rawSegments epi
  return Elf { elfData       = d
             , elfVersion    = ei_version
             , elfOSABI      = ei_osabi
             , elfABIVersion = ei_abiver
             , elfType       = e_type
             , elfMachine    = e_machine
             , elfEntry      = e_entry
             , elfFlags      = e_flags
             , _elfFileData  = parseElfRegions epi segments
             , elfRelroRange = asRelroInfo segments
             }

-- | Parse a 32-bit elf.
parseElf64 :: ElfData -> Word8 -> ElfOSABI -> Word8 -> B.ByteString -> Get (Elf Word64)
parseElf64 d ei_version ei_osabi ei_abiver b = do
  e_type      <- toElfType    <$> getWord16 d
  e_machine   <- toElfMachine <$> getWord16 d
  e_version   <- getWord32 d
  unless (fromIntegral ei_version == e_version) $
    fail "ELF Version mismatch"
  e_entry     <- getWord64 d
  e_phoff     <- getWord64 d
  e_shoff     <- getWord64 d
  e_flags     <- getWord32 d
  e_ehsize    <- getWord16 d
  e_phentsize <- getWord16 d
  e_phnum     <- getWord16 d
  e_shentsize <- getWord16 d
  e_shnum     <- getWord16 d
  e_shstrndx  <- getWord16 d
  let epi = ElfParseInfo
                  { ehdrSize    = e_ehsize
                  , phdrTable   = mkTableLayout e_phoff e_phentsize e_phnum
                  , getPhdr     = getPhdr64 d
                  , shdrNameIdx = e_shstrndx
                  , shdrTable   = mkTableLayout e_shoff e_shentsize e_shnum
                  , getShdr     = getShdr64 d
                  , fileContents = b
                  }
  let segments = rawSegments epi
  return Elf { elfData       = d
             , elfVersion    = ei_version
             , elfOSABI      = ei_osabi
             , elfABIVersion = ei_abiver
             , elfType       = e_type
             , elfMachine    = e_machine
             , elfEntry      = e_entry
             , elfFlags      = e_flags
             , _elfFileData  = parseElfRegions epi segments
             , elfRelroRange = asRelroInfo segments
             }

-- | A component in the field as written.
data ElfField v
  = EFBS Word16 (v -> Builder)
  | EFWord16 (v -> Word16)
  | EFWord32 (v -> Word32)
  | EFWord64 (v -> Word64)

-- | A record to be written to the Elf file.
type ElfRecord v = [(String, ElfField v)]

sizeOfField :: ElfField v -> Word16
sizeOfField (EFBS s _)   = s
sizeOfField (EFWord16 _) = 2
sizeOfField (EFWord32 _) = 4
sizeOfField (EFWord64 _) = 8

sizeOfRecord :: ElfRecord v -> Word16
sizeOfRecord = sum . map (sizeOfField . snd)

writeField :: ElfField v -> ElfData -> v -> Builder
writeField (EFBS _ f)   _           = f
writeField (EFWord16 f) ELFDATA2LSB = U.putWord16le . f
writeField (EFWord16 f) ELFDATA2MSB = U.putWord16be . f
writeField (EFWord32 f) ELFDATA2LSB = U.putWord32le . f
writeField (EFWord32 f) ELFDATA2MSB = U.putWord32be . f
writeField (EFWord64 f) ELFDATA2LSB = U.putWord64le . f
writeField (EFWord64 f) ELFDATA2MSB = U.putWord64be . f

writeRecord :: ElfRecord v -> ElfData -> v -> Builder
writeRecord fields d v =
  mconcat $ map (\(_,f) -> writeField f d v) fields

-- | Contains elf file, program header offset, section header offset.
type Ehdr w = (Elf w, ElfLayout w)
type Phdr w = ElfSegmentF w (Range w)
-- | Contains Elf section data, name offset, and data offset.
type Shdr w = (ElfSection w, Word32, w)

class (Bits w, Integral w, Show w) => ElfWidth w where
  -- | Returns elf class associated with width.
  -- Argument is not evaluated
  elfClass :: Elf w -> ElfClass

  ehdrFields :: ElfRecord (Ehdr w)
  phdrFields :: ElfRecord (Phdr w)
  shdrFields :: ElfRecord (Shdr w)

  symbolTableEntrySize :: w

  getSymbolTableEntry :: Elf w
                      -> (Word32 -> String)
                         -- ^ Function for mapping offset in string table
                         -- to bytestring.
                      -> Get (ElfSymbolTableEntry w)

-- | Write elf file out to bytestring.
renderElf :: ElfWidth w => Elf w -> L.ByteString
renderElf e = U.toLazyByteString (view elfOutput (elfLayout e))

type RenderedElfSegment w = ElfSegmentF w B.ByteString

-- | Returns elf segments with data in them.
renderedElfSegments :: ElfWidth w => Elf w -> [RenderedElfSegment w]
renderedElfSegments e = segFn <$> F.toList (allPhdrs l)
  where l = elfLayout e
        b = U.toStrictByteString (l^.elfOutput)
        segFn = elfSegmentData %~ flip slice b

elfIdentBuilder :: ElfWidth w  => Elf w -> Builder
elfIdentBuilder e =
  mconcat [ U.fromByteString elfMagic
          , U.singleton (fromElfClass (elfClass e))
          , U.singleton (fromElfData (elfData e))
          , U.singleton (elfVersion e)
          , U.singleton (fromElfOSABI (elfOSABI e))
          , U.singleton (fromIntegral (elfABIVersion e))
          , mconcat (replicate 7 (U.singleton 0))
          ]

ehdr32Fields :: ElfRecord (Ehdr Word32)
ehdr32Fields =
  [ ("e_ident",     EFBS 16  (\(e,_) -> elfIdentBuilder e))
  , ("e_type",      EFWord16 (\(e,_) -> fromElfType    $ elfType e))
  , ("e_machine",   EFWord16 (\(e,_) -> fromElfMachine $ elfMachine e))
  , ("e_version",   EFWord32 (\(e,_) -> fromIntegral   $ elfVersion e))
  , ("e_entry",     EFWord32 (\(e,_) -> elfEntry e))
  , ("e_phoff",     EFWord32 (view (_2.phdrTableOffset)))
  , ("e_shoff",     EFWord32 (view (_2.shdrTableOffset)))
  , ("e_flags",     EFWord32 (\(e,_) -> elfFlags e))
  , ("e_ehsize",    EFWord16 (\(_,_) -> sizeOfEhdr32))
  , ("e_phentsize", EFWord16 (\(_,_) -> sizeOfPhdr32))
  , ("e_phnum",     EFWord16 (\(_,l) -> phnum l))
  , ("e_shentsize", EFWord16 (\(_,_) -> sizeOfShdr32))
  , ("e_shnum",     EFWord16 (\(_,l) -> shnum l))
  , ("e_shstrndx",  EFWord16 (view $ _2.shstrndx))
  ]

ehdr64Fields :: ElfRecord (Ehdr Word64)
ehdr64Fields =
  [ ("e_ident",     EFBS 16  $ elfIdentBuilder . fst)
  , ("e_type",      EFWord16 $ fromElfType . elfType . fst)
  , ("e_machine",   EFWord16 $ fromElfMachine . elfMachine . fst)
  , ("e_version",   EFWord32 $ fromIntegral . elfVersion . fst)
  , ("e_entry",     EFWord64 $ view $ _1.to elfEntry)
  , ("e_phoff",     EFWord64 $ view $ _2.phdrTableOffset)
  , ("e_shoff",     EFWord64 $ view $ _2.shdrTableOffset)
  , ("e_flags",     EFWord32 $ view $ _1.to elfFlags)
  , ("e_ehsize",    EFWord16 $ const sizeOfEhdr64)
  , ("e_phentsize", EFWord16 $ const sizeOfPhdr64)
  , ("e_phnum",     EFWord16 $ view $ _2.to phnum)
  , ("e_shentsize", EFWord16 $ const sizeOfShdr64)
  , ("e_shnum",     EFWord16 $ view $ _2.to shnum)
  , ("e_shstrndx",  EFWord16 $ view $ _2.shstrndx)
  ]

phdr32Fields :: ElfRecord (Phdr Word32)
phdr32Fields =
  [ ("p_type",   EFWord32 $  fromElfSegmentType . elfSegmentType)
  , ("p_offset", EFWord32 $                view $ elfSegmentData._1)
  , ("p_vaddr",  EFWord32 $                       elfSegmentVirtAddr)
  , ("p_paddr",  EFWord32 $                       elfSegmentPhysAddr)
  , ("p_filesz", EFWord32 $                view $ elfSegmentData._2)
  , ("p_memsz",  EFWord32 $                       elfSegmentMemSize)
  , ("p_flags",  EFWord32 $ fromElfSegmentFlags . elfSegmentFlags)
  , ("p_align",  EFWord32 $                       elfSegmentAlign)
  ]

phdr64Fields :: ElfRecord (Phdr Word64)
phdr64Fields =
  [ ("p_type",   EFWord32 $ fromElfSegmentType . elfSegmentType)
  , ("p_flags",  EFWord32 $ fromElfSegmentFlags . elfSegmentFlags)
  , ("p_offset", EFWord64 $ view $ elfSegmentData._1)
  , ("p_vaddr",  EFWord64 $ elfSegmentVirtAddr)
  , ("p_paddr",  EFWord64 $ elfSegmentPhysAddr)
  , ("p_filesz", EFWord64 $ view $ elfSegmentData._2)
  , ("p_memsz",  EFWord64 $ elfSegmentMemSize)
  , ("p_align",  EFWord64 $ elfSegmentAlign)
  ]

shdr32Fields :: ElfRecord (Shdr Word32)
shdr32Fields =
  [ ("sh_name",      EFWord32 (\(_,n,_) -> n))
  , ("sh_type",      EFWord32 (\(s,_,_) -> fromElfSectionType  $ elfSectionType s))
  , ("sh_flags",     EFWord32 (\(s,_,_) -> fromElfSectionFlags $ elfSectionFlags s))
  , ("sh_addr",      EFWord32 (\(s,_,_) -> elfSectionAddr s))
  , ("sh_offset",    EFWord32 (\(_,_,o) -> o))
  , ("sh_size",      EFWord32 (\(s,_,_) -> elfSectionSize s))
  , ("sh_link",      EFWord32 (\(s,_,_) -> elfSectionLink s))
  , ("sh_info",      EFWord32 (\(s,_,_) -> elfSectionInfo s))
  , ("sh_addralign", EFWord32 (\(s,_,_) -> elfSectionAddrAlign s))
  , ("sh_entsize",   EFWord32 (\(s,_,_) -> elfSectionEntSize s))
  ]

-- Fields that take section, name offset, data offset, and data length.
shdr64Fields :: ElfRecord (Shdr Word64)
shdr64Fields =
  [ ("sh_name",      EFWord32 (\(_,n,_) -> n))
  , ("sh_type",      EFWord32 (\(s,_,_) -> fromElfSectionType  $ elfSectionType s))
  , ("sh_flags",     EFWord64 (\(s,_,_) -> fromElfSectionFlags $ elfSectionFlags s))
  , ("sh_addr",      EFWord64 (\(s,_,_) -> elfSectionAddr s))
  , ("sh_offset",    EFWord64 (\(_,_,o) -> o))
  , ("sh_size",      EFWord64 (\(s,_,_) -> elfSectionSize s))
  , ("sh_link",      EFWord32 (\(s,_,_) -> elfSectionLink s))
  , ("sh_info",      EFWord32 (\(s,_,_) -> elfSectionInfo s))
  , ("sh_addralign", EFWord64 (\(s,_,_) -> elfSectionAddrAlign s))
  , ("sh_entsize",   EFWord64 (\(s,_,_) -> elfSectionEntSize s))
  ]

sizeOfEhdr32 :: Word16
sizeOfEhdr32 = sizeOfRecord ehdr32Fields

sizeOfEhdr64 :: Word16
sizeOfEhdr64 = sizeOfRecord ehdr64Fields

sizeOfPhdr32 :: Word16
sizeOfPhdr32 = sizeOfRecord phdr32Fields

sizeOfPhdr64 :: Word16
sizeOfPhdr64 = sizeOfRecord phdr64Fields

sizeOfShdr32 :: Word16
sizeOfShdr32 = sizeOfRecord shdr32Fields

sizeOfShdr64 :: Word16
sizeOfShdr64 = sizeOfRecord shdr64Fields

-- | Intermediate data structure used for rendering Elf file.
data ElfLayout w = ElfLayout {
        _elfOutput :: Builder
      , _phdrTableOffset :: w
        -- | Lift of phdrs that must appear before loadable segments.
      , _preLoadPhdrs :: Seq.Seq (Phdr w)
        -- | List of other segments.
      , _phdrs :: Seq.Seq (Phdr w)
        -- | Offset to section header table.
      , _shdrTableOffset :: w
        -- | Index of section for string table.
      , _shstrndx :: Word16
        -- | List of section headers found so far.
      , _shdrs :: Seq.Seq Builder
      }

-- | Lens containing all data for an Elf file.
elfOutput :: Simple Lens (ElfLayout w) Builder
elfOutput = lens _elfOutput (\s v -> s { _elfOutput = v })

phdrTableOffset :: Simple Lens (ElfLayout w) w
phdrTableOffset = lens _phdrTableOffset (\s v -> s { _phdrTableOffset = v })

preLoadPhdrs :: Simple Lens (ElfLayout w) (Seq.Seq (Phdr w))
preLoadPhdrs = lens _preLoadPhdrs (\s v -> s { _preLoadPhdrs = v })

phdrs :: Simple Lens (ElfLayout w) (Seq.Seq (Phdr w))
phdrs = lens _phdrs (\s v -> s { _phdrs = v })

shdrTableOffset :: Simple Lens (ElfLayout w) w
shdrTableOffset = lens _phdrTableOffset (\s v -> s { _phdrTableOffset = v })

shstrndx :: Simple Lens (ElfLayout w) Word16
shstrndx = lens _shstrndx (\s v -> s { _shstrndx = v })

shdrs :: Simple Lens (ElfLayout w) (Seq.Seq Builder)
shdrs = lens _shdrs (\s v -> s { _shdrs = v })

allPhdrs :: ElfLayout w -> Seq.Seq (Phdr w)
allPhdrs l = l^.preLoadPhdrs Seq.>< l^.phdrs

-- | Return total size of output.
outputSize :: Num w => ElfLayout w -> w
outputSize = fromIntegral . U.length . view elfOutput

-- | Return number of sections in layout.
shnum :: ElfLayout w -> Word16
shnum = fromIntegral . Seq.length . view shdrs

-- | Returns number of segments in layout.
phnum :: ElfLayout w -> Word16
phnum = fromIntegral . Seq.length . allPhdrs

isPreloadPhdr :: ElfSegmentType -> Bool
isPreloadPhdr PT_PHDR = True
isPreloadPhdr PT_INTERP = True
isPreloadPhdr _ = False

addRelroToLayout :: Num w => Maybe (Range w) -> ElfLayout w -> ElfLayout w
addRelroToLayout Nothing l = l
addRelroToLayout (Just (f,c)) l = l & phdrs %~ (Seq.|> s)
  where s = ElfSegment { elfSegmentType = PT_GNU_RELRO
                       , elfSegmentFlags = pf_r
                       , elfSegmentVirtAddr = f
                       , elfSegmentPhysAddr = f
                       , elfSegmentAlign = 1
                       , elfSegmentMemSize = c
                       , _elfSegmentData = (f,c)
                       }

-- | Return layout information from elf file.
elfLayout :: ElfWidth w => Elf w -> ElfLayout w
elfLayout e = final
  where d = elfData e
        section_names = map elfSectionName $ toListOf elfSections e
        (name_data,name_map) = stringTable section_names
        initl = ElfLayout { _elfOutput = mempty
                          , _phdrTableOffset = 0
                          , _preLoadPhdrs = Seq.empty
                          , _phdrs = Seq.empty
                          , _shdrTableOffset = 0
                          , _shstrndx = 0
                          , _shdrs = Seq.empty
                          }
        -- Get final elf layout after processing elements.
        final0 = foldl impl initl (e^.elfFileData)
        -- Add relro information if needed.
        final = addRelroToLayout (elfRelroRange e) final0

        -- Process element.
        impl :: ElfWidth w => ElfLayout w -> ElfDataRegion w -> ElfLayout w
        impl l ElfDataElfHeader =
             l & elfOutput <>~ writeRecord ehdrFields d (e,final)
        impl l ElfDataSegmentHeaders =
             l & elfOutput <>~ headers
               & phdrTableOffset .~ outputSize l
          where headers = mconcat (writeRecord phdrFields d <$> F.toList (allPhdrs final))
        impl l (ElfDataSegment s) = l2 & phdrLens %~ (Seq.|> s1)
          where l2 = foldl impl l (s^.elfSegmentData)
                -- Length of phdr data.
                o = outputSize l
                c = outputSize l2 - o
                s1 = s & elfSegmentData .~ (o,c)
                phdrLens | isPreloadPhdr (elfSegmentType s) = preLoadPhdrs
                         | otherwise = phdrs
        impl l ElfDataSectionHeaders =
             l & elfOutput <>~ mconcat (F.toList (final^.shdrs))
               & shdrTableOffset .~ outputSize l
        impl l ElfDataSectionNameTable = impl l' (ElfDataSection s)
          where l' = l & shstrndx .~ shnum l
                s  = elfNameTableSection name_data
        impl l (ElfDataGOT g) = addSectionToLayout d name_map l (elfGotSection g)
        impl l (ElfDataSection s) = addSectionToLayout d name_map l s
        impl l (ElfDataRaw b) = l & elfOutput <>~ U.fromByteString b

-- | Add section information to layout.
addSectionToLayout :: ElfWidth w
                   => ElfData
                   -> Map.Map String Word32 -- ^ Name to offset map.
                   -> ElfLayout w
                   -> ElfSection w
                   -> ElfLayout w
addSectionToLayout d name_map l s =
    l & elfOutput <>~ pad <> fn
      & shdrs %~ (Seq.|> writeRecord shdrFields d (s,no, o))
  where Just no = Map.lookup (elfSectionName s) name_map
        base = outputSize l
        o = fixAlignment base (elfSectionAddrAlign s)
        pad = U.fromByteString (B.replicate (fromIntegral (o - base)) 0)
        fn  = U.fromByteString (elfSectionData s)

------------------------------------------------------------------------
-- ElfSymbolVisibility

-- | Visibility for elf symbol
newtype ElfSymbolVisibility = ElfSymbolVisibility { visAsWord :: Word8 }

-- | Visibility is specified by binding type
stv_default :: ElfSymbolVisibility
stv_default = ElfSymbolVisibility 0

-- | OS specific version of STV_HIDDEN.
stv_internal :: ElfSymbolVisibility
stv_internal = ElfSymbolVisibility 1

-- | Can only be seen inside currect component.
stv_hidden :: ElfSymbolVisibility
stv_hidden = ElfSymbolVisibility 2

-- | Can only be seen inside currect component.
stv_protected :: ElfSymbolVisibility
stv_protected = ElfSymbolVisibility 3

instance Show ElfSymbolVisibility where
  show (ElfSymbolVisibility w) =
    case w of
      0 -> "DEFAULT"
      1 -> "INTERNAL"
      2 -> "HIDDEN"
      3 -> "PROTECTED"
      _ -> "BadVis"

------------------------------------------------------------------------
-- ElfSymbolTableEntry

-- | The symbol table entries consist of index information to be read from other
-- parts of the ELF file. Some of this information is automatically retrieved
-- for your convenience (including symbol name, description of the enclosing
-- section, and definition).
data ElfSymbolTableEntry w = EST
    { steName             :: String
    , steType             :: ElfSymbolType
    , steBind             :: ElfSymbolBinding
    , steOther            :: Word8
    , steIndex            :: ElfSectionIndex  -- ^ Section in which the def is held
    , steValue            :: w
    , steSize             :: w
    } deriving (Eq, Show)

steEnclosingSection :: ElfWidth w => Elf w -> ElfSymbolTableEntry w -> Maybe (ElfSection w)
steEnclosingSection e s = sectionByIndex e (steIndex s)

steVisibility :: ElfSymbolTableEntry w -> ElfSymbolVisibility
steVisibility e = ElfSymbolVisibility (steOther e .&. 0x3)

alignLeft :: Int -> [String] -> [String]
alignLeft minw l = ar <$> l
  where w = maximum $ minw : (length <$> l)
        ar s = s ++ replicate (w-n) ' '
          where n = length s

alignRight :: Int -> [String] -> [String]
alignRight minw l = ar <$> l
  where w = maximum $ minw : (length <$> l)
        ar s = replicate (w-n) ' ' ++ s 
          where n = length s

norm :: [[String] -> [String]] -> [[String]] -> Doc
norm colFns rows = vcat (hsep . fmap text <$> fixed_rows) 
  where cols = transpose rows
        fixed_cols = zipWith ($) colFns cols
        fixed_rows = transpose fixed_cols

-- | Pretty print symbol table entries in format used by readelf.
ppSymbolTableEntries :: ElfWidth w => [ElfSymbolTableEntry w] -> Doc
ppSymbolTableEntries l = norm (snd <$> cols) (fmap fst cols : entries)
  where entries = zipWith ppSymbolTableEntry [0..] l
        cols = [ ("Num:",     alignRight 6)
               , ("   Value", alignLeft 0)
               , ("Size",     alignRight 5)
               , ("Type",     alignLeft  7)
               , ("Bind",     alignLeft  6)
               , ("Vis",      alignLeft 8)
               , ("Ndx",      alignLeft 3)
               , ("Name", id)
               ]

ppSymbolTableEntry :: ElfWidth w => Int -> ElfSymbolTableEntry w -> [String]
ppSymbolTableEntry i e =
  [ show i ++ ":"
  , ppHex (steValue e)
  , show (steSize e)
  , ppElfSymbolType (steType e)
  , ppElfSymbolBinding (steBind e)
  , show (steVisibility e)
    -- Ndx
  , show (steIndex e)
  , steName e
  ]

-- | Parse the symbol table section into a list of symbol table entries. If
-- no symbol table is found then an empty list is returned.
-- This function does not consult flags to look for SHT_STRTAB (when naming symbols),
-- it just looks for particular sections of ".strtab" and ".shstrtab".
parseSymbolTables :: ElfWidth w => Elf w -> [[ElfSymbolTableEntry w]]
parseSymbolTables e = map (getSymbolTableEntries e) $ symbolTableSections e

-- | Assumes the given section is a symbol table, type SHT_SYMTAB
-- (guaranteed by parseSymbolTables).
getSymbolTableEntries :: ElfWidth w => Elf w -> ElfSection w -> [ElfSymbolTableEntry w]
getSymbolTableEntries e s =
  let link   = elfSectionLink s
      strtab = lookup link (zip [0..] (toListOf elfSections e))
      strs = fromMaybe B.empty (elfSectionData <$> strtab)
      nameFn idx = B.toString (lookupString idx strs)
   in runGetMany (getSymbolTableEntry e nameFn) (L.fromChunks [elfSectionData s])

-- | Use the symbol offset and size to extract its definition
-- (in the form of a ByteString).
-- If the size is zero, or the offset larger than the 'elfSectionData',
-- then 'Nothing' is returned.
findSymbolDefinition :: ElfWidth w => Elf w -> ElfSymbolTableEntry w -> Maybe B.ByteString
findSymbolDefinition elf e =
    let enclosingData = elfSectionData <$> steEnclosingSection elf e
        start = steValue e
        len = steSize e
        def = slice (start, len) <$> enclosingData
    in if def == Just B.empty then Nothing else def

hasSectionType :: ElfSectionType -> ElfSection w -> Bool
hasSectionType tp s = elfSectionType s == tp

symbolTableSections :: ElfWidth w => Elf w -> [ElfSection w]
symbolTableSections = toListOf $ elfSections.filtered (hasSectionType SHT_SYMTAB)

-- Get a string from a strtab ByteString.
stringByIndex :: Word32 -> B.ByteString -> Maybe B.ByteString
stringByIndex n strtab = if B.length str == 0 then Nothing else Just str
  where str = lookupString n strtab

instance ElfWidth Word32 where
  elfClass _ = ELFCLASS32

  ehdrFields = ehdr32Fields
  phdrFields = phdr32Fields
  shdrFields = shdr32Fields

  symbolTableEntrySize = 16
  getSymbolTableEntry e nameFn = do
    let d = elfData e
    nameIdx <- getWord32 d
    value <- getWord32 d
    size  <- getWord32 d
    info  <- getWord8
    other <- getWord8
    sTlbIdx <- ElfSectionIndex <$> getWord16 d
    let (typ,bind) = infoToTypeAndBind info
    return $ EST { steName = nameFn nameIdx
                 , steType  = typ
                 , steBind  = bind
                 , steOther = other
                 , steIndex = sTlbIdx
                 , steValue = value
                 , steSize  = size
                 }


-- | Gets a single entry from the symbol table, use with runGetMany.
instance ElfWidth Word64 where
  elfClass _ = ELFCLASS32

  ehdrFields = ehdr64Fields
  phdrFields = phdr64Fields
  shdrFields = shdr64Fields

  symbolTableEntrySize = 24
  getSymbolTableEntry e nameFn = do
    let er = elfData e
    nameIdx <- getWord32 er
    info <- getWord8
    other <- getWord8
    sTlbIdx <- ElfSectionIndex <$> getWord16 er
    symVal <- getWord64 er
    size <- getWord64 er
    let (typ,bind) = infoToTypeAndBind info
    return $ EST { steName = nameFn nameIdx
                 , steType = typ
                 , steBind = bind
                 , steOther = other
                 , steIndex = sTlbIdx
                 , steValue = symVal
                 , steSize = size
                 }

sectionByIndex :: ElfWidth w
               => Elf w
               -> ElfSectionIndex
               -> Maybe (ElfSection w)
sectionByIndex e si = do
  i <- asSectionIndex si
  listToMaybe $ genericDrop i (e^..elfSections)

------------------------------------------------------------------------
-- Dynamic information

[enum|
 ElfDynamicArrayTag :: Word32
 DT_NULL          0
 DT_NEEDED        1
 DT_PLTRELSZ      2
 DT_PLTGOT        3
 DT_HASH          4
 DT_STRTAB        5
 DT_SYMTAB        6
 DT_RELA          7
 DT_RELASZ        8
 DT_RELAENT       9
 DT_STRSZ        10
 DT_SYMENT       11
 DT_INIT         12
 DT_FINI         13
 DT_SONAME       14
 DT_RPATH        15
 DT_SYMBOLIC     16
 DT_REL          17
 DT_RELSZ        18
 DT_RELENT       19
 DT_PLTREL       20
 DT_DEBUG        21
 DT_TEXTREL      22
 DT_JMPREL       23
 DT_BIND_NOW     24
 DT_INIT_ARRAY   25
 DT_FINI_ARRAY   26
 DT_INIT_ARRAYSZ    27
 DT_FINI_ARRAYSZ    28
 DT_RUNPATH         29 -- Library search path
 DT_FLAGS           30 -- Flags for the object being loaded
 DT_PREINIT_ARRAY   32 -- Start of encoded range (also DT_PREINIT_ARRAY)
 DT_PREINIT_ARRAYSZ 33 -- Size in bytes of DT_PREINIT_ARRAY

 -- DT_LOOS   0x60000000
 -- DT_VALRNGLO    0x6ffffd00
 DT_GNU_PRELINKED  0x6ffffdf5 -- Prelinking timestamp
 DT_GNU_CONFLICTSZ 0x6ffffdf6 -- Size of conflict section.
 DT_GNU_LIBLISTSZ  0x6ffffdf7 -- Size of lbirary list
 DT_CHECKSUM       0x6ffffdf8
 DT_PLTPADSZ       0x6ffffdf9
 DT_MOVEENT        0x6ffffdfa
 DT_MOVESZ         0x6ffffdfb
 DT_FEATURE_1      0x6ffffdfc -- Feature selection (DTF_*).
 DT_POSFLAG_1      0x6ffffdfd -- Flags for DT_* entries, effecting the following DT_* entry.
 DT_SYMINSZ        0x6ffffdfe -- Size of syminfo table (in bytes)
 DT_SYMINENT       0x6ffffdff -- Entry size of syminfo
 -- DT_VALRNGHI    0x6ffffdff


-- DT_* entries between DT_ADDRRNGHI & DT_ADDRRNGLO use the
-- d_ptr field
 -- DT_ADDRRNGLO   0x6ffffe00
 DT_GNU_HASH       0x6ffffef5 -- GNU-style hash table.
 DT_TLSDESC_PLT	   0x6ffffef6
 DT_TLSDESC_GOT	   0x6ffffef7
 DT_GNU_CONFLICT   0x6ffffef8 -- Start of conflict section
 DT_GNU_LIBLIST	   0x6ffffef9 -- Library list
 DT_CONFIG	   0x6ffffefa -- Configuration information
 DT_DEPAUDIT       0x6ffffefb -- Dependency auditing
 DT_AUDIT          0x6ffffefc -- Object auditing
 DT_PLTPAD         0x6ffffefd -- PLT padding
 DT_MOVETAB        0x6ffffefe -- Move table
 DT_SYMINFO        0x6ffffeff -- Syminfo table
  -- DT_ADDRRNGHI  0x6ffffeff

 DT_VERSYM         0x6ffffff0
 DT_RELACOUNT      0x6ffffff9
 DT_RELCOUNT       0x6ffffffa
 DT_FLAGS_1        0x6ffffffb -- State flags
 DT_VERDEF         0x6ffffffc -- Address of version definition.
 DT_VERDEFNUM      0x6ffffffd
 DT_VERNEED        0x6ffffffe
 DT_VERNEEDNUM     0x6fffffff -- Number of needed versions.
 -- DT_HIOS        0x6FFFFFFF

 -- DT_LOPROC 0x70000000
 -- DT_HIPROC 0x7FFFFFFF
 DT_Other         _
|]

-- | Dynamic array entry
data Dynamic w 
   = Dynamic { dynamicTag :: !ElfDynamicArrayTag
             , dynamicVal :: !w
             }
  deriving (Show)

class ElfWidth w => DynamicWidth w where
  getDynamic :: ElfData -> Get (Dynamic w)

  -- | Size of one relocation entry.
  relaEntSize :: w
 
  -- | Convert info paramter to relocation sym.
  relaSym :: w -> Word32

  -- | Get relocation entry element.
  getRelaEntryElt :: ElfData -> Get w

instance DynamicWidth Word32 where
  getDynamic d = do
    tag <- toElfDynamicArrayTag <$> getWord32 d
    v <- getWord32 d
    return (Dynamic tag v)

  relaEntSize = 12
  relaSym info = info `shiftR` 8
  getRelaEntryElt = getWord32


instance DynamicWidth Word64 where
  getDynamic d = do
    tag <- toElfDynamicArrayTag . fromIntegral <$> getWord64 d
    v <- getWord64 d
    return (Dynamic tag v)

  relaEntSize = 24
  relaSym info = fromIntegral (info `shiftR` 32)
  getRelaEntryElt = getWord64

dynamicList :: DynamicWidth w => ElfData -> Get [Dynamic w]
dynamicList d = go []
  where go l = do
          done <- isEmpty
          if done then
            return l
          else do
            e <- getDynamic d
            case dynamicTag e of
              DT_NULL -> return (reverse l)
              _ -> go (e:l)

type DynamicMap w = Map.Map ElfDynamicArrayTag [w]

insertDynamic :: Dynamic w -> DynamicMap w -> DynamicMap w
insertDynamic (Dynamic tag v) = Map.insertWith (++) tag [v]

dynamicEntry :: ElfDynamicArrayTag -> DynamicMap w -> [w]
dynamicEntry tag m = fromMaybe [] (Map.lookup tag m)

-- | Get the mandatory entry with the given tag from the map.
-- It is required that there is exactly one tag with this type.
optionalDynamicEntry :: Monad m => ElfDynamicArrayTag -> DynamicMap w -> m (Maybe w)
optionalDynamicEntry tag m =
  case dynamicEntry tag m of
    [w] -> return (Just w)
    [] -> return Nothing
    _ -> fail $ "Dynamic information contains multiple " ++ show tag ++ " entries."

-- | Get the mandatory entry with the given tag from the map.
-- It is required that there is exactly one tag with this type.
mandatoryDynamicEntry :: Monad m => ElfDynamicArrayTag -> DynamicMap w -> m w 
mandatoryDynamicEntry tag m =
  case dynamicEntry tag m of
    [w] -> return w
    [] -> fail $ "Dynamic information missing " ++ show tag
    _ -> fail $ "Dynamic information contains multiple " ++ show tag ++ " entries."

-- | Return ranges in file containing the given address range.
-- In a well-formed file, the list should contain at most one element.
fileOffsetOfAddr :: (Ord w, Num w) => w -> ElfLayout w -> [Range w] 
fileOffsetOfAddr w l =
  [ (dta + offset, n-offset)
  | seg <- F.toList (l^.phdrs)
  , elfSegmentType seg == PT_LOAD
  , let base = elfSegmentVirtAddr seg
  , let (dta, n) = seg^.elfSegmentData
  , inRange w (base, n)
  , let offset = w - base
  ]

addressToFile :: (Integral w, Monad m)
                   => ElfLayout w -- ^ Layout of Elf file
                   -> L.ByteString -- ^ Bytestring with contents.
                   -> String
                   -> w -- ^ Address in memory.
                   -> m L.ByteString
addressToFile l b nm w =
  case fileOffsetOfAddr w l of
    [] -> fail $ "Could not find " ++ nm ++ "."
    [r] -> return (sliceL r b)
    _ -> fail $ "Multiple overlapping segments containing " ++ nm ++ "."

-- | Return  ranges in file containing the given address range.
-- In a well-formed file, the list should contain at most one element.
fileOffsetOfRange :: (Ord w, Num w) => Range w -> ElfLayout w -> [Range w] 
fileOffsetOfRange (w,sz) l =
  [ (dta + offset, sz)
  | seg <- F.toList (l^.phdrs)
  , elfSegmentType seg == PT_LOAD
  , let base = elfSegmentVirtAddr seg
  , let (dta, n) = seg^.elfSegmentData
  , inRange w (base, n)
  , let offset = w - base
  , n-offset >= sz
  ]

addressRangeToFile :: (Integral w, Monad m)
                   => ElfLayout w -- ^ Layout of Elf file
                   -> L.ByteString -- ^ Bytestring with contents.
                   -> String
                   -> Range w
                   -> m L.ByteString
addressRangeToFile l b nm rMem =
  case fileOffsetOfRange rMem l of
    [] -> fail $ "Could not find " ++ nm ++ "."
    [r] -> return (sliceL r b)
    _ -> fail $ "Multiple overlapping segments containing " ++ nm ++ "."

-- | Return contents of dynamic string tab.
dynStrTab :: (DynamicWidth w, Monad m)
          => ElfLayout w -> L.ByteString -> DynamicMap w -> m L.ByteString
dynStrTab l b m = do
  w <-  mandatoryDynamicEntry DT_STRTAB m
  sz <- mandatoryDynamicEntry DT_STRSZ m
  addressRangeToFile l b "dynamic string table" (w,sz)

getDynNeeded :: Integral w => L.ByteString -> DynamicMap w -> [FilePath]
getDynNeeded strTab m =
  let entries = dynamicEntry DT_NEEDED m
      getName w = L.toString $ lookupStringL (fromIntegral w) strTab
   in getName <$> entries

nameFromIndex :: L.ByteString -> Int64 -> String
nameFromIndex strTab o = L.toString $ lookupStringL o strTab



-- | Get string from strTab read by 32-bit offset.
getOffsetString :: ElfData -> L.ByteString -> Get String
getOffsetString d strTab = do
  nameFromIndex strTab . fromIntegral <$> getWord32 d

gnuLinkedList :: Monad m
              => (L.ByteString -> Get a) -- ^ Function for reading.
              -> ElfData
              -> Int -- ^ Number of entries expected.
              -> L.ByteString -- ^ Buffer to read.
              -> m [a]
gnuLinkedList readFn d cnt0 b0 = do
  let readNextVal b = (,) <$> readFn b <*> getWord32 d
  let go 0 _ prev = return (reverse prev)
      go cnt b prev = do
        case runGetOrFail (readNextVal b) b of
          Left (_,_,msg) -> fail msg
          Right (_,_,(d,next)) -> do
            go (cnt-1) (L.drop (fromIntegral next) b) (d:prev)
  go cnt0 b0 []

dynSymTab :: (DynamicWidth w, Monad m)
          => Elf w
          -> ElfLayout w
          -> L.ByteString
          -> DynamicMap w
          -> m [ElfSymbolTableEntry w]
dynSymTab e l file m = do
  -- Get string table.
  strTab <- dynStrTab l file m

  sym_off <- mandatoryDynamicEntry DT_SYMTAB m
  -- According to a comment in GNU Libc 2.19 (dl-fptr.c:175), you get the
  -- size of the dynamic symbol table by assuming that the string table follows
  -- immediately afterwards. 
  str_off <- mandatoryDynamicEntry DT_STRTAB m
  when (str_off < sym_off) $ do
    fail $ "The string table offset is before the symbol table offset."  
  -- Size of each symbol table entry.
  syment <- mandatoryDynamicEntry DT_SYMENT m
  when (syment /= symbolTableEntrySize) $ do
    fail "Unexpected symbol table entry size"
  let sym_sz = str_off - sym_off
  symtab <- addressRangeToFile l file "dynamic symbol table" (sym_off,sym_sz)
  let nameFn idx = L.toString $ lookupStringL (fromIntegral idx) strTab
  return $ runGetMany (getSymbolTableEntry e nameFn) symtab

class Show s => IsData s where
  getData :: ElfData -> Get s
  
instance IsData Int32 where
  getData d = fromIntegral <$> getWord32 d

instance IsData Int64 where
  getData d = fromIntegral <$> getWord64 d

instance IsData Word32 where
  getData = getWord32

instance IsData Word64 where
  getData = getWord64

class (DynamicWidth u, IsData u, IsData s, Show tp)
   => RelocationType u s tp | tp -> u, tp -> s where

  -- | Convert unsigned value to type.
  relaType :: u -> Maybe tp

  -- | Return true if this is a relative relocation type.
  isRelative :: tp -> Bool

data RelaEntry u s tp  = Rela { r_offset :: !u
                              , r_sym    :: !Word32
                              , r_type   :: !tp
                              , r_addend :: !s
                              } deriving (Show)

-- | Return true if this is a relative relocation entry.
isRelativeRelaEntry :: RelocationType u s tp => RelaEntry u s tp -> Bool
isRelativeRelaEntry r = isRelative (r_type r)

ppRelaEntries :: RelocationType u s tp => [RelaEntry u s tp] -> Doc
ppRelaEntries l = norm (snd <$> cols) (fmap fst cols : entries)
  where entries = zipWith ppRelaEntry [0..] l
        cols = [ ("Num", alignRight 0)
               , ("Offset", alignLeft 0)
               , ("Symbol", alignLeft 0)
               , ("Type", alignLeft 0)
               , ("Addend", alignLeft 0)
               ]

ppRelaEntry :: RelocationType u s tp => Int -> RelaEntry u s tp -> [String]
ppRelaEntry i e =
  [ shows i ":" 
  , ppHex (r_offset e)
  , show (r_sym e)
  , show (r_type e)
  , show (r_addend e)
  ]

-- | Read a relocation entry.
getRelaEntry :: RelocationType u s tp => ElfData -> Get (RelaEntry u s tp) 
getRelaEntry d = do
  offset <- getData d
  info   <- getData d
  addend <- getData d
  let msg = "Could not parse relocation type: " ++ showHex info ""
  tp <- maybe (fail msg) return $ relaType info
  return Rela { r_offset = offset
              , r_sym = relaSym info
              , r_type = tp
              , r_addend = addend
              }

checkPLTREL :: (Integral u, Monad m) => DynamicMap u -> m ()
checkPLTREL dm = do
  mw <- optionalDynamicEntry DT_PLTREL dm
  case mw of
    Nothing -> return ()
    Just w -> do
      when (fromIntegral w /= fromElfDynamicArrayTag DT_RELA) $ do
        fail $ "Only DT_RELA entries are supported."

-- | Return range for ".rela.plt" from DT_JMPREL and DT_PLTRELSZ if
-- defined.
dynRelaPLT :: Monad m => DynamicMap u -> m (Maybe (Range u))
dynRelaPLT dm = do
  mrelaplt <- optionalDynamicEntry DT_JMPREL dm
  case mrelaplt of
    Nothing -> return Nothing
    Just relaplt -> do
      sz <- mandatoryDynamicEntry DT_PLTRELSZ dm
      return $ Just (relaplt, sz)

dynRelaArray :: (RelocationType u s tp, Monad m)
             => ElfData
             -> ElfLayout u
             -> L.ByteString
             -> DynamicMap u
             -> m [RelaEntry u s tp]
dynRelaArray d l file dm = do
  checkPLTREL dm
  mrela_offset <- optionalDynamicEntry DT_RELA dm
  case mrela_offset of
    Nothing -> return []
    Just rela_offset -> do
      --cnt <- mandatoryDynamicEntry DT_RELACOUNT dm
      ent <- mandatoryDynamicEntry DT_RELAENT dm
      sz  <- mandatoryDynamicEntry DT_RELASZ dm
      --when (cnt * ent /= sz) $ do
      --  fail $ "Unexpected size of relocation array:" ++ show (cnt,ent,sz)
      when (ent /= relaEntSize) $ fail "Unexpected size for relocation entry."
      rela <- addressRangeToFile l file "relocation array" (rela_offset,sz)
      return $ runGetMany (getRelaEntry d) rela

checkRelaCount :: (RelocationType u s tp, Monad m)
               => [RelaEntry u s tp]
               -> DynamicMap u
               -> m ()
checkRelaCount relocations dm = do
  let relaCount = length (filter isRelativeRelaEntry relocations)
  mexpRelaCount <- optionalDynamicEntry DT_RELACOUNT dm
  let correctCount = case mexpRelaCount of
                       Just c -> c == fromIntegral relaCount
                       Nothing -> True
  when (not correctCount) $ do
    fail $ "Incorrect DT_RELACOUNT"

[enum|
  I386_RelocationType :: Word32
  R_386_NONE      0
  R_386_32        1
  R_386_PC32      2
  R_386_GOT32     3
  R_386_PLT32     4
  R_386_COPY      5
  R_386_GLOB_DAT  6
  R_386_JMP_SLOT  7
  R_386_RELATIVE  8
  R_386_GOTOFF    9
  R_386_GOTPC    10 
|]

instance RelocationType Word32 Int32 I386_RelocationType where
  relaType = toI386_RelocationType

  isRelative R_386_RELATIVE = True
  isRelative _ = False

[enum|
 X86_64_RelocationType :: Word32
 R_X86_64_NONE           0  -- No reloc
 R_X86_64_64             1  -- Direct 64 bit
 R_X86_64_PC32           2  -- PC relative 32 bit signed
 R_X86_64_GOT32          3  -- 32 bit GOT entry
 R_X86_64_PLT32          4  -- 32 bit PLT address
 R_X86_64_COPY           5  -- Copy symbol at runtime
 R_X86_64_GLOB_DAT       6  -- Create GOT entry
 R_X86_64_JUMP_SLOT      7  -- Create PLT entry
 R_X86_64_RELATIVE       8  -- Adjust by program base
 R_X86_64_GOTPCREL       9  -- 32 bit signed pc relative offset to GOT
 R_X86_64_32             10 -- Direct 32 bit zero extended
 R_X86_64_32S            11 -- Direct 32 bit sign extended
 R_X86_64_16             12 -- Direct 16 bit zero extended
 R_X86_64_PC16           13 -- 16 bit sign extended pc relative
 R_X86_64_8              14 -- Direct 8 bit sign extended
 R_X86_64_PC8            15 -- 8 bit sign extended pc relative
|]

instance RelocationType Word64 Int64 X86_64_RelocationType where
  relaType = toX86_64_RelocationType . fromIntegral

  isRelative R_X86_64_RELATIVE = True
  isRelative _ = False

-- | Version definition 
data VersionDef = VersionDef { vd_flags :: !Word16
                               -- ^ Version information flags bitmask.
                             , vd_ndx  :: !Word16
                               -- ^ Index in SHT_GNU_versym section of this version.
                             , vd_hash :: !Word32
                               -- ^ Version name hash value.
                             , vd_aux  :: ![String]
                               -- ^ Version or dependency names.
                             } deriving (Show)

gnuVersionDefs :: (Integral w, Show w, Monad m)
               => ElfData
               -> ElfLayout w
               -> L.ByteString
                  -- ^ Contents of file.
               -> L.ByteString
                  -- ^ Dynamic string table.
               -> DynamicMap w
               -> m [VersionDef]
gnuVersionDefs d l file strTab dm = do
  mvd <- optionalDynamicEntry DT_VERDEF dm
  case mvd of
    Nothing -> return []
    Just vd -> do
      vdnum <- mandatoryDynamicEntry DT_VERDEFNUM dm
      def_buffer <- addressToFile l file "symbol version definitions" vd
      gnuLinkedList (readVersionDef d strTab) d (fromIntegral vdnum) def_buffer

readVersionDef :: ElfData -> L.ByteString -> L.ByteString -> Get VersionDef
readVersionDef d strTab b = do
  ver   <- getWord16 d
  when (ver /= 1) $
    fail $ "Unexpected version definition version: " ++ show ver
  flags <- getWord16 d
  ndx   <- getWord16 d
  cnt   <- getWord16 d
  hash  <- getWord32 d
  aux   <- getWord32 d
  let entry_cnt = fromIntegral cnt
  let entry_buffer = L.drop (fromIntegral aux) b
  entries <- gnuLinkedList (\_ -> getOffsetString d strTab) d entry_cnt entry_buffer
  return VersionDef { vd_flags = flags
                    , vd_ndx   = ndx
                    , vd_hash  = hash
                    , vd_aux   = entries
                    }
  
-- | Version requirement informaito.nx
data VersionReq = VersionReq { vn_file :: String
                             , vn_aux :: [VersionReqAux]
                             } deriving (Show)

readVersionReq :: ElfData -> L.ByteString -> L.ByteString -> Get VersionReq
readVersionReq d strTab b = do
  ver <- getWord16 d
  when (ver /= 1) $ do
    fail $ "Unexpected version need version: " ++ show ver
  cnt  <- getWord16 d
  file <- getOffsetString d strTab
  aux  <- getWord32 d
  let entry_buffer = L.drop (fromIntegral aux) b
  entries <- gnuLinkedList (readVersionReqAux d strTab) d (fromIntegral cnt) entry_buffer
  return VersionReq { vn_file = file
                    , vn_aux = entries
                    }

-- | Version requirement information.
data VersionReqAux = VersionReqAux { vna_hash :: !Word32
                                   , vna_flags :: !Word16
                                   , vna_other :: !Word16
                                   , vna_name :: !String
                                   } deriving (Show)

readVersionReqAux :: ElfData -> L.ByteString -> L.ByteString -> Get VersionReqAux
readVersionReqAux d strTab _ = do
  hash <- getWord32 d
  flags <- getWord16 d
  other   <- getWord16 d
  name <- getOffsetString d strTab
  return VersionReqAux { vna_hash  = hash
                       , vna_flags = flags
                       , vna_other = other
                       , vna_name  = name
                       }

gnuVersionReqs :: (Integral w, Show w, Monad m)
               => ElfData
               -> ElfLayout w
               -> L.ByteString
                  -- ^ Contents of file.
               -> L.ByteString
                  -- ^ Dynamic string table.
               -> DynamicMap w
               -> m [VersionReq]
gnuVersionReqs d l file strTab dm = do
  mvn <- optionalDynamicEntry DT_VERNEED dm
  case mvn of
    Nothing -> return []
    Just vn -> do
      vnnum <- mandatoryDynamicEntry DT_VERNEEDNUM dm
      req_buffer <- addressToFile l file "symbol version requirements" vn
      gnuLinkedList (readVersionReq d strTab) d (fromIntegral vnnum) req_buffer

data DynamicSection u s tp 
   = DynSection { dynNeeded :: ![FilePath]
                , dynSOName :: Maybe String
                , dynInit :: [u]
                , dynFini :: [u]
                , dynSymbols :: [ElfSymbolTableEntry u]
                , dynRelocations :: ![RelaEntry u s tp]
                , dynSymVersionTable :: ![Word16]
                , dynVersionDefs :: ![VersionDef]
                , dynVersionReqs :: ![VersionReq]
                  -- | Address of GNU Hash address.
                , dynGNUHASH_Addr :: !(Maybe u)
                  -- | Address of PLT in memory.
                , dynPLTAddr :: !(Maybe u)
                , dynRelaPLTRange :: !(Maybe (Range u))
                  -- | Value of DT_DEBUG.
                , dynDebug :: !(Maybe u)
                , dynUnparsed :: !(DynamicMap u)
                }
  deriving (Show)

gnuSymVersionTable :: (DynamicWidth w, Monad m)
                   => ElfData
                   -> ElfLayout w
                   -> L.ByteString
                   -> DynamicMap w
                   -> Int -- ^ Number of symbols
                   -> m [Word16]
gnuSymVersionTable d l file dm symcnt = do
  mvs <- optionalDynamicEntry DT_VERSYM dm
  case mvs of
    Nothing -> return []
    Just vs -> do
      buffer <- addressToFile l file "symbol version requirements" vs
      return $ runGet (replicateM symcnt (getWord16 d)) buffer

parsed_dyntags :: [ElfDynamicArrayTag]
parsed_dyntags =
  [ DT_NEEDED
  , DT_PLTRELSZ
  , DT_PLTGOT

  , DT_STRTAB
  , DT_SYMTAB
  , DT_RELA
  , DT_RELASZ
  , DT_RELAENT
  , DT_STRSZ
  , DT_SYMENT
  , DT_INIT
  , DT_FINI
  , DT_SONAME
    
  , DT_PLTREL
  , DT_DEBUG

  , DT_JMPREL
  
  , DT_GNU_HASH

  , DT_VERSYM
  , DT_RELACOUNT

  , DT_VERDEF
  , DT_VERDEFNUM
  , DT_VERNEED
  , DT_VERNEEDNUM
  ]

dynamicEntries :: (RelocationType u s tp, Monad m)
               => Elf u
               -> m (Maybe (DynamicSection u s tp))
dynamicEntries e = do
  let l = elfLayout e
  let file = U.toLazyByteString $ l^.elfOutput
  case filter (hasSegmentType PT_DYNAMIC) (F.toList (l^.phdrs)) of
    [] -> return Nothing
    [sec] -> do
      let p = sec^.elfSegmentData
      let elts = runGet (dynamicList (elfData e)) (sliceL p file)
      let m = foldl' (flip insertDynamic) Map.empty elts
    
      strTab <- dynStrTab l file m

      mnm_index <- optionalDynamicEntry DT_SONAME m
      let mnm = nameFromIndex strTab . fromIntegral <$> mnm_index

      symbols <- dynSymTab e l file m

      let isUnparsed tag _ = not (tag `elem` parsed_dyntags)
      sym_versions <- gnuSymVersionTable (elfData e) l file m (length symbols)
      version_defs <- gnuVersionDefs (elfData e) l file strTab m
      version_reqs <- gnuVersionReqs (elfData e) l file strTab m

      relocations <- dynRelaArray (elfData e) l file m
      checkRelaCount relocations m

      gnuhashAddr <- optionalDynamicEntry DT_GNU_HASH m
      pltAddr     <- optionalDynamicEntry DT_PLTGOT m
      relaPLTRange <- dynRelaPLT m
      mdebug <- optionalDynamicEntry DT_DEBUG m

      return $ Just DynSection { dynNeeded = getDynNeeded strTab m
                               , dynSOName = mnm
                               , dynInit = dynamicEntry DT_INIT m
                               , dynFini = dynamicEntry DT_FINI m
                               , dynSymbols = symbols
                               , dynRelocations = relocations
                               , dynSymVersionTable = sym_versions
                               , dynVersionDefs = version_defs
                               , dynVersionReqs = version_reqs
                               , dynGNUHASH_Addr = gnuhashAddr
                               , dynPLTAddr = pltAddr
                               , dynRelaPLTRange = relaPLTRange
                               , dynDebug = mdebug
                               , dynUnparsed = Map.filterWithKey isUnparsed m
                               }
    _ -> fail "Multiple dynamic segments."


------------------------------------------------------------------------
-- Elf symbol information

[enum|
  ElfSymbolBinding :: Word8
  STB_LOCAL 0 -- Symbol not visible outside obj
  STB_GLOBAL 1 -- Symbol visible outside obj
  STB_WEAK 2 -- Like globals, lower precedence
  STB_GNU_UNIQUE 10 --Symbol is unique in namespace
  STB_Other w
|]

ppElfSymbolBinding :: ElfSymbolBinding -> String
ppElfSymbolBinding b =
  case b of
    STB_LOCAL -> "LOCAL"
    STB_GLOBAL -> "GLOBAL"
    STB_WEAK   -> "WEAK"
    STB_GNU_UNIQUE -> "UNIQUE"
    STB_Other w | 11 <= w && w <= 12 -> "<OS specific>: " ++ show w
                | 13 <= w && w <= 15 -> "<processor specific>: " ++ show w
                | otherwise -> "<unknown>: " ++ show w

infoToTypeAndBind :: Word8 -> (ElfSymbolType,ElfSymbolBinding)
infoToTypeAndBind i =
  let tp = toElfSymbolType (i .&. 0x0F)
      b = (i `shiftR` 4) .&. 0xF 
   in (tp, toElfSymbolBinding b)

[enum|
 ElfSymbolType :: Word8
 STT_NOTYPE     0 -- Symbol type is unspecified
 STT_OBJECT     1 -- Symbol is a data object
 STT_FUNC       2 -- Symbol is a code object
 STT_SECTION    3 -- Symbol associated with a section.
 STT_FILE       4 -- Symbol gives a file name.
 STT_COMMON     5 -- An uninitialised common block.
 STT_TLS        6 -- Thread local data object.
 STT_RELC       8 -- Complex relocation expression.
 STT_SRELC      9 -- Signed Complex relocation expression.
 STT_GNU_IFUNC 10 -- Symbol is an indirect code object.
 STT_Other      _
|]

isOSSpecificSymbolType :: ElfSymbolType -> Bool
isOSSpecificSymbolType tp =
  case tp of
    STT_GNU_IFUNC -> True
    STT_Other w | 10 <= w && w <= 12 -> True
    _ -> False

isProcSpecificSymbolType :: ElfSymbolType -> Bool
isProcSpecificSymbolType tp =
  case tp of
    STT_Other w | 13 <= w && w <= 15 -> True
    _ -> False

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
    STT_Other w | isOSSpecificSymbolType tp -> "<OS specific>: " ++ show w
                | isProcSpecificSymbolType tp -> "<processor specific>: " ++ show w
                | otherwise -> "<unknown>: " ++ show w


newtype ElfSectionIndex = ElfSectionIndex Word16
  deriving (Eq, Ord)

asSectionIndex :: ElfSectionIndex -> Maybe Word16
asSectionIndex si@(ElfSectionIndex w)
  | shn_undef < si && si < shn_loreserve = Just (w-1)
  | otherwise = Nothing

-- | Undefined section
shn_undef :: ElfSectionIndex
shn_undef = ElfSectionIndex 0

-- | Associated symbol is absolute.
shn_abs :: ElfSectionIndex
shn_abs = ElfSectionIndex 0xfff1

-- | Associated symbol is common.
shn_common :: ElfSectionIndex
shn_common = ElfSectionIndex 0xfff2

-- | Start of reserved indices.
shn_loreserve :: ElfSectionIndex
shn_loreserve = ElfSectionIndex 0xff00

-- | Start of processor specific.
shn_loproc :: ElfSectionIndex
shn_loproc = shn_loreserve

-- | Like SHN_COMMON but symbol in .lbss
shn_x86_64_lcommon :: ElfSectionIndex
shn_x86_64_lcommon = ElfSectionIndex 0xff02

-- | Only used by HP-UX, because HP linker gives
-- weak symbols precdence over regular common symbols.
shn_ia_64_ansi_common :: ElfSectionIndex
shn_ia_64_ansi_common = shn_loreserve

-- | Small common symbols
shn_mips_scommon :: ElfSectionIndex
shn_mips_scommon = ElfSectionIndex 0xff03

-- | Small undefined symbols
shn_mips_sundefined  :: ElfSectionIndex
shn_mips_sundefined = ElfSectionIndex 0xff04

-- | Small data area common symbol.
shn_tic6x_scommon :: ElfSectionIndex
shn_tic6x_scommon = shn_loreserve

-- | End of processor specific.
shn_hiproc :: ElfSectionIndex
shn_hiproc = ElfSectionIndex 0xff1f

-- | Start of OS-specific.
shn_loos :: ElfSectionIndex
shn_loos = ElfSectionIndex 0xff20

-- | End of OS-specific.
shn_hios :: ElfSectionIndex
shn_hios = ElfSectionIndex 0xff3f

instance Show ElfSectionIndex where
  show i = ppElfSectionIndex EM_NONE ELFOSABI_SYSV maxBound i

ppElfSectionIndex :: ElfMachine
                  -> ElfOSABI
                  -> Word16 -- ^ Number of sections.
                  -> ElfSectionIndex
                  -> String
ppElfSectionIndex m abi shnum tp@(ElfSectionIndex w)
  | tp == shn_undef  = "UND"
  | tp == shn_abs    = "ABS"
  | tp == shn_common = "COM"
  | tp == shn_ia_64_ansi_common
  , m == EM_IA_64
  , abi == ELFOSABI_HPUX = "ANSI_COM"
  | tp == shn_x86_64_lcommon
  , m `elem` [ EM_X86_64, EM_L1OM, EM_K1OM]
  = "LARGE_COM"
  | (tp,m) == (shn_mips_scommon, EM_MIPS)
    || (tp,m) == (shn_tic6x_scommon, EM_TI_C6000)
  = "SCOM"
  | (tp,m) == (shn_mips_sundefined, EM_MIPS)
  = "SUND"
  | tp >= shn_loproc && tp <= shn_hiproc
  = "PRC[0x" ++ showHex w "]"
  | tp >= shn_loos && tp <= shn_hios
  = "OS [0x" ++ showHex w "]"
  | tp >= shn_loreserve
  = "RSV[0x" ++ showHex w "]"
  | w >= shnum = "bad section index[" ++ show w ++ "]"
  | otherwise = show w

-- | Return elf interpreter in a PT_INTERP section if one exists, or Nothing is no interpreter
-- is defined.  This will call the Monad fail operation if the contents of the data cannot be
-- parsed.
elfInterpreter :: Monad m => Elf w -> m (Maybe FilePath)
elfInterpreter e =
  case filter (hasSegmentType PT_INTERP) (elfSegments e) of
    [] -> return Nothing
    seg:_ -> do
      case seg^.elfSegmentData of
        [ElfDataSection s] -> return (Just (B.toString (elfSectionData s)))
        _ -> fail "Could not parse elf section."