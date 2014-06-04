{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE TemplateHaskell #-}
-- | Data.Elf  is a module for parsing a ByteString of an ELF file into an Elf record.
module Data.Elf ( Elf(..)
                , ElfClass(..)
                , ElfData(..)
                , ElfOSABI(..)
                , ElfType(..)
                , ElfMachine(..)
                , ElfDataRegion(..)
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
                , ElfSegment
                , ElfSegmentF(..)
                , ElfSegmentType(..)
                , ElfSegmentFlags
                , pf_none, pf_x, pf_w, pf_r
                , ElfSymbolTableEntry(..)
                , ElfSymbolType(..)
                , ElfSymbolBinding(..)
                , ElfSectionIndex(..)
                , parseSymbolTables
                , findSymbolDefinition
                ) where

import Data.Binary
import Data.Binary.Get as G
import Data.Bits
import Data.Int (Int64)
import Data.List (intercalate, sort, find)
import qualified Data.Map as Map
import Data.Maybe
import Data.Monoid
import qualified Data.Vector as V
import Numeric
import Control.Applicative ((<$>))
import Control.Monad
import Control.Exception ( assert )
import qualified Data.ByteString          as B
import qualified Data.ByteString.Lazy     as L
import qualified Data.ByteString.UTF8 as B (fromString, toString)

import Data.Binary.Builder.Sized (Builder)
import qualified Data.Binary.Builder.Sized as U

import Data.Elf.TH

enumCnt :: (Enum e, Real r) => e -> r -> [e]
enumCnt e x = if x > 0 then e : enumCnt (succ e) (x-1) else []

type Range = (Int,Int)

slice :: Range -> B.ByteString -> B.ByteString
slice (i,c) = B.take c . B.drop i

-- | @fixAlignment v a@ returns the smallest multiple of @a@ 
-- that is not less than @v@. 
fixAlignment :: Word64 -> Word64 -> Word64
fixAlignment v 0 = v
fixAlignment v 1 = v
fixAlignment v a
    | m == 0 = c * a
    | otherwise = (c + 1) * a
  where (c,m) = v `divMod` a

-- | Downcase word64 into a word32.
as32 :: Word64 -> Word32
as32 w | w >= 2^(32::Word32) = error $ "Word is too large to be treated as a 32-bit integer."
       | otherwise = fromIntegral w

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

data Elf = Elf
    { elfClass      :: ElfClass      -- ^ Identifies the class of the object file.
    , elfData       :: ElfData       -- ^ Identifies the data encoding of the object file.
    , elfVersion    :: Word8         -- ^ Identifies the version of the object file format.
    , elfOSABI      :: ElfOSABI      -- ^ Identifies the operating system and ABI for which the object is prepared.
    , elfABIVersion :: Word8         -- ^ Identifies the ABI version for which the object is prepared.
    , elfType       :: ElfType       -- ^ Identifies the object file type.
    , elfMachine    :: ElfMachine    -- ^ Identifies the target architecture.
    , elfEntry      :: Word64        -- ^ Virtual address of the program entry point. 0 for non-executable Elfs.
    , elfFlags      :: Word32          -- ^ Machine specific flags
    , elfFileData   :: [ElfDataRegion] -- ^ Data to be stored in elf file.
    } deriving (Show)

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
 EM_EXT           _  -- ^ Other
|]

-- | Describes a block of data in the file.
data ElfDataRegion
    -- | Identifies the elf header (should appear 1st in an in-order traversal of the file).
  = ElfDataElfHeader 
    -- | Identifies the program header table.
  | ElfDataSegmentHeaders
  | ElfDataSegment ElfSegment
    -- | Identifies the section header table.
  | ElfDataSectionHeaders
    -- | The section for storing the section names.
  | ElfDataSectionNameTable
    -- | Uninterpreted sections.
  | ElfDataSection ElfSection
    -- | Identifies an uninterpreted array of bytes.
  | ElfDataRaw B.ByteString
  deriving (Show)  

data ElfSection = ElfSection
    { elfSectionName      :: String          -- ^ Identifies the name of the section.
    , elfSectionType      :: ElfSectionType  -- ^ Identifies the type of the section.
    , elfSectionFlags     :: ElfSectionFlags -- ^ Identifies the attributes of the section.
    , elfSectionAddr      :: Word64          -- ^ The virtual address of the beginning of the section in memory. 0 for sections that are not loaded into target memory.
    , elfSectionSize      :: Word64          -- ^ The size of the section. Except for SHT_NOBITS sections, this is the size of elfSectionData.
    , elfSectionLink      :: Word32          -- ^ Contains a section index of an associated section, depending on section type.
    , elfSectionInfo      :: Word32          -- ^ Contains extra information for the index, depending on type.
    , elfSectionAddrAlign :: Word64          -- ^ Contains the required alignment of the section. Must be a power of two.
    , elfSectionEntSize   :: Word64          -- ^ Size of entries if section has a table.
    , elfSectionData      :: B.ByteString    -- ^ Data in section.  
    } deriving (Eq, Show)

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

newtype ElfSectionFlags = ElfSectionFlags { fromElfSectionFlags :: Word64 }
  deriving (Eq, Num, Bits)

instance Show ElfSectionFlags where
  showsPrec d (ElfSectionFlags w) = showFlags names d w
    where names = V.fromList ["shf_write", "shf_alloc", "shf_execinstr"]

-- | Empty set of flags
shf_none :: ElfSectionFlags
shf_none = 0

-- | Section contains writable data
shf_write :: ElfSectionFlags
shf_write = 1

-- | Section is allocated in memory image of program
shf_alloc :: ElfSectionFlags
shf_alloc = 2

-- | Section contains executable instructions
shf_execinstr :: ElfSectionFlags
shf_execinstr = 4
  
-- | Information about an elf segment (parameter is for type of data).
data ElfSegmentF v = ElfSegment
  { elfSegmentType      :: ElfSegmentType  -- ^ Segment type
  , elfSegmentFlags     :: ElfSegmentFlags -- ^ Segment flags
  , elfSegmentVirtAddr  :: Word64          -- ^ Virtual address for the segment
  , elfSegmentPhysAddr  :: Word64          -- ^ Physical address for the segment
  , elfSegmentAlign     :: Word64          -- ^ Segment alignment
  , elfSegmentMemSize   :: Word64          -- ^ Size in memory (may be larger then segment data)
  , elfSegmentData      :: v               -- ^ Identifies data in the segment.
  } deriving (Functor, Show)

type ElfSegment = ElfSegmentF [ElfDataRegion]

setElfSegmentData :: ElfSegmentF u -> v -> ElfSegmentF v 
setElfSegmentData s v = fmap (\_ -> v) s

[enum| 
 ElfSegmentType :: Word32
 PT_NULL    0 -- ^ Unused entry
 PT_LOAD    1 -- ^ Loadable segment
 PT_DYNAMIC 2 -- ^ Dynamic linking tables
 PT_INTERP  3 -- ^ Program interpreter path name
 PT_NOTE    4 -- ^ Note sectionks
 PT_SHLIB   5 -- ^ Reserved
 PT_PHDR    6 -- ^ Program header table
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

-- | Name of shstrtab (used to reduce spelling errors).
shstrtab :: String
shstrtab = ".shstrtab"

type StringTable = (Map.Map B.ByteString Word32, Builder)

-- | Insert bytestring in list of strings.
insertString :: StringTable -> B.ByteString -> StringTable
insertString a@(m,b) bs 
    | Map.member bs m = a
    | otherwise = (m', b')
  where  insertTail i = Map.insertWith (\_n o -> o) (B.drop i bs) offset
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
        myFind bs = case Map.lookup bs m of
                      Just v -> v
                      Nothing -> error $ "Can't find " ++ show bs ++ " in " ++ show m ++ "\n" ++ show strings
        stringMap = Map.fromList $ strings `zip` map myFind bsl

-- | Returns null-terminated string at given index in bytestring.
lookupString :: Word32 -> B.ByteString -> B.ByteString
lookupString o b = B.takeWhile (/= 0) $ B.drop (fromIntegral o) b

-- | Create a section for the section name table from the data.
elfNameTableSection :: B.ByteString -> ElfSection
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

-- | List of sections in the file.
elfSections :: Elf -> [ElfSection]
elfSections e = r
  where r = concatMap impl (elfFileData e)
        impl (ElfDataSegment s) = concatMap impl (elfSegmentData s)
        impl ElfDataSectionNameTable = [elfNameTableSection t]
          where (t,_) = stringTable (map elfSectionName r) 
        impl (ElfDataSection s) = [s]
        impl _ = []

-- | Given a section name, extract the ElfSection.
findSectionByName      :: String -> Elf -> Maybe ElfSection
findSectionByName name  = find byName . elfSections
  where byName section  = elfSectionName section == name

-- | Update sections in elf file.  
updateSections :: (ElfSection -> Maybe ElfSection) -> Elf -> Elf
updateSections fn e = e { elfFileData = mapMaybe impl (elfFileData e) }
  where (t,_) = stringTable $ map elfSectionName (elfSections e)
        norm s | elfSectionName s == shstrtab = ElfDataSectionNameTable
               | otherwise = ElfDataSection s
        impl (ElfDataSegment s) = Just (ElfDataSegment s')
          where s' = s { elfSegmentData = mapMaybe impl (elfSegmentData s) }
        impl ElfDataSectionNameTable = norm <$> fn (elfNameTableSection t)
        impl (ElfDataSection s) = norm <$> fn s
        impl d = Just d
        
-- | Remove section with given name.
removeSectionByName :: String -> Elf -> Elf
removeSectionByName nm = updateSections fn
  where fn s | elfSectionName s == nm = Nothing
             | otherwise = Just s

-- | List of segments in the file.
elfSegments :: Elf -> [ElfSegment]  
elfSegments e = concatMap impl (elfFileData e)
  where impl (ElfDataSegment s) = s : concatMap impl (elfSegmentData s)
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

getWord32As64 :: ElfData -> Get Word64
getWord32As64 d = fromIntegral <$> getWord32 d

-- | Returns length of section in file.
sectionFileLen :: ElfSectionType -> Word64 -> Int
sectionFileLen SHT_NOBITS _ = 0
sectionFileLen _ s = fromIntegral s

sectionData :: ElfSectionType -> Int -> Word64 -> B.ByteString -> B.ByteString
sectionData SHT_NOBITS _ _ _ = B.empty
sectionData _ o s b = slice (o,fromIntegral s) b

type GetShdrFn = B.ByteString
                 -> B.ByteString
                 -> Get (Range, ElfSection)

getShdr32 :: ElfData -> GetShdrFn
getShdr32 d file string_section = do
  sh_name      <- getWord32 d
  sh_type      <- toElfSectionType    <$> getWord32 d
  sh_flags     <- ElfSectionFlags <$> getWord32As64 d
  sh_addr      <- fromIntegral <$> getWord32 d
  sh_offset    <- fromIntegral <$> getWord32 d
  sh_size      <- getWord32As64 d
  sh_link      <- getWord32 d
  sh_info      <- getWord32 d
  sh_addralign <- fromIntegral <$> getWord32 d
  sh_entsize   <- fromIntegral <$> getWord32 d
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

getShdr64 :: ElfData -> GetShdrFn
getShdr64 er file string_section = do
  sh_name      <- getWord32 er
  sh_type      <- toElfSectionType <$> getWord32 er
  sh_flags     <- ElfSectionFlags  <$> getWord64 er
  sh_addr      <- getWord64 er
  sh_offset    <- fromIntegral     <$> getWord64 er
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

type GetPhdrFn = Get (ElfSegmentF Range)

getPhdr32 :: ElfData -> GetPhdrFn
getPhdr32 d = do
  p_type   <- toElfSegmentType  <$> getWord32 d
  p_offset <- fromIntegral <$> getWord32 d
  p_vaddr  <- getWord32As64 d
  p_paddr  <- getWord32As64 d
  p_filesz <- fromIntegral <$> getWord32 d
  p_memsz  <- getWord32As64 d
  p_flags  <- ElfSegmentFlags <$> getWord32 d
  p_align  <- getWord32As64 d
  return ElfSegment
       { elfSegmentType      = p_type
       , elfSegmentFlags     = p_flags
       , elfSegmentVirtAddr  = p_vaddr
       , elfSegmentPhysAddr  = p_paddr
       , elfSegmentAlign     = p_align
       , elfSegmentMemSize   = p_memsz
       , elfSegmentData      = (p_offset, p_filesz)
       }

getPhdr64 :: ElfData -> GetPhdrFn  
getPhdr64 d = do
  p_type   <- toElfSegmentType  <$> getWord32 d
  p_flags  <- ElfSegmentFlags <$> getWord32 d
  p_offset <- fromIntegral <$> getWord64 d
  p_vaddr  <- getWord64 d
  p_paddr  <- getWord64 d
  p_filesz <- fromIntegral <$> getWord64 d
  p_memsz  <- getWord64 d
  p_align  <- getWord64 d
  return ElfSegment
         { elfSegmentType     = p_type
         , elfSegmentFlags    = p_flags
         , elfSegmentVirtAddr = p_vaddr
         , elfSegmentPhysAddr = p_paddr
         , elfSegmentAlign    = p_align
         , elfSegmentMemSize  = p_memsz
         , elfSegmentData     = (p_offset,p_filesz)
         }

-- | Defines the layout of a table with elements of a fixed size. 
data TableLayout =
  TableLayout { tableOffset :: Int
              , entrySize :: Int
              , entryNum :: Word16 
              }
  
mkTableLayout :: Int -> Word16 -> Word16 -> TableLayout
mkTableLayout o s n = TableLayout o (fromIntegral s) n

-- | Returns offset of entry in table.
tableEntry :: TableLayout -> Word16 -> B.ByteString -> L.ByteString
tableEntry l i b = L.fromChunks [B.drop o b]
  where sz = entrySize l
        o = tableOffset l + fromIntegral i * sz

-- | Returns size of table.
tableSize :: TableLayout -> Int
tableSize l = fromIntegral (entryNum l) * entrySize l

-- | Returns range in memory of table.
tableRange :: TableLayout -> Range
tableRange l = (fromIntegral $ tableOffset l, tableSize l) 

-- | Returns size of region.
type RegionSizeFn = ElfDataRegion -> Int

-- | Function that transforms list of regions into new list.
type RegionPrefixFn = [ElfDataRegion] -> [ElfDataRegion]

-- | Create a singleton list with a raw data region if one exists
insertRawRegion :: B.ByteString -> RegionPrefixFn
insertRawRegion b r | B.length b == 0 = r
                    | otherwise = ElfDataRaw b : r

-- | Insert an elf data region at a given offset.
insertAtOffset :: RegionSizeFn   -- ^ Returns size of region.
               -> Range
               -> RegionPrefixFn -- ^ Insert function
               -> RegionPrefixFn
insertAtOffset sizeOf (o,c) fn (p:r)
    -- Go to next segment if offset to insert is after p.
  | o >= sz = p:insertAtOffset sizeOf (o-sz,c) fn r
    -- Recurse inside segment if p is a segment that contains region to insert.
  | o + c <= sz 
  , ElfDataSegment s <- p = -- New region ends before p ends and p is a segment.
      let d' = insertAtOffset sizeOf (o,c) fn (elfSegmentData s)
       in ElfDataSegment s { elfSegmentData = d' } : r
    -- Insert into current region is offset is 0.
  | o == 0 = fn (p:r)
    -- Split a raw segment into prefix and post.
  | ElfDataRaw b <- p =
      -- We know offset is less than length of bytestring as otherwise we would
      -- have gone to next segment
      assert (o < B.length b) $ do
        let (pre,post) = B.splitAt o b
        insertRawRegion pre $ fn $ insertRawRegion post r
  | otherwise = error "Attempt to insert overlapping Elf region"
  where sz = fromIntegral $ sizeOf p
insertAtOffset _ (0,0) fn [] = fn []
insertAtOffset _ _ _ [] = error "Invalid region"

-- | Insert a leaf region into the region.
insertSpecialRegion :: RegionSizeFn -- ^ Returns size of region.
                    -> Range
                    -> ElfDataRegion  -- ^ New region
                    -> RegionPrefixFn 
insertSpecialRegion sizeOf r n = insertAtOffset sizeOf r fn
  where c = snd r
        fn l | c == 0 = n : l     
        fn (ElfDataRaw b:l)
          | c <= B.length b = n : insertRawRegion (B.drop c b) l
        fn _ = error $ "Elf file contained a non-empty header that overlapped with another.\n"
                       ++ "  This is not supported by the Elf parser"

insertSegment :: RegionSizeFn
              -> ElfSegmentF Range
              -> RegionPrefixFn
insertSegment sizeOf d = insertAtOffset sizeOf rng (gather szd [])
  where rng@(_,szd) = elfSegmentData d
        -- | @gather@ inserts new segment into head of list after collecting existings 
        -- data it contains.
        gather :: Int -> [ElfDataRegion] -> RegionPrefixFn
        gather 0 l r = ElfDataSegment (d `setElfSegmentData` reverse l):r
        gather cnt l (p:r)
          | fromIntegral (sizeOf p) <= cnt
          = gather (cnt - fromIntegral (sizeOf p)) (p:l) r
        gather cnt l (ElfDataRaw b:r) =
            ElfDataSegment d' : insertRawRegion post r  
          where pre = B.take cnt b
                post = B.drop cnt b
                newData = reverse l ++ insertRawRegion pre []
                d' = d `setElfSegmentData` newData
        gather _ _ (_:_) = error "insertSegment: Data overlaps unexpectedly"
        gather _ _ []    = error "insertSegment: Data ended before completion"

-- | Contains information needed to parse elf files.
data ElfParseInfo = ElfParseInfo {
       -- | Size of ehdr table
       ehdrSize :: Int
       -- | Layout of segment header table.
     , phdrTable :: TableLayout
     , getPhdr :: GetPhdrFn
       -- | Index of section for storing section names.
     , shdrNameIdx :: Word16
       -- | Layout of section header table.
     , shdrTable :: TableLayout
     , getShdr :: GetShdrFn  
     }

-- | Return size of region given parse information.
regionSize :: ElfParseInfo
           -> Int -- ^ Contains size of name table
           -> RegionSizeFn
regionSize epi nameSize = sizeOf
  where sizeOf ElfDataElfHeader        = ehdrSize epi
        sizeOf ElfDataSegmentHeaders   = tableSize $ phdrTable epi
        sizeOf (ElfDataSegment s)      = sum $ map sizeOf (elfSegmentData s)
        sizeOf ElfDataSectionHeaders   = tableSize $ shdrTable epi
        sizeOf ElfDataSectionNameTable = nameSize
        sizeOf (ElfDataSection s)      = B.length (elfSectionData s)
        sizeOf (ElfDataRaw b)          = B.length b

elfMagic :: B.ByteString
elfMagic = B.fromString "\DELELF"

-- | Parse elf region.
parseElfRegions :: ElfParseInfo -- ^ Information for parsing.
                -> B.ByteString -- ^ File bytestream
                -> [ElfDataRegion]
parseElfRegions epi file = final
  where getSection i = runGet (getShdr epi file names) 
                              (tableEntry (shdrTable epi) i file)
        nameRange = fst $ getSection (shdrNameIdx epi)
        sizeOf = regionSize epi (snd nameRange)
        names = slice nameRange file
        -- Define table with special data regions. 
        headers = [ ((0, ehdrSize epi), ElfDataElfHeader)
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
        -- Define final region list with segments.
        getSegment i =
          runGet (getPhdr epi)
                 (tableEntry (phdrTable epi) i file)
        segments = map getSegment $ enumCnt 0 (entryNum (phdrTable epi))
        final = foldr (insertSegment sizeOf) initial $ segments

-- | Parses a ByteString into an Elf record. Parse failures call error. 32-bit ELF objects have their
-- fields promoted to 64-bit so that the 32- and 64-bit ELF records can be the same.
parseElf :: B.ByteString -> Elf
parseElf b = flip runGet (L.fromChunks [b]) $ do
  ei_magic    <- getByteString 4
  unless (ei_magic == elfMagic) $
    fail "Invalid magic number for ELF"
  ei_class   <- tryParse "ELF class" toElfClass =<< getWord8
  d          <- tryParse "ELF data"  toElfData =<< getWord8
  ei_version <- getWord8
  unless (ei_version == 1) $ 
    fail "Invalid version number for ELF"
  ei_osabi    <- toElfOSABI <$> getWord8 
  ei_abiver   <- getWord8
  skip 7
  case ei_class of
    ELFCLASS32 -> do
      e_type      <- toElfType    <$> getWord16 d
      e_machine   <- toElfMachine <$> getWord16 d
      e_version   <- getWord32 d
      unless (fromIntegral ei_version == e_version) $
        fail "ELF Version mismatch"
      e_entry     <- getWord32As64 d
      e_phoff     <- fromIntegral <$> getWord32 d
      e_shoff     <- fromIntegral <$> getWord32 d
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
      let epi = ElfParseInfo {
                    ehdrSize = fromIntegral e_ehsize
                  , phdrTable = mkTableLayout e_phoff e_phentsize e_phnum
                  , getPhdr = getPhdr32 d
                  , shdrNameIdx = e_shstrndx
                  , shdrTable = mkTableLayout e_shoff e_shentsize e_shnum
                  , getShdr = getShdr32 d
                  }
      return Elf { elfClass      = ei_class
                 , elfData       = d
                 , elfVersion    = ei_version
                 , elfOSABI      = ei_osabi
                 , elfABIVersion = ei_abiver
                 , elfType       = e_type
                 , elfMachine    = e_machine
                 , elfEntry      = e_entry
                 , elfFlags      = e_flags
                 , elfFileData   = parseElfRegions epi b
                 }
    ELFCLASS64 -> do
      e_type      <- toElfType    <$> getWord16 d
      e_machine   <- toElfMachine <$> getWord16 d
      e_version   <- getWord32 d
      unless (fromIntegral ei_version == e_version) $
        fail "ELF Version mismatch"
      e_entry     <- getWord64 d
      e_phoff     <- fromIntegral <$> getWord64 d
      e_shoff     <- fromIntegral <$> getWord64 d
      e_flags     <- getWord32 d
      e_ehsize    <- getWord16 d
      e_phentsize <- getWord16 d
      e_phnum     <- getWord16 d
      e_shentsize <- getWord16 d
      e_shnum     <- getWord16 d
      e_shstrndx  <- getWord16 d
      let epi = ElfParseInfo {
                    ehdrSize = fromIntegral e_ehsize
                  , phdrTable = mkTableLayout e_phoff e_phentsize e_phnum
                  , getPhdr = getPhdr64 d
                  , shdrNameIdx = e_shstrndx
                  , shdrTable = mkTableLayout e_shoff e_shentsize e_shnum
                  , getShdr = getShdr64 d
                  }
      return Elf { elfClass      = ei_class
                 , elfData       = d
                 , elfVersion    = ei_version
                 , elfOSABI      = ei_osabi
                 , elfABIVersion = ei_abiver
                 , elfType       = e_type
                 , elfMachine    = e_machine
                 , elfEntry      = e_entry
                 , elfFlags      = e_flags
                 , elfFileData   = parseElfRegions epi b
                 }

data ElfField v
  = EFBS Int (v -> Builder)                                
  | EFWord16 (v -> Word16)
  | EFWord32 (v -> Word32)
  | EFWord64 (v -> Word64)

type ElfRecord v = [(String, ElfField v)]

sizeOfField :: ElfField v -> Int
sizeOfField (EFBS s _) = s
sizeOfField (EFWord16 _) = 2
sizeOfField (EFWord32 _) = 4
sizeOfField (EFWord64 _) = 8

sizeOfRecord :: ElfRecord v -> Word16
sizeOfRecord = fromIntegral . sum . map (sizeOfField . snd)

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
type Ehdr w = (Elf, ElfLayout w)
type Phdr w = (ElfSegmentF (w, w))
-- | Contains Elf section data, name offset, and data offset.
type Shdr w = (ElfSection, Word32, w)

elfIdentBuilder :: Elf -> Builder
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
  , ("e_entry",     EFWord32 (\(e,_) -> as32 $ elfEntry e))
  , ("e_phoff",     EFWord32 (\(_,l) -> phdrTableOffset l))
  , ("e_shoff",     EFWord32 (\(_,l) -> shdrTableOffset l))
  , ("e_flags",     EFWord32 (\(e,_) -> elfFlags e))
  , ("e_ehsize",    EFWord16 (\(_,_) -> sizeOfEhdr32))
  , ("e_phentsize", EFWord16 (\(_,_) -> sizeOfPhdr32))
  , ("e_phnum",     EFWord16 (\(_,l) -> phnum l)) 
  , ("e_shentsize", EFWord16 (\(_,_) -> sizeOfShdr32))
  , ("e_shnum",     EFWord16 (\(_,l) -> shnum l))
  , ("e_shstrndx",  EFWord16 (\(_,l) -> shstrndx l))
  ]

ehdr64Fields :: ElfRecord (Ehdr Word64)
ehdr64Fields =
  [ ("e_ident",     EFBS 16  (\(e,_) -> elfIdentBuilder e))
  , ("e_type",      EFWord16 (\(e,_) -> fromElfType    $ elfType e))
  , ("e_machine",   EFWord16 (\(e,_) -> fromElfMachine $ elfMachine e))
  , ("e_version",   EFWord32 (\(e,_) -> fromIntegral   $ elfVersion e))
  , ("e_entry",     EFWord64 (\(e,_) -> elfEntry e))
  , ("e_phoff",     EFWord64 (\(_,l) -> phdrTableOffset l))
  , ("e_shoff",     EFWord64 (\(_,l) -> shdrTableOffset l))
  , ("e_flags",     EFWord32 (\(e,_) -> elfFlags e))
  , ("e_ehsize",    EFWord16 (\(_,_) -> sizeOfEhdr64))
  , ("e_phentsize", EFWord16 (\(_,_) -> sizeOfPhdr64))
  , ("e_phnum",     EFWord16 (\(_,l) -> phnum l))
  , ("e_shentsize", EFWord16 (\(_,_) -> sizeOfShdr64))
  , ("e_shnum",     EFWord16 (\(_,l) -> shnum l))
  , ("e_shstrndx",  EFWord16 (\(_,l) -> shstrndx l))
  ]

phdr32Fields :: ElfRecord (Phdr Word32)
phdr32Fields =
  [ ("p_type",   EFWord32 $  fromElfSegmentType . elfSegmentType)
  , ("p_offset", EFWord32 $                 fst . elfSegmentData)
  , ("p_vaddr",  EFWord32 $                as32 . elfSegmentVirtAddr)
  , ("p_paddr",  EFWord32 $                as32 . elfSegmentPhysAddr)
  , ("p_filesz", EFWord32 $                 snd . elfSegmentData)
  , ("p_memsz",  EFWord32 $                as32 . elfSegmentMemSize)
  , ("p_flags",  EFWord32 $ fromElfSegmentFlags . elfSegmentFlags)
  , ("p_align",  EFWord32 $                as32 . elfSegmentAlign)
  ]

phdr64Fields :: ElfRecord (Phdr Word64)
phdr64Fields =
  [ ("p_type",   EFWord32 $ fromElfSegmentType . elfSegmentType)
  , ("p_flags",  EFWord32 $ fromElfSegmentFlags . elfSegmentFlags)
  , ("p_offset", EFWord64 $ fst . elfSegmentData)
  , ("p_vaddr",  EFWord64 $ elfSegmentVirtAddr)
  , ("p_paddr",  EFWord64 $ elfSegmentPhysAddr)
  , ("p_filesz", EFWord64 $ snd . elfSegmentData)
  , ("p_memsz",  EFWord64 $ elfSegmentMemSize)
  , ("p_align",  EFWord64 $ elfSegmentAlign)
  ]

shdr32Fields :: ElfRecord (Shdr Word32)
shdr32Fields = 
  [ ("sh_name",      EFWord32 (\(_,n,_) -> n))
  , ("sh_type",      EFWord32 (\(s,_,_) -> fromElfSectionType  $ elfSectionType s))
  , ("sh_flags",     EFWord32 (\(s,_,_) -> as32 $ fromElfSectionFlags $ elfSectionFlags s))
  , ("sh_addr",      EFWord32 (\(s,_,_) -> as32 $ elfSectionAddr s))
  , ("sh_offset",    EFWord32 (\(_,_,o) -> o))
  , ("sh_size",      EFWord32 (\(s,_,_) -> as32 $ elfSectionSize s))
  , ("sh_link",      EFWord32 (\(s,_,_) -> elfSectionLink s))
  , ("sh_info",      EFWord32 (\(s,_,_) -> elfSectionInfo s))
  , ("sh_addralign", EFWord32 (\(s,_,_) -> as32 $ elfSectionAddrAlign s))
  , ("sh_entsize",   EFWord32 (\(s,_,_) -> as32 $ elfSectionEntSize s))
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
        elfOutput :: Builder
      , phdrTableOffset :: w
        -- | Lift of phdrs that must appear before loadable segments.
      , preLoadPhdrs :: [Builder]
        -- | List of other segments.
      , phdrs :: [Builder]
        -- | Offset to section header table.
      , shdrTableOffset :: w
        -- Index of string table. 
      , shstrndx :: Word16
        -- | List of section headers found so far.
      , shdrs :: [Builder]
      }

-- | Return total size of output.
outputSize :: ElfLayout w -> Int64
outputSize = U.length . elfOutput

-- | Return number of sections in layout.
shnum :: ElfLayout w -> Word16
shnum = fromIntegral . length . shdrs

-- | Returns number of segments in layout.
phnum :: Num i => ElfLayout w -> i
phnum l = fromIntegral $ length (preLoadPhdrs l) + length (phdrs l)

isPreloadPhdr :: ElfSegmentType -> Bool
isPreloadPhdr PT_PHDR = True
isPreloadPhdr PT_INTERP = True
isPreloadPhdr _ = False

elfLayout :: Integral w
          => ElfRecord (Ehdr w) -> ElfRecord (Phdr w) -> ElfRecord (Shdr w)
          -> Elf 
          -> L.ByteString
elfLayout ehdr phdr shdr e = U.toLazyByteString (elfOutput final)
  where d = elfData e
        region = elfFileData e
        section_names = map elfSectionName (elfSections e)
        (name_data,name_map) = stringTable section_names 
        initl = ElfLayout { elfOutput = mempty
                          , phdrTableOffset = 0
                          , preLoadPhdrs = []
                          , phdrs = []
                          , shdrTableOffset = 0
                          , shstrndx = 0
                          , shdrs = []
                          }
        -- Get final elf layout after processing elements.
        final = foldl impl initl region
        -- Process element.
        impl l ElfDataElfHeader = 
             l { elfOutput = elfOutput l `mappend` fn 
               }
          where fn = writeRecord ehdr d (e,final)
        impl l ElfDataSegmentHeaders =
             l { elfOutput = elfOutput l 
                             `mappend` (mconcat (preLoadPhdrs final))
                             `mappend` (mconcat (phdrs final))
               , phdrTableOffset = fromIntegral (outputSize l)
               }
        impl l (ElfDataSegment s)
          | isPreloadPhdr (elfSegmentType s) =
             l2 { preLoadPhdrs = preLoadPhdrs l2 ++ [b] } 
          | otherwise =
             l2 { phdrs = phdrs l2 ++ [b] }
          where l2 = foldl impl l (elfSegmentData s)
                -- Length of phdr data.
                o = fromIntegral (outputSize l)
                c = fromIntegral (outputSize l2) - o
                b = writeRecord phdr d (s `setElfSegmentData` (o,c))
        impl l ElfDataSectionHeaders =
             l { elfOutput = elfOutput l `mappend` mconcat (shdrs final)
               , shdrTableOffset = fromIntegral (outputSize l)
               }
        impl l ElfDataSectionNameTable = impl l' (ElfDataSection s)
          where l' = l { shstrndx  = shnum l }
                s  = elfNameTableSection name_data
        impl l (ElfDataSection s) =
             l { elfOutput = elfOutput l `mappend` pad `mappend` fn
               , shdrs = shdrs l ++ [writeRecord shdr d (s,no, fromIntegral o)]
               }
          where Just no = Map.lookup (elfSectionName s) name_map
                base = fromIntegral (outputSize l)
                o = fixAlignment base (elfSectionAddrAlign s)
                pad = U.fromByteString (B.replicate (fromIntegral (o - base)) 0)
                fn = U.fromByteString (elfSectionData s)
        impl l (ElfDataRaw b) =
             l { elfOutput = elfOutput l `mappend` U.fromByteString b
               }
  
renderElf :: Elf -> L.ByteString
renderElf e = 
  case elfClass e of
    ELFCLASS32 -> elfLayout ehdr32Fields phdr32Fields shdr32Fields e
    ELFCLASS64 -> elfLayout ehdr64Fields phdr64Fields shdr64Fields e

-- | The symbol table entries consist of index information to be read from other
-- parts of the ELF file. Some of this information is automatically retrieved
-- for your convenience (including symbol name, description of the enclosing
-- section, and definition).
data ElfSymbolTableEntry = EST
    { steName             :: (Word32,Maybe B.ByteString)
    , steEnclosingSection :: Maybe ElfSection -- ^ Section from steIndex
    , steType             :: ElfSymbolType
    , steBind             :: ElfSymbolBinding
    , steOther            :: Word8
    , steIndex            :: ElfSectionIndex  -- ^ Section in which the def is held
    , steValue            :: Word64
    , steSize             :: Word64
    } deriving (Eq, Show)

-- | Parse the symbol table section into a list of symbol table entries. If
-- no symbol table is found then an empty list is returned.
-- This function does not consult flags to look for SHT_STRTAB (when naming symbols),
-- it just looks for particular sections of ".strtab" and ".shstrtab".
parseSymbolTables :: Elf -> [[ElfSymbolTableEntry]]
parseSymbolTables e = map (getSymbolTableEntries e) $ symbolTableSections e

-- | Assumes the given section is a symbol table, type SHT_SYMTAB
-- (guaranteed by parseSymbolTables).
getSymbolTableEntries :: Elf -> ElfSection -> [ElfSymbolTableEntry]
getSymbolTableEntries e s =
    let link   = elfSectionLink s
        strtab = lookup link (zip [0..] (elfSections e))
    in runGetMany (getSymbolTableEntry e strtab) (L.fromChunks [elfSectionData s])

-- | Use the symbol offset and size to extract its definition
-- (in the form of a ByteString).
-- If the size is zero, or the offset larger than the 'elfSectionData',
-- then 'Nothing' is returned.
findSymbolDefinition :: ElfSymbolTableEntry -> Maybe B.ByteString
findSymbolDefinition e =
    let enclosingData = elfSectionData <$> steEnclosingSection e
        start = fromIntegral (steValue e)
        len = fromIntegral (steSize e)
        def = slice (start, len) <$> enclosingData
    in if def == Just B.empty then Nothing else def

runGetMany :: Get a -> L.ByteString -> [a]
runGetMany g0 bs0 = go g0 (L.toChunks bs0) (runGetIncremental g0)
  where go :: Get a -> [B.ByteString] -> Decoder a -> [a]
        go _ _ (Fail _ _ msg)  = error msg
        go g [] (Partial f)    = go g [] (f Nothing)
        go g (h:r) (Partial f) = go g r (f (Just h))
        go g l (Done bs _ v)   = v : go g (bs:l) (runGetIncremental g)

symbolTableSections :: Elf -> [ElfSection]
symbolTableSections e = filter ((== SHT_SYMTAB) . elfSectionType) (elfSections e)

-- Get a string from a strtab ByteString.
stringByIndex :: Word32 -> B.ByteString -> Maybe B.ByteString
stringByIndex n strtab = if B.length str == 0 then Nothing else Just str
  where str = lookupString n strtab

-- | Gets a single entry from the symbol table, use with runGetMany.
getSymbolTableEntry :: Elf -> Maybe ElfSection -> Get ElfSymbolTableEntry
getSymbolTableEntry e strtlb =
    if elfClass e == ELFCLASS32 then getSymbolTableEntry32 else getSymbolTableEntry64
  where
  strs = fromMaybe B.empty (elfSectionData <$> strtlb)
  er = elfData e
  getSymbolTableEntry32 = do
    nameIdx <- getWord32 er
    value <- fromIntegral <$> getWord32 er
    size  <- fromIntegral <$> getWord32 er
    info  <- getWord8
    other <- getWord8
    sTlbIdx <- liftM (toEnum . fromIntegral) (getWord16 er)
    let name = stringByIndex nameIdx strs
        (typ,bind) = infoToTypeAndBind info
        sec = sectionByIndex e sTlbIdx
    return $ EST (nameIdx,name) sec typ bind other sTlbIdx value size
  getSymbolTableEntry64 = do
    nameIdx <- getWord32 er
    info <- getWord8
    other <- getWord8
    sTlbIdx <- liftM (toEnum . fromIntegral) (getWord16 er)
    symVal <- getWord64 er
    size <- getWord64 er
    let name = stringByIndex nameIdx strs
        (typ,bind) = infoToTypeAndBind info
        sec = sectionByIndex e sTlbIdx
    return $ EST (nameIdx,name) sec typ bind other sTlbIdx symVal size

sectionByIndex :: Elf -> ElfSectionIndex -> Maybe ElfSection
sectionByIndex e (SHNIndex i) = lookup i . zip [1..] $ (elfSections e)
sectionByIndex _ _ = Nothing

infoToTypeAndBind :: Word8 -> (ElfSymbolType,ElfSymbolBinding)
infoToTypeAndBind i =
    let t = fromIntegral $ i .&. 0x0F
        b = fromIntegral $ (i .&. 0xF) `shiftR` 4
    in (toEnum t, toEnum b)

data ElfSymbolBinding
    = STBLocal
    | STBGlobal
    | STBWeak
    | STBLoOS
    | STBHiOS
    | STBLoProc
    | STBHiProc
    deriving (Eq, Ord, Show, Read)

instance Enum ElfSymbolBinding where
    fromEnum STBLocal  = 0
    fromEnum STBGlobal = 1
    fromEnum STBWeak   = 2
    fromEnum STBLoOS   = 10
    fromEnum STBHiOS   = 12
    fromEnum STBLoProc = 13
    fromEnum STBHiProc = 15
    toEnum  0 = STBLocal
    toEnum  1 = STBGlobal
    toEnum  2 = STBWeak
    toEnum 10 = STBLoOS
    toEnum 12 = STBHiOS
    toEnum 13 = STBLoProc
    toEnum 15 = STBHiProc
    toEnum _  = error "toEnum ElfSymbolBinding given invalid index"

data ElfSymbolType
    = STTNoType
    | STTObject
    | STTFunc
    | STTSection
    | STTFile
    | STTCommon
    | STTTLS
    | STTLoOS
    | STTHiOS
    | STTLoProc
    | STTHiProc
    deriving (Eq, Ord, Show, Read)

instance Enum ElfSymbolType where
    fromEnum STTNoType  = 0
    fromEnum STTObject  = 1
    fromEnum STTFunc    = 2
    fromEnum STTSection = 3
    fromEnum STTFile    = 4
    fromEnum STTCommon  = 5
    fromEnum STTTLS     = 6

    fromEnum STTLoOS    = 10
    fromEnum STTHiOS    = 12
    fromEnum STTLoProc  = 13
    fromEnum STTHiProc  = 15

    toEnum  0 = STTNoType
    toEnum  1 = STTObject
    toEnum  2 = STTFunc
    toEnum  3 = STTSection
    toEnum  4 = STTFile
    toEnum  5 = STTCommon
    toEnum  6 = STTTLS
    toEnum 10 = STTLoOS
    toEnum 12 = STTHiOS
    toEnum 13 = STTLoProc
    toEnum 15 = STTHiProc
    toEnum x = error ("Error in toEnum for ElfSymbolType " ++ show x)

data ElfSectionIndex
    = SHNUndef
    | SHNLoProc
    | SHNCustomProc Word64
    | SHNHiProc
    | SHNLoOS
    | SHNCustomOS Word64
    | SHNHiOS
    | SHNAbs
    | SHNCommon
    | SHNIndex Word64
    deriving (Eq, Ord, Show, Read)

instance Enum ElfSectionIndex where
    fromEnum SHNUndef = 0
    fromEnum SHNLoProc = 0xFF00
    fromEnum SHNHiProc = 0xFF1F
    fromEnum SHNLoOS   = 0xFF20
    fromEnum SHNHiOS   = 0xFF3F
    fromEnum SHNAbs    = 0xFFF1
    fromEnum SHNCommon = 0xFFF2
    fromEnum (SHNCustomProc x) = fromIntegral x
    fromEnum (SHNCustomOS x) = fromIntegral x
    fromEnum (SHNIndex x) = fromIntegral x
    toEnum 0 = SHNUndef
    toEnum 0xff00 = SHNLoProc
    toEnum 0xFF1F = SHNHiProc
    toEnum 0xFF20 = SHNLoOS
    toEnum 0xFF3F = SHNHiOS
    toEnum 0xFFF1 = SHNAbs
    toEnum 0xFFF2 = SHNCommon
    toEnum x
        | x > fromEnum SHNLoProc && x < fromEnum SHNHiProc = SHNCustomProc (fromIntegral x)
        | x > fromEnum SHNLoOS && x < fromEnum SHNHiOS = SHNCustomOS (fromIntegral x)
        | x < fromEnum SHNLoProc || x > 0xFFFF = SHNIndex (fromIntegral x)
        | otherwise = error "Section index number is in a reserved range but we don't recognize the value from any standard."
