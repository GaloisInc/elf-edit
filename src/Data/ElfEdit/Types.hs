{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE Trustworthy #-} -- Cannot be Safe due to GeneralizedNewtypeDeriving
module Data.ElfEdit.Types
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
    -- * ElfDataRegion
  , ElfDataRegion(..)
  , asumDataRegions
    -- * ElfSection
  , ElfSection(..)
  , elfSectionFileSize
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
    -- ** Symbol Table
  , ElfSymbolTable(..)
  , ElfSymbolTableEntry(..)
  , infoToTypeAndBind
  , typeAndBindToInfo
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

import           Control.Applicative
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

import           Data.ElfEdit.Enums

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
    { elfSectionIndex     :: !Word16
      -- ^ Unique index to identify section.
    , elfSectionName      :: !String
      -- ^ Name of the section.
    , elfSectionType      :: !ElfSectionType
      -- ^ Type of the section.
    , elfSectionFlags     :: !(ElfSectionFlags w)
      -- ^ Attributes of the section.
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

elfSectionFileSize :: Integral w => ElfSection w -> w
elfSectionFileSize = fromIntegral . B.length . elfSectionData

------------------------------------------------------------------------
-- ElfGOT

-- | A global offset table section.
data ElfGOT w = ElfGOT
    { elfGotIndex     :: !Word16
    , elfGotName      :: !String -- ^ Name of section.
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
  ElfSection { elfSectionIndex = elfGotIndex g
             , elfSectionName = elfGotName g
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
-- ElfSymbolTableEntry

-- | The symbol table entries consist of index information to be read from other
-- parts of the ELF file.
--
-- Some of this information is automatically retrieved
-- for your convenience (including symbol name, description of the enclosing
-- section, and definition).
data ElfSymbolTableEntry w = EST
    { steName             :: !B.ByteString
      -- ^ This is the name of the symbol
      --
      -- We use bytestrings for encoding the name rather than a 'Text' or 'String'
      -- value because the elf format does not specify an encoding for symbol table
      -- entries -- it only specifies that they are null-terminated.  This also
      -- makes checking equality and reading symbol tables faster.
    , steType             :: !ElfSymbolType
    , steBind             :: !ElfSymbolBinding
    , steOther            :: !Word8
    , steIndex            :: !ElfSectionIndex
      -- ^ Section in which the def is held
    , steValue            :: !w
      -- ^ Value associated with symbol.
    , steSize             :: !w
    } deriving (Eq, Show)

-- | Convert 8-bit symbol info to symbol type and binding.
infoToTypeAndBind :: Word8 -> (ElfSymbolType,ElfSymbolBinding)
infoToTypeAndBind i =
  let tp = ElfSymbolType (i .&. 0x0F)
      b = (i `shiftR` 4) .&. 0xF
   in (tp, ElfSymbolBinding b)

-- | Convert type and binding information to symbol info field.
typeAndBindToInfo :: ElfSymbolType -> ElfSymbolBinding -> Word8
typeAndBindToInfo (ElfSymbolType tp) (ElfSymbolBinding b) = tp .|. (b `shiftL` 4)

------------------------------------------------------------------------
-- ElfSymbolTable

-- | This entry corresponds to the symbol table index.
data ElfSymbolTable w
  = ElfSymbolTable { elfSymbolTableIndex :: !Word16
                     -- ^ Index of section storing symbol table
                   , elfSymbolTableEntries :: !(V.Vector (ElfSymbolTableEntry w))
                     -- ^ Vector of symbol table entries.
                     --
                     -- Local entries should appear before global entries in vector.
                   , elfSymbolTableLocalEntries :: !Word32
                     -- ^ Number of local entries in table.
                     -- First entry should be a local entry.
                   } deriving (Show)

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
     -- ^ The region  has the given absolute size.
     --
     -- Note that when writing out files, we will only use this size if it is larger
     -- than the computed size, otherwise we use the computed size.
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
    -- ^ Virtual address for the segment.
    --
    -- The elf standard for some ABIs proscribes that the virtual address for a
    -- file should be in ascending order of the segment addresses.  This does not
    -- appear to be the case for the x86 ABI documents, but valgrind warns of it.
  , elfSegmentPhysAddr  :: !w
    -- ^ Physical address for the segment.
    --
    -- This contents are typically not used on executables and shared libraries
    -- as they are not loaded at fixed physical addresses.  The convention
    -- seems to be to set the phyiscal address equal to the virtual address.
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
   | ElfDataSegment !(ElfSegment w)
     -- ^ A segment that contains other segments.
   | ElfDataSectionHeaders
     -- ^ Identifies the section header table.
     --
     -- This is represented explicitly as an elf data region as it may be part of
     -- an elf segment, and thus we need to know whether a segment contains it.
   | ElfDataSectionNameTable !Word16
     -- ^ The section for storing the section names.
     --
     -- The contents are auto-generated, so we only need to know which section
     -- index to give it.
   | ElfDataGOT !(ElfGOT w)
     -- ^ A global offset table.
   | ElfDataStrtab !Word16
     -- ^ Elf strtab section (with index)
   | ElfDataSymtab !(ElfSymbolTable w)
     -- ^ Elf symtab section
   | ElfDataSection !(ElfSection w)
     -- ^ A section that has no special interpretation.
   | ElfDataRaw B.ByteString
     -- ^ Identifies an uninterpreted array of bytes.
  deriving Show

-- | This applies a function to each data region in an elf file, returning
-- the sum using 'Alternative' operations for combining results.
asumDataRegions :: Alternative f => (ElfDataRegion w -> f a) -> Elf w -> f a
asumDataRegions f e = F.asum $ g <$> e^.elfFileData
  where g r@(ElfDataSegment s) = f r <|> F.asum (g <$> elfSegmentData s)
        g r = f r

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
