{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE UndecidableInstances #-}
module Data.ElfEdit.HighLevel.Types
  ( -- * Top level declarations
    Elf(..)
  , emptyElf
  , elfFileData
  , elfHeader
  , asumDataRegions
    -- * ElfDataRegion
  , ElfDataRegion(..)
  , ppRegion
    -- * ElfSegment
  , ElfSegment(..)
  , SegmentIndex
  , ppSegment
  , hasSegmentType
  , ElfMemSize(..)
    -- * Symbol tab
  , symtabSize
    -- * GNU sections
  , GnuRelroRegion(..)
  , GnuStack(..)
  , gnuStackPhdr
  ) where

import           Control.Applicative
import           Control.Lens hiding (enum)
import           Data.Bits
import qualified Data.ByteString as B
import qualified Data.Foldable as F
import qualified Data.Sequence as Seq
import           Data.Word
import           GHC.TypeLits
import           Text.PrettyPrint.ANSI.Leijen hiding ((<>), (<$>))

import           Data.ElfEdit.Prim
import           Data.ElfEdit.HighLevel.GOT
import           Data.ElfEdit.HighLevel.Sections
import           Data.ElfEdit.Utils (ppHex)

ppShow :: Show v => v -> Doc
ppShow = text . show

------------------------------------------------------------------------
-- ElfMemSize

-- | This describes the size of a elf segment memory size.
data ElfMemSize w
   = ElfAbsoluteSize !w
     -- ^ The region  has the given absolute size.
     --
     -- Note that when writing out files, we will only use this size if it is larger
     -- than the computed size, otherwise we use the computed size.
   | ElfRelativeSize !w
     -- ^ The given offset should be added to the computed size.
  deriving (Show)

{-
------------------------------------------------------------------------
-- Symtab

-- | This entry corresponds to the symbol table index.
--
-- The name of a symbol is a paramter to support indices and bytestrings.
data Symtab nm w
   = Symtab { symtabIndex :: !Word16
              -- ^ Index of section storing symbol table
            , symtabEntries :: !(V.Vector (SymtabEntry nm w))
              -- ^ Vector of symbol table entries.
              --
              -- Local entries should appear before global entries in vector.
            , symtabLocalEntries :: !Word32
              -- ^ Number of local entries in table.  First entry
              -- should be a local entry.
            } deriving (Show)

-- | Get size of symbol table
symtabSize :: ElfClass w -> Symtab nm (ElfWordType w) -> ElfWordType w
symtabSize c symtab = elfClassInstances c $
  let cnt = fromIntegral $ V.length $ symtabEntries symtab
   in fromIntegral (symtabEntrySize c) * cnt
-}

$(pure [])

------------------------------------------------------------------------
-- ElfSegment and ElfDataRegion

type SegmentIndex = Word16

-- | This provides a more abstract high-level view of an Elf segment.
--
-- The contents directly contain sections and other data regions wholy contained
-- within this segment.
--
-- The parameter should be a @32@ or @64@ depending on whether this
-- is a 32 or 64-bit elf file.
data ElfSegment (w :: Nat) = ElfSegment
  { elfSegmentType      :: !PhdrType
    -- ^ Segment type
  , elfSegmentFlags     :: !ElfSegmentFlags
    -- ^ Segment flags
  , elfSegmentIndex     :: !SegmentIndex
    -- ^ A 0-based index indicating the position of the segment in the Phdr table
    --
    -- The index of a segment should be unique and range from @0@ to one less than
    -- the number of segments in the Elf file.
    -- Since the phdr table is typically stored in a loaded segment, the number of
    -- entries affects the layout of binaries.
  , elfSegmentVirtAddr  :: !(ElfWordType w)
    -- ^ Virtual address for the segment.
    --
    -- The elf standard for some ABIs proscribes that the virtual address for a
    -- file should be in ascending order of the segment addresses.  This does not
    -- appear to be the case for the x86 ABI documents, but valgrind warns of it.
  , elfSegmentPhysAddr  :: !(ElfWordType w)
    -- ^ Physical address for the segment.
    --
    -- This contents are typically not used on executables and shared libraries
    -- as they are not loaded at fixed physical addresses.  The convention
    -- seems to be to set the phyiscal address equal to the virtual address.
  , elfSegmentAlign     :: !(ElfWordType w)
    -- ^ The value to which this segment is aligned in memory and the file.
    -- This field is called @p_align@ in Elf documentation.
    --
    -- A value of 0 or 1 means no alignment is required.  This gives the
    -- value to which segments are loaded in the file.  If it is not 0 or 1,
    -- then is hould be a positve power of two.  'elfSegmentVirtAddr' should
    -- be congruent to the segment offset in the file modulo 'elfSegmentAlign'.
    -- e.g., if file offset is @o@, alignment is @n@, and virtual address is @a@,
    -- then @o mod n = a mod n@
    --
    -- Note that when writing files, no effort is made to add padding so that the
    -- alignment property is expected.  It is up to the user to insert raw data segments
    -- as needed for padding.  We considered inserting padding automatically, but this
    -- can result in extra bytes inadvertently appearing in loadable segments, thus
    -- breaking layout constraints.
  , elfSegmentMemSize   :: !(ElfMemSize (ElfWordType w))
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
   | ElfDataGOT !(ElfGOT (ElfWordType w))
     -- ^ A global offset table.
   | ElfDataStrtab !Word16
     -- ^ Elf strtab section (with index)
   | ElfDataSymtab !Word16 !(Symtab w)
     -- ^ Elf symtab section with index and symbol table values.
   | ElfDataSection !(ElfSection (ElfWordType w))
     -- ^ A section that has no special interpretation.
   | ElfDataRaw B.ByteString
     -- ^ Identifies an uninterpreted array of bytes.

deriving instance ElfWidthConstraints w => Show (ElfDataRegion w)

$(pure [])

ppSegment :: ElfWidthConstraints w => ElfSegment w -> Doc
ppSegment s =
  text "type: " <+> ppShow (elfSegmentType s) <$$>
  text "flags:" <+> ppShow (elfSegmentFlags s) <$$>
  text "index:" <+> ppShow (elfSegmentIndex s) <$$>
  text "vaddr:" <+> text (ppHex (elfSegmentVirtAddr s)) <$$>
  text "paddr:" <+> text (ppHex (elfSegmentPhysAddr s)) <$$>
  text "align:" <+> ppShow (elfSegmentAlign s) <$$>
  text "msize:" <+> ppShow (elfSegmentMemSize s) <$$>
  text "data:"  <$$>
  indent 2 (vcat . map ppRegion . F.toList $ elfSegmentData s)

instance ElfWidthConstraints w => Show (ElfSegment w) where
  show s = show (ppSegment s)

ppRegion :: ElfWidthConstraints w => ElfDataRegion w -> Doc
ppRegion r = case r of
  ElfDataElfHeader -> text "ELF header"
  ElfDataSegmentHeaders -> text "segment header table"
  ElfDataSegment s -> hang 2 (text "contained segment" <$$> ppSegment s)
  ElfDataSectionHeaders -> text "section header table"
  ElfDataSectionNameTable w -> text "section name table" <+> parens (text "section number" <+> ppShow w)
  ElfDataGOT got -> text "global offset table:" <+> ppShow got
  ElfDataStrtab w -> text "strtab section" <+> parens (text "section number" <+> ppShow w)
  ElfDataSymtab _idx symtab -> text "symtab section:" <+> ppShow symtab
  ElfDataSection sec -> text "other section:" <+> ppShow sec
  ElfDataRaw bs -> text "raw bytes:" <+> ppShow bs

$(pure [])

-- | This applies a function to each data region in an elf file, returning
-- the sum using 'Alternative' operations for combining results.
asumDataRegions :: Alternative f => (ElfDataRegion w -> f a) -> Elf w -> f a
asumDataRegions f e = F.asum $ g <$> e^.elfFileData
  where g r@(ElfDataSegment s) = f r <|> F.asum (g <$> elfSegmentData s)
        g r = f r

-- | Return true if the segment has the given type.
hasSegmentType :: PhdrType -> ElfSegment w -> Bool
hasSegmentType tp s = elfSegmentType s == tp

------------------------------------------------------------------------
-- GnuRelroRegion

-- | Information about a PT_GNU_STACK segment.
data GnuStack =
  GnuStack { gnuStackSegmentIndex :: !Word16
             -- ^ Index to use for GNU stack.
           , gnuStackIsExecutable :: !Bool
             -- ^ Flag that indicates whether the stack should be executable.
           }

gnuStackPhdr :: Num (ElfWordType w) => GnuStack -> Phdr w
gnuStackPhdr gnuStack =
  let thisIdx = gnuStackSegmentIndex gnuStack
      perm | gnuStackIsExecutable gnuStack = pf_r .|. pf_w .|. pf_x
           |  otherwise = pf_r .|. pf_w
   in Phdr { phdrSegmentIndex = thisIdx
           , phdrSegmentType  = PT_GNU_STACK
           , phdrSegmentFlags = perm
           , phdrSegmentVirtAddr = 0
           , phdrSegmentPhysAddr = 0
           , phdrSegmentAlign = 0x8
           , phdrFileStart = startOfFile
           , phdrFileSize  = 0
           , phdrMemSize   = 0
           }

------------------------------------------------------------------------
-- GnuRelroRegion

-- | Information about a PT_GNU_RELRO segment
data GnuRelroRegion w =
  GnuRelroRegion { relroSegmentIndex :: !SegmentIndex
                 -- ^ Index to use for Relro region.
                 , relroRefSegmentIndex :: !SegmentIndex
                 -- ^ Index of the segment this relro refers to.
                 , relroAddrStart :: !(ElfWordType w)
                 -- ^ Identifies the base virtual address of the
                 -- region that should be made read-only.
                 --
                 -- This is typically the base address of the segment,
                 -- but could be an offset.  The actual address used is
                 -- the relro rounded down.
                 , relroSize :: !(ElfWordType w)
                 -- ^ Size of relro protection in number of bytes.
                 }

------------------------------------------------------------------------
-- Elf

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
    , elfEntry      :: !(ElfWordType w)
      -- ^ Virtual address of the program entry point.
      --
      -- 0 for non-executable Elfs.
    , elfFlags      :: !Word32
      -- ^ Machine specific flags
    , _elfFileData  :: Seq.Seq (ElfDataRegion w)
      -- ^ Data to be stored in elf file.
    , elfGnuStackSegment :: !(Maybe GnuStack)
      -- ^ PT_GNU_STACK segment info (if any).
      --
      -- If present, this tells loaders that support it whether to set the executable
    , elfGnuRelroRegions :: ![GnuRelroRegion w]
      -- ^ PT_GNU_RELRO regions.
    }

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
      , elfGnuStackSegment = Nothing
      , elfGnuRelroRegions = []
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

-- | Lens to access top-level regions in Elf file.
elfFileData :: Simple Lens (Elf w) (Seq.Seq (ElfDataRegion w))
elfFileData = lens _elfFileData (\s v -> s { _elfFileData = v })
