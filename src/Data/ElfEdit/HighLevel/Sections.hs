module Data.ElfEdit.HighLevel.Sections
  ( -- * ElfSection
    ElfSection(..)
  , elfSectionFileSize
  ) where

import Data.ByteString as B
import Data.Word

import Data.ElfEdit.Prim.Shdr

------------------------------------------------------------------------
-- ElfSection

-- | A section in the Elf file.
data ElfSection w = ElfSection
    { elfSectionIndex     :: !Word16
      -- ^ Unique index to identify section.
    , elfSectionName      :: !B.ByteString
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
      -- ^ The size of the section. Except for @SHT_NOBITS@ sections, this is the
      -- size of elfSectionData.
    , elfSectionLink      :: !Word32
      -- ^ Contains a section index of an associated section, depending on section type.
    , elfSectionInfo      :: !Word32
      -- ^ Contains extra information for the index, depending on type.
    , elfSectionAddrAlign :: !w
      -- ^ Contains the required alignment of the section.  This
      -- should be a power of two, and the address of the section
      -- should be a multiple of the alignment.
      --
      -- Note that when writing files, no effort is made to add
      -- padding so that the alignment constraint is correct.  It is
      -- up to the user to insert raw data segments as needed for
      -- padding.  We considered inserting padding automatically, but
      -- this can result in extra bytes inadvertently appearing in
      -- loadable segments, thus breaking layout constraints.  In
      -- particular, @ld@ sometimes generates files where the @.bss@
      -- section address is not a multiple of the alignment.
    , elfSectionEntSize   :: !w
      -- ^ Size of entries if section has a table.
    , elfSectionData      :: !B.ByteString
      -- ^ Data in section.
    } deriving (Eq, Show)

-- | Returns number of bytes in file used by section.
elfSectionFileSize :: Integral w => ElfSection w -> w
elfSectionFileSize = fromIntegral . B.length . elfSectionData
