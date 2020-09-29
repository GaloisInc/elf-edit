{-|
This module declares a basic type for representing section headers that can be
parsed and written without additional information.
-}
{-# LANGUAGE GADTs #-}
module Data.ElfEdit.ShdrEntry
  ( shdrEntrySize
  , ShdrEntry(..)
  , shdrFileSize
  , shdrFileRange
  , getShdr
  , writeShdrEntry
  ) where

import           Data.Binary.Get
import qualified Data.ByteString.Builder as Bld
import           Data.Word

import           Data.ElfEdit.Sections
import           Data.ElfEdit.Types

-- | Size of entry in Elf section header table for given width.
shdrEntrySize :: ElfClass w -> Word16
shdrEntrySize ELFCLASS32 = 40
shdrEntrySize ELFCLASS64 = 64

-- | A section header record
--
-- Note. The name field uses a separate type parameter so that we can construct
-- section headers with bytestring names and onces with names that are indices into
-- the section header string table.
data ShdrEntry nm w = ShdrEntry
    { shdrName :: !nm
      -- ^ Offset of section in name table.
    , shdrType      :: !ElfSectionType
      -- ^ Type of the section.
    , shdrFlags     :: !(ElfSectionFlags w)
      -- ^ Attributes of the section.
    , shdrAddr      :: !w
      -- ^ The virtual address of the beginning of the section in memory.
      --
      -- This should be 0 for sections that are not loaded into target memory.
    , shdrOff       :: !w
      -- ^ Offset of section in file.
    , shdrSize      :: !w
      -- ^ The size of the section.
    , shdrLink      :: !Word32
      -- ^ Contains a section index of an associated section, depending on section type.
    , shdrInfo      :: !Word32
      -- ^ Contains extra information for the index, depending on type.
    , shdrAddrAlign :: !w
      -- ^ Contains the required alignment of the section.
    , shdrEntSize   :: !w
      -- ^ Size of entries if section has a table.
    } deriving (Eq, Show)

-- | Return expected file size of shdr entry
shdrFileSize :: Num w => ShdrEntry nm w -> w
shdrFileSize shdr =
  case shdrType shdr of
    SHT_NOBITS -> 0
    _ -> shdrSize shdr

shdrFileRange :: Num w => ShdrEntry nm w -> Range w
shdrFileRange shdr = (shdrOff shdr, shdrFileSize shdr)

------------------------------------------------------------------------
-- GetShdr


getShdr32 :: ElfData -> Get (ShdrEntry Word32 Word32)
getShdr32 d = do
  sh_name      <- getWord32 d
  sh_type      <- ElfSectionType  <$> getWord32 d

  sh_flags     <- ElfSectionFlags <$> getWord32 d
  sh_addr      <- getWord32 d
  sh_offset    <- getWord32 d
  sh_size      <- getWord32 d

  sh_link      <- getWord32 d
  sh_info      <- getWord32 d
  sh_addralign <- getWord32 d
  sh_entsize   <- getWord32 d
  pure $! ShdrEntry { shdrName      = sh_name
                    , shdrType      = sh_type
                    , shdrFlags     = sh_flags
                    , shdrAddr      = sh_addr
                    , shdrOff       = sh_offset
                    , shdrSize      = sh_size
                    , shdrLink      = sh_link
                    , shdrInfo      = sh_info
                    , shdrAddrAlign = sh_addralign
                    , shdrEntSize   = sh_entsize
                    }

getShdr64 :: ElfData -> Get (ShdrEntry Word32 Word64)
getShdr64 d = do
  sh_name      <- getWord32 d
  sh_type      <- ElfSectionType  <$> getWord32 d
  sh_flags     <- ElfSectionFlags <$> getWord64 d
  sh_addr      <- getWord64 d
  sh_offset    <- getWord64 d
  sh_size      <- getWord64 d
  sh_link      <- getWord32 d
  sh_info      <- getWord32 d
  sh_addralign <- getWord64 d
  sh_entsize   <- getWord64 d
  pure $! ShdrEntry { shdrName      = sh_name
                    , shdrType      = sh_type
                    , shdrFlags     = sh_flags
                    , shdrAddr      = sh_addr
                    , shdrOff       = sh_offset
                    , shdrSize      = sh_size
                    , shdrLink      = sh_link
                    , shdrInfo      = sh_info
                    , shdrAddrAlign = sh_addralign
                    , shdrEntSize   = sh_entsize
                    }

getShdr :: ElfData -> ElfClass w -> Get (ShdrEntry Word32 (ElfWordType w))
getShdr d ELFCLASS32 = getShdr32 d
getShdr d ELFCLASS64 = getShdr64 d


writeShdrEntry :: ElfData -> ElfClass w -> ShdrEntry Word32 (ElfWordType w) -> Bld.Builder
writeShdrEntry d ELFCLASS32 shdr
  =  putWord32 d (shdrName shdr)
  <> putWord32 d (fromElfSectionType (shdrType shdr))
  <> putWord32 d (fromElfSectionFlags (shdrFlags shdr))
  <> putWord32 d (shdrAddr shdr)
  <> putWord32 d (shdrOff shdr)
  <> putWord32 d (shdrSize shdr)
  <> putWord32 d (shdrLink shdr)
  <> putWord32 d (shdrInfo shdr)
  <> putWord32 d (shdrAddrAlign shdr)
  <> putWord32 d (shdrEntSize shdr)
writeShdrEntry d ELFCLASS64 shdr
  =  putWord32 d (shdrName shdr)
  <> putWord32 d (fromElfSectionType (shdrType shdr))
  <> putWord64 d (fromElfSectionFlags (shdrFlags shdr))
  <> putWord64 d (shdrAddr shdr)
  <> putWord64 d (shdrOff shdr)
  <> putWord64 d (shdrSize shdr)
  <> putWord32 d (shdrLink shdr)
  <> putWord32 d (shdrInfo shdr)
  <> putWord64 d (shdrAddrAlign shdr)
  <> putWord64 d (shdrEntSize shdr)
