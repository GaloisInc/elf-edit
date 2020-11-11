{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE UndecidableInstances #-}
module Data.ElfEdit.Prim.HeaderInfo
  ( -- * EhfHeaderInfo
    ElfHeaderInfo
  , decodeElfHeaderInfo
  , SomeElf(..)
    -- ** Top level sections
  , header
  , headerFileContents
    -- ** Section header strtab
  , shstrtabIndex
  , shstrtabRangeAndData
    -- ** Program headers
  , headerPhdrs
  , phdrCount
  , phdrTableRange
  , phdrByIndex
    -- ** Section headers
  , headerShdrs
  , headerNamedShdrs
  , shdrCount
  , shdrTableRange
  , shdrByIndex
    -- ** Symbol table
  , Symtab(..)
  , symtabSize
  , decodeHeaderSymtab
  ) where

import Control.Monad
import           Data.Binary
import           Data.Binary.Get
import qualified Data.ByteString as B
import qualified Data.Vector as V
import           GHC.Stack

import           Data.ElfEdit.Prim.Ehdr
import           Data.ElfEdit.Prim.File
import           Data.ElfEdit.Prim.Phdr
import           Data.ElfEdit.Prim.Shdr
import           Data.ElfEdit.Prim.StringTable
import           Data.ElfEdit.Prim.SymbolTable
import           Data.ElfEdit.Utils (enumCnt, strictRunGetOrFail)

------------------------------------------------------------------------
-- TableLayout

-- | Defines the layout of a table with elements of a fixed size.
data TableLayout w =
  TableLayout { tableOffset :: !(FileOffset (ElfWordType w))
                -- ^ Offset where table starts relative to start of file.
              , entrySize :: Word16
                -- ^ Size of entries in bytes.
              , entryNum :: Word16
                -- ^ Number of entries.
              }

-- | Returns size of table.
tableSize :: Integral (ElfWordType w) => TableLayout w -> ElfWordType w
tableSize l = fromIntegral (entryNum l) * fromIntegral (entrySize l)

-- | Returns range in memory of table.
tableRange :: Integral (ElfWordType w) => TableLayout w -> FileRange (ElfWordType w)
tableRange l = (tableOffset l, tableSize l)

-- | Returns offset of entry in table.
tableEntry :: Integral (ElfWordType w)
           => TableLayout w -- ^ Table
           -> Word16 -- Index
           -> B.ByteString -- ^ File region
           -> B.ByteString
tableEntry l i b
    | i >= entryNum l = error $ "Entry out of range."
    | otherwise = B.take sz (B.drop o b)
  where sz = fromIntegral (entrySize l)
        o = fromIntegral (tableOffset l) + fromIntegral i * sz

------------------------------------------------------------------------
-- GetPhdr

getPhdr32 :: ElfData -> Word16 -> Get (Phdr 32)
getPhdr32 d idx = do
  p_type   <- PhdrType  <$> getWord32 d
  p_offset <- getWord32 d
  p_vaddr  <- getWord32 d
  p_paddr  <- getWord32 d
  p_filesz <- getWord32 d
  p_memsz  <- getWord32 d
  p_flags  <- ElfSegmentFlags <$> getWord32 d
  p_align  <- getWord32 d
  return $! Phdr { phdrSegmentIndex = idx
                 , phdrSegmentType = p_type
                 , phdrSegmentFlags = p_flags
                 , phdrSegmentVirtAddr = p_vaddr
                 , phdrSegmentPhysAddr = p_paddr
                 , phdrSegmentAlign = p_align
                 , phdrFileStart = FileOffset p_offset
                 , phdrFileSize  = p_filesz
                 , phdrMemSize   = p_memsz
                 }

getPhdr64 :: ElfData -> Word16 -> Get (Phdr 64)
getPhdr64 d idx = do
  p_type   <- PhdrType  <$> getWord32 d
  p_flags  <- ElfSegmentFlags <$> getWord32 d
  p_offset <- getWord64 d
  p_vaddr  <- getWord64 d
  p_paddr  <- getWord64 d
  p_filesz <- getWord64 d
  p_memsz  <- getWord64 d
  p_align  <- getWord64 d
  return $! Phdr { phdrSegmentIndex = idx
                 , phdrSegmentType = p_type
                 , phdrSegmentFlags = p_flags
                 , phdrSegmentVirtAddr = p_vaddr
                 , phdrSegmentPhysAddr = p_paddr
                 , phdrSegmentAlign = p_align
                 , phdrFileStart = FileOffset p_offset
                 , phdrFileSize  = p_filesz
                 , phdrMemSize   = p_memsz
                 }

-- | Function for reading elf segments.
getPhdr :: ElfHeader w -> Word16 -> Get (Phdr w)
getPhdr h =
  case headerClass h of
    ELFCLASS32 -> getPhdr32 (headerData h)
    ELFCLASS64 -> getPhdr64 (headerData h)

------------------------------------------------------------------------
-- ElfHeaderInfo

-- | Top-level primitive interface for extracting information from elf file.
data ElfHeaderInfo w = ElfHeaderInfo {
       header :: !(ElfHeader w)
       -- ^ Elf header information
     , phdrTable :: !(TableLayout w)
       -- ^ Layout of segment header table.
     , shstrtabIndex :: !Word16
       -- ^ Index of @.shstrtab@ section that contains section names.
       --
       -- Note. At initialization time we check that the index
       -- is valid if the file has any sections.
     , shdrTable :: !(TableLayout w)
       -- ^ Layout of section header table.
     , headerFileContents :: !B.ByteString
       -- ^ Contents of file as a bytestring.
     }

--------------------------------------------------------------------------------
-- Program headers

phdrCount :: ElfHeaderInfo w -> Word16
phdrCount = entryNum . phdrTable

-- | Get range of bytes in file for program header table
phdrTableRange :: ElfHeaderInfo w -> FileRange (ElfWordType w)
phdrTableRange e = elfClassInstances (headerClass (header e)) $ tableRange (phdrTable e)

-- | Parse program header at given index
phdrByIndex :: ElfHeaderInfo w -- ^ Information for parsing
            -> Word16 -- ^ Index
            -> Phdr w
phdrByIndex ehi i =
  let hdr = header ehi
      b = elfClassInstances (headerClass hdr) $ tableEntry (phdrTable ehi) i (headerFileContents ehi)
   in case strictRunGetOrFail (getPhdr (header ehi) i) b of
        Left _ -> error "phdrByIndex failed."
        Right (_,_,r) -> r

-- | Return list of segments program headers from
headerPhdrs :: ElfHeaderInfo w -> [Phdr w]
headerPhdrs ehi = phdrByIndex ehi <$> enumCnt 0 (phdrCount ehi)

--------------------------------------------------------------------------------
-- Section headers

-- | Number of sections headers.
shdrCount :: ElfHeaderInfo w -> Word16
shdrCount = entryNum . shdrTable

-- | Get range of bytes in file for section header table
shdrTableRange :: ElfHeaderInfo w -> FileRange (ElfWordType w)
shdrTableRange e = elfClassInstances (headerClass (header e)) $ tableRange (shdrTable e)

-- | Get file range and contents of ".shstrtab".
shstrtabRangeAndData :: HasCallStack
                     => ElfHeaderInfo w
                     -> (FileRange (ElfWordType w), B.ByteString)
shstrtabRangeAndData ehi = elfClassInstances (headerClass (header ehi)) $
  case shstrtabIndex ehi of
    0 -> ((0,0), B.empty)
    idx | idx < shdrCount ehi ->
          let r = shdrFileRange (shdrByIndex ehi idx)
           in (r, slice r (headerFileContents ehi))
        | otherwise -> error "Invalid section name index"

-- | Return the section entry
shdrByIndex :: ElfHeaderInfo w
            -> Word16 -- ^ Index of section (note assumed to be a legal section index)
            -> Shdr Word32 (ElfWordType w)
shdrByIndex ehi i = do
  let hdr = header ehi
      cl = headerClass hdr
      d  = headerData hdr
      -- Get buffer for section header entry
      b = elfClassInstances cl $ tableEntry (shdrTable ehi) i (headerFileContents ehi)
   in decodeShdr d cl b

-- | Get section headers with names as indices into @".shstrtab"@.
headerShdrs :: ElfHeaderInfo w
            -> V.Vector (Shdr Word32 (ElfWordType w))
headerShdrs ehi = V.generate cnt (shdrByIndex ehi . fromIntegral)
  where cnt = fromIntegral (shdrCount ehi)

-- | Get section headers with names as bytestrings.
--
-- This returns the error and index of the section if any name lookup fails.
headerNamedShdrs :: ElfHeaderInfo w
                 -> Either (Word16, LookupStringError) (V.Vector (Shdr B.ByteString (ElfWordType w)))
headerNamedShdrs ehi = V.generateM cnt go
  where cnt = fromIntegral (shdrCount ehi)
        (_, shstrtabBuf) = shstrtabRangeAndData ehi
        go idx =
          let shdr = shdrByIndex ehi (fromIntegral idx)
           in case lookupString (shdrName shdr) shstrtabBuf of
                Left e -> Left (fromIntegral idx, e)
                Right nm -> Right (shdr { shdrName = nm })

--------------------------------------------------------------------------------
-- decodeElfHeaderInfo

mkElfHeader :: Ehdr w -> B.ByteString -> ElfHeaderInfo w
mkElfHeader e b =
  let cl = headerClass (ehdrHeader e)
   in ElfHeaderInfo { header = ehdrHeader e
                    , phdrTable     = TableLayout (ehdrPhoff e) (phdrEntrySize cl) (ehdrPhnum e)
                    , shstrtabIndex = ehdrShstrndx e
                    , shdrTable     = TableLayout (ehdrShoff e) (shdrEntrySize cl) (ehdrShnum e)
                    , headerFileContents = b
                    }

-- | Creates a `ElfHeaderInfo` from a bytestring with data in the Elf format.
-- their fields promoted to 64-bit so that the 32- and 64-bit ELF records can be the same.
decodeElfHeaderInfo :: B.ByteString -> Either (ByteOffset,String) (SomeElf ElfHeaderInfo)
decodeElfHeaderInfo b = do
  SomeElf e <- decodeEhdr b
  pure $ SomeElf (mkElfHeader e b)

--------------------------------------------------------------------------------
-- decodeElfHeaderInfo

data Symtab w =
     Symtab { symtabLocalCount :: !Word32
            , symtabEntries :: !(V.Vector (SymtabEntry B.ByteString (ElfWordType w)))
            }

deriving instance Show (ElfWordType w) => Show (Symtab w)

-- | Decodes the static symbol table using elf header info
--
-- If no symbol table is present then @Nothing@ is returned.
decodeHeaderSymtab :: ElfHeaderInfo w -> Maybe (Either SymtabError (Symtab w))
decodeHeaderSymtab elf = elfClassInstances (headerClass (header elf)) $ do
  let hdr = header elf
  let contents = headerFileContents elf
  let cl = headerClass hdr
  let dta = headerData hdr
  let shdrs = headerShdrs elf
  let symtabs = V.filter (\s -> shdrType s == SHT_SYMTAB) shdrs
  when (V.length symtabs == 0) $ Nothing
  Just $ do
    when (V.length symtabs > 1) $ Left MultipleSymtabs
    let symtabShdr = symtabs V.! 0
    unless (isValidFileRange (shdrFileRange symtabShdr) contents) $ do
      Left InvalidSymtabFileRange
    let symtabBuffer = slice (shdrFileRange symtabShdr) contents
    when (shdrLink symtabShdr >= fromIntegral (shdrCount elf)) $ do
      Left InvalidSymtabLink
    let strtabShdr = shdrs V.! fromIntegral (shdrLink symtabShdr)
    unless (isValidFileRange (shdrFileRange strtabShdr) contents) $ do
      Left InvalidSymtabFileRange
    let strtabBuffer = slice (shdrFileRange strtabShdr) contents
    -- Decode the symbol table
    v <- decodeSymtab cl dta strtabBuffer symtabBuffer
    unless (toInteger (shdrInfo symtabShdr) <= toInteger (V.length v)) $ do
      Left InvalidSymtabLocalCount
    pure $! Symtab { symtabLocalCount = fromIntegral (shdrInfo symtabShdr)
                   , symtabEntries = v
                   }

-- | Get size of symbol table
symtabSize :: ElfClass w -> Symtab w -> ElfWordType w
symtabSize c symtab = elfClassInstances c $
  let cnt = fromIntegral $ V.length $ symtabEntries symtab
   in fromIntegral (symtabEntrySize c) * cnt
