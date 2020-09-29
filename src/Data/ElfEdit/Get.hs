{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE Trustworthy #-}
{-# LANGUAGE UndecidableInstances #-}
module Data.ElfEdit.Get
  ( -- * elfHeaderInfo low-level interface
    ElfHeaderInfo
  , shdrNameIdx
  , header
  , headerFileContents
  , headerSections
  , headerSectionHeaders
  , headerSectionCount
  , getShdrEntry
  , parseElfHeaderInfo
  , phdrCount
  , phdrByIndex
    -- ** Symbol table parsers
  , SymbolTableError(..)
  , parseSymbolTableEntry
  , getSymbolTableEntries
    -- * Elf high-level interface
  , SomeElf(..)
  , getElf
  , parseElf
  , ElfGetResult(..)
  , ElfParseError(..)
    -- * Utilities
  , getWord16
  , getWord32
  , getWord64
  , LookupStringError(..)
  , lookupString
  , runGetMany
  ) where

import           Control.Monad
import qualified Control.Monad.Fail as Fail
import qualified Control.Monad.State.Strict as MTL
import           Data.Binary
import           Data.Binary.Get
import qualified Data.Binary.Get as Get
import           Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy as L
import           Data.Foldable (foldl', foldlM)
import           Data.Int
import           Data.List (partition, sortBy)
import           Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import           Data.Maybe
import qualified Data.Sequence as Seq
import qualified Data.Vector as V
import           GHC.Stack
import           Numeric (showHex)

import           Data.ElfEdit.Enums
import           Data.ElfEdit.Layout
  ( FileOffset(..)
  , Phdr(..)
  , elfMagic
  , phdrEntrySize
  , symbolTableEntrySize
  )
import           Data.ElfEdit.ShdrEntry
import           Data.ElfEdit.Types
import           Data.ElfEdit.Utils (enumCnt)

------------------------------------------------------------------------
-- Utilities

-- | @revApp x y@ returns the list @reverse x ++ y@.
revApp :: [a] -> [a] -> [a]
revApp [] r = r
revApp (h:l) r = revApp l $! seq h (h:r)

------------------------------------------------------------------------
-- Parsing combinators

-- | Apply the get operation repeatedly to bystring until all bits are done.
--
-- This returns a list contain all the values read or the message for the failure.
runGetMany :: forall a . Get a -> L.ByteString -> Either String [a]
runGetMany g bs0 = start [] (L.toChunks bs0)
  where go :: [a] -> [B.ByteString] -> Decoder a -> Either String [a]
        go _pre _     (Fail _ _ msg) = Left msg
        go prev []    (Partial f)    = go prev [] (f Nothing)
        go prev (h:r) (Partial f)    = go prev r (f (Just h))
        go prev l     (Done bs _ v)  = start (v:prev) (bs:l)

        start :: [a] -> [B.ByteString] -> Either String [a]
        start prev [] = Right $! reverse prev
        start prev (h:r) | B.null h = start prev r
        start prev l = go prev l (runGetIncremental g)

-- | @tryParse msg f v@ returns @fromJust (f v)@ is @f v@ returns a value,
-- and calls @fail@ otherwise.
tryParse :: Fail.MonadFail m => String -> (a -> Maybe b) -> a -> m b
tryParse desc toFn = maybe (fail ("Invalid " ++ desc)) return . toFn

------------------------------------------------------------------------
-- Phdr functions

-- | Return true if the program header has the givne type.
hasSegmentType :: ElfSegmentType -> Phdr w -> Bool
hasSegmentType tp p = phdrSegmentType p == tp

-- | Generate a phdr from the given
phdrSegment :: Phdr w -> Seq.Seq (ElfDataRegion w) -> ElfSegment w
phdrSegment phdr regions =
  ElfSegment { elfSegmentType     = phdrSegmentType phdr
             , elfSegmentFlags    = phdrSegmentFlags phdr
             , elfSegmentIndex    = phdrSegmentIndex phdr
             , elfSegmentVirtAddr = phdrSegmentVirtAddr phdr
             , elfSegmentPhysAddr = phdrSegmentPhysAddr phdr
             , elfSegmentAlign    = phdrSegmentAlign phdr
             , elfSegmentMemSize  = ElfAbsoluteSize (phdrMemSize phdr)
             , elfSegmentData     = regions
             }

phdrName :: Phdr w -> String
phdrName phdr = "segment" ++ show (phdrSegmentIndex phdr)

$(pure [])

------------------------------------------------------------------------
-- String table lookup

-- | An error that occurs when looking up a string in a table
data LookupStringError
   = IllegalStrtabIndex !Word32
   | MissingNullTerminator

instance Show LookupStringError where
  show (IllegalStrtabIndex i) = "Illegal strtab index " ++ show i ++ "."
  show MissingNullTerminator = "Missing null terminator in strtab."

-- | Returns null-terminated string at given index in bytestring, or returns
-- error if that fails.
lookupString :: Word32 -> B.ByteString -> Either LookupStringError B.ByteString
lookupString o b | toInteger o >= toInteger (B.length b) = Left $ IllegalStrtabIndex o
                 | B.length r == B.length s = Left MissingNullTerminator
                 | otherwise = Right r
  where s = B.drop (fromIntegral o) b
        r = B.takeWhile (/= 0) s

$(pure [])

------------------------------------------------------------------------
-- SymbolTableError

-- | Error from parsing a symbol table
data SymbolTableError
   = InvalidName !Word32 !LookupStringError
     -- ^ The name of the symbol at the given index could not be obtained.
   | IllegalSymbolIndex !Word32
     -- ^ The index above exceeds the size of the symbol table.
   | InvalidLink !Word32
     -- ^ The link attribute of the section did not refer to a valid
     -- symbol table.

instance Show SymbolTableError where
  show (InvalidName idx msg) = "Error parsing symbol " ++ show idx ++ " name: " ++ show msg
  show (IllegalSymbolIndex idx) = "Index " ++ show idx ++ " exceeds number of entries."
  show (InvalidLink lnk) = "The link index " ++ show lnk ++ " was invalid."

$(pure [])

------------------------------------------------------------------------
-- ElfParseError

-- | A parse error
data ElfParseError
  = ElfSymtabError !SymbolTableError
    -- ^ We received an error parsing the symbol table section.
  | GnuStackNotRW
    -- ^ The GNU Stack segment was not read and write.
  | MultipleGnuStacks
    -- ^ Multiple sections with type PT_GNU_STACK
  | UnassociatedGnuRelro
    -- ^ We could not find which loadable segment was affected by the GNU relro entry.
  | OverlapMovedLater !String !Int !Integer
    -- ^ @OverlapMoved nm new old@ indicates that region @nm@ was moved to @new@ bytes
    -- from @old@ bytes in the file.
  | PhdrTooLarge !SegmentIndex !Int !Int
    -- ^ @PhdrTooLarge i end fileSize@ indicates phdr file end @end@
    -- exceeds file size @fileSize@.
  | PhdrSizeIncreased !SegmentIndex !Integer
    -- ^ @PhdrSizeIncreased i n@ indicates the size of the program
    -- header was increased by a given number of bytes to accomodate
    -- moved segments.

instance Show ElfParseError where
  showsPrec _ (ElfSymtabError msg) =
    showString "Could not parse symtab entries: " . shows msg
  showsPrec _ UnassociatedGnuRelro =
   showString "Could not resolve load segment for GNU relro segment."
  showsPrec _ GnuStackNotRW =
    showString "PT_GNU_STACK segment will be set to read/write if saved."
  showsPrec _ MultipleGnuStacks =
    showString"Multiple GNU stack segments. We will drop all but the first."
  showsPrec _ (OverlapMovedLater nm new old)
    = showString "The " . showString nm . showString " was moved from offset 0x"
    . showHex old . showString " to offset 0x" . showHex new
    . showString " to avoid overlaps."
  showsPrec _ (PhdrTooLarge i end fileSize)
    =  showString "The segment " . shows i . showString " ends at offset 0x"
    . showHex end . showString " which is after 0x" . showHex fileSize . showString "."
  showsPrec _ (PhdrSizeIncreased i adj)
    = showString "The size of segment " . shows i . showString " increased by "
    . shows adj . showString " bytes to fit shifted contents."

------------------------------------------------------------------------
-- GetResult

-- | This is a type that captures an insertion error, but returns a result
-- anyways.
newtype GetResult a = GetResult { unGetResult :: MTL.State [ElfParseError] a }
  deriving (Functor, Applicative, Monad)

errorPair :: GetResult a -> ([ElfParseError], a)
errorPair c =
  let (a,s) = MTL.runState (unGetResult c) []
   in (reverse s,a)

-- | Add a warning to get result
warn :: ElfParseError -> GetResult ()
warn e = seq e $ GetResult $ MTL.modify' $ (e:)

------------------------------------------------------------------------
-- Relro handling

-- | Extract relro information.
asRelroRegion :: Ord (ElfWordType w)
              => Map (FileOffset (ElfWordType w)) SegmentIndex
              -> Phdr w
              -> GetResult (Maybe (GnuRelroRegion w))
asRelroRegion segMap phdr = do
  case Map.lookupLE (phdrFileStart phdr) segMap of
    Nothing -> warn UnassociatedGnuRelro >> pure Nothing
    Just (_,refIdx) -> do
      pure $ Just $
        GnuRelroRegion { relroSegmentIndex    = phdrSegmentIndex phdr
                       , relroRefSegmentIndex = refIdx
                       , relroAddrStart       = phdrSegmentVirtAddr phdr
                       , relroSize            = phdrFileSize phdr
                       }

------------------------------------------------------------------------
-- TableLayout

-- | Defines the layout of a table with elements of a fixed size.
data TableLayout w =
  TableLayout { tableOffset :: !(ElfWordType w)
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
tableRange :: Integral (ElfWordType w) => TableLayout w -> Range (ElfWordType w)
tableRange l = (tableOffset l, tableSize l)

-- | Returns offset of entry in table.
tableEntry :: Integral (ElfWordType w)
           => TableLayout w -- ^ Table
           -> Word16 -- Index
           -> B.ByteString -- ^ File region
           -> L.ByteString
tableEntry l i b
    | i >= entryNum l = error $ "Entry out of range."
    | otherwise = L.fromChunks [B.take sz (B.drop o b)]
  where sz = fromIntegral (entrySize l)
        o = fromIntegral (tableOffset l) + fromIntegral i * sz

------------------------------------------------------------------------
-- GetPhdr

getPhdr32 :: ElfData -> Word16 -> Get (Phdr 32)
getPhdr32 d idx = do
  p_type   <- ElfSegmentType  <$> getWord32 d
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
  p_type   <- ElfSegmentType  <$> getWord32 d
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

$(pure [])

transShdrEntry :: Integral w
               => B.ByteString -- ^ Contents fof file.
               -> B.ByteString -- ^ String table for sectionnames
               -> Word16 -- ^ Index of section
               -> ShdrEntry Word32 w
               -> Either String (Range w, ElfSection w)
transShdrEntry file strtab idx shdr = do
  nm <- case lookupString (shdrName shdr) strtab of
          Right r -> Right r
          Left e -> Left (show e)
  let s = ElfSection
          { elfSectionIndex     = idx
          , elfSectionName      = nm
          , elfSectionType      = shdrType shdr
          , elfSectionFlags     = shdrFlags shdr
          , elfSectionAddr      = shdrAddr shdr
          , elfSectionSize      = shdrSize shdr
          , elfSectionLink      = shdrLink shdr
          , elfSectionInfo      = shdrInfo shdr
          , elfSectionAddrAlign = shdrAddrAlign shdr
          , elfSectionEntSize   = shdrEntSize shdr
          , elfSectionData      = slice (shdrFileRange shdr) file
          }
  seq s $ pure $ (shdrFileRange shdr, s)

$(pure [])

------------------------------------------------------------------------
-- Symbol table entries

-- | Create a symbol table entry from a Get monad
getSymbolTableEntry :: ElfClass w
                    -> ElfData
                    -> Get (ElfSymbolTableEntry Word32 (ElfWordType w))
getSymbolTableEntry ELFCLASS32 d = do
  nameIdx <- getWord32 d
  value   <- getWord32 d
  size    <- getWord32 d
  info    <- getWord8
  other   <- getWord8
  sTlbIdx <- getWord16 d
  let (typ,bind) = infoToTypeAndBind info
  pure $! EST { steName  = nameIdx
              , steType  = typ
              , steBind  = bind
              , steOther = other
              , steIndex = ElfSectionIndex sTlbIdx
              , steValue = value
              , steSize  = size
              }
getSymbolTableEntry ELFCLASS64 d = do
  nameIdx <- getWord32 d
  info    <- getWord8
  other   <- getWord8
  sTlbIdx <- getWord16 d
  value   <- getWord64 d
  size    <- getWord64 d
  let (typ,bind) = infoToTypeAndBind info
  pure $! EST { steName  = nameIdx
              , steType  = typ
              , steBind  = bind
              , steOther = other
              , steIndex = ElfSectionIndex sTlbIdx
              , steValue = value
              , steSize  = size
              }

-- | Parse a symbol table entry
parseSymbolTableEntry :: ElfClass w -- ^ Identifies 32 or 64-bit elf.
                      -> ElfData -- ^ Endianness
                      -> B.ByteString
                       -- ^ The string table
                      -> L.ByteString
                         -- ^ Contents of symbol table.
                      -> Word32
                         -- ^ Index of symbol table to retrieve
                      -> Either SymbolTableError (ElfSymbolTableEntry B.ByteString (ElfWordType w))
parseSymbolTableEntry cl d strTab symTab idx = do
  let symEntSize :: Int64
      symEntSize = elfClassInstances cl $ fromIntegral (symbolTableEntrySize cl)
  let symOff :: Int64
      symOff = fromIntegral idx * symEntSize
  let symEntry = L.drop symOff symTab
  when (symEntSize > L.length symEntry) $ do
    Left (IllegalSymbolIndex idx)
  case runGetOrFail (getSymbolTableEntry cl d) symEntry of
    -- This should never occur.
    Left (_,_,msg) -> error $ "Internal error on parseSymbolTableEntry: " ++ msg
    Right (_,_,sym) ->
      case lookupString (steName sym) strTab of
        Left  e  -> Left  $! InvalidName idx e
        Right nm -> Right $! sym { steName = nm }

-- | Parse the section as a list of symbol table entries.
getSymbolTableEntries :: ElfClass w
                      -> ElfData
                      -> BSC.ByteString
                         -- ^ String table for symtab
                      -> BSC.ByteString
                         -- ^ Symtab section
                      -> Either SymbolTableError (V.Vector (ElfSymbolTableEntry BSC.ByteString (ElfWordType w)))
getSymbolTableEntries cl dta strtab symtab = do
  let symEntSize :: Int
      symEntSize = elfClassInstances cl $ fromIntegral (symbolTableEntrySize cl)

  let symDataSize = B.length symtab
  -- Get number of entries (ignore extra bytes as they may be padding)
  let n :: Int
      n = symDataSize `quot` symEntSize

  let symtabData = L.fromChunks [symtab]
  V.generateM n $ \i->
    parseSymbolTableEntry cl dta strtab symtabData (fromIntegral i)

------------------------------------------------------------------------
-- ElfHeaderInfo

-- | Information parsed from the ELF header need to parse the
-- segments and sections.
data ElfHeaderInfo w = ElfHeaderInfo {
       header :: !(ElfHeader w)
       -- ^ Elf header information
     , ehdrSize :: !Word16
       -- ^ Size of ehdr table
     , phdrTable :: !(TableLayout w)
       -- ^ Layout of segment header table.
     , shdrNameIdx :: !Word16
       -- ^ Index of section for storing section names.
       --
       -- Note. At initialization time we check that the index
       -- is valid if the file has any sections.
     , shdrTable :: !(TableLayout w)
       -- ^ Layout of section header table.
     , headerFileContents :: !B.ByteString
       -- ^ Contents of file as a bytestring.
     }

phdrCount :: ElfHeaderInfo w -> Word16
phdrCount = entryNum . phdrTable

-- | Parse program header at given index
phdrByIndex :: ElfHeaderInfo w -- ^ Information for parsing
            -> Word16 -- ^ Index
            -> Phdr w
phdrByIndex ehi i = elfClassInstances (headerClass (header ehi)) $
  Get.runGet (getPhdr (header ehi) i) (tableEntry (phdrTable ehi) i (headerFileContents ehi))

-- | Return list of segments program headers from
headerPhdrs :: ElfHeaderInfo w -> [Phdr w]
headerPhdrs ehi = phdrByIndex ehi <$> enumCnt 0 (phdrCount ehi)

-- | Return number of headers in info
headerSectionCount :: ElfHeaderInfo w -> Word16
headerSectionCount = entryNum . shdrTable

-- | Return the section entry
getShdrEntry :: ElfHeaderInfo w
             -> Word16 -- ^ Index of section (note assumed to be a legal section index)
             -> ShdrEntry Word32 (ElfWordType w)
getShdrEntry ehi i = elfClassInstances (headerClass (header ehi)) $ do
  -- Get buffer for section header entry
  let shdrEntryBuffer = tableEntry (shdrTable ehi) i (headerFileContents ehi)
  let hdr = header ehi
  case Get.runGetOrFail (getShdr (headerData hdr) (headerClass hdr)) shdrEntryBuffer of
    Left (_,_,msg) -> error $ "Internal error: " ++ msg
    Right (_,_,v) -> v

-- | Get list of sections from Elf parse info.
-- This includes the initial section
headerSectionHeaders :: ElfHeaderInfo w
                     -> V.Vector (ShdrEntry Word32 (ElfWordType w))
headerSectionHeaders ehi = V.generate cnt (getShdrEntry ehi . fromIntegral)
  where cnt = fromIntegral (headerSectionCount ehi)

-- | Get name region and bytes
nameSectionInfo :: HasCallStack
                => ElfHeaderInfo w
                -> (Range (ElfWordType w), B.ByteString)
nameSectionInfo ehi = elfClassInstances (headerClass (header ehi)) $
  case shdrNameIdx ehi of
    0 -> ((0,0), B.empty)
    idx | idx < entryNum (shdrTable ehi) ->
          let r = shdrFileRange (getShdrEntry ehi idx)
           in (r, slice r (headerFileContents ehi))
        | otherwise -> error "Invalid section name index"

-- | Get list of sections from Elf parse info.
-- This includes the initial section
--
-- Note. this may call `error`
headerSections :: ElfHeaderInfo w
               -> V.Vector (Range (ElfWordType w), ElfSection (ElfWordType w))
headerSections ehi = V.imap getSectionByIndex (headerSectionHeaders ehi)
  where -- Return range used to store name index.
        strtab :: B.ByteString
        (_, strtab) = nameSectionInfo ehi

        getSectionByIndex i shdr = elfClassInstances (headerClass (header ehi)) $
          case transShdrEntry (headerFileContents ehi) strtab (fromIntegral i) shdr of
            Left e -> error e
            Right p -> p

-- | Return section and file offset and size.
getSectionAndRange :: HasCallStack
                   => ElfHeaderInfo w
                   -> B.ByteString -- ^ String table
                   -> Word16 -- ^ Index of section.
                   -> (Range (ElfWordType w), ElfSection (ElfWordType w))
getSectionAndRange ehi strtab i = elfClassInstances (headerClass (header ehi)) $
  case transShdrEntry (headerFileContents ehi) strtab i (getShdrEntry ehi i) of
    Left e -> error e
    Right p -> p

------------------------------------------------------------------------
-- Region collection

-- | Maps each offset in the file to the contents that begin at that region.
data CollectedRegion w
   = AtomicRegion !B.ByteString !(ElfWordType w) !(ElfWordType w) !(ElfDataRegion w)
     -- ^ A region with the name, start offset, one past the end, and contents.
   | SegmentRegion !(Phdr w) !([CollectedRegion w])
     -- ^ A Program header and additional regions.

-- | Return the starting offset of the region
roFileOffset :: CollectedRegion w -> ElfWordType w
roFileOffset (AtomicRegion _ o _ _) = o
roFileOffset (SegmentRegion phdr _) = fromFileOffset (phdrFileStart phdr)

-- | @roEnd r@ returns the offset at the end of the file.
roEnd :: Num (ElfWordType w) => CollectedRegion w -> ElfWordType w
roEnd (AtomicRegion _ _ e _) = e
roEnd (SegmentRegion phdr _)  = fromFileOffset (phdrFileStart phdr) + phdrFileSize phdr

atomicRO :: (Num (ElfWordType w), Ord (ElfWordType w))
         => B.ByteString -> ElfWordType w -> ElfWordType w -> ElfDataRegion w -> CollectedRegion w
atomicRO nm o sz r
  | o + sz < o = error $ "atomicRO: Overflow for computing end of " ++ BSC.unpack nm
  | otherwise = AtomicRegion nm o (o+sz) r

segmentRO :: (Num (ElfWordType w), Ord (ElfWordType w))
          => Phdr w -> [CollectedRegion w] -> CollectedRegion w
segmentRO phdr inner
  | o <- fromFileOffset (phdrFileStart phdr)
  , sz <- phdrFileSize phdr
  , o + sz < o = error $ "segmentRO: Overflow for computing end of segment " ++ show (phdrSegmentIndex phdr)
  | otherwise = SegmentRegion phdr inner

-- | A list of region offsets.  This maintains the invariant that offsets
-- are non-decreasing, but there may be overlaps.
newtype CollectedRegionList w = CRL [CollectedRegion w]

-- | Add a list of regions in reverse order to the collection.
prependRevRegions :: [CollectedRegion w] -> CollectedRegionList w -> CollectedRegionList w
prependRevRegions l (CRL r) = CRL (revApp l r)

-- | This prepends a program header to list by collecting regions that are inside it.
prependPhdr' :: Integral (ElfWordType w)
             => [CollectedRegion w] -- ^ Regions to include in phdr
             -> Phdr w
             -> CollectedRegionList w
             -> CollectedRegionList w
prependPhdr' prev phdr (CRL (p:l))
  | roEnd p <= fromFileOffset (phdrFileStart phdr) + fromIntegral (phdrFileSize phdr) =
    prependPhdr' (p:prev) phdr (CRL l)
prependPhdr' prev phdr (CRL l) = do
  CRL (segmentRO phdr (reverse prev):l)

-- | Add elf segment after collecting regions.
--
-- Note. This code may assume that the file offset of the phdr is less than or equal to
-- all the file offsets in the region list.
prependPhdr :: Integral (ElfWordType w)
            => Phdr w
            -> CollectedRegionList w
            -> CollectedRegionList w
prependPhdr = prependPhdr' []

insertNewRegion' :: (Ord (ElfWordType w), Num (ElfWordType w))
                 => [CollectedRegion w] -- ^ Processed regions in reverse order
                 -> B.ByteString -- ^ Name of this region
                 -> ElfWordType w -- ^ File offset
                 -> ElfWordType w -- ^ File size
                 -> ElfDataRegion w -- ^ Region to insert
                 -> CollectedRegionList w -- ^ Remaining regions
                 -> CollectedRegionList w
-- Put existing region first if it is before region to insert or
-- at the same location and inserting new region would move existing
-- region
insertNewRegion' prev nm o sz reg (CRL (p:rest))
  | o > roFileOffset p || o == roFileOffset p && sz > 0 = do
      insertNewRegion' (p:prev) nm o sz reg (CRL rest)
-- Otherwise stick it first
insertNewRegion' prev nm o sz reg (CRL l) = do
  CRL (revApp prev (atomicRO nm o sz reg:l))

-- | Insert a new atomic region into the list.
insertNewRegion :: Integral (ElfWordType w)
                => B.ByteString -- ^ Name of this region
                -> ElfWordType w -- ^ File offset
                -> ElfWordType w -- ^ File size
                -> ElfDataRegion w -- ^ Region to insert
                -> CollectedRegionList w
                -> CollectedRegionList w
insertNewRegion = insertNewRegion' []

insertSegment' :: Integral (ElfWordType w)
               => [CollectedRegion w] -- ^ Processed regions in reverse order
               -> Phdr w -- ^ Region to insert
               -> CollectedRegionList w -- ^ Remaining regions
               -> CollectedRegionList w
insertSegment' prev phdr (CRL (p:rest))
  -- If offset is after end of next segment, then just go to next segment.
  | fromFileOffset (phdrFileStart phdr) > roFileOffset p = do
      insertSegment' (p:prev) phdr (CRL rest)
-- In this case, we know that either l is empty or phdr is less than
-- or equal to the first file offset.
insertSegment' prev phdr l =
  prependRevRegions prev $ prependPhdr phdr l

-- | Insert a segment into the region offset list.
insertSegment :: Integral (ElfWordType w)
              => Phdr w -- ^ Region to insert
              -> CollectedRegionList w -- ^ Remaining regions
              -> CollectedRegionList w
insertSegment = insertSegment' []

-- | This type is used
data SizedRegions w
  = SizedRegions
  { sizedRegions :: !(Seq.Seq (ElfDataRegion w))
    -- ^ The regions added so far in the current segment or the overall file.
  , sizedLength :: !Int
    -- ^ The total number of bytes in the regions passed so far.
    --
    -- Note. This will be larger than the sum of the size of regions when we are
    -- inside a segment.
  }

appendSizedRegion :: SizedRegions w -> ElfDataRegion w -> Int -> SizedRegions w
appendSizedRegion sr r sz =
  SizedRegions { sizedRegions = sizedRegions sr Seq.|> r
               , sizedLength  = sizedLength  sr + sz
               }

addPadding :: Integral (ElfWordType w)
           => B.ByteString
           -> Int
           -> ElfWordType w -- ^ New offset
           -> SizedRegions w
           -> SizedRegions w
addPadding contents endOff nextOff sr
   | B.length b > 0 = appendSizedRegion sr (ElfDataRaw b) (B.length b)
   | otherwise = sr
  where b = B.take (fromIntegral nextOff-endOff) (B.drop endOff contents)

-- | This constructs a sequence of data regions from the region offset.
--
-- It returns the generated sequence, and the the length of the buffer.
mkSequence' :: ElfWidthConstraints w
            => B.ByteString
               -- ^ File contents
            -> SizedRegions w
               -- ^ Regions generated so far.
            -> Int
               -- ^ The offset of the last segment added.
               -- Due to overlaps this may exceed the start of the next region
               -- In recursive calls, we take max.
            -> [CollectedRegion w]
            -> GetResult (SizedRegions w)
mkSequence' contents sr endOff [] = do
  let b = B.drop endOff contents
  if B.length b > 0 then
    pure $! appendSizedRegion sr (ElfDataRaw b) (B.length b)
   else
    pure $! sr
mkSequence' contents sr endOff (p:rest) =
  case p of
    AtomicRegion nm o e reg -> do
      let sz = e-o
      let padded = addPadding contents endOff o sr
      when (sizedLength padded > fromIntegral o && e > o) $ do
        warn $ OverlapMovedLater (BSC.unpack nm) (sizedLength padded) (toInteger o)
      let cur = appendSizedRegion padded reg (fromIntegral sz)
      mkSequence' contents cur (max endOff (fromIntegral e)) rest
    SegmentRegion phdr inner -> do
     let o  = fromFileOffset (phdrFileStart phdr)
     let sz = fromIntegral (phdrFileSize  phdr)
     let newEnd :: Int
         newEnd = fromIntegral o + sz
     let padded = addPadding contents endOff o sr
     when (sizedLength padded > fromIntegral o && sz > 0) $ do
       warn $ OverlapMovedLater (phdrName phdr) (sizedLength padded) (toInteger o)
     -- Check program header is inside file.
     when (sz > 0 && newEnd > B.length contents) $ do
       warn $ PhdrTooLarge (phdrSegmentIndex phdr) newEnd (B.length contents)
     let contentsPrefix = B.take newEnd contents
     let phdrInitRegions = SizedRegions { sizedRegions = Seq.empty
                                        , sizedLength = sizedLength padded
                                        }
     phdrRegions <- mkSequence' contentsPrefix phdrInitRegions (max endOff (fromIntegral o)) inner
     -- Add program header size
     let phdrSize = toInteger (sizedLength phdrRegions) - toInteger (sizedLength padded)
     when (phdrSize > toInteger sz) $ do
       warn $ PhdrSizeIncreased (phdrSegmentIndex phdr) (phdrSize - toInteger sz)

     -- Segment after program header added.
     let cur =
           let reg = ElfDataSegment (phdrSegment phdr (sizedRegions phdrRegions))
            in appendSizedRegion padded reg (fromInteger phdrSize)
     mkSequence' contents cur (max endOff newEnd) rest

mkSequence :: ElfWidthConstraints w
           => B.ByteString
           -> CollectedRegionList w
           -> GetResult (Seq.Seq (ElfDataRegion w))
mkSequence contents (CRL l) = do
  let sr = SizedRegions Seq.empty 0
  sizedRegions <$> mkSequence' contents sr 0 l

isSymtabSection :: ElfSection w -> Bool
isSymtabSection s
  =  elfSectionName s == ".symtab"
  && elfSectionType s == SHT_SYMTAB


-- | This returns an elf from the header information along with and
-- errors that occured when generating it.
getElf :: forall w
       .  ElfHeaderInfo w
       -> ([ElfParseError], Elf w)
getElf ehi = elfClassInstances (headerClass (header ehi)) $ errorPair $ do
  let phdrs = headerPhdrs ehi
  -- Return range used to store name index.
  let (nameRange, sectionNames) = nameSectionInfo ehi

  let sectionCnt :: Word16
      sectionCnt = entryNum $ shdrTable ehi

      -- Get vector with section information
  let sectionVec :: V.Vector (Range (ElfWordType w), ElfSection (ElfWordType w))
      sectionVec = V.generate (fromIntegral sectionCnt) $
        getSectionAndRange ehi sectionNames . fromIntegral

  let msymtab :: Maybe (Range (ElfWordType w), ElfSection (ElfWordType w))
      msymtab = V.find (\(_,s) -> isSymtabSection s) sectionVec

  let mstrtab_index  = elfSectionLink . snd <$> msymtab

  -- Define initial region list without program headers.
  let postHeaders =
        -- Define table with special data regions.
        let headers :: [(Range (ElfWordType w), B.ByteString, ElfDataRegion w)]
            headers = [ ((0, fromIntegral (ehdrSize ehi)), "file header"
                        , ElfDataElfHeader)
                      , (tableRange (phdrTable ehi), "program header table"
                        , ElfDataSegmentHeaders)
                      , (tableRange (shdrTable ehi), "section header table"
                        , ElfDataSectionHeaders)
                      , (nameRange,                  ".shstrtab"
                        , ElfDataSectionNameTable (shdrNameIdx ehi))
                      ]
            insertRegion :: CollectedRegionList w
                         -> (Range (ElfWordType w), BSC.ByteString, ElfDataRegion w)
                         -> CollectedRegionList w
            insertRegion l ((o,c), nm, n) =
              insertNewRegion nm o c n l
        in foldl' insertRegion (CRL []) headers

  postSections <- do
    -- Get list of all sections other than the first section (which is skipped)
    let sections :: [(Range (ElfWordType w), ElfSection (ElfWordType w))]
        sections = fmap (\i -> sectionVec V.! fromIntegral i)
                   $ filter (\i -> i /= shdrNameIdx ehi && i /= 0)
                   $ enumCnt 0 sectionCnt
    -- Define table with regions for sections.
    -- TODO: Modify this so that it correctly recognizes the GOT section
    -- and generate the appropriate type.
    let dataSection :: ElfSection (ElfWordType w)
                    -> GetResult (ElfDataRegion w)
        dataSection s
          | Just (fromIntegral (elfSectionIndex s)) == mstrtab_index
          , elfSectionName s == ".strtab"
          , elfSectionType s == SHT_STRTAB =
            pure $ ElfDataStrtab (elfSectionIndex s)
          | isSymtabSection s = do
              case sectionVec V.!? fromIntegral (elfSectionLink s) of
                Nothing -> do
                  warn (ElfSymtabError (InvalidLink (elfSectionLink s)))
                  pure (ElfDataSection s)
                Just (_, strtab) -> do
                  let hdr = header ehi
                  let cl = headerClass hdr
                  let dta = headerData hdr
                  let strtabData = elfSectionData strtab
                  case getSymbolTableEntries cl dta strtabData (elfSectionData s) of
                    Left msg -> do
                      warn (ElfSymtabError msg)
                      pure (ElfDataSection s)
                    Right entries -> do
                      let symtab =
                            ElfSymbolTable { elfSymbolTableIndex = elfSectionIndex s
                                           , elfSymbolTableEntries = entries
                                           , elfSymbolTableLocalEntries = elfSectionInfo s
                                           }
                      pure $ ElfDataSymtab symtab
          | otherwise =
              pure $ ElfDataSection s
    let insertSection :: CollectedRegionList w
                      -> (Range (ElfWordType w), ElfSection (ElfWordType w))
                      -> GetResult (CollectedRegionList w)
        insertSection l ((o,c), sec) = do
          reg <- dataSection sec
          pure $! insertNewRegion (elfSectionName sec) o c reg l
    foldlM insertSection postHeaders sections

  -- Do relro processing

  -- Partition headers based on different types.
  let (loadPhdrs,  phdrs1)       = partition (hasSegmentType PT_LOAD)      phdrs
  let (stackPhdrs, phdrs2)       = partition (hasSegmentType PT_GNU_STACK) phdrs1
  let (relroPhdrs, unclassPhdrs) = partition (hasSegmentType PT_GNU_RELRO) phdrs2

  -- Create segment sequence for segments that are PT_LOAD or not one
  -- of the special ones.
  let dta =
        -- Sort with smallest phdr first.
        let sortPhdr x y = compare (phdrFileSize x) (phdrFileSize y)
            -- Insert segments with smallest last segment first.
         in foldl' (flip insertSegment) postSections $ sortBy sortPhdr $ loadPhdrs ++ unclassPhdrs

  -- Parse PT_GNU_STACK phdrs
  anyGnuStack <-
    case stackPhdrs of
      [] -> pure Nothing
      (stackPhdr:r) -> do
        let flags = phdrSegmentFlags stackPhdr

        unless (null r) $ do
          warn MultipleGnuStacks
        when ((flags .&. complement pf_x) /= (pf_r .|. pf_w)) $ do
          warn GnuStackNotRW

        let isExec = (flags .&. pf_x) == pf_x
        let gnuStack = GnuStack { gnuStackSegmentIndex = phdrSegmentIndex stackPhdr
                                , gnuStackIsExecutable = isExec
                                }
        pure $ Just gnuStack

  -- Parse PT_GNU_RELRO phdrs
  relroRegions <- do
    let loadMap = Map.fromList [ (phdrFileStart p, phdrSegmentIndex p) | p <- loadPhdrs ]
    catMaybes <$> traverse (asRelroRegion loadMap) relroPhdrs

  fileD <- mkSequence (headerFileContents ehi) dta

  -- Create final elf file.
  pure $! Elf { elfData       = headerData       (header ehi)
              , elfClass      = headerClass      (header ehi)
              , elfOSABI      = headerOSABI      (header ehi)
              , elfABIVersion = headerABIVersion (header ehi)
              , elfType       = headerType       (header ehi)
              , elfMachine    = headerMachine    (header ehi)
              , elfEntry      = headerEntry      (header ehi)
              , elfFlags      = headerFlags      (header ehi)
              , _elfFileData  = fileD
              , elfGnuStackSegment = anyGnuStack
              , elfGnuRelroRegions = relroRegions
              }

-- | Parse a 32-bit elf.
parseElf32ParseInfo :: ElfData
                    -> ElfOSABI
                    -> Word8 -- ^ ABI Version
                    -> B.ByteString -- ^ File contents
                    -> Get (ElfHeaderInfo 32)
parseElf32ParseInfo d ei_osabi ei_abiver b = do
  e_type      <- ElfType      <$> getWord16 d
  e_machine   <- ElfMachine   <$> getWord16 d
  e_version   <- getWord32 d
  when (fromIntegral expectedElfVersion /= e_version) $
    fail "ELF Version mismatch"
  e_entry     <- getWord32 d
  e_phoff     <- getWord32 d
  e_shoff     <- getWord32 d
  e_flags     <- getWord32 d
  e_ehsize    <- getWord16 d
  e_phentsize <- getWord16 d
  e_phnum     <- getWord16 d
  e_shentsize <- getWord16 d
  e_shnum     <- getWord16 d
  e_shstrndx  <- getWord16 d
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
  return $! ElfHeaderInfo
                  { header       = hdr
                  , ehdrSize     = e_ehsize
                  , phdrTable    = TableLayout e_phoff expected_phdr_entry_size e_phnum
                  , shdrNameIdx  = e_shstrndx
                  , shdrTable    = TableLayout e_shoff expected_shdr_entry_size e_shnum
                  , headerFileContents = b
                  }

-- | Parse a 64-bit elf header.
parseElf64ParseInfo :: ElfData
                    -> ElfOSABI
                    -> Word8 -- ^ ABI Version
                    -> B.ByteString -- ^ File contents
                    -> Get (ElfHeaderInfo 64)
parseElf64ParseInfo d ei_osabi ei_abiver b = do
  e_type      <- ElfType    <$> getWord16 d
  e_machine   <- ElfMachine <$> getWord16 d
  e_version   <- getWord32 d
  when (fromIntegral expectedElfVersion /= e_version) $
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
  let expected_phdr_entry_size = phdrEntrySize ELFCLASS64
  let expected_shdr_entry_size = shdrEntrySize ELFCLASS64

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
  return $! ElfHeaderInfo
                  { header       = hdr
                  , ehdrSize     = e_ehsize
                  , phdrTable    = TableLayout e_phoff expected_phdr_entry_size e_phnum
                  , shdrNameIdx  = e_shstrndx
                  , shdrTable    = TableLayout e_shoff expected_shdr_entry_size e_shnum
                  , headerFileContents = b
                  }

parseElfResult :: Either (L.ByteString, ByteOffset, String) (L.ByteString, ByteOffset, a)
               -> Either (ByteOffset,String) a
parseElfResult (Left (_,o,e)) = Left (o,e)
parseElfResult (Right (_,_,v)) = Right v

-- | Wraps a either a 32-bit or 64-bit typed value.
data SomeElf f
   = Elf32 (f 32)
   | Elf64 (f 64)

-- | Parses a ByteString into an Elf record. Parse failures call error. 32-bit ELF objects have
-- their fields promoted to 64-bit so that the 32- and 64-bit ELF records can be the same.
parseElfHeaderInfo :: B.ByteString -> Either (ByteOffset,String) (SomeElf ElfHeaderInfo)
parseElfHeaderInfo b = parseElfResult $ flip Get.runGetOrFail (L.fromChunks [b]) $ do
  ei_magic    <- Get.getByteString 4
  unless (ei_magic == elfMagic) $
    fail $ "Invalid magic number for ELF: " ++ show (ei_magic, elfMagic)
  ei_class   <- tryParse "ELF class" toSomeElfClass =<< getWord8
  d          <- tryParse "ELF data"  toElfData =<< getWord8
  ei_version <- getWord8
  unless (ei_version == expectedElfVersion) $
    fail "Invalid version number for ELF"
  ei_osabi    <- ElfOSABI <$> getWord8
  ei_abiver   <- getWord8
  skip 7
  case ei_class of
    SomeElfClass ELFCLASS32 -> do
      Elf32 <$> parseElf32ParseInfo d ei_osabi ei_abiver b
    SomeElfClass ELFCLASS64 -> do
      Elf64 <$> parseElf64ParseInfo d ei_osabi ei_abiver b

data ElfGetResult
   = Elf32Res !([ElfParseError]) (Elf 32)
   | Elf64Res !([ElfParseError]) (Elf 64)
   | ElfHeaderError !ByteOffset !String
     -- ^ Attempt to parse header failed.
     --
     -- First argument is byte offset, second is string.

-- | Parses a ByteString into an Elf record. Parse failures call error. 32-bit ELF objects hav
-- their fields promoted to 64-bit so that the 32- and 64-bit ELF records can be the same.
parseElf :: B.ByteString -> ElfGetResult
parseElf b =
  case parseElfHeaderInfo b of
    Left (o, m) -> ElfHeaderError o m
    Right (Elf32 hdr) -> Elf32Res l e
      where (l, e) = getElf hdr
    Right (Elf64 hdr) -> Elf64Res l e
      where (l, e) = getElf hdr
