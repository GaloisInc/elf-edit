{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE Trustworthy #-}
{-# LANGUAGE UndecidableInstances #-}
module Data.ElfEdit.Get
  ( -- * parseElf
    parseElf
  , ElfGetResult(..)
    -- * elfHeaderInfo low-level interface
  , ElfHeaderInfo
  , header
  , headerPhdrs
  , parseElfHeaderInfo
  , SomeElf(..)
  , getElf
  , ElfParseError(..)
  , getSectionTable
  , SymbolTableError(..)
  , parseSymbolTableEntry
  , getSymbolTableEntries
    -- * Utilities
  , getWord16
  , getWord32
  , getWord64
  , LookupStringError(..)
  , lookupString
  , runGetMany
  ) where

import           Control.Lens
import           Control.Monad
import           Control.Monad.Except
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
  , shdrEntrySize
  , symbolTableEntrySize
  )
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
tryParse :: Monad m => String -> (a -> Maybe b) -> a -> m b
tryParse desc toFn = maybe (fail ("Invalid " ++ desc)) return . toFn

------------------------------------------------------------------------
-- Segment

-- | Return true if the program header has the givne type.
hasSegmentType :: ElfSegmentType -> Phdr w -> Bool
hasSegmentType tp p = phdrSegmentType p == tp

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
    =  showString "The size of segment " . shows i . showString " increased by "
    . shows adj . showString " bytes to fit shifted contents."

------------------------------------------------------------------------
-- Low level getters

getWord16 :: ElfData -> Get Word16
getWord16 ELFDATA2LSB = Get.getWord16le
getWord16 ELFDATA2MSB = Get.getWord16be

getWord32 :: ElfData -> Get Word32
getWord32 ELFDATA2LSB = Get.getWord32le
getWord32 ELFDATA2MSB = Get.getWord32be

getWord64 :: ElfData -> Get Word64
getWord64 ELFDATA2LSB = Get.getWord64le
getWord64 ELFDATA2MSB = Get.getWord64be

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
                -- ^ Number of entries in bytes.
              }

-- | Returns size of table.
tableSize :: Integral (ElfWordType w) => TableLayout w -> ElfWordType w
tableSize l = fromIntegral (entryNum l) * fromIntegral (entrySize l)

-- | Returns range in memory of table.
tableRange :: Integral (ElfWordType w) => TableLayout w -> Range (ElfWordType w)
tableRange l = (tableOffset l, tableSize l)

-- | Returns offset of entry in table.
tableEntry :: Integral (ElfWordType w) => TableLayout w -> Word16 -> B.ByteString -> L.ByteString
tableEntry l i b = L.fromChunks [B.drop (fromIntegral o) b]
  where sz = fromIntegral (entrySize l)
        o = tableOffset l + fromIntegral i * sz

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

------------------------------------------------------------------------
-- GetShdr

type GetShdrFn w = Word16 -- ^ Index of section
                 -> Maybe B.ByteString -- ^ String table (optionally defined)
                 -> Get (Range w, ElfSection w)

-- | Returns length of section in file.
sectionFileLen :: Num w => ElfSectionType -> w -> w
sectionFileLen SHT_NOBITS _ = 0
sectionFileLen _ s = s

getShdr32 :: ElfData -> B.ByteString -> GetShdrFn Word32
getShdr32 d file idx mstrtab = do
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
  let file_sz = sectionFileLen sh_type sh_size
  nm <- case mstrtab of
          Nothing -> pure ""
          Just strtab -> either (fail . show) pure $
            lookupString sh_name strtab
  let s = ElfSection
           { elfSectionIndex     = idx
           , elfSectionName      = nm
           , elfSectionType      = sh_type
           , elfSectionFlags     = sh_flags
           , elfSectionAddr      = sh_addr
           , elfSectionSize      = sh_size
           , elfSectionLink      = sh_link
           , elfSectionInfo      = sh_info
           , elfSectionAddrAlign = sh_addralign
           , elfSectionEntSize   = sh_entsize
           , elfSectionData      = slice (sh_offset, file_sz) file
           }
  return ((sh_offset, file_sz), s)

getShdr64 :: ElfData -> B.ByteString -> GetShdrFn Word64
getShdr64 er file idx mstrtab = do
  sh_name      <- getWord32 er
  sh_type      <- ElfSectionType  <$> getWord32 er
  sh_flags     <- ElfSectionFlags <$> getWord64 er
  sh_addr      <- getWord64 er
  sh_offset    <- getWord64 er
  sh_size      <- getWord64 er
  sh_link      <- getWord32 er
  sh_info      <- getWord32 er
  sh_addralign <- getWord64 er
  sh_entsize   <- getWord64 er
  let file_sz = sectionFileLen sh_type sh_size
  nm <- case mstrtab of
          Nothing -> pure ""
          Just strtab -> either (fail . show) pure $
            lookupString sh_name strtab
  let s = ElfSection
           { elfSectionIndex     = idx
           , elfSectionName      = nm
           , elfSectionType      = sh_type
           , elfSectionFlags     = sh_flags
           , elfSectionAddr      = sh_addr
           , elfSectionSize      = sh_size
           , elfSectionLink      = sh_link
           , elfSectionInfo      = sh_info
           , elfSectionAddrAlign = sh_addralign
           , elfSectionEntSize   = sh_entsize
           , elfSectionData      = slice (sh_offset, file_sz) file
           }
  return ((sh_offset, file_sz), s)

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
     , getPhdr :: !(Word16 -> Get (Phdr w))
       -- ^ Function for reading elf segments.
     , shdrNameIdx :: !Word16
       -- ^ Index of section for storing section names.
     , shdrTable :: !(TableLayout w)
       -- ^ Layout of section header table.
     , getShdr   :: !(GetShdrFn (ElfWordType w))
       -- ^ Function for reading elf sections.
     , fileContents :: !B.ByteString
       -- ^ Contents of file as a bytestring.
     }

-- | Parse program header at given index
phdrByIndex :: ElfHeaderInfo w -- ^ Information for parsing
            -> Word16 -- ^ Index
            -> Phdr w
phdrByIndex ehi i = elfClassInstances (headerClass (header ehi)) $
  Get.runGet (getPhdr ehi i) (tableEntry (phdrTable ehi) i (fileContents ehi))

-- | Return list of segments program headers from
headerPhdrs :: ElfHeaderInfo w -> [Phdr w]
headerPhdrs ehi = phdrByIndex ehi <$> enumCnt 0 (entryNum (phdrTable ehi))

-- | Return section and file offset and size.
getSectionAndRange :: HasCallStack
                   => ElfHeaderInfo w
                   -> Maybe B.ByteString -- ^ String table (if defined)
                   -> Word16 -- ^ Index of section.
                   -> (Range (ElfWordType w), ElfSection (ElfWordType w))
getSectionAndRange ehi mstrtab i = elfClassInstances (headerClass (header ehi)) $ do
  let file = fileContents ehi
  case Get.runGetOrFail (getShdr ehi i mstrtab) (tableEntry (shdrTable ehi) i file) of
    Left (_,_,msg) -> error msg
    Right (_,_,v) -> v

nameSectionInfo :: ElfHeaderInfo w
                -> (Range (ElfWordType w), B.ByteString)
nameSectionInfo ehi =
  over _2 elfSectionData $ getSectionAndRange ehi Nothing (shdrNameIdx ehi)

------------------------------------------------------------------------
-- Symbol table entries

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

-- | Create a symbol table entry from a Get monad
getSymbolTableEntry :: ElfClass w
                    -> ElfData
                    -> B.ByteString
                       -- ^ The string table
                    -> Word32
                       -- ^ The index of the symbol in table
                    -> ExceptT SymbolTableError Get (ElfSymbolTableEntry (ElfWordType w))
getSymbolTableEntry ELFCLASS32 d strTab idx = do
  nameIdx <- lift $ getWord32 d
  value <- lift $ getWord32 d
  size  <- lift $ getWord32 d
  info  <- lift $ getWord8
  other <- lift $ getWord8
  sTlbIdx <- lift $ getWord16 d
  let (typ,bind) = infoToTypeAndBind info
  nm <- case lookupString nameIdx strTab of
          Left e -> throwError (InvalidName idx e)
          Right v -> pure v
  pure $! EST { steName  = nm
              , steType  = typ
              , steBind  = bind
              , steOther = other
              , steIndex = ElfSectionIndex sTlbIdx
              , steValue = value
              , steSize  = size
              }
getSymbolTableEntry ELFCLASS64 d strTab idx = do
  nameIdx <- lift $ getWord32 d
  info    <- lift $ getWord8
  other   <- lift $ getWord8
  sTlbIdx <- lift $ getWord16 d
  symVal  <- lift $ getWord64 d
  size    <- lift $ getWord64 d
  nm <- case lookupString nameIdx strTab of
          Left e -> throwError (InvalidName idx e)
          Right v -> pure v
  let (typ,bind) = infoToTypeAndBind info
  pure $! EST { steName  = nm
              , steType  = typ
              , steBind  = bind
              , steOther = other
              , steIndex = ElfSectionIndex sTlbIdx
              , steValue = symVal
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
                      -> Either SymbolTableError (ElfSymbolTableEntry (ElfWordType w))
parseSymbolTableEntry cl d strTab symTab idx = do
  let symEntSize :: Int64
      symEntSize = elfClassInstances cl $ fromIntegral (symbolTableEntrySize cl)
  let symOff :: Int64
      symOff = fromIntegral idx * symEntSize
  let symEntry = L.drop symOff symTab
  when (symEntSize > L.length symTab) $ do
    Left (IllegalSymbolIndex idx)
  case runGetOrFail (runExceptT (getSymbolTableEntry cl d strTab idx)) symEntry of
    -- This should never occur.
    Left (_,_,msg) -> error $ "Internal error on parseSymbolTableEntry: " ++ msg
    Right (_,_,r) -> r

------------------------------------------------------------------------
-- Region parsing

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

-- | Get list of sections from Elf parse info.
-- This includes the initial section
getSectionTable :: forall w . ElfHeaderInfo w -> V.Vector (ElfSection (ElfWordType w))
getSectionTable ehi = V.generate cnt $ getSectionByIndex
  where cnt = fromIntegral (entryNum (shdrTable ehi)) :: Int

        c = headerClass (header ehi)

        -- Return range used to store name index.
        names :: B.ByteString
        names = snd $ nameSectionInfo ehi

        getSectionByIndex :: Int -> ElfSection (ElfWordType w)
        getSectionByIndex i = elfClassInstances c $
          snd $ getSectionAndRange ehi (Just names) (fromIntegral i)

isSymtabSection :: ElfSection w -> Bool
isSymtabSection s
  =  elfSectionName s == ".symtab"
  && elfSectionType s == SHT_SYMTAB

-- | Parse the section as a list of symbol table entries.
getSymbolTableEntries :: ElfClass w
                      -> ElfData
                      -> (Word32 -> Maybe (ElfSection (ElfWordType w)))
                         -- ^ Function that given a section index
                         -- returns the section associated with that
                         -- index (if any).
                      -> ElfSection (ElfWordType w)
                         -- ^ Symtab section
                      -> Either SymbolTableError [ElfSymbolTableEntry (ElfWordType w)]
getSymbolTableEntries cl dta sectionFn s = do
  strtab <-
    case sectionFn (elfSectionLink s) of
      Just t -> Right $ elfSectionData t
      Nothing -> Left $! InvalidLink (elfSectionLink s)

  let symEntSize :: Int
      symEntSize = elfClassInstances cl $ fromIntegral (symbolTableEntrySize cl)

  let symData = elfSectionData s

  let symDataSize = B.length symData
  -- Get number of entries (ignore extra bytes as they may be padding)
  let n :: Word32
      n = fromIntegral $ symDataSize `quot` symEntSize

  let symtab = L.fromChunks [elfSectionData s]
  case traverse (parseSymbolTableEntry cl dta strtab symtab) [0..(n-1)] of
    Left e -> Left e
    Right l -> Right l


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

-- | This returns an elf from the header information along with and
-- errors that occured when generating it.
getElf :: forall w
       .  ElfHeaderInfo w
       -> ([ElfParseError], Elf w)
getElf ehi = elfClassInstances (headerClass (header ehi)) $ errorPair $ do
  let phdrs = headerPhdrs ehi
  let -- Return range used to store name index.
      nameRange :: Range (ElfWordType w)
      nameRange = fst $ nameSectionInfo ehi

  let section_cnt :: Word16
      section_cnt = entryNum $ shdrTable ehi

  let section_names = slice nameRange $ fileContents ehi

      -- Get vector with section information
  let section_vec :: V.Vector (Range (ElfWordType w), ElfSection (ElfWordType w))
      section_vec = V.generate (fromIntegral section_cnt) $
        getSectionAndRange ehi (Just section_names) . fromIntegral

  let msymtab :: Maybe (Range (ElfWordType w), ElfSection (ElfWordType w))
      msymtab = V.find (\(_,s) -> isSymtabSection s) section_vec

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
        sections = fmap (\i -> section_vec V.! fromIntegral i)
                   $ filter (\i -> i /= shdrNameIdx ehi && i /= 0)
                   $ enumCnt 0 section_cnt
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
              let sectionFn idx = snd <$> section_vec V.!? fromIntegral idx
              case getSymbolTableEntries (headerClass (header ehi)) (headerData (header ehi)) sectionFn s of
                Left msg -> do
                  warn (ElfSymtabError msg)
                  pure (ElfDataSection s)
                Right entries -> do
                  let symtab =
                        ElfSymbolTable { elfSymbolTableIndex = elfSectionIndex s
                                       , elfSymbolTableEntries = V.fromList entries
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

  fileD <- mkSequence (fileContents ehi) dta

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
                    -> B.ByteString
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
                  , getPhdr      = getPhdr32 d
                  , shdrNameIdx  = e_shstrndx
                  , shdrTable    = TableLayout e_shoff expected_shdr_entry_size e_shnum
                  , getShdr      = getShdr32 d b
                  , fileContents = b
                  }

-- | Parse a 32-bit elf.
parseElf64ParseInfo :: ElfData
                    -> ElfOSABI
                    -> Word8 -- ^ ABI Version
                    -> B.ByteString
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
                  , getPhdr      = getPhdr64 d
                  , shdrNameIdx  = e_shstrndx
                  , shdrTable    = TableLayout e_shoff expected_shdr_entry_size e_shnum
                  , getShdr      = getShdr64 d b
                  , fileContents = b
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
