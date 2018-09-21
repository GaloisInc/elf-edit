{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
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
  , parseElfHeaderInfo
  , SomeElf(..)
  , getElf
  , ElfParseError(..)
  , elfParseErrorIsWarning
  , ElfInsertError(..)
  , getSectionTable
  , getSymbolTableEntry
    -- * Utilities
  , getWord16
  , getWord32
  , getWord64
  , LookupStringError(..)
  , lookupString
  , runGetMany
  ) where

import           Control.Exception ( assert )
import           Control.Lens
import           Control.Monad
import           Data.Binary
import           Data.Binary.Get
import qualified Data.Binary.Get as Get
import           Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy as L
--import qualified Data.ByteString.UTF8 as B (toString)
import           Data.Foldable (foldlM, foldrM)
import           Data.List (partition)
import           Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import           Data.Maybe
import qualified Data.Sequence as Seq
import qualified Data.Vector as V
import GHC.Stack
import           GHC.TypeLits
import           Numeric (showHex)

import           Data.ElfEdit.Enums
import           Data.ElfEdit.Layout
  ( FileOffset(..)
  , Phdr(..)
  , phdrFileRange
  , elfMagic
  , phdrEntrySize
  , shdrEntrySize
  , symbolTableSize
  )
import           Data.ElfEdit.Types
import           Data.ElfEdit.Utils (enumCnt)

------------------------------------------------------------------------
-- Utilities

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

-- | Return true if
hasSegmentType :: ElfSegmentType -> Phdr w -> Bool
hasSegmentType tp p = phdrSegmentType p == tp

------------------------------------------------------------------------
-- ElfParseError

-- | Describes reason an insertion failed.
data ElfInsertError w
   = OverlapSegment !(ElfDataRegion w) !(Range (ElfWordType w))
     -- ^ The inserted segment overlaps with another, and we needed to insert
     -- it in the given range.
   | OutOfRange !(Range (ElfWordType w))
     -- ^ This indicates we tried to insert some region, but we reached the end
     -- of the contents, and still had an offset.

-- | A parse error
data ElfParseError w
  = ElfInsertError !String !(ElfInsertError w)
    -- ^ Attempt to insert region failed.
  | ElfSymtabError !String
    -- ^ Error related to symtab parsing
  | GnuStackWarning !String
    -- ^ An error with the given message related to GNU stack handling.
  | UnassociatedGnuRelro
    -- ^ We could not find which loadable segment was affected by the GNU relro entry.

gnuStackWarning :: String -> GetResult (ElfParseError w) ()
gnuStackWarning = warn . GnuStackWarning

-- | This returns true if the parse error is not very serious
-- because, for example, it concerns a region with size 0.
--
-- Binutils generates binaries that sometimes contain these
-- warnings.
elfParseErrorIsWarning :: (Eq (ElfWordType w), Num (ElfWordType w)) => ElfParseError w -> Bool
elfParseErrorIsWarning pe =
  case pe of
    ElfInsertError _ (OverlapSegment _ (_,0)) -> True
    ElfInsertError _ (OutOfRange (_,0)) -> True
    _ -> False

instance (Integral (ElfWordType w), Show (ElfWordType w))
      => Show (ElfParseError w) where
  show (ElfSymtabError msg) =
    "Could not parse symtab entries: " ++ msg
  show UnassociatedGnuRelro =
    "Could not resolve load segment for GNU relro segment."
  show (GnuStackWarning msg) =
    "Unexpected PT_GNU_STACK feature -- " ++ msg
  show (ElfInsertError nm (OverlapSegment prev (_,0))) =
    "WARNING: Attempt to insert empty "
    ++ nm
    ++ " that overlaps with "
    ++ elfDataRegionName prev
    ++ "."
  show (ElfInsertError nm (OverlapSegment prev _)) =
    "Attempt to insert "
    ++ nm
    ++ " overlapping Elf region into "
    ++ elfDataRegionName prev
    ++ "."
  show (ElfInsertError nm (OutOfRange (o,0))) =
    "WARNING: Could not insert empty region " ++ nm
    ++ " at offset 0x" ++ showHex o "."
  show (ElfInsertError nm (OutOfRange (o,c))) =
    "Could not insert region " ++ nm
    ++ " with size " ++ show c ++ " at offset 0x" ++ showHex o "."

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
newtype GetResult e a = GetResult { unGetResult :: [e] -> ([e], a) }


errorPair :: GetResult e a -> ([e], a)
errorPair (GetResult c) = c []

-- | Apply a function to all errors collected.
mapError :: (e -> f) -> GetResult e a -> GetResult f a
mapError f (GetResult c) = GetResult $ \prev ->
  let (errList,a) = c []
   in (fmap f errList ++ prev, a)

-- | Add a warning to get result
warn :: e -> GetResult e ()
warn e = seq e $ GetResult $ \prev -> (e : prev, ())

instance Functor (GetResult e) where
  fmap f (GetResult c) = GetResult $ over _2 f . c

instance Applicative (GetResult e) where
  pure a = GetResult $ \prev -> (prev, a)
  GetResult fc <*> GetResult gc = GetResult $ \prev -> do
    let (cur, f) = fc prev
        (next, x) = gc cur
     in (next, f x)

instance Monad (GetResult e) where
  return = pure
  GetResult xc >>= f = GetResult $ \prev ->
    let (cur,x) = xc prev
     in unGetResult (f x) cur

------------------------------------------------------------------------
-- Relro handling

-- | Extract relro information.
asRelroRegion :: Ord (ElfWordType w)
              => Map (FileOffset (ElfWordType w)) SegmentIndex
              -> Phdr w
              -> GetResult (ElfParseError w) (Maybe (GnuRelroRegion w))
asRelroRegion segMap phdr = do
  case Map.lookupLE (phdrFileStart phdr) segMap of
    Nothing -> warn UnassociatedGnuRelro >> pure Nothing
    Just (_,refIdx) -> do
      pure $ Just $
        GnuRelroRegion { relroSegmentIndex = phdrSegmentIndex phdr
                       , relroRefSegmentIndex = refIdx
                       , relroAddrStart    = phdrSegmentVirtAddr phdr
                       , relroSize         = phdrFileSize phdr
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

-- | Return list of segments with contents.
rawSegments :: ElfHeaderInfo w -> [Phdr w]
rawSegments ehi = phdrByIndex ehi <$> enumCnt 0 (entryNum (phdrTable ehi))

-- | Information needed to compute region sizes.
data ElfSizingInfo (w :: Nat)
   = ElfSizingInfo
     { esiHeaderInfo :: !(ElfHeaderInfo w)
       -- ^ Header info
     , esiSectionNameTableSize :: !(ElfWordType w)
       -- ^ Contains size of section name table
     , esiStrtabSize :: !(ElfWordType w)
       -- ^ Return string table size
     }

-- | Return filesize of region given some additional information.
regionSize :: forall w . ElfSizingInfo w -> ElfDataRegion w -> ElfWordType w
regionSize esi = esiInstances esi $ sizeOf
  where ehi = esiHeaderInfo esi
        sizeOf :: Integral (ElfWordType w) => ElfDataRegion w -> ElfWordType w
        sizeOf ElfDataElfHeader            = fromIntegral $ ehdrSize ehi
        sizeOf ElfDataSegmentHeaders       = tableSize $ phdrTable ehi
        sizeOf (ElfDataSegment s)          = sum $ sizeOf <$> elfSegmentData s
        sizeOf ElfDataSectionHeaders       = tableSize $ shdrTable ehi
        sizeOf (ElfDataSectionNameTable _) = esiSectionNameTableSize esi
        sizeOf (ElfDataGOT g)              = elfGotSize g
        sizeOf (ElfDataStrtab _)           = esiStrtabSize esi
        sizeOf (ElfDataSymtab s)           = symbolTableSize c s
          where c = headerClass (header ehi)
        sizeOf (ElfDataSection s)          = fromIntegral $ B.length (elfSectionData s)
        sizeOf (ElfDataRaw b)              = fromIntegral $ B.length b

-- | Parse program header at given index
phdrByIndex :: ElfHeaderInfo w -- ^ Information for parsing
            -> Word16 -- ^ Index
            -> Phdr w
phdrByIndex ehi i = elfClassInstances (headerClass (header ehi)) $
  Get.runGet (getPhdr ehi i) (tableEntry (phdrTable ehi) i (fileContents ehi))

-- Return section
getSection' :: HasCallStack
            => ElfHeaderInfo w
            -> Maybe B.ByteString -- ^ String table (if defined)
            -> Word16 -- ^ Index of section.
            -> (Range (ElfWordType w), ElfSection (ElfWordType w))
getSection' ehi mstrtab i = elfClassInstances (headerClass (header ehi)) $ do
  let file = fileContents ehi
  case Get.runGetOrFail (getShdr ehi i mstrtab) (tableEntry (shdrTable ehi) i file) of
    Left (_,_,msg) -> error msg
    Right (_,_,v) -> v

nameSectionInfo :: ElfHeaderInfo w
                -> (Range (ElfWordType w), B.ByteString)
nameSectionInfo ehi =
  over _2 elfSectionData $ getSection' ehi Nothing (shdrNameIdx ehi)

------------------------------------------------------------------------
-- Symbol table entries

-- | Create a symbol table entry from a Get monad
getSymbolTableEntry :: ElfClass w
                    -> ElfData
                    -> B.ByteString
                       -- ^ The string table
                      -> Get (ElfSymbolTableEntry (ElfWordType w))
getSymbolTableEntry ELFCLASS32 d strTab = do
  nameIdx <- getWord32 d
  value <- getWord32 d
  size  <- getWord32 d
  info  <- getWord8
  other <- getWord8
  sTlbIdx <- ElfSectionIndex <$> getWord16 d
  let (typ,bind) = infoToTypeAndBind info
  nm <- case lookupString nameIdx strTab of
          Left e -> fail (show e)
          Right v -> pure v
  return $ EST { steName  = nm
               , steType  = typ
               , steBind  = bind
               , steOther = other
               , steIndex = sTlbIdx
               , steValue = value
               , steSize  = size
               }
getSymbolTableEntry ELFCLASS64 d strTab = do
  nameIdx <- getWord32 d
  info <- getWord8
  other <- getWord8
  sTlbIdx <- ElfSectionIndex <$> getWord16 d
  symVal <- getWord64 d
  size <- getWord64 d
  nm <- case lookupString nameIdx strTab of
          Left e -> fail (show e)
          Right v -> pure v
  let (typ,bind) = infoToTypeAndBind info
  return $ EST { steName  = nm
               , steType  = typ
               , steBind  = bind
               , steOther = other
               , steIndex = sTlbIdx
               , steValue = symVal
               , steSize  = size
               }

------------------------------------------------------------------------
-- Region name

elfDataRegionName :: ElfDataRegion w -> String
elfDataRegionName reg =
  case reg of
    ElfDataElfHeader          -> "elf header"
    ElfDataSegmentHeaders     -> "phdr table"
    ElfDataSegment s          -> show (elfSegmentType s) ++ " segment"
    ElfDataSectionHeaders     -> "shdr table"
    ElfDataSectionNameTable _ -> "section name table"
    ElfDataGOT g              -> BSC.unpack (elfGotName g)
    ElfDataStrtab _           -> ".strtab"
    ElfDataSymtab _           -> ".symtab"
    ElfDataSection s          -> BSC.unpack (elfSectionName s)
    ElfDataRaw _              -> "elf raw"

------------------------------------------------------------------------
-- Region parsing

-- | Function that transforms the sequence regions into new list.
--
--
type RegionPrefixFn w = Seq.Seq (ElfDataRegion w) -> Seq.Seq (ElfDataRegion w)

-- | Create a singleton list with a raw data region if one exists
insertRawRegion :: B.ByteString -> RegionPrefixFn w
insertRawRegion b r | B.length b == 0 = r
                    | otherwise = ElfDataRaw b Seq.<| r

-- | Insert an elf data region at a given offset.
insertAtOffset :: Integral (ElfWordType w)
               => ElfSizingInfo w
                  -- ^ Information for getting size of a region.
               -> (Range (ElfWordType w) -> RegionPrefixFn w)
                  -- ^ Insert function
               -> Range (ElfWordType w)
                  -- ^ Range to insert in.
               -> Seq.Seq (ElfDataRegion w)
                  -- ^ Existing sequence to insert into.
               -> GetResult (ElfInsertError w) (Seq.Seq (ElfDataRegion w))
insertAtOffset esi fn rng@(o,c) r0 =
  case Seq.viewl r0 of
    Seq.EmptyL
      | rng == (0,0) ->
        pure $! fn rng Seq.empty
      | otherwise -> do
        warn (OutOfRange rng)
        pure (fn rng Seq.empty)
    p Seq.:< r
      -- Go to next segment if offset to insert is after p.
      | o >= sz ->
        (p Seq.<|) <$> insertAtOffset esi fn (o-sz,c) r
        -- Recurse inside segment if p is a segment that contains region to insert.
        -- New region ends before p ends and p is a segment.
      | o + c <= sz, ElfDataSegment s <- p ->
        let combine seg_data' = ElfDataSegment s' Seq.<| r
                where s' = s { elfSegmentData = seg_data' }
         in combine <$> insertAtOffset esi fn rng (elfSegmentData s)
        -- Insert into current region when offset is 0 or when size is 0
      | o == 0 || c == 0 -> pure $! fn rng r0
        -- Split a raw segment into prefix and post.
      | ElfDataRaw b <- p ->
          -- We know offset is less than length of bytestring as otherwise we would
          -- have gone to next segment
          if (c == 0) then
            pure $ insertRawRegion b $ fn rng r
           else assert (fromIntegral o < B.length b) $ do
            let (pref,post) = B.splitAt (fromIntegral o) b
            pure $! insertRawRegion pref $ fn rng $ insertRawRegion post r
        --
      | otherwise -> do
        warn (OverlapSegment p rng)
        pure ((p Seq.<|) $! fn (o,c) r)
     where sz = regionSize esi p

-- | Insert a leaf region into the region.
insertSpecialRegion :: forall w
                    .  ElfSizingInfo w -- ^ Returns size of region.
                    -> String
                    -> Range (ElfWordType w)
                    -> ElfDataRegion w -- ^ New region
                    -> Seq.Seq (ElfDataRegion w)
                    -> GetResult (ElfParseError w) (Seq.Seq (ElfDataRegion w))
insertSpecialRegion esi nm r n segs
    = esiInstances esi
    $ mapError (ElfInsertError nm)
    $ insertAtOffset esi fn r segs
  where c = snd r
        -- Insert function
        fn :: ElfWidthConstraints w => Range (ElfWordType w) -> RegionPrefixFn w
        fn _ l | c == 0 = n Seq.<| l
        fn _ l0
          | ElfDataRaw b Seq.:< l <- Seq.viewl l0
          , fromIntegral c <= B.length b =
            n Seq.<| insertRawRegion (B.drop (fromIntegral c) b) l
        fn _ _ = error $ "Elf file contained a non-empty header that overlapped with another.\n"
                       ++ "  This is not supported by the Elf parser."

esiInstances :: ElfSizingInfo w -> (ElfWidthConstraints w => a) -> a
esiInstances = elfClassInstances . headerClass . header . esiHeaderInfo

-- | Generate a phdr from the given
phdrSegment :: Phdr w -> Seq.Seq (ElfDataRegion w) -> ElfSegment w
phdrSegment phdr regions =
  ElfSegment { elfSegmentType = phdrSegmentType phdr
             , elfSegmentFlags = phdrSegmentFlags phdr
             , elfSegmentIndex = phdrSegmentIndex phdr
             , elfSegmentVirtAddr = phdrSegmentVirtAddr phdr
             , elfSegmentPhysAddr = phdrSegmentPhysAddr phdr
             , elfSegmentAlign = phdrSegmentAlign phdr
             , elfSegmentMemSize = ElfAbsoluteSize (phdrMemSize phdr)
             , elfSegmentData = regions
             }

-- | Insert a segment/phdr into a sequence of elf regions, returning the new sequence.
insertSegment :: forall w
               . ElfSizingInfo w
              -> Seq.Seq (ElfDataRegion w) -- ^ Regions generated so far.
              -> Phdr w -- ^ New program header to add.
              -> GetResult (ElfParseError w) (Seq.Seq (ElfDataRegion w))
insertSegment esi segs phdr = esiInstances esi $ do
  let rng = phdrFileRange phdr
      szd = phdrFileSize  phdr
      -- | @gather@ inserts new segment into head of list after collecting existings
      -- data it contains.
      gather :: Integral (ElfWordType w)
             => ElfWordType w -- ^ Number of bytes to insert.
             -> Seq.Seq (ElfDataRegion w)
                -- ^ Subsegments that occur before this segment.
             -> Seq.Seq (ElfDataRegion w)
                -- ^ Segments after insertion point.
             -> Seq.Seq (ElfDataRegion w)
      -- Gather the segment if it fits (this is before the 0 byte case
      -- to deal with 0-sized sections.
      gather cnt l r0
        | p Seq.:< r <- Seq.viewl r0
        , regionSize esi p <= cnt =
          gather (cnt - regionSize esi p) (l Seq.|> p) r
      -- Insert segment if there are 0 bytes left to process.
      gather 0 l r =
          ElfDataSegment (phdrSegment phdr l) Seq.<| r
      -- Collect p if it is contained within segment we are inserting.
      gather cnt l r0 =
          case Seq.viewl r0 of
            p Seq.:< r
                -- Split raw bytes into contiguous segments.
              | ElfDataRaw b <- p ->
                  let pref = B.take (fromIntegral cnt) b
                      post = B.drop (fromIntegral cnt) b
                      newData = l Seq.>< insertRawRegion pref Seq.empty
                      d' = phdrSegment phdr newData
                   in ElfDataSegment d' Seq.<| insertRawRegion post r
              | otherwise ->
                error $ "insertSegment: Inserted segments overlaps a previous segment.\n"
                     ++ "  Previous segment: " ++ show p ++ "\n"
                     ++ "  Previous segment size: " ++ show (regionSize esi p) ++ "\n"
                     ++ "  New segment index: " ++ show (phdrSegmentIndex phdr) ++ "\n"
                     ++ "  Remaining bytes: " ++ show cnt
            Seq.EmptyL -> error "insertSegment: Data ended before completion"
  -- TODO: See if we can do better than dropping the segment.
  mapError (ElfInsertError ("segment" ++ show (phdrSegmentIndex phdr))) $
    insertAtOffset esi (\_ -> gather szd Seq.empty) rng segs

-- | Get list of sections from Elf parse info.
-- This includes the initial section
getSectionTable :: forall w . ElfHeaderInfo w -> V.Vector (ElfSection (ElfWordType w))
getSectionTable ehi = V.generate cnt $ getSection
  where cnt = fromIntegral (entryNum (shdrTable ehi)) :: Int

        c = headerClass (header ehi)

        -- Return range used to store name index.
        names :: B.ByteString
        names = snd $ nameSectionInfo ehi

        getSection :: Int -> ElfSection (ElfWordType w)
        getSection i = elfClassInstances c $
          snd $ getSection' ehi (Just names) (fromIntegral i)

isSymtabSection :: ElfSection w -> Bool
isSymtabSection s
  =  elfSectionName s == ".symtab"
  && elfSectionType s == SHT_SYMTAB


-- | Parse the section as a list of symbol table entries.
getSymbolTableEntries :: ElfHeader w
                      -> V.Vector (Range (ElfWordType w), ElfSection (ElfWordType w))
                      -> ElfSection (ElfWordType w)
                      -> Either String [ElfSymbolTableEntry (ElfWordType w)]
getSymbolTableEntries hdr sections s = do
  let link   = elfSectionLink s

  strtab <- if 0 <= link && link < fromIntegral (V.length sections) then
              Right $ elfSectionData (snd (sections V.! fromIntegral link))
             else
              Left "Could not find section string table."
  let getEntry = getSymbolTableEntry (headerClass hdr) (headerData hdr) strtab
  runGetMany getEntry (L.fromChunks [elfSectionData s])


-- | This returns an elf from the header information along with and
-- errors that occured when generating it.
getElf :: forall w
       .  ElfHeaderInfo w
       -> ([ElfParseError w], Elf w)
getElf ehi = elfClassInstances (headerClass (header ehi)) $ errorPair $ do
  let phdrs = rawSegments ehi
  let -- Return range used to store name index.
      nameRange :: Range (ElfWordType w)
      nameRange = fst $ nameSectionInfo ehi

  let section_cnt :: Word16
      section_cnt = entryNum $ shdrTable ehi

  let section_names = slice nameRange $ fileContents ehi

      -- Get vector with section information
  let section_vec :: V.Vector (Range (ElfWordType w), ElfSection (ElfWordType w))
      section_vec = V.generate (fromIntegral section_cnt) $
        getSection' ehi (Just section_names) . fromIntegral

  let msymtab :: Maybe (Range (ElfWordType w), ElfSection (ElfWordType w))
      msymtab = V.find (\(_,s) -> isSymtabSection s) section_vec

  let mstrtab_index  = elfSectionLink . snd <$> msymtab

      -- Return size of section at given index.
  let section_size :: Word32 -> ElfWordType w
      section_size i =
        case section_vec V.!? fromIntegral i of
          Just ((_,n),_) -> n
          Nothing -> 0

      -- Get information needed to compute region sizes.
  let esi_size :: ElfWordType w
      esi_size = maybe 0 section_size mstrtab_index

  let esi = ElfSizingInfo { esiHeaderInfo = ehi
                          , esiSectionNameTableSize = snd nameRange
                          , esiStrtabSize = esi_size
                          }

      -- Define table with special data regions.
  let headers :: [(Range (ElfWordType w), String, ElfDataRegion w)]
      headers = [ ((0, fromIntegral (ehdrSize ehi)), "file header"
                  , ElfDataElfHeader)
                , (tableRange (phdrTable ehi), "program header table"
                  , ElfDataSegmentHeaders)
                , (tableRange (shdrTable ehi), "section header table"
                  , ElfDataSectionHeaders)
                , (nameRange,                  ".shstrtab"
                  , ElfDataSectionNameTable (shdrNameIdx ehi))
                ]

      -- Get list of all sections other than the first section (which is skipped)
  let sections :: [(Range (ElfWordType w), ElfSection (ElfWordType w))]
      sections = fmap (\i -> section_vec V.! fromIntegral i)
               $ filter (\i -> i /= shdrNameIdx ehi && i /= 0)
               $ enumCnt 0 section_cnt

      -- Define table with regions for sections.
      -- TODO: Modify this so that it correctly recognizes the GOT section
      -- and generate the appropriate type.
  let dataSection :: ElfSection (ElfWordType w)
                  -> GetResult (ElfParseError w) (ElfDataRegion w)
      dataSection s
          | Just (fromIntegral (elfSectionIndex s)) == mstrtab_index
          , elfSectionName s == ".strtab"
          , elfSectionType s == SHT_STRTAB =
            pure $ ElfDataStrtab (elfSectionIndex s)
          | isSymtabSection s =
              case getSymbolTableEntries (header ehi) section_vec s of
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


  let initSeq = insertRawRegion (fileContents ehi) Seq.empty

  let insertSection :: (Range (ElfWordType w), ElfSection (ElfWordType w))
                    -> Seq.Seq (ElfDataRegion w)
                    -> GetResult (ElfParseError w) (Seq.Seq (ElfDataRegion w))
      insertSection (rgn, sec) segs = do
        reg <- dataSection sec
        insertSpecialRegion esi (BSC.unpack (elfSectionName sec)) rgn reg segs
  s <- foldrM insertSection initSeq sections
  -- Define initial region list without program headers.

  let insertRegion :: (Range (ElfWordType w), String, ElfDataRegion w)
                   -> Seq.Seq (ElfDataRegion w)
                   -> GetResult (ElfParseError w) (Seq.Seq (ElfDataRegion w))
      insertRegion (r, nm, n) segs = insertSpecialRegion esi nm r n segs
  postHeaders <- foldrM insertRegion s headers

  -- Do relro processing

  -- Partition headers based on different types.
  let (loadPhdrs,  phdrs1)       = partition (hasSegmentType PT_LOAD)      phdrs
  let (stackPhdrs, phdrs2)       = partition (hasSegmentType PT_GNU_STACK) phdrs1
  let (relroPhdrs, unclassPhdrs) = partition (hasSegmentType PT_GNU_RELRO) phdrs2

  -- Create segment sequence for segments that are PT_LOAD or classified
  dta <- foldlM (insertSegment esi) postHeaders (loadPhdrs ++ unclassPhdrs)

  -- Parse PT_GNU_STACK phdrs
  anyGnuStack <-
    case stackPhdrs of
      [] -> pure Nothing
      (stackPhdr:r) -> do
        let flags = phdrSegmentFlags stackPhdr

        unless (null r) $ gnuStackWarning "Multiple GNU stack segments; choosing first."
        when ((flags .&. complement pf_x) /= (pf_r .|. pf_w)) $ do
          gnuStackWarning $ "Unexpected flags: " ++ show flags

        let isExec = (flags .&. pf_x) == pf_x
        let gnuStack = GnuStack { gnuStackSegmentIndex = phdrSegmentIndex stackPhdr
                                , gnuStackIsExecutable = isExec
                                }
        pure $ Just gnuStack

  -- Parse PT_GNU_RELRO phdrs
  relroRegions <- do
    let loadMap = Map.fromList [ (phdrFileStart p, phdrSegmentIndex p) | p <- loadPhdrs ]
    catMaybes <$> traverse (asRelroRegion loadMap) relroPhdrs

  -- Create final elf file.
  pure $! Elf { elfData       = headerData       (header ehi)
              , elfClass      = headerClass      (header ehi)
              , elfOSABI      = headerOSABI      (header ehi)
              , elfABIVersion = headerABIVersion (header ehi)
              , elfType       = headerType       (header ehi)
              , elfMachine    = headerMachine    (header ehi)
              , elfEntry      = headerEntry      (header ehi)
              , elfFlags      = headerFlags      (header ehi)
              , _elfFileData  = dta
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

-- | Wraps a either a 32-bit or 64-bit typed value.
data SomeElf f
   = Elf32 (f 32)
   | Elf64 (f 64)

parseElfResult :: Either (L.ByteString, ByteOffset, String) (L.ByteString, ByteOffset, a)
               -> Either (ByteOffset,String) a
parseElfResult (Left (_,o,e)) = Left (o,e)
parseElfResult (Right (_,_,v)) = Right v

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
   = Elf32Res !([ElfParseError 32]) (Elf 32)
   | Elf64Res !([ElfParseError 64]) (Elf 64)
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
