{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}

module Data.ElfEdit.HighLevel.Get
  ( -- Elf parsing
    getElf
  , parseElf
  , ElfGetResult(..)
  , ElfParseError(..)
    -- * Section translation
  , headerSections
  ) where

import           Control.Monad
import qualified Control.Monad.State.Strict as MTL
import qualified Data.Binary.Get as Get
import           Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BSC
import           Data.Foldable
import           Data.List (partition, sortBy)
import           Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import           Data.Maybe
import qualified Data.Sequence as Seq
import qualified Data.Vector as V
import           Data.Word
import           GHC.Stack
import           Numeric (showHex)

import           Data.ElfEdit.HighLevel.Sections
import           Data.ElfEdit.HighLevel.Types
import           Data.ElfEdit.Prim
import           Data.ElfEdit.Utils (enumCnt)

------------------------------------------------------------------------
-- Utilities

-- | @revApp x y@ returns the list @reverse x ++ y@.
revApp :: [a] -> [a] -> [a]
revApp [] r = r
revApp (h:l) r = revApp l $! seq h (h:r)

------------------------------------------------------------------------
-- ElfParseError

-- | A parse error
data ElfParseError
  = SymtabError !SymtabError
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
  showsPrec _ (SymtabError msg) =
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
-- Shdr lifting

transShdr :: Integral w
          => B.ByteString -- ^ Contents fof file.
          -> B.ByteString -- ^ String table for sectionnames
          -> Word16 -- ^ Index of section
          -> Shdr Word32 w
          -> Either String (FileRange w, ElfSection w)
transShdr file strtab idx shdr = do
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
  seq s $ pure (shdrFileRange shdr, s)

-- | Get list of sections from Elf parse info.
-- This includes the initial section
--
-- Note. this may call `error`
headerSections :: ElfHeaderInfo w
               -> V.Vector (FileRange (ElfWordType w), ElfSection (ElfWordType w))
headerSections ehi = V.imap getSectionByIndex (headerShdrs ehi)
  where -- Return range used to store name index.
        strtab :: B.ByteString
        (_, strtab) = shstrtabRangeAndData ehi

        getSectionByIndex i shdr = elfClassInstances (headerClass (header ehi)) $
          case transShdr (headerFileContents ehi) strtab (fromIntegral i) shdr of
            Left e -> error e
            Right p -> p

-- | Return section and file offset and size.
getSectionAndRange :: HasCallStack
                   => ElfHeaderInfo w
                   -> B.ByteString -- ^ String table
                   -> Word16 -- ^ Index of section.
                   -> (FileRange (ElfWordType w), ElfSection (ElfWordType w))
getSectionAndRange ehi strtab i = elfClassInstances (headerClass (header ehi)) $
  case transShdr (headerFileContents ehi) strtab i (shdrByIndex ehi i) of
    Left e -> error e
    Right p -> p

------------------------------------------------------------------------
-- Phdr lifting

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
warn e = seq e $ GetResult $ MTL.modify' (e:)

------------------------------------------------------------------------
-- CollectedRegion

-- | Maps each offset in the file to the contents that begin at that region.
data CollectedRegion w
   = AtomicRegion !B.ByteString !(FileOffset (ElfWordType w)) !(FileOffset (ElfWordType w)) !(ElfDataRegion w)
     -- ^ A region with the name, start offset, one past the end, and contents.
   | SegmentRegion !(Phdr w) ![CollectedRegion w]
     -- ^ A Program header and additional regions.

-- | Return the starting offset of the region
roFileOffset :: CollectedRegion w -> FileOffset (ElfWordType w)
roFileOffset (AtomicRegion _ o _ _) = o
roFileOffset (SegmentRegion phdr _) = phdrFileStart phdr

-- | @roEnd r@ returns the offset at the end of the file.
roEnd :: Num (ElfWordType w) => CollectedRegion w -> FileOffset (ElfWordType w)
roEnd (AtomicRegion _ _ e _) = e
roEnd (SegmentRegion phdr _)  = phdrFileStart phdr `incOffset` phdrFileSize phdr

atomicRO :: (Num (ElfWordType w), Ord (ElfWordType w))
         => B.ByteString
         -> FileOffset (ElfWordType w)
         -> ElfWordType w
         -> ElfDataRegion w
         -> CollectedRegion w
atomicRO nm o sz r
  | o `incOffset` sz < o = error $ "atomicRO: Overflow for computing end of " ++ BSC.unpack nm
  | otherwise = AtomicRegion nm o (o `incOffset` sz) r

segmentRO :: (Num (ElfWordType w), Ord (ElfWordType w))
          => Phdr w -> [CollectedRegion w] -> CollectedRegion w
segmentRO phdr inner
  | o <- fromFileOffset (phdrFileStart phdr)
  , sz <- phdrFileSize phdr
  , o + sz < o = error $ "segmentRO: Overflow for computing end of segment " ++ show (phdrSegmentIndex phdr)
  | otherwise = SegmentRegion phdr inner

--------------------------------------------------------------------------------
-- CollectedRegionList

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
  | roEnd p <= (phdrFileStart phdr `incOffset` phdrFileSize phdr) =
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


insertSegment' :: Integral (ElfWordType w)
               => [CollectedRegion w] -- ^ Processed regions in reverse order
               -> Phdr w -- ^ Region to insert
               -> CollectedRegionList w -- ^ Remaining regions
               -> CollectedRegionList w
insertSegment' prev phdr (CRL (p:rest))
  -- If offset is after end of next segment, then just go to next segment.
  | phdrFileStart phdr > roFileOffset p = do
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

insertNewRegion' :: (Ord (ElfWordType w), Num (ElfWordType w))
                 => [CollectedRegion w] -- ^ Processed regions in reverse order
                 -> B.ByteString -- ^ Name of this region
                 -> FileOffset (ElfWordType w) -- ^ File offset
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
                -> FileOffset (ElfWordType w) -- ^ File offset
                -> ElfWordType w -- ^ File size
                -> ElfDataRegion w -- ^ Region to insert
                -> CollectedRegionList w
                -> CollectedRegionList w
insertNewRegion = insertNewRegion' []

--------------------------------------------------------------------------------
-- SizedRegions

-- | Information about collected regions
data SizedRegions w
  = SizedRegions
  { sizedRegions :: !(Seq.Seq (ElfDataRegion w))
    -- ^ The regions added so far in the current segment or the overall file.
  , sizedLength :: !Int
    -- ^ The total number of bytes in the regions passed so far.
    --
    -- Note. This may be larger than the sum of the size of regions when we are
    -- inside a segment due to padding.
  }

appendSizedRegion :: SizedRegions w -> ElfDataRegion w -> Int -> SizedRegions w
appendSizedRegion sr r sz =
  SizedRegions { sizedRegions = sizedRegions sr Seq.|> r
               , sizedLength  = sizedLength  sr + sz
               }

addPadding :: Integral (ElfWordType w)
           => B.ByteString
           -> Int
           -> FileOffset (ElfWordType w) -- ^ New offset
           -> SizedRegions w
           -> SizedRegions w
addPadding contents endOff nextOff sr
   | B.length b > 0 = appendSizedRegion sr (ElfDataRaw b) (B.length b)
   | otherwise = sr
  where b = B.take (fromIntegral nextOff-endOff) (B.drop endOff contents)

--------------------------------------------------------------------------------
-- mkSequence

phdrName :: Phdr w -> String
phdrName phdr = "segment" ++ show (phdrSegmentIndex phdr)

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
      let sz = fromFileOffset (e-o)
      let padded = addPadding contents endOff o sr
      -- Get computed offset from length of data added so far.
      let actualOff = sizedLength padded
      -- Check region is non-empty
      let isNonEmpty = e > 0
      -- Warn when actual offset is later and region is non-empty
      when (actualOff > fromIntegral o && isNonEmpty) $ do
        warn $ OverlapMovedLater (BSC.unpack nm) actualOff (toInteger o)
      -- Append data to region and continue
      let cur = appendSizedRegion padded reg (fromIntegral sz)
      mkSequence' contents cur (max endOff (fromIntegral e)) rest
    SegmentRegion phdr inner -> do
     let o  = phdrFileStart phdr
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

-- | Create a sequence of data regions from the collected regions
mkSequence :: ElfWidthConstraints w
           => B.ByteString
           -> CollectedRegionList w
           -> GetResult (Seq.Seq (ElfDataRegion w))
mkSequence contents (CRL l) = do
  let sr = SizedRegions Seq.empty 0
  sizedRegions <$> mkSequence' contents sr 0 l

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

--------------------------------------------------------------------------------
-- getElf

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
  let hdr = header ehi
  let cl = headerClass hdr
  let dta = headerData hdr
  let phdrs = headerPhdrs ehi
  -- Return range used to store name index.
  let (nameRange, sectionNames) = shstrtabRangeAndData ehi

  let sectionCnt :: Word16
      sectionCnt = shdrCount ehi

      -- Get vector with section information
  let sectionVec :: V.Vector (FileRange (ElfWordType w), ElfSection (ElfWordType w))
      sectionVec = V.generate (fromIntegral sectionCnt) $
        getSectionAndRange ehi sectionNames . fromIntegral

  let msymtab :: Maybe (FileRange (ElfWordType w), ElfSection (ElfWordType w))
      msymtab = V.find (\(_,s) -> isSymtabSection s) sectionVec

  let mstrtab_index  = elfSectionLink . snd <$> msymtab

  -- Define initial region list without program headers.
  let postHeaders =
        -- Define table with special data regions.
        let headers :: [(FileRange (ElfWordType w), B.ByteString, ElfDataRegion w)]
            headers = [ ((0, fromIntegral (ehdrSize cl)), "file header"
                        , ElfDataElfHeader)
                      , (phdrTableRange ehi, "program header table"
                        , ElfDataSegmentHeaders)
                      , (shdrTableRange ehi, "section header table"
                        , ElfDataSectionHeaders)
                      , (nameRange,                  ".shstrtab"
                        , ElfDataSectionNameTable (shstrtabIndex ehi))
                      ]
            insertRegion :: CollectedRegionList w
                         -> (FileRange (ElfWordType w), BSC.ByteString, ElfDataRegion w)
                         -> CollectedRegionList w
            insertRegion l ((o,c), nm, n) =
              insertNewRegion nm o c n l
        in foldl' insertRegion (CRL []) headers

  postSections <- do
    -- Get list of all sections other than the first section (which is skipped)
    let sections :: [(FileRange (ElfWordType w), ElfSection (ElfWordType w))]
        sections = fmap (\i -> sectionVec V.! fromIntegral i)
                   $ filter (\i -> i /= shstrtabIndex ehi && i /= 0)
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
                  warn (SymtabError (InvalidLink (elfSectionLink s)))
                  pure (ElfDataSection s)
                Just (_, strtab) -> do
                  let strtabData = elfSectionData strtab
                  case decodeSymtab cl dta strtabData (elfSectionData s) of
                    Left msg -> do
                      warn (SymtabError msg)
                      pure (ElfDataSection s)
                    Right entries -> do
                      let symtab =
                            Symtab { symtabEntries = entries
                                   , symtabLocalCount = elfSectionInfo s
                                   }
                      pure $ ElfDataSymtab (elfSectionIndex s) symtab
          | otherwise =
              pure $ ElfDataSection s
    let insertSection :: CollectedRegionList w
                      -> (FileRange (ElfWordType w), ElfSection (ElfWordType w))
                      -> GetResult (CollectedRegionList w)
        insertSection l ((o,c), sec) = do
          reg <- dataSection sec
          pure $! insertNewRegion (elfSectionName sec) o c reg l
    foldlM insertSection postHeaders sections

  -- Do relro processing

  -- Partition headers based on different types.
  let (loadPhdrs,  phdrs1)       = partition (phdrHasType PT_LOAD)      phdrs
  let (stackPhdrs, phdrs2)       = partition (phdrHasType PT_GNU_STACK) phdrs1
  let (relroPhdrs, unclassPhdrs) = partition (phdrHasType PT_GNU_RELRO) phdrs2

  -- Create segment sequence for segments that are PT_LOAD or not one
  -- of the special ones.
  let colRegions =
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

  fileD <- mkSequence (headerFileContents ehi) colRegions

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

--------------------------------------------------------------------------------
-- parseElf

data ElfGetResult
   = Elf32Res ![ElfParseError] (Elf 32)
   | Elf64Res ![ElfParseError] (Elf 64)
   | ElfHeaderError !Get.ByteOffset !String
     -- ^ Attempt to parse header failed.
     --
     -- First argument is byte offset, second is string.

-- | Parses a ByteString into an Elf record. Parse failures call error. 32-bit ELF objects hav
-- their fields promoted to 64-bit so that the 32- and 64-bit ELF records can be the same.
parseElf :: B.ByteString -> ElfGetResult
parseElf b =
  case decodeElfHeaderInfo b of
    Left (o, m) -> ElfHeaderError o m
    Right (SomeElf hdr) ->
        case headerClass (header hdr) of
          ELFCLASS32 -> Elf32Res l e
          ELFCLASS64 -> Elf64Res l e
      where (l, e) = getElf hdr
