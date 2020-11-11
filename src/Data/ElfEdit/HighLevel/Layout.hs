{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE TemplateHaskell #-}
{-# OPTIONS_GHC -Wwarn #-}
module Data.ElfEdit.HighLevel.Layout
  ( renderElf
  , elfSections
  , updateSections
  , traverseElfDataRegions
  , traverseElfSegments
  , elfRegionFileSize
  ) where

import           Control.Lens hiding (enum)
import           Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Builder as Bld
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy as L
import           Data.Foldable
import           Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import           Data.Maybe
import qualified Data.Sequence as Seq
import qualified Data.Vector as V
import           Data.Word
import           Numeric

import           Data.ElfEdit.HighLevel.GOT
import           Data.ElfEdit.HighLevel.Sections
import           Data.ElfEdit.HighLevel.Types
import           Data.ElfEdit.Prim

-- | Traverse elements in a list and modify or delete them.
updateSeq :: Traversal (Seq.Seq a) (Seq.Seq b) a (Maybe b)
updateSeq f l0 =
  case Seq.viewl l0 of
    Seq.EmptyL -> pure Seq.empty
    h Seq.:< l -> compose <$> f h <*> updateSeq f l
      where compose Nothing  r = r
            compose (Just e) r = e Seq.<| r

$(pure [])

-- | Traverse segments in an ELF file and modify or delete them
updateSegments :: forall w f
               . Monad f
               => (ElfSegment w -> f (Maybe (ElfSegment w)))
               -> Elf w
               -> f (Elf w)
updateSegments fn = elfFileData (updateSeq impl)
  where
    impl (ElfDataSegment seg) =
      let inner = updateSeq impl (elfSegmentData seg)
          updateData s d = s { elfSegmentData = d }
          newSeg :: f (Maybe (ElfSegment w))
          newSeg = fn =<< (fmap (updateData seg) inner)
      in fmap ElfDataSegment <$> newSeg
    impl d = pure (Just d)

-- | Traverse elf segments other than `PT_GNU_RELRO` and `PT_GNU_STACK`.
traverseElfSegments :: Monad f => (ElfSegment w -> f (ElfSegment w)) -> Elf w -> f (Elf w)
traverseElfSegments f = updateSegments (fmap Just . f)

-- | Traverse the data regions in an ELF file and modify or delete them
updateDataRegions :: forall w f
                  .  Monad f
                  => (ElfDataRegion w -> f (Maybe (ElfDataRegion w)))
                  -> Elf w
                  -> f (Elf w)
updateDataRegions fn = elfFileData (updateSeq impl)
  where
    impl (ElfDataSegment seg) =
      let inner = updateSeq impl (elfSegmentData seg)
          updateData s d = s { elfSegmentData = d }
      in fmap (updateData seg) inner >>= (fn . ElfDataSegment)
    impl d = fn d

-- | Traverse all data regions including nested.
traverseElfDataRegions :: Monad f
                       => (ElfDataRegion w -> f (ElfDataRegion w))
                       -> Elf w
                       -> f (Elf w)
traverseElfDataRegions f = updateDataRegions (fmap Just . f)

$(pure [])

-- | Return name of all elf sections.
elfSectionNames :: forall w . Elf w -> [B.ByteString]
elfSectionNames e = concatMap regionNames (toList (e^.elfFileData))
  where regionNames :: ElfDataRegion w -> [B.ByteString]
        regionNames (ElfDataSegment s) =
          concatMap regionNames (toList (elfSegmentData s))
        regionNames (ElfDataSectionNameTable _) = [".shstrtab"]
        regionNames (ElfDataGOT g)              = [elfGotName g]
        regionNames (ElfDataStrtab _)           = [".strtab"]
        regionNames (ElfDataSymtab _ _)         = [".symtab"]
        regionNames (ElfDataSection s)          = [elfSectionName s]
        regionNames _                           = []

$(pure [])

------------------------------------------------------------------------
-- elfSectionAsGOT

-- | Create a section for a string table.
strtabSection :: Num w
              => B.ByteString
                 -- ^ Name of section
              -> Word16
                 -- ^ Index of section
              -> B.ByteString
                 -- ^ Data for name information
              -> ElfSection w
strtabSection name idx nameData =
  ElfSection {
      elfSectionIndex = idx
    , elfSectionName = name
    , elfSectionType = SHT_STRTAB
    , elfSectionFlags = shf_none
    , elfSectionAddr = 0
    , elfSectionSize = fromIntegral (B.length nameData)
    , elfSectionLink = 0
    , elfSectionInfo = 0
    , elfSectionAddrAlign = 1
    , elfSectionEntSize = 0
    , elfSectionData = nameData
    }

------------------------------------------------------------------------
-- Section traversal

-- This does some rendering to replace special sections with generic
-- ones.

-- | Traverse sections in Elf file and modify or delete them.
updateSections :: Traversal (Elf w)
                            (Elf w)
                            (ElfSection (ElfWordType w))
                            (Maybe (ElfSection (ElfWordType w)))
updateSections fn0 e0 = elfClassInstances (elfClass e0) $ elfFileData (updateSeq (impl fn0)) e0
  where t = fst $ encodeStringTable $ elfSectionNames e0
        norm :: ElfWidthConstraints w => ElfSection (ElfWordType w) -> ElfDataRegion w
        norm s
          | elfSectionName s == ".shstrtab" = ElfDataSectionNameTable (elfSectionIndex s)
          | elfSectionName s `elem` [".got", ".got.plt"] =
            case elfSectionAsGOT s of
              Left e -> error $ "Error in Data.ElfEdit.updateSections: " ++ e
              Right v -> ElfDataGOT v
          | otherwise = ElfDataSection s

        impl :: (Applicative f, ElfWidthConstraints w)
             => (ElfSection (ElfWordType w) -> f (Maybe (ElfSection (ElfWordType w))))
             -> ElfDataRegion w
             -> f (Maybe (ElfDataRegion w))
        impl fn (ElfDataSegment s) = fix <$> updateSeq (impl fn) (elfSegmentData s)
          where fix d = Just $ ElfDataSegment $ s { elfSegmentData = d }
        impl fn (ElfDataSectionNameTable idx) = fmap norm <$> fn (strtabSection ".shstrtab" idx t)
        impl fn (ElfDataGOT g) = fmap norm <$> fn (elfGotSection g)
        impl fn (ElfDataSection s) = fmap norm <$> fn s
        impl _  d = pure (Just d)

$(pure [])

-- | Traverse elf sections
elfSections :: Simple Traversal (Elf w) (ElfSection (ElfWordType w))
elfSections f = updateSections (fmap Just . f)

$(pure [])

------------------------------------------------------------------------
-- Utilities

rangeSize :: (Ord w, Num w) => FileOffset w -> FileOffset w -> w
rangeSize (FileOffset s) (FileOffset e)
  | e >= s = e - s
  | otherwise = error "Negative range"

--------------------------------------------------------------------------------
-- ElfSection

-- | Make a section header
mkShdr :: ElfSection w
       -> Word32 -- ^ Offset for name
       -> FileOffset w -- ^ File offset
       -> Shdr Word32 w
mkShdr s n o = Shdr { shdrName = n
                    , shdrType = elfSectionType s
                    , shdrFlags = elfSectionFlags s
                    , shdrAddr = elfSectionAddr s
                    , shdrOff  = o
                    , shdrSize = elfSectionSize s
                    , shdrLink = elfSectionLink s
                    , shdrInfo = elfSectionInfo s
                    , shdrAddrAlign = elfSectionAddrAlign s
                    , shdrEntSize = elfSectionEntSize s
                    }

-- | @sectionContents o s inLoad@ computes the contents and size of a section
-- for rendering.
--
-- It is allowed to add padding as needed to ensure the alignment constraint is
-- satisfied if the section is not loadable and non-empty.
sectionContents :: (Bits o, Integral o)
                => FileOffset o
                -> ElfSection o
                -> Bool -- ^ Flag indicating if section is inside loadable segment.
                -> (Bld.Builder, o)
sectionContents o s inLoad
  | not (B.null (elfSectionData s))
  , inLoad
  , not (isAligned o (elfSectionAddrAlign s)) =
    error "sectionContents out of alignment."
  | B.null (elfSectionData s) = (mempty, 0)
  | otherwise =
    let o' = alignFileOffset (elfSectionAddrAlign s) o
        paddingCnt = fromFileOffset o' - fromFileOffset o
        dta = elfSectionData s
     in ( Bld.byteString (B.replicate (fromIntegral paddingCnt) 0) <> Bld.byteString dta
        , paddingCnt + fromIntegral (B.length dta)
        )

------------------------------------------------------------------------
-- Special sections

-- | Create an elf section for symbol table and string table of symbol names.
symtabSection :: ElfClass w
              -> ElfData
              -> Map B.ByteString Word32
              -> Word16 -- ^ Index of string table for symbol names
              -> Word16 -- ^ Index of symbol table section header
              -> Symtab w -- ^ The symbol table
              -> ElfSection (ElfWordType w)
symtabSection cl d nameMap thisStrtabIdx symtabShdrIndex symtab = sec
  where nameFn nm =
          case Map.lookup nm nameMap of
            Just nameIdx -> nameIdx
            Nothing -> error "internal: symtabData given undefined symbol name."
        encodeSym s = encodeSymtabEntry cl d (s { steName = nameFn (steName s) })
        bld = mconcat $ V.toList $ encodeSym <$> symtabEntries symtab
        dta = L.toStrict $ Bld.toLazyByteString bld
        sec = elfClassInstances cl $
            ElfSection { elfSectionIndex = symtabShdrIndex
                       , elfSectionName  = ".symtab"
                       , elfSectionType  = SHT_SYMTAB
                       , elfSectionFlags = shf_none
                       , elfSectionAddr  = 0
                       , elfSectionSize  = fromIntegral (B.length dta)
                       , elfSectionLink  = fromIntegral thisStrtabIdx
                       , elfSectionInfo  = symtabLocalCount symtab
                       , elfSectionAddrAlign = symtabAlign cl
                       , elfSectionEntSize = fromIntegral (symtabEntrySize cl)
                       , elfSectionData = dta
                       }

------------------------------------------------------------------------
-- ElfLayout

-- | This maintains information about the layout of an elf file.
--
-- It can be used when constructing an Elf file to obtain precise
-- control over the layout so that alignment restrictions are maintained.
data ElfLayout w = ElfLayout {
        elfLayoutHeader :: !(ElfHeader w)
        -- ^ Header information for elf file
      , elfLayoutRegions :: !(Seq.Seq (ElfDataRegion w))
        -- ^ Data regions from elf file
      , elfLayoutPhdrCount :: ElfWordType w
        -- ^ Number of program headers
      , elfLayoutShdrCount :: ElfWordType w
        -- ^ Number of section headers
      , elfLayoutSectionNameData :: !B.ByteString
        -- ^ Contents of section name table data.
      , elfLayoutSectionNameOffsets :: !(Map B.ByteString Word32)
        -- ^ Map from each section name to offset where it is stored.
      , strtab_idx :: !Word16
        -- ^ Index of strtab (or 'Nothing' if not defined).
        --
        -- This is assigned by inspecting the 'ElfDataStrtab' entry.
      , strtab_data :: !B.ByteString
        -- ^ Data for elf string table (or empt if not assigned)
      , strtab_map :: !(Map B.ByteString Word32)
        -- ^ Maps bytestrings to associated index.
      , _elfOutputSize :: !(FileOffset (ElfWordType w))
        -- ^ Elf output size
      , _phdrTableOffset :: !(FileOffset (ElfWordType w))
        -- ^ Offset to phdr table.
      , _phdrs :: !(Map Word16 (Phdr w))
        -- ^ Map from phdr index to phdr.
        --
        -- Once the layout has been generated there should be an
        -- entry for each index from '0' to the number of phdrs minus one.
      , _shdrTableOffset :: !(FileOffset (ElfWordType w))
        -- ^ Offset to section header table.
      , _shstrndx :: !Word16
        -- ^ Index of section for string table.
      , _shdrs :: !(Map Word16 (Shdr Word32 (ElfWordType w)))
        -- ^ Map each section index to the section header entry for that section.
      }

elfLayoutClass :: ElfLayout w -> ElfClass w
elfLayoutClass = headerClass . elfLayoutHeader

elfLayoutData :: ElfLayout w -> ElfData
elfLayoutData = headerData . elfLayoutHeader

-- | Lens containing size of sections processed so far in layout.
elfOutputSize :: Simple Lens (ElfLayout w) (FileOffset (ElfWordType w))
elfOutputSize = lens _elfOutputSize (\s v -> s { _elfOutputSize = v })

-- | Get ehdr from elf layout
layoutEhdr :: ElfLayout w -> Ehdr w
layoutEhdr l = Ehdr { ehdrHeader   = elfLayoutHeader l
                    , ehdrPhoff    = l^.phdrTableOffset
                    , ehdrShoff    = l^.shdrTableOffset
                    , ehdrPhnum    = phnum l
                    , ehdrShnum    = shnum l
                    , ehdrShstrndx = l^.shstrndx
                    }

phdrTableOffset :: Simple Lens (ElfLayout w) (FileOffset (ElfWordType w))
phdrTableOffset = lens _phdrTableOffset (\s v -> s { _phdrTableOffset = v })

phdrs :: Simple Lens (ElfLayout w) (Map Word16 (Phdr w))
phdrs = lens _phdrs (\s v -> s { _phdrs = v })

shdrTableOffset :: Simple Lens (ElfLayout w) (FileOffset (ElfWordType w))
shdrTableOffset = lens _shdrTableOffset (\s v -> s { _shdrTableOffset = v })

shstrndx :: Simple Lens (ElfLayout w) Word16
shstrndx = lens _shstrndx (\s v -> s { _shstrndx = v })

shdrs :: Simple Lens (ElfLayout w) (Map Word16 (Shdr Word32 (ElfWordType w)))
shdrs = lens _shdrs (\s v -> s { _shdrs = v })

allPhdrs :: ElfLayout w -> [Phdr w]
allPhdrs l = Map.elems (l^.phdrs)

-- | Returns number of segments in layout.
phnum :: ElfLayout w -> Word16
phnum l | r < 0 || r > 65536 = error "Number of segments is too large."
        | otherwise          = fromIntegral r
  where r = Map.size (l^.phdrs)

-- | Return number of sections in layout.
shnum :: ElfLayout w -> Word16
shnum l | r > 65536 = error "Number of sections is too large."
        | otherwise = fromIntegral r
  where r = Map.size $ l^.shdrs


-- | Increment output size
incOutputSize :: Num (ElfWordType w) => ElfWordType w -> ElfLayout w -> ElfLayout w
incOutputSize n l = l & elfOutputSize %~ (`incOffset` n)

------------------------------------------------------------------------
-- Adding to elf layout

-- | Add section information to layout.
-- This may call an erorr if not defined.
addSectionToLayout :: ElfWidthConstraints w
                   => ElfLayout w
                   -> ElfSection (ElfWordType w)
                   -> Bool -- ^ Flag indicating if this section will be loaded.
                   -> ElfLayout w
addSectionToLayout l s inLoad
  | align <- elfSectionAddrAlign s
  , not (B.null (elfSectionData s)) &&  (elfSectionAddr s .&. (align - 1)) /= 0 =
      error $ BSC.unpack (elfSectionName s)
          ++ " address of 0x" ++ showHex (elfSectionAddr s) ""
          ++ " does not respect the alignment of 0x" ++ showHex align "."
    -- If section is non-empty and file offset is not aligned, then fail.
  | not (B.null (elfSectionData s))
  , inLoad
  , not (isAligned (l^.elfOutputSize) (elfSectionAddrAlign s)) =
      error $ "Section " ++ show (elfSectionName s) ++ " is in a loadable segment and not aligned."
    -- Report error is section index already defined.
  | Map.member (elfSectionIndex s) (l^.shdrs) =
      error $ "Section index " ++ show (elfSectionIndex s) ++ " already exists; cannot add "
      ++ show (elfSectionName s) ++ "."
  | otherwise =
    let alignedOff
          | inLoad || B.null (elfSectionData s) = fileOff
          | otherwise = alignFileOffset (elfSectionAddrAlign s) fileOff
        Just no = Map.lookup (elfSectionName s) (elfLayoutSectionNameOffsets l)
        fileOff =  l^.elfOutputSize
        idx = elfSectionIndex s
     in l & elfOutputSize .~ incOffset alignedOff (elfSectionFileSize s)
          & shdrs %~ Map.insert idx (mkShdr s no alignedOff)

addSectionHeadersToLayout :: ElfLayout w -> ElfLayout w
addSectionHeadersToLayout l = elfClassInstances  (elfLayoutClass l) $
   let cl = elfLayoutClass l
       shdrCnt = elfLayoutShdrCount l
       o' = alignFileOffset (shdrTableAlign cl) (l^.elfOutputSize)
       shdrTableSize = shdrCnt * fromIntegral (shdrEntrySize cl)
    in l & shdrTableOffset .~ o'
         & elfOutputSize   .~ incOffset o' shdrTableSize

addPhdrToLayout :: String -> ElfLayout w -> Phdr w -> ElfLayout w
addPhdrToLayout nm l phdr
  | Map.member (phdrSegmentIndex phdr) (l^.phdrs) =
      error $ nm ++ " " ++ show (phdrSegmentIndex phdr) ++ " already exists."
  | otherwise =
      l & phdrs %~ Map.insert (phdrSegmentIndex phdr) phdr

gnuRelroPhdr :: Num (ElfWordType w) => GnuRelroRegion w -> FileOffset (ElfWordType w) -> Phdr w
gnuRelroPhdr r foff =
  let thisIdx = relroSegmentIndex r
      vaddr = relroAddrStart r
   in Phdr { phdrSegmentIndex = thisIdx
           , phdrSegmentType  = PT_GNU_RELRO
           , phdrSegmentFlags = pf_r
           , phdrSegmentVirtAddr = vaddr
           , phdrSegmentPhysAddr = vaddr
           , phdrSegmentAlign = 1
           , phdrFileStart = foff
           , phdrFileSize  = relroSize r
           , phdrMemSize   = relroSize r
           }

addRelroToLayout :: ElfLayout w -> GnuRelroRegion w -> ElfLayout w
addRelroToLayout l r
  | otherwise = elfClassInstances (elfLayoutClass l) $ do
      let refIdx = relroRefSegmentIndex r
      case Map.lookup refIdx (l^.phdrs) of
        Nothing -> error $ "Error segment index " ++ show refIdx ++ " could not be found."
        Just refPhdr ->
          let vaddr = relroAddrStart r
              fstart = phdrFileStart refPhdr `incOffset` (vaddr - phdrSegmentVirtAddr refPhdr)
              phdr = gnuRelroPhdr r fstart
           in addPhdrToLayout "Relro segment index" l phdr

--------------------------------------------------------------------------------
-- ElfRegions

-- | This returns true if we can ignore the region file offset
-- alignment constraint as the size is zero.
regionOffsetIgnorable :: ElfDataRegion w -> Bool
regionOffsetIgnorable reg =
  case reg of
    ElfDataElfHeader -> False
    ElfDataSegmentHeaders -> False
    ElfDataSegment s  -> all regionOffsetIgnorable $ elfSegmentData s
    ElfDataSectionHeaders -> False
    ElfDataSectionNameTable _ -> False
    ElfDataGOT g              -> B.null (elfGotData g)
    ElfDataStrtab _           -> False
    ElfDataSymtab _ _         -> False
    ElfDataSection s          -> B.null (elfSectionData s)
    ElfDataRaw b              -> B.null b

-- | Render the given list of regions at a particular file offeset.
buildRegions :: forall w
             .  ElfWidthConstraints w
             => ElfLayout w
             -> FileOffset (ElfWordType w)
                -- ^ Current offset in file.
             -> [(ElfDataRegion w, Bool)]
                -- ^ List of regions to process next, and Bool that indicates if
                -- we are inside a loadable segment.
             -> Bld.Builder
buildRegions _ _ [] = mempty
buildRegions l o ((reg,inLoad):rest) = do
  let hdr = elfLayoutHeader l
  let cl = headerClass hdr
  let d = elfLayoutData l
  let doRest sz = buildRegions l (o `incOffset` sz) rest
  case reg of
    ElfDataElfHeader
      | o /= startOfFile ->
          error "buildRegions given elf header outside start of file."
      | otherwise ->
        encodeEhdr (layoutEhdr l)
        <> doRest (fromIntegral (ehdrSize cl))
    ElfDataSegmentHeaders
      | not (isAligned o (phdrTableAlign cl)) ->
          error $ "internal error: buildRegions phdr alignment check failed; Fix layoutRegion."
      | otherwise ->
          let phdrSize = fromIntegral (phnum l) * fromIntegral (phdrEntrySize cl)
           in encodePhdrTable cl d (allPhdrs l)
              <> buildRegions l (o `incOffset` phdrSize) rest
    ElfDataSegment s -> do
      buildRegions l o $ ((,True) <$> toList (elfSegmentData s)) ++ rest
    ElfDataSectionHeaders ->
      let o' = alignFileOffset (shdrTableAlign cl) o
          sz = fromIntegral (shnum l) * fromIntegral (shdrEntrySize cl)
       in Bld.byteString (B.replicate (fromIntegral (o' - o)) 0)
            <> encodeShdrTable (headerClass hdr) (headerData hdr) (Map.elems (l^.shdrs))
            <> buildRegions l (o' `incOffset` sz) rest
    ElfDataSectionNameTable idx -> do
      let s = strtabSection ".shstrtab" idx (elfLayoutSectionNameData l)
          (dta, sz) = sectionContents o s inLoad
       in dta <> doRest sz
    ElfDataGOT g -> do
      let s = elfGotSection g
          (dta, sz) = sectionContents o s inLoad
       in dta <> doRest sz
    ElfDataStrtab idx ->
      let s = strtabSection ".strtab" idx (strtab_data l)
          (dta, sz) = sectionContents o s inLoad
       in dta <> doRest sz
    ElfDataSymtab idx symtab ->
      let s = symtabSection cl d (strtab_map l) (strtab_idx l) idx symtab
          (dta, sz) = sectionContents o s inLoad
       in dta <> doRest sz
    ElfDataSection s ->
      let (dta, sz) = sectionContents o s inLoad
       in dta <> doRest sz
    ElfDataRaw dta ->
      Bld.byteString dta <> doRest (fromIntegral (B.length dta))

-- | Return the bytes in the Elf file as a lazy bytestring.
elfLayoutBytes :: ElfLayout w -> L.ByteString
elfLayoutBytes l = elfClassInstances (elfLayoutClass l) $
    Bld.toLazyByteString $ buildRegions l startOfFile ((,False) <$> regions)
  where regions = toList (elfLayoutRegions l)

------------------------------------------------------------------------
-- Elf region file size

-- | Return the size of a region given the elf region data.
elfRegionFileSize :: ElfLayout w -> ElfDataRegion w -> ElfWordType w
elfRegionFileSize l reg =
  let c = elfLayoutClass l
   in elfClassInstances c $
        case reg of
          ElfDataElfHeader          -> fromIntegral (ehdrSize c)
          ElfDataSegmentHeaders     -> fromIntegral (phnum l) * fromIntegral (phdrEntrySize c)
          ElfDataSegment s          -> sum (elfRegionFileSize l <$> elfSegmentData s)
          ElfDataSectionHeaders     -> fromIntegral (shnum l) * fromIntegral (shdrEntrySize c)
          ElfDataSectionNameTable _ -> fromIntegral $ B.length $ elfLayoutSectionNameData l
          ElfDataGOT g              -> elfGotSize g
          ElfDataStrtab _           -> fromIntegral $ B.length $ strtab_data l
          ElfDataSymtab _ symtab    -> symtabSize c symtab
          ElfDataSection s          -> elfSectionFileSize s
          ElfDataRaw b              -> fromIntegral (B.length b)

------------------------------------------------------------------------
-- Generating ElfLayout from elf

-- | Return index for .strtab if defined or '0' if undefined.
elfStrtabSectionIndex :: Elf w -> Word16
elfStrtabSectionIndex e = fromMaybe 0 $ asumDataRegions f e
  where f (ElfDataStrtab idx) = Just idx
        f _ = Nothing

-- | Return symbol table names in elf.
elfSymtabNames :: Elf w -> [B.ByteString]
elfSymtabNames = asumDataRegions f
  where f (ElfDataSymtab _ symtab) = V.toList $ steName <$> symtabEntries symtab
        f _ = []

elfSegmentCount :: Elf w -> Int
elfSegmentCount e = foldl' f 0 (e^.elfFileData)
  where f c (ElfDataSegment s) = foldl' f (c + 1) (elfSegmentData s)
        f c _ = c

-- Process element.
layoutRegion :: forall w
             .  ElfWidthConstraints w
             => Bool -- ^ Flag that stores true if this region is inside a segment.
             -> ElfLayout w
             -> ElfDataRegion w
             -> ElfLayout w
layoutRegion inLoad l reg = do
  let cl = elfLayoutClass l
  let d = elfLayoutData l
  let phdrCnt = elfLayoutPhdrCount l
  let o = l^.elfOutputSize
  case reg of
    ElfDataElfHeader
      | o /= startOfFile ->
          error "elfLayout given elf header outside start of file."
      | otherwise ->
          l & elfOutputSize .~ FileOffset (fromIntegral (ehdrSize cl))
    ElfDataSegmentHeaders
      | not (isAligned o (phdrTableAlign cl)) ->
          error $ "Segment header table file offset " ++ show o
               ++ " must be a multiple of " ++ show (phdrTableAlign cl) ++ "."
      | otherwise ->
        let phdrSize = phdrCnt * fromIntegral (phdrEntrySize cl)
         in l & phdrTableOffset .~ o
              & elfOutputSize .~ o `incOffset` phdrSize
    ElfDataSegment s -> do
      let -- Update layout by folding over segment data.
          l2 :: ElfLayout w
          l2 = foldl (layoutRegion True)  l (elfSegmentData s)
          -- Get bytes at start of elf
      let segSize   = rangeSize o (l2^.elfOutputSize)
          -- Get memory size of segment
      let memSize =
            case elfSegmentMemSize s of
              -- Absolute sizes are lower bounds
              ElfAbsoluteSize sz -> max segSize sz
              -- Relative sizes are offsets of the computed sizes.
              ElfRelativeSize delta  -> segSize + delta
      let idx = elfSegmentIndex s
      let addr = elfSegmentVirtAddr s
      let align = elfSegmentAlign s
          -- Create program header
      case () of
        -- Check file offset and address are compatible.
        _ | any (not . regionOffsetIgnorable) (elfSegmentData s)
          , (fromFileOffset o .&. (align - 1)) /= (addr .&. (align - 1)) ->
            error $ "segment " ++ show idx
                ++ " address of 0x" ++ showHex addr " and file offset 0x"
                ++ showHex (fromFileOffset o) ""
                ++ " does not respect the alignment of 0x" ++ showHex align "."
          | Map.member idx (l2^.phdrs) ->
              error $ "Segment index " ++ show idx ++ " already exists."
          | otherwise -> do
            let phdr = Phdr { phdrSegmentIndex = idx
                            , phdrSegmentType = elfSegmentType s
                            , phdrSegmentFlags = elfSegmentFlags s
                            , phdrSegmentVirtAddr = addr
                            , phdrSegmentPhysAddr = elfSegmentPhysAddr s
                            , phdrSegmentAlign = align
                            , phdrFileStart = o
                            , phdrFileSize  = segSize
                            , phdrMemSize   = memSize
                            }
            l2 & phdrs %~ Map.insert idx phdr
    ElfDataSectionHeaders
      | inLoad ->
          error $ "Section headers should not be within a segment."
      | otherwise -> addSectionHeadersToLayout l
    ElfDataSectionNameTable idx ->
      let l' = l & shstrndx .~ idx
          s  = strtabSection ".shstrtab" idx (elfLayoutSectionNameData l)
       in addSectionToLayout l' s inLoad
    ElfDataGOT g ->
      let s = elfGotSection g
       in addSectionToLayout l s inLoad
    ElfDataStrtab idx ->
      let s = strtabSection ".strtab" idx (strtab_data l)
       in addSectionToLayout l s inLoad
    ElfDataSymtab idx symtab ->
      let s = symtabSection cl d (strtab_map l) (strtab_idx l) idx symtab
       in addSectionToLayout l s inLoad
    ElfDataSection s ->
      addSectionToLayout l s inLoad
    ElfDataRaw b ->
      l & incOutputSize (fromIntegral (B.length b))

-- | Return layout information from elf file.
elfLayout' :: forall w . ElfWidthConstraints w => Elf w -> ElfLayout w
elfLayout' e = initl & flip (foldl' (layoutRegion False)) (e^.elfFileData)
                     & flip (foldl' (addPhdrToLayout "GNU stack segment index")) (fmap gnuStackPhdr (elfGnuStackSegment e))
                     & flip (foldl' addRelroToLayout)    (elfGnuRelroRegions e)
  where sec_names = elfSectionNames e
        (nameData,nameMap) = encodeStringTable sec_names

        (this_strtab_data, this_strtab_map) = encodeStringTable (elfSymtabNames e)

        phdrCnt = fromIntegral $
                  elfSegmentCount e
                 + (if isJust (elfGnuStackSegment e) then 1 else 0)
                 + length (elfGnuRelroRegions e)

        -- Section names can be determed from counter
        shdrCnt = fromIntegral $ length sec_names + 1

        initl = ElfLayout { elfLayoutHeader = elfHeader e
                          , elfLayoutRegions = e^.elfFileData
                          , elfLayoutPhdrCount = phdrCnt
                          , elfLayoutShdrCount = shdrCnt
                          , elfLayoutSectionNameData = nameData
                          , elfLayoutSectionNameOffsets = nameMap
                          , strtab_idx  = elfStrtabSectionIndex e
                          , strtab_data = this_strtab_data
                          , strtab_map  = this_strtab_map
                          , _elfOutputSize = startOfFile
                          , _phdrTableOffset = startOfFile
                          , _phdrs = Map.empty
                          , _shdrTableOffset = startOfFile
                          , _shstrndx = 0
                          , _shdrs = Map.singleton 0 (initShdr 0)
                          }

-- | Return layout information from elf file.
elfLayout :: Elf w -> ElfLayout w
elfLayout e = elfClassInstances  (elfClass e) $ elfLayout' e

-- | Write elf file out to bytestring.
renderElf :: Elf w -> L.ByteString
renderElf = elfLayoutBytes . elfLayout
