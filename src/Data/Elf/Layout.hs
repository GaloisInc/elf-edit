{-# LANGUAGE GADTs #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Data.Elf.Layout
  ( -- * ElfLayout
    ElfLayout
  , elfLayoutClass
  , Phdr(..)
  , phdrFileRange
  , phdrs
  , allPhdrs
  , elfLayout
  , elfLayoutBytes
  , elfLayoutSize
  , buildElfHeader
  , buildElfSegmentHeaderTable
  , buildElfSectionHeaderTable
  , elfRegionFileSize
    -- * Traversal
  , elfSections
  , updateSections
  , traverseElfSegments
  , updateSegments
    -- * Low level constants
  , elfMagic
  , ehdrSize
  , phdrEntrySize
  , shdrEntrySize
  , ElfWidth
  , FileOffset(..)
  , stringTable
  ) where

import           Control.Exception (assert)
import           Control.Lens hiding (enum)
import           Control.Monad
import           Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Builder as Bld
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.UTF8 as B (fromString)
import qualified Data.Foldable as F
import           Data.List (sort)
import           Data.Map (Map)
import qualified Data.Map as Map
import           Data.Maybe
import           Data.Monoid
import qualified Data.Sequence as Seq
import           Data.Word
import           Numeric

import           Data.Elf.Types

------------------------------------------------------------------------
-- Utilities

-- | Traverse elements in a list and modify or delete them.
updateSeq :: Traversal (Seq.Seq a) (Seq.Seq b) a (Maybe b)
updateSeq f l0 =
  case Seq.viewl l0 of
    Seq.EmptyL -> pure Seq.empty
    h Seq.:< l -> compose <$> f h <*> updateSeq f l
      where compose Nothing  r = r
            compose (Just e) r = e Seq.<| r

------------------------------------------------------------------------
-- FileOffset

-- | A offset in the file (implemented as a newtype to avoid confusion with virtual addresses)
newtype FileOffset w = FileOffset { fromFileOffset :: w }

instance Show w => Show (FileOffset w) where
  show (FileOffset o) = show o

startOfFile :: Num w => FileOffset w
startOfFile = FileOffset 0

incOffset :: Num w => FileOffset w -> w -> FileOffset w
incOffset (FileOffset b) o = FileOffset (b + o)

rangeSize :: (Ord w, Num w) => FileOffset w -> FileOffset w -> w
rangeSize (FileOffset s) (FileOffset e) = assert (e >= s) $ e - s

------------------------------------------------------------------------
-- Phdr

-- | Provides concrete information about an elf segment and its layout.
data Phdr w = Phdr { phdrSegment   :: !(ElfSegment w)
                   , phdrFileStart :: !(FileOffset w)
                   , phdrFileSize  :: !w
                   , phdrMemSize   :: !w
                   }

alignLeft :: Int -> String -> Char -> String
alignLeft n s c | l < n = s ++ replicate (n - l) c
                | otherwise = take n s
  where l = length s

alignRight :: Int -> Char -> String -> String
alignRight n c s | l < n = replicate (n - l) c ++ s
                 | otherwise = take n s
  where l = length s

fixedHex :: Integral a => Int -> a -> String
fixedHex n v = alignRight n '0' s
  where s = showHex (toInteger v) ""

showSegFlags :: ElfSegmentFlags -> String
showSegFlags f =
    [ ' '
    , set_if pf_r 'R'
    , set_if pf_w 'W'
    , set_if pf_x 'E'
    ]
  where set_if req c | f `hasPermissions` req = c
                     | otherwise = ' '

instance (Integral w) => Show (Phdr w) where
  show p = unlines (unwords <$> [ col1, col2 ])
    where seg = phdrSegment p
          col1 = [ alignLeft 15 (show (elfSegmentType seg)) ' '
                 , "0x" ++ fixedHex 16 (fromFileOffset (phdrFileStart p))
                 , "0x" ++ fixedHex 16 (elfSegmentVirtAddr seg)
                 , "0x" ++ fixedHex 16 (elfSegmentPhysAddr seg)
                 ]
          col2 = [ replicate 14 ' '
                 , "0x" ++ fixedHex 16 (phdrFileSize p)
                 , "0x" ++ fixedHex 16 (phdrMemSize  p)
                 , alignLeft 7 (showSegFlags (elfSegmentFlags seg)) ' '
                 , showHex (toInteger (elfSegmentAlign seg)) ""
                 ]

phdrFileRange :: Phdr w -> Range w
phdrFileRange phdr = (fromFileOffset (phdrFileStart phdr), phdrFileSize phdr)

------------------------------------------------------------------------
-- ElfLayout

-- | This provides information about the layout of an Elf file.
--
-- It can be used to obtain precise information about Elf file layout.
data ElfLayout w = ElfLayout {
        elfLayoutHeader :: !(ElfHeader w)
        -- ^ Header information for elf file
      , elfLayoutRegions :: !(Seq.Seq (ElfDataRegion w))
        -- ^ Data regions from elf file
      , elfLayoutSectionNameData :: B.ByteString
        -- ^ Contents of section name table data.
      , _elfOutputSize :: !(FileOffset w)
        -- ^ Elf output size
      , _phdrTableOffset :: !(FileOffset w)
        -- ^ Offset to phdr table.
      , _phdrs :: !(Map Word16 (Phdr w))
        -- ^ Map from phdr index to phdr.
        --
        -- Once the layout has been generated there should be an
        -- entry for each index from '0' to the number of phdrs minus one.
      , _shdrTableOffset :: !(FileOffset w)
        -- ^ Offset to section header table.
      , _shstrndx :: Word16
        -- ^ Index of section for string table.
      , _shdrs :: Seq.Seq Bld.Builder
        -- ^ List of section headers found so far.
      }

elfLayoutClass :: ElfLayout w -> ElfClass w
elfLayoutClass = headerClass . elfLayoutHeader

-- | Lens containing size of sections processed so far in layout.
elfOutputSize :: Simple Lens (ElfLayout w) (FileOffset w)
elfOutputSize = lens _elfOutputSize (\s v -> s { _elfOutputSize = v })

phdrTableOffset :: Simple Lens (ElfLayout w) (FileOffset w)
phdrTableOffset = lens _phdrTableOffset (\s v -> s { _phdrTableOffset = v })

phdrs :: Simple Lens (ElfLayout w) (Map Word16 (Phdr w))
phdrs = lens _phdrs (\s v -> s { _phdrs = v })

shdrTableOffset :: Simple Lens (ElfLayout w) (FileOffset w)
shdrTableOffset = lens _shdrTableOffset (\s v -> s { _shdrTableOffset = v })

shstrndx :: Simple Lens (ElfLayout w) Word16
shstrndx = lens _shstrndx (\s v -> s { _shstrndx = v })

shdrs :: Simple Lens (ElfLayout w) (Seq.Seq Bld.Builder)
shdrs = lens _shdrs (\s v -> s { _shdrs = v })

-- | Return total size of elf file.
elfLayoutSize :: ElfLayout w -> w
elfLayoutSize l = w
  where FileOffset w = l^.elfOutputSize

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
  where r = Seq.length $ l^.shdrs

------------------------------------------------------------------------
-- ElfField

-- | A component in the field as written.
data ElfField v
  = EFBS Word16 (v -> Bld.Builder)
  | EFWord16 (v -> Word16)
  | EFWord32 (v -> Word32)
  | EFWord64 (v -> Word64)

sizeOfField :: ElfField v -> Word16
sizeOfField (EFBS s _)   = s
sizeOfField (EFWord16 _) = 2
sizeOfField (EFWord32 _) = 4
sizeOfField (EFWord64 _) = 8

writeField2 :: ElfField v -> ElfData -> v -> Bld.Builder
writeField2 (EFBS _   f) _           = f
writeField2 (EFWord16 f) ELFDATA2LSB = Bld.word16LE . f
writeField2 (EFWord16 f) ELFDATA2MSB = Bld.word16BE . f
writeField2 (EFWord32 f) ELFDATA2LSB = Bld.word32LE . f
writeField2 (EFWord32 f) ELFDATA2MSB = Bld.word32BE . f
writeField2 (EFWord64 f) ELFDATA2LSB = Bld.word64LE . f
writeField2 (EFWord64 f) ELFDATA2MSB = Bld.word64BE . f

------------------------------------------------------------------------
-- ElfRecord

-- | A record to be written to the Elf file.
type ElfRecord v = [(String, ElfField v)]

sizeOfRecord :: ElfRecord v -> Word16
sizeOfRecord = sum . map (sizeOfField . snd)

writeRecord2 :: ElfRecord v -> ElfData -> v -> Bld.Builder
writeRecord2 fields d v =
  mconcat $ map (\(_,f) -> writeField2 f d v) fields

------------------------------------------------------------------------
-- ElfWidth


-- | Contains elf file, program header offset, section header offset.
type Ehdr w = ElfLayout w
-- | Contains Elf section data, name offset, and data offset.
type Shdr w = (ElfSection w, Word32, w)

-- | @ElfWidth w@ is used to capture the constraint that Elf files are
-- either 32 or 64 bit.  It is not meant to be implemented by others.
class (Bits w, Integral w, Show w) => ElfWidth w where

------------------------------------------------------------------------
-- elfLayoutBytes

buildElfHeader :: ElfLayout w -> Bld.Builder
buildElfHeader l = writeRecord2 (ehdrFields (headerClass hdr)) d l
  where hdr = elfLayoutHeader l
        d = headerData hdr

buildElfSegmentHeaderTable :: ElfLayout w -> Bld.Builder
buildElfSegmentHeaderTable l =
    mconcat $ writeRecord2 (phdrFields (headerClass hdr)) d <$> allPhdrs l
  where hdr = elfLayoutHeader l
        d = headerData hdr

buildElfSectionHeaderTable :: ElfLayout w -> Bld.Builder
buildElfSectionHeaderTable l =
  mconcat (F.toList (l^.shdrs))

-- | Return the bytes in the Elf file as a lazy bytestring.
buildRegions :: ElfWidth w
                => ElfLayout w
                -> FileOffset w
                -> [ElfDataRegion w]
                -> Bld.Builder
buildRegions _ _ [] = mempty
buildRegions l o (reg:rest) = do
  let o' = nextRegionOffset l o reg
  case reg of
    ElfDataElfHeader ->
      buildElfHeader l
        <> buildRegions l o' rest
    ElfDataSegmentHeaders ->
      buildElfSegmentHeaderTable l
        <> buildRegions l o' rest
    ElfDataSegment s ->
      buildRegions l o' (F.toList (elfSegmentData s) ++ rest)
    ElfDataSectionHeaders ->
      buildElfSectionHeaderTable l
        <> buildRegions l o' rest
    ElfDataSectionNameTable ->
      Bld.byteString (elfLayoutSectionNameData l)
        <> buildRegions l o' rest
    ElfDataGOT g ->
      Bld.byteString (elfGotData g)
        <> buildRegions l o' rest
    ElfDataSection s ->
      Bld.byteString (elfSectionData s)
        <> buildRegions l o' rest
    ElfDataRaw b ->
      Bld.byteString b
        <> buildRegions l o' rest

-- | Return the offset of the next data region to traverse.
--
-- Note that for segments, this just returns the offset by adding
-- padding to get alignment correct, it does not return the offset
-- including all subsections.
nextRegionOffset :: (Bits w, Integral w)
                 => ElfLayout w
                 -> FileOffset w
                 -> ElfDataRegion w
                 -> FileOffset w
nextRegionOffset l o reg = do
  let e = elfLayoutHeader l
  let c = headerClass e
  case reg of
    ElfDataElfHeader      -> o `incOffset` fromIntegral (ehdrSize c)
    ElfDataSegmentHeaders -> o `incOffset` phdr_size
      where phdr_size = fromIntegral (phnum l) * fromIntegral (phdrEntrySize c)
    ElfDataSegment _ -> o
    ElfDataSectionHeaders -> o `incOffset` sz
      where sz = fromIntegral (shnum l) * fromIntegral (shdrEntrySize c)
    ElfDataSectionNameTable -> nextSectionOffset o s
      where s = elfNameTableSection (elfLayoutSectionNameData l)
    ElfDataGOT g -> nextSectionOffset o s
      where s = elfGotSection g
    ElfDataSection s -> nextSectionOffset o s
    ElfDataRaw b -> o `incOffset` sz
      where sz = fromIntegral (B.length b)

nextSectionOffset :: (Bits w, Integral w) => FileOffset w -> ElfSection w -> FileOffset w
nextSectionOffset o s = o `incOffset` data_size
  where dta = elfSectionData s
        data_size = fromIntegral (B.length dta)

{-
-- | Return the offset after all data in region.
fileOffsetAfterRegion :: (Bits w, Integral w)
                      => ElfLayout w
                      -> FileOffset w
                      -> ElfDataRegion w
                      -> FileOffset w
fileOffsetAfterRegion l b (ElfDataSegment seg) =
    fileOffsetAfterRegions l next (elfSegmentData seg)
  where next = nextRegionOffset l b (ElfDataSegment seg)
fileOffsetAfterRegion l b reg = nextRegionOffset l b reg

-- | Return offset after all regions in file.
fileOffsetAfterRegions :: (Bits w, Integral w, Foldable t)
                       => ElfLayout w
                       -> FileOffset w
                       -> t (ElfDataRegion w)
                       -> FileOffset w
fileOffsetAfterRegions l = F.foldl' (fileOffsetAfterRegion l)
-}
------------------------------------------------------------------------
-- elfNameTableSection

-- | Create a section for the section name table from the data.
elfNameTableSection :: Num w => B.ByteString -> ElfSection w
elfNameTableSection name_data =
  ElfSection {
      elfSectionName = shstrtab
    , elfSectionType = SHT_STRTAB
    , elfSectionFlags = shf_none
    , elfSectionAddr = 0
    , elfSectionSize = fromIntegral (B.length name_data)
    , elfSectionLink = 0
    , elfSectionInfo = 0
    , elfSectionAddrAlign = 1
    , elfSectionEntSize = 0
    , elfSectionData = name_data
    }

------------------------------------------------------------------------
-- elfSectionAsGOT

-- | Attempt to convert a section to a GOT.
elfSectionAsGOT :: (Bits w, Num w)
                => ElfSection w
                -> Either String (ElfGOT w)
elfSectionAsGOT s = do
  -- TODO: Perform checks
  when (elfSectionType s /= SHT_PROGBITS) $ do
    Left "Unexpected type"
  when (elfSectionFlags s /= elfGotSectionFlags) $ do
    Left "Unexpected type"
  let d = elfSectionData s
  when (elfSectionSize s /= fromIntegral (B.length d)) $ do
    Left "Section size does not match data length."
  when (elfSectionLink s /= 0) $ do
    Left "Unexpected section length"
  when (elfSectionInfo s /= 0) $ do
    Left "Unexpected section info"
  return ElfGOT { elfGotName = elfSectionName s
                , elfGotAddr = elfSectionAddr s
                , elfGotAddrAlign = elfSectionAddrAlign s
                , elfGotEntSize = elfSectionEntSize s
                , elfGotData = d
                }


------------------------------------------------------------------------
-- StringTable

-- | Name of shstrtab (used to reduce spelling errors).
shstrtab :: String
shstrtab = ".shstrtab"

type StringTable = (Map.Map B.ByteString Word32, Word32, Bld.Builder)

insertTail :: B.ByteString
           -> Word32
           -> Word32
           -> Map.Map B.ByteString Word32
           -> Map.Map B.ByteString Word32
insertTail bs base i = Map.insertWith (\_n o -> o) (B.drop (fromIntegral i) bs) offset
  where offset  = base + fromIntegral i

-- | Insert bytestring in list of strings.
insertString :: StringTable -> B.ByteString -> StringTable
insertString a@(m, base, b) bs
    | Map.member bs m = a
    | otherwise = (m', base',  b')
  where -- Insert all tails of the bytestring into the map so that
        -- we can find the index later if needed.
        m' = foldr (insertTail bs base) m (enumCnt 0 (base + 1))
        b' = b `mappend` Bld.byteString bs `mappend` Bld.word8 0
        base' = base + fromIntegral (B.length bs) + 1

-- | Create a string table from the list of strings, and return list of offsets.
stringTable :: [String] -> (B.ByteString, Map.Map String Word32)
stringTable strings = (res, stringMap)
  where -- Get list of strings as bytestrings.
        bsl = map B.fromString strings

        -- Compress entries by removing a string if it is the prefiex of
        -- another string.
        --
        -- The inputs of compress have been sorted, so we know that if
        -- a string 'x' is a prefix of a string 'y', then 'y' appears after
        -- 'x', and any string 'z' betweeen 'x' and 'y' is also a prefix of 'x'.
        -- Thus to eliminate prefixes,
        compress :: [B.ByteString] -> [B.ByteString]
        compress (f:r@(s:_)) | f `B.isSuffixOf` s = compress r
        compress (f:r) = f:compress r
        compress [] = []

        -- The entries is obtained by taksing the list of names of bytestrings
        -- and eliminating all bytestrings that are suffixes of other strings.
        --
        -- To do this in near-linear time with respect to the number of strings
        -- (as opposed to quadratic), this is
        -- done by reversing each string, sorting it, then eliminating
        -- prefixes, before reversing the strings again.
        entries = compress $ fmap B.reverse $ sort $ fmap B.reverse bsl

        -- Insert strings into map (first string must be empty string)
        empty_string = B.fromString ""
        empty_table = (Map.empty, 0, mempty)

        -- We insert strings in order so that they will appear in sorted
        -- order in the bytestring.  This is likely not essential, but
        -- corresponds to ld's behavior.
        (m,_,b) = F.foldl' insertString empty_table (empty_string : entries)

        myFind bs =
          case Map.lookup bs m of
            Just v -> v
            Nothing -> error $ "internal: stringTable missing entry."
        stringMap = Map.fromList $ strings `zip` map myFind bsl

        res = L.toStrict (Bld.toLazyByteString b)


------------------------------------------------------------------------
-- Section traversal

-- | Return name of all elf sections.
elfSectionNames :: forall w . Elf w -> [String]
elfSectionNames e = concatMap regionNames (F.toList (e^.elfFileData))
  where regionNames :: ElfDataRegion w -> [String]
        regionNames (ElfDataSegment s) =
          concatMap regionNames (F.toList (elfSegmentData s))
        regionNames ElfDataSectionNameTable = [shstrtab]
        regionNames (ElfDataGOT g)          = [elfGotName g]
        regionNames (ElfDataSection s)      = [elfSectionName s]
        regionNames _                       = []

-- | Traverse sections in Elf file and modify or delete them.
updateSections' :: (Bits w, Num w)
                => Traversal (Elf w) (Elf w) (ElfSection w) (Maybe (ElfSection w))
updateSections' fn e0 = elfFileData (updateSeq impl) e0
  where t = fst $ stringTable $ elfSectionNames e0

        norm :: (Bits w, Num w) => ElfSection w -> ElfDataRegion w
        norm s
          | elfSectionName s == shstrtab = ElfDataSectionNameTable
          | elfSectionName s `elem` [".got", ".got.plt"] =
            case elfSectionAsGOT s of
              Left e -> error $ "Error in Data.Elf.updateSections: " ++ e
              Right v -> ElfDataGOT v
          | otherwise = ElfDataSection s

        impl (ElfDataSegment s) = fix <$> updateSeq impl (elfSegmentData s)
          where fix d = Just $ ElfDataSegment $ s { elfSegmentData = d }
        impl ElfDataSectionNameTable = fmap norm <$> fn (elfNameTableSection t)
        impl (ElfDataGOT g) = fmap norm <$> fn (elfGotSection g)
        impl (ElfDataSection s) = fmap norm <$> fn s
        impl d = pure (Just d)

updateSegments' :: forall w f . (Monad f, Bits w, Num w)
                => (ElfSegment w -> f (Maybe (ElfSegment w)))
                -> Elf w
                -> f (Elf w)
updateSegments' fn = elfFileData (updateSeq impl)
  where
    impl (ElfDataSegment seg) =
      let inner = updateSeq impl (elfSegmentData seg)
          updateData s d = s { elfSegmentData = d }
          newSeg :: (Monad f) => f (Maybe (ElfSegment w))
          newSeg = fn =<< (fmap (updateData seg) inner)
      in fmap ElfDataSegment <$> newSeg
    impl d = pure (Just d)

-- | Traverse elf sections
elfSections' :: (Bits w, Num w) => Simple Traversal (Elf w) (ElfSection w)
elfSections' f = updateSections' (fmap Just . f)

------------------------------------------------------------------------
-- Section Elf Layout

-- | Add section information to layout.
addSectionToLayout :: Integral w
                   => Map.Map String Word32 -- ^ Name to offset map.
                   -> ElfLayout w
                   -> ElfSection w
                   -> ElfLayout w
addSectionToLayout name_map l s = do
    l & elfOutputSize %~ (`incOffset` data_size)
      & shdrs %~ (Seq.|> writeRecord2 (shdrFields cl) d (s, no, fromFileOffset base))
  where d = headerData (elfLayoutHeader l)
        cl = headerClass (elfLayoutHeader l)
        Just no = Map.lookup (elfSectionName s) name_map
        base =  l^.elfOutputSize
        data_size = elfSectionFileSize s

------------------------------------------------------------------------
-- elfLayout

addRelroToLayout :: Num w => Maybe (Range w) -> ElfLayout w -> ElfLayout w
addRelroToLayout Nothing l = l
addRelroToLayout (Just (f,c)) l = l & phdrs %~ Map.insert idx phdr
  where idx = fromIntegral (Map.size (l^.phdrs))
        s = ElfSegment { elfSegmentType     = PT_GNU_RELRO
                       , elfSegmentFlags    = pf_r
                       , elfSegmentIndex    = idx
                       , elfSegmentVirtAddr = f
                       , elfSegmentPhysAddr = f
                       , elfSegmentAlign    = 1
                       , elfSegmentMemSize  = ElfRelativeSize 0
                       , elfSegmentData     = Seq.empty
                       }

        phdr = Phdr { phdrSegment   = s
                    , phdrFileStart = FileOffset f
                    , phdrFileSize  = c
                    , phdrMemSize   = c
                    }

elfSegmentCount :: Elf w -> Int
elfSegmentCount e = F.foldl' f 0 (e^.elfFileData)
  where f c (ElfDataSegment s) = F.foldl' f (c + 1) (elfSegmentData s)
        f c _ = c

elfSectionCount :: Elf w -> Int
elfSectionCount e = F.foldl' f 0 (e^.elfFileData)
  where f c (ElfDataSegment s) = F.foldl' f c (elfSegmentData s)
        f c ElfDataSectionNameTable{} = c + 1
        f c ElfDataGOT{}              = c + 1
        f c ElfDataSection{}          = c + 1
        f c _                         = c

-- | Return the size of a region given the elf region data.
elfRegionFileSize :: ElfLayout w -> ElfDataRegion w -> w
elfRegionFileSize l reg = elfClassInstances c $ do
    case reg of
      ElfDataElfHeader        -> fromIntegral (ehdrSize c)
      ElfDataSegmentHeaders   -> fromIntegral (phnum l) * fromIntegral (phdrEntrySize c)
      ElfDataSegment s        -> sum (elfRegionFileSize l <$> elfSegmentData s)
      ElfDataSectionHeaders   -> fromIntegral (shnum l) * fromIntegral (shdrEntrySize c)
      ElfDataSectionNameTable -> fromIntegral $ B.length $ elfLayoutSectionNameData l
      ElfDataGOT g            -> elfGotSize g
      ElfDataSection s        -> elfSectionFileSize s
      ElfDataRaw b             -> fromIntegral (B.length b)
  where c = elfLayoutClass l

-- | Return layout information from elf file.
elfLayout' :: forall w . ElfWidth w => Elf w -> ElfLayout w
elfLayout' e = final
  where c = elfClass e
        (name_data,name_map) = stringTable $
          elfSectionName <$> toListOf elfSections' e

        has_relro = isJust (elfRelroRange e)

        phdr_cnt = elfSegmentCount e
                 + (if has_relro then 1 else 0)

        shdr_cnt = elfSectionCount e

        initl = ElfLayout { elfLayoutHeader = elfHeader e
                          , elfLayoutRegions = e^.elfFileData
                          , elfLayoutSectionNameData = name_data
                          , _elfOutputSize = startOfFile
                          , _phdrTableOffset = startOfFile
                          , _phdrs = Map.empty
                          , _shdrTableOffset = startOfFile
                          , _shstrndx = 0
                          , _shdrs = Seq.empty
                          }

        -- Process element.
        layoutRegion :: ElfWidth w
                        => ElfLayout w
                        -> ElfDataRegion w
                        -> ElfLayout w
        layoutRegion l ElfDataElfHeader =
             l & elfOutputSize %~ (`incOffset` (fromIntegral (ehdrSize c)))
        layoutRegion l ElfDataSegmentHeaders =
             l & elfOutputSize %~ (`incOffset` phdr_size)
               & phdrTableOffset .~ l^.elfOutputSize
          where phdr_size = fromIntegral phdr_cnt * fromIntegral (phdrEntrySize c)
        layoutRegion l (ElfDataSegment s) = l3
          where -- Update layout by folding over segment data.
                l2 :: ElfLayout w
                l2 = l & flip (foldl layoutRegion) (elfSegmentData s)
                -- Get bytes at start of elf
                seg_offset = l^.elfOutputSize
                seg_size   = rangeSize seg_offset (l2^.elfOutputSize)
                mem_size =
                  case elfSegmentMemSize s of
                    ElfAbsoluteSize sz -> sz
                    ElfRelativeSize o  -> seg_size + o
                phdr = Phdr { phdrSegment = s
                            , phdrFileStart = seg_offset
                            , phdrFileSize  = seg_size
                            , phdrMemSize   = mem_size -- FIXME: Not large enough -- things work if this is seg_size
                            }
                idx = elfSegmentIndex s
                -- Add segment to appropriate
                l3 :: ElfLayout w
                l3 | Map.member idx (l2^.phdrs) =
                     error $ "Segment index " ++ show idx ++ " already exists."
                   | otherwise = l2 & phdrs %~ Map.insert idx phdr
        layoutRegion l ElfDataSectionHeaders =
             l & elfOutputSize   %~ (`incOffset` shdr_size)
               & shdrTableOffset .~ l^.elfOutputSize
          where shdr_size = fromIntegral shdr_cnt * fromIntegral (shdrEntrySize c)
        layoutRegion l ElfDataSectionNameTable =
            addSectionToLayout name_map l' s
          where l' = l & shstrndx .~ shnum l
                s  = elfNameTableSection name_data
        layoutRegion l (ElfDataGOT g) = addSectionToLayout name_map l (elfGotSection g)
        layoutRegion l (ElfDataSection s) = addSectionToLayout name_map l s
        layoutRegion l (ElfDataRaw b) =
          l & elfOutputSize %~ (`incOffset` fromIntegral (B.length b))

        final = initl & flip (foldl layoutRegion) (e^.elfFileData)
                      & addRelroToLayout (elfRelroRange e)

{-
-- | Return true if the section headers are stored in a loadable part of
-- memory.
loadableSectionHeaders :: Elf w -> Bool
loadableSectionHeaders e = any containsLoadableSectionHeaders (e^.elfFileData)
  where containsLoadableSectionHeaders :: ElfDataRegion w -> Bool
        containsLoadableSectionHeaders (ElfDataSegment s)
          | elfSegmentType s == PT_LOAD =
              any containsSectionHeaders (elfSegmentData s)
        containsLoadableSectionHeaders _ = False

        containsSectionHeaders :: ElfDataRegion w -> Bool
        containsSectionHeaders ElfDataSectionHeaders = True
        containsSectionHeaders (ElfDataSegment s) =
          any containsSectionHeaders (elfSegmentData s)
        containsSectionHeaders _ = False
-}
------------------------------------------------------------------------
-- Elf Width instances

elfMagic :: B.ByteString
elfMagic = B.fromString "\DELELF"

elfIdentBuilder :: ElfHeader w -> Bld.Builder
elfIdentBuilder e =
  mconcat [ Bld.byteString elfMagic
          , Bld.word8 (fromElfClass (headerClass e))
          , Bld.word8 (fromElfData  (headerData e))
          , Bld.word8 expectedElfVersion
          , Bld.word8 (fromElfOSABI (headerOSABI e))
          , Bld.word8 (fromIntegral (headerABIVersion e))
          , mconcat (replicate 7 (Bld.word8 0))
          ]

ehdrSize32 :: Word16
ehdrSize32 = sizeOfRecord ehdr32Fields

ehdrSize64 :: Word16
ehdrSize64 = sizeOfRecord ehdr64Fields

phdrEntrySize32 :: Word16
phdrEntrySize32 = sizeOfRecord phdr32Fields

phdrEntrySize64 :: Word16
phdrEntrySize64 = sizeOfRecord phdr64Fields

shdrEntrySize32 :: Word16
shdrEntrySize32 = sizeOfRecord shdr32Fields

shdrEntrySize64 :: Word16
shdrEntrySize64 = sizeOfRecord shdr64Fields

-- | Return the size of the main elf header table.
ehdrSize :: ElfClass w -> Word16
ehdrSize ELFCLASS32 = ehdrSize32
ehdrSize ELFCLASS64 = ehdrSize64

-- | Return size of entry in Elf programs header table.
phdrEntrySize :: ElfClass w -> Word16
phdrEntrySize ELFCLASS32 = phdrEntrySize32
phdrEntrySize ELFCLASS64 = phdrEntrySize64

-- | Return size of entry in Elf section header table.
shdrEntrySize :: ElfClass w -> Word16
shdrEntrySize ELFCLASS32 = shdrEntrySize32
shdrEntrySize ELFCLASS64 = shdrEntrySize64

ehdr32Fields :: ElfRecord (Ehdr Word32)
ehdr32Fields =
  [ ("e_ident",     EFBS 16  $ elfIdentBuilder . elfLayoutHeader)
  , ("e_type",      EFWord16 $ fromElfType     . headerType    . elfLayoutHeader)
  , ("e_machine",   EFWord16 $ fromElfMachine  . headerMachine . elfLayoutHeader)
  , ("e_version",   EFWord32 $ \_ -> fromIntegral expectedElfVersion)
  , ("e_entry",     EFWord32 $ headerEntry . elfLayoutHeader)
  , ("e_phoff",     EFWord32 $ fromFileOffset . view phdrTableOffset)
  , ("e_shoff",     EFWord32 $ fromFileOffset . view shdrTableOffset)
  , ("e_flags",     EFWord32 $ headerFlags . elfLayoutHeader)
  , ("e_ehsize",    EFWord16 $ \_ -> ehdrSize32)
  , ("e_phentsize", EFWord16 $ \_ -> phdrEntrySize32)
  , ("e_phnum",     EFWord16 $ phnum)
  , ("e_shentsize", EFWord16 $ \_ -> shdrEntrySize32)
  , ("e_shnum",     EFWord16 $ shnum)
  , ("e_shstrndx",  EFWord16 $ view shstrndx)
  ]

ehdr64Fields :: ElfRecord (Ehdr Word64)
ehdr64Fields =
  [ ("e_ident",     EFBS 16  $ elfIdentBuilder . elfLayoutHeader)
  , ("e_type",      EFWord16 $ fromElfType    . headerType    . elfLayoutHeader)
  , ("e_machine",   EFWord16 $ fromElfMachine . headerMachine . elfLayoutHeader)
  , ("e_version",   EFWord32 $ \_ -> fromIntegral expectedElfVersion)
  , ("e_entry",     EFWord64 $ headerEntry . elfLayoutHeader)
  , ("e_phoff",     EFWord64 $ fromFileOffset . view phdrTableOffset)
  , ("e_shoff",     EFWord64 $ fromFileOffset . view shdrTableOffset)
  , ("e_flags",     EFWord32 $ headerFlags . elfLayoutHeader)
  , ("e_ehsize",    EFWord16 $ \_ -> ehdrSize64)
  , ("e_phentsize", EFWord16 $ \_ -> phdrEntrySize64)
  , ("e_phnum",     EFWord16 $ phnum)
  , ("e_shentsize", EFWord16 $ \_ -> shdrEntrySize64)
  , ("e_shnum",     EFWord16 $ shnum)
  , ("e_shstrndx",  EFWord16 $ view shstrndx)
  ]

ehdrFields :: ElfClass w -> ElfRecord (Ehdr w)
ehdrFields ELFCLASS32 = ehdr32Fields
ehdrFields ELFCLASS64 = ehdr64Fields

phdr32Fields :: ElfRecord (Phdr Word32)
phdr32Fields =
  [ ("p_type",   EFWord32 $ fromElfSegmentType . elfSegmentType . phdrSegment)
  , ("p_offset", EFWord32 $ fromFileOffset . phdrFileStart)
  , ("p_vaddr",  EFWord32 $ elfSegmentVirtAddr . phdrSegment)
  , ("p_paddr",  EFWord32 $ elfSegmentPhysAddr . phdrSegment)
  , ("p_filesz", EFWord32 $ phdrFileSize)
  , ("p_memsz",  EFWord32 $ phdrMemSize)
  , ("p_flags",  EFWord32 $ fromElfSegmentFlags . elfSegmentFlags . phdrSegment)
  , ("p_align",  EFWord32 $                       elfSegmentAlign . phdrSegment)
  ]

phdr64Fields :: ElfRecord (Phdr Word64)
phdr64Fields =
  [ ("p_type",   EFWord32 $ fromElfSegmentType  . elfSegmentType  . phdrSegment)
  , ("p_flags",  EFWord32 $ fromElfSegmentFlags . elfSegmentFlags . phdrSegment)
  , ("p_offset", EFWord64 $ fromFileOffset . phdrFileStart)
  , ("p_vaddr",  EFWord64 $ elfSegmentVirtAddr . phdrSegment)
  , ("p_paddr",  EFWord64 $ elfSegmentPhysAddr . phdrSegment)
  , ("p_filesz", EFWord64 $ phdrFileSize)
  , ("p_memsz",  EFWord64 $ phdrMemSize)
  , ("p_align",  EFWord64 $ elfSegmentAlign    . phdrSegment)
  ]

phdrFields :: ElfClass w -> ElfRecord (Phdr w)
phdrFields ELFCLASS32 = phdr32Fields
phdrFields ELFCLASS64 = phdr64Fields

shdr32Fields :: ElfRecord (Shdr Word32)
shdr32Fields =
  [ ("sh_name",      EFWord32 (\(_,n,_) -> n))
  , ("sh_type",      EFWord32 (\(s,_,_) -> fromElfSectionType  $ elfSectionType s))
  , ("sh_flags",     EFWord32 (\(s,_,_) -> fromElfSectionFlags $ elfSectionFlags s))
  , ("sh_addr",      EFWord32 (\(s,_,_) -> elfSectionAddr s))
  , ("sh_offset",    EFWord32 (\(_,_,o) -> o))
  , ("sh_size",      EFWord32 (\(s,_,_) -> elfSectionSize s))
  , ("sh_link",      EFWord32 (\(s,_,_) -> elfSectionLink s))
  , ("sh_info",      EFWord32 (\(s,_,_) -> elfSectionInfo s))
  , ("sh_addralign", EFWord32 (\(s,_,_) -> elfSectionAddrAlign s))
  , ("sh_entsize",   EFWord32 (\(s,_,_) -> elfSectionEntSize s))
  ]

-- Fields that take section, name offset, data offset, and data length.
shdr64Fields :: ElfRecord (Shdr Word64)
shdr64Fields =
  [ ("sh_name",      EFWord32 (\(_,n,_) -> n))
  , ("sh_type",      EFWord32 (\(s,_,_) -> fromElfSectionType  $ elfSectionType s))
  , ("sh_flags",     EFWord64 (\(s,_,_) -> fromElfSectionFlags $ elfSectionFlags s))
  , ("sh_addr",      EFWord64 (\(s,_,_) -> elfSectionAddr s))
  , ("sh_offset",    EFWord64 (\(_,_,o) -> o))
  , ("sh_size",      EFWord64 (\(s,_,_) -> elfSectionSize s))
  , ("sh_link",      EFWord32 (\(s,_,_) -> elfSectionLink s))
  , ("sh_info",      EFWord32 (\(s,_,_) -> elfSectionInfo s))
  , ("sh_addralign", EFWord64 (\(s,_,_) -> elfSectionAddrAlign s))
  , ("sh_entsize",   EFWord64 (\(s,_,_) -> elfSectionEntSize s))
  ]


shdrFields :: ElfClass w -> ElfRecord (Shdr w)
shdrFields ELFCLASS32 = shdr32Fields
shdrFields ELFCLASS64 = shdr64Fields

instance ElfWidth Word32 where
instance ElfWidth Word64 where

elfClassElfWidthInstance :: ElfClass w -> (ElfWidth w => a) -> a
elfClassElfWidthInstance ELFCLASS32 a = a
elfClassElfWidthInstance ELFCLASS64 a = a


-- | Return the bytes in the Elf file as a lazy bytestring.
elfLayoutBytes :: ElfLayout w -> L.ByteString
elfLayoutBytes l = elfClassElfWidthInstance (elfLayoutClass l) $
    Bld.toLazyByteString $ buildRegions l startOfFile regions
  where regions = F.toList (elfLayoutRegions l)


------------------------------------------------------------------------
-- elfLayout

-- | Traverse sections in Elf file and modify or delete them.
updateSections :: Traversal (Elf w) (Elf w) (ElfSection w) (Maybe (ElfSection w))
updateSections fn e0 = elfClassElfWidthInstance (elfClass e0) $
  updateSections' fn e0

-- | Traverse segments in an ELF file and modify or delete them
updateSegments :: (Monad f) => (ElfSegment w -> f (Maybe (ElfSegment w))) -> Elf w -> f (Elf w)
updateSegments fn e0 = elfClassElfWidthInstance (elfClass e0) $
  updateSegments' fn e0

-- | Traverse elf sections
elfSections :: Simple Traversal (Elf w) (ElfSection w)
elfSections f = updateSections (fmap Just . f)

-- | Traverse elf segments
traverseElfSegments :: (Monad f) => (ElfSegment w -> f (ElfSegment w)) -> Elf w -> f (Elf w)
traverseElfSegments f = updateSegments (fmap Just . f)

-- | Return layout information from elf file.
elfLayout :: Elf w -> ElfLayout w
elfLayout e = elfClassElfWidthInstance (elfClass e) $ elfLayout' e

{-
------------------------------------------------------------------------
-- ElfSegmentUpdater

-- | This provides information and operations for modifying the contents of a
-- loadable segment without modifying the position in memory of existing code.
data ElfSegmentUpdater w
   = ElfSegmentUpdater { updaterVirtEnd :: !w
                         -- ^ The virtual address for the end of the segment.
                       , updaterAppendSection :: !(ElfSection w -> Elf w)
                         -- ^ This appends a section to the selected segment, and
                         -- returns a new elf file.
                         --
                         -- Note: This is not allowed if the section headers are
                         -- loadable (which is atypical), and 'error' will be
                         -- called if this is the case.
                       , updaterAppendData :: !(B.ByteString -> Elf w)
                         -- ^ This appends raw data to the selected segment, and
                         -- returns a new elf file.
                       }

-- | Given an elf file and a predicate on segments, this looks for the first
-- segment matching the predicate, and returns a 'ElfSegmentUpdater' that
-- allows changes to the segment that do not change the position of
-- any data in memory.
updateElfLoadableSegment :: Elf w
                         -> (ElfSegment w -> Bool)
                         -> Maybe (ElfSegmentUpdater w)
updateElfLoadableSegment  e isSegment =
    elfClassIntegralInstance (elfClass e) $
      updateElfLoadableSegment' e (elfLayout e) isSegment Seq.empty startOfFile (e^.elfFileData)

updateElfLoadableSegment' :: (Bits w, Integral w)
                          => Elf w
                          -> ElfLayout w
                          -> (ElfSegment w -> Bool)
                          -> Seq.Seq (ElfDataRegion w)
                          -> FileOffset w
                          -> Seq.Seq (ElfDataRegion w)
                          -> Maybe (ElfSegmentUpdater w)
updateElfLoadableSegment' e l isSegment prev o s =
  case Seq.viewl s of
    Seq.EmptyL -> Nothing
    h Seq.:< r
      | ElfDataSegment seg <- h
      , elfSegmentType seg == PT_LOAD
      , isSegment seg -> do
        let appendData new = e & elfFileData .~ prev Seq.>< (seg' Seq.<| r)
              where seg' = ElfDataSegment $
                       seg { elfSegmentMemSize = undefined
                           , elfSegmentData = elfSegmentData seg Seq.|> new
                           }
--            seg_start = nextRegionOffset l o (ElfDataSegment seg)
--            seg_end   = fileOffsetAfterRegions l seg_start (elfSegmentData seg)

--            seg_length = rangeSize seg_start seg_end

            -- Compute address where the new segment will be loaded.
            new_addr = elfSegmentVirtAddr seg + elfSegmentMemSize seg

            appendSection sec
              | loadableSectionHeaders e =
                error "Cannot create section when section headers are loadable."
              | otherwise = appendData (ElfDataSection sec)
            updater = ElfSegmentUpdater { updaterVirtEnd = new_addr
                                        , updaterAppendSection = appendSection
                                        , updaterAppendData = appendData . ElfDataRaw
                                        }
        return $! updater
      | otherwise ->
        let next_offset = fileOffsetAfterRegion l o h
         in updateElfLoadableSegment' e l isSegment (prev Seq.|> h) next_offset r
-}
