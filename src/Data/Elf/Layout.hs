{-# LANGUAGE GADTs #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Data.Elf.Layout
  ( -- * ElfLayout
    ElfLayout
  , elfLayoutClass
  , Phdr
  , phdrs
  , allPhdrs
  , elfLayout
  , elfLayoutBytes
  , elfLayoutSize
    -- * Traversal
  , elfSections
  , updateSections
    -- * Low level constants
  , elfMagic
  , sizeOfPhdr32
  , sizeOfShdr32
  , ElfWidth
    -- * Operations that require layout information
  , ElfSegmentUpdater(..)
  , updateElfLoadableSegment
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
import qualified Data.Map as Map
import           Data.Monoid
import qualified Data.Sequence as Seq
import           Data.Word

import           Data.Elf.SizedBuilder (Builder)
import qualified Data.Elf.SizedBuilder as U
import           Data.Elf.Types

------------------------------------------------------------------------
-- Utilities

safeFromIntegral :: (Integral r, Integral w) => w -> Maybe r
safeFromIntegral v
    | fromIntegral r == v = Just r
    | otherwise = Nothing
  where r = fromIntegral v

-- | @fixAlignment v a@ returns the smallest multiple of @a@
-- that is not less than @v@.
fixAlignment :: Integral w => w -> w -> w
fixAlignment v 0 = v
fixAlignment v 1 = v
fixAlignment v a0
    | m == 0 = c * a
    | otherwise = (c + 1) * a
  where a = fromIntegral a0
        (c,m) = v `divMod` a

-- | Traverse elements in a list and modify or delete them.
updateSeq :: Traversal (Seq.Seq a) (Seq.Seq b) a (Maybe b)
updateSeq f l0 =
  case Seq.viewl l0 of
    Seq.EmptyL -> pure Seq.empty
    h Seq.:< l -> compose <$> f h <*> updateSeq f l
      where compose Nothing  r = r
            compose (Just e) r = e Seq.<| r

bldPad :: Integral w => w -> Bld.Builder
bldPad sz = Bld.lazyByteString (L.replicate sz' 0)
  where Just sz' = safeFromIntegral sz

------------------------------------------------------------------------
-- ElfGOTSection

elfGotSectionFlags :: (Bits w, Num w) => ElfSectionFlags w
elfGotSectionFlags = shf_write .|. shf_alloc


-- | Convert a GOT section to a standard section.
elfGotSection :: (Bits w, Num w) => ElfGOT w -> ElfSection w
elfGotSection g =
  ElfSection { elfSectionName = elfGotName g
             , elfSectionType = SHT_PROGBITS
             , elfSectionFlags = elfGotSectionFlags
             , elfSectionAddr = elfGotAddr g
             , elfSectionSize = elfGotSize g
             , elfSectionLink = 0
             , elfSectionInfo = 0
             , elfSectionAddrAlign = elfGotAddrAlign g
             , elfSectionEntSize = elfGotEntSize g
             , elfSectionData = elfGotData g
             }

------------------------------------------------------------------------
-- FileOffset

-- | A offset in the file (implemented as a newtype to avoid confusion with virtual addresses)
newtype FileOffset w = FileOffset { fromFileOffset :: w }

startOfFile :: Num w => FileOffset w
startOfFile = FileOffset 0

alignOffset :: Integral w => FileOffset w -> w -> FileOffset w
alignOffset (FileOffset w) a = FileOffset (fixAlignment w a)

incOffset :: Num w => FileOffset w -> w -> FileOffset w
incOffset (FileOffset b) o = FileOffset (b + o)

rangeSize :: (Ord w, Num w) => FileOffset w -> FileOffset w -> w
rangeSize (FileOffset s) (FileOffset e) = assert (e >= s) $ e - s

------------------------------------------------------------------------
-- Phdr

type Phdr w = (ElfSegment w, Range w)

-- | Returns true if the segment should appear before a loadable segment.
isPreloadPhdr :: ElfSegmentType -> Bool
isPreloadPhdr PT_PHDR = True
isPreloadPhdr PT_INTERP = True
isPreloadPhdr _ = False

-- | Compute number of bytes of padding to add to file so that phdr's virtual
-- address is aligned with the file offset correctly.
phdr_padding_count :: (Integral w, Ord w) => ElfSegment w -> FileOffset w -> w
phdr_padding_count s (FileOffset file_pos)
      -- Loadable segments need no padding
    | elfSegmentType s /= PT_LOAD = 0
    | n <= 1 = 0
      -- Increment addr_mod up to file_mod if it can be.
    | file_mod <= addr_mod = addr_mod - file_mod
      -- Otherwise add padding to We
    | otherwise = (n - file_mod) + addr_mod
  where mem_addr = elfSegmentVirtAddr s
        n = elfSegmentAlign s
        file_mod = file_pos `mod` n
        addr_mod = mem_addr `mod` n

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
      , _preLoadPhdrs :: Seq.Seq (Phdr w)
        -- ^ Phdrs that must appear before loadable segments.
      , _phdrs :: Seq.Seq (Phdr w)
        -- ^ Phdrs that not required to appear before loadable segments.
      , _shdrTableOffset :: !(FileOffset w)
        -- ^ Offset to section header table.
      , _shstrndx :: Word16
        -- ^ Index of section for string table.
      , _shdrs :: Seq.Seq Builder
        -- ^ List of section headers found so far.
      }

elfLayoutClass :: ElfLayout w -> ElfClass w
elfLayoutClass = headerClass . elfLayoutHeader

-- | Lens containing size of sections processed so far in layout.
elfOutputSize :: Simple Lens (ElfLayout w) (FileOffset w)
elfOutputSize = lens _elfOutputSize (\s v -> s { _elfOutputSize = v })

phdrTableOffset :: Simple Lens (ElfLayout w) (FileOffset w)
phdrTableOffset = lens _phdrTableOffset (\s v -> s { _phdrTableOffset = v })

preLoadPhdrs :: Simple Lens (ElfLayout w) (Seq.Seq (Phdr w))
preLoadPhdrs = lens _preLoadPhdrs (\s v -> s { _preLoadPhdrs = v })

phdrs :: Simple Lens (ElfLayout w) (Seq.Seq (Phdr w))
phdrs = lens _phdrs (\s v -> s { _phdrs = v })

shdrTableOffset :: Simple Lens (ElfLayout w) (FileOffset w)
shdrTableOffset = lens _shdrTableOffset (\s v -> s { _shdrTableOffset = v })

shstrndx :: Simple Lens (ElfLayout w) Word16
shstrndx = lens _shstrndx (\s v -> s { _shstrndx = v })

shdrs :: Simple Lens (ElfLayout w) (Seq.Seq Builder)
shdrs = lens _shdrs (\s v -> s { _shdrs = v })

-- | Return total size of elf file.
elfLayoutSize :: ElfLayout w -> w
elfLayoutSize l = w
  where FileOffset w = l^.elfOutputSize

allPhdrs :: ElfLayout w -> Seq.Seq (Phdr w)
allPhdrs l = l^.preLoadPhdrs Seq.>< l^.phdrs

-- | Returns number of segments in layout.
phnum :: ElfLayout w -> Word16
phnum l | r < 0 || r > 65536 = error "Number of segments is too large."
        | otherwise          = fromIntegral $ r
  where r = Seq.length (l^.preLoadPhdrs) + Seq.length (l^.phdrs)

-- | Return number of sections in layout.
shnum :: ElfLayout w -> Word16
shnum l | r > 65536 = error "Number of sections is too large."
        | otherwise = fromIntegral r
  where r = Seq.length $ l^.shdrs


------------------------------------------------------------------------
-- ElfField

-- | A component in the field as written.
data ElfField v
  = EFBS Word16 (v -> Builder)
  | EFWord16 (v -> Word16)
  | EFWord32 (v -> Word32)
  | EFWord64 (v -> Word64)

sizeOfField :: ElfField v -> Word16
sizeOfField (EFBS s _)   = s
sizeOfField (EFWord16 _) = 2
sizeOfField (EFWord32 _) = 4
sizeOfField (EFWord64 _) = 8

writeField :: ElfField v -> ElfData -> v -> Builder
writeField (EFBS _ f)   _           = f
writeField (EFWord16 f) ELFDATA2LSB = U.putWord16le . f
writeField (EFWord16 f) ELFDATA2MSB = U.putWord16be . f
writeField (EFWord32 f) ELFDATA2LSB = U.putWord32le . f
writeField (EFWord32 f) ELFDATA2MSB = U.putWord32be . f
writeField (EFWord64 f) ELFDATA2LSB = U.putWord64le . f
writeField (EFWord64 f) ELFDATA2MSB = U.putWord64be . f

cvtBuilder :: Builder -> Bld.Builder
cvtBuilder = Bld.lazyByteString . U.toLazyByteString

writeField2 :: ElfField v -> ElfData -> v -> Bld.Builder
writeField2 (EFBS _   f) _           = cvtBuilder . f
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

writeRecord :: ElfRecord v -> ElfData -> v -> Builder
writeRecord fields d v =
  mconcat $ map (\(_,f) -> writeField f d v) fields

writeRecord2 :: ElfRecord v -> ElfData -> v -> Bld.Builder
writeRecord2 fields d v =
  mconcat $ map (\(_,f) -> writeField2 f d v) fields

------------------------------------------------------------------------
-- ElfWidth


-- | Contains elf file, program header offset, section header offset.
type Ehdr w = (ElfHeader w, ElfLayout w)
-- | Contains Elf section data, name offset, and data offset.
type Shdr w = (ElfSection w, Word32, w)

-- | @ElfWidth w@ is used to capture the constraint that Elf files are
-- either 32 or 64 bit.  It is not meant to be implemented by others.
class (Bits w, Integral w, Show w) => ElfWidth w where
  ehdrFields :: ElfRecord (Ehdr w)
  phdrFields :: ElfRecord (Phdr w)
  shdrFields :: ElfRecord (Shdr w)


------------------------------------------------------------------------
-- elfLayoutBytes

-- | Return the bytes in the Elf file as a lazy bytestring.
elfLayoutBytes2 :: ElfWidth w
                => ElfLayout w
                -> FileOffset w
                -> [ElfDataRegion w]
                -> Bld.Builder
elfLayoutBytes2 _ _ [] = mempty
elfLayoutBytes2 l o (reg:rest) = do
  let e = elfLayoutHeader l
  let d = headerData e
  let o' = nextRegionOffset l o reg
  case reg of
    ElfDataElfHeader -> do
      writeRecord2 ehdrFields d (e,l)
        <> elfLayoutBytes2 l o' rest
    ElfDataSegmentHeaders -> do
      mconcat (writeRecord2 phdrFields d <$> F.toList (allPhdrs l))
        <> elfLayoutBytes2 l o' rest
    ElfDataSegment s -> do
      let sz = phdr_padding_count s o
      bldPad sz
        <> elfLayoutBytes2 l o' (F.toList (elfSegmentData s) ++ rest)
    ElfDataSectionHeaders -> do
      mconcat (cvtBuilder <$> F.toList (l^.shdrs))
        <> elfLayoutBytes2 l o' rest
    ElfDataSectionNameTable -> do
      let s = elfNameTableSection (elfLayoutSectionNameData l)
      elfLayoutSection o s
        <> elfLayoutBytes2 l o' rest
    ElfDataGOT g -> do
      let s = elfGotSection g
      elfLayoutSection o s
        <> elfLayoutBytes2 l o' rest
    ElfDataSection s -> do
      elfLayoutSection o s
        <> elfLayoutBytes2 l o' rest
    ElfDataRaw b -> do
      Bld.byteString b
        <> elfLayoutBytes2 l o' rest

elfLayoutSection :: ElfWidth w
                 => FileOffset w
                 -> ElfSection w
                 -> Bld.Builder
elfLayoutSection o s =
    bldPad (rangeSize o pad_offset')
      <> Bld.byteString dta
  where pad_offset' = alignOffset o (elfSectionAddrAlign s)
        dta = elfSectionData s

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
    ElfDataElfHeader -> o `incOffset` fromIntegral (sizeOfEhdr c)
    ElfDataSegmentHeaders -> o `incOffset` phdr_size
      where phdr_size = fromIntegral (phnum l) * fromIntegral (sizeOfPhdr c)
    ElfDataSegment s -> o `incOffset` phdr_padding_count s o
    ElfDataSectionHeaders -> o `incOffset` sz
      where sz = fromIntegral (shnum l) * fromIntegral (sizeOfShdr c)
    ElfDataSectionNameTable -> nextSectionOffset o s
      where s = elfNameTableSection (elfLayoutSectionNameData l)
    ElfDataGOT g -> nextSectionOffset o s
      where s = elfGotSection g
    ElfDataSection s -> nextSectionOffset o s
    ElfDataRaw b -> o `incOffset` sz
      where sz = fromIntegral (B.length b)

nextSectionOffset :: (Bits w, Integral w) => FileOffset w -> ElfSection w -> FileOffset w
nextSectionOffset o s = pad_offset' `incOffset` data_size
  where pad_offset' =  o `alignOffset` elfSectionAddrAlign s
        dta = elfSectionData s
        data_size = fromIntegral (B.length dta)


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

type StringTable = (Map.Map B.ByteString Word32, Builder)

-- | Insert bytestring in list of strings.
insertString :: StringTable -> B.ByteString -> StringTable
insertString a@(m,b) bs
    | Map.member bs m = a
    | otherwise = (m', b')
  where insertTail i = Map.insertWith (\_n o -> o) (B.drop i bs) offset
          where offset  = fromIntegral (U.length b) + fromIntegral i
        m' = foldr insertTail m (enumCnt 0 (B.length bs + 1))
        b' = b `mappend` U.fromByteString bs `mappend` U.singleton 0

-- | Create a string table from the list of strings, and return list of offsets.
stringTable :: [String] -> (B.ByteString, Map.Map String Word32)
stringTable strings = (res, stringMap)
  where res = B.concat $ L.toChunks (U.toLazyByteString b)
        empty_table = (Map.empty, mempty)
        -- Get list of strings as bytestrings.
        bsl = map B.fromString strings
        -- | Reverses individual bytestrings in list.
        revl = map B.reverse
        -- Compress entries by removing a string if it is the suffix of
        -- another string.
        compress (f:r@(s:_)) | B.isPrefixOf f s = compress r
        compress (f:r) = f:compress r
        compress [] = []
        entries = revl $ compress $ sort $ revl bsl
        -- Insert strings into map (first string must be empty string)
        empty_string = B.fromString ""
        (m,b) = foldl insertString empty_table (empty_string : entries)
        myFind bs =
          case Map.lookup bs m of
            Just v -> v
            Nothing -> error $ "internal: stringTable missing entry."
        stringMap = Map.fromList $ strings `zip` map myFind bsl

------------------------------------------------------------------------
-- Section traversal

-- | Return name of all elf sections.
elfSectionNames :: Elf w -> [String]
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

-- | Traverse elf sections
elfSections' :: (Bits w, Num w) => Simple Traversal (Elf w) (ElfSection w)
elfSections' f = updateSections' (fmap Just . f)

------------------------------------------------------------------------
-- Section Elf Layout

-- | Add section information to layout.
addSectionToLayout :: ElfWidth w
                   => ElfData
                   -> Map.Map String Word32 -- ^ Name to offset map.
                   -> ElfLayout w
                   -> ElfSection w
                   -> ElfLayout w
addSectionToLayout d name_map l s =
    l & elfOutputSize %~ (`incOffset` rangeSize base o)
      & shdrs %~ (Seq.|> writeRecord shdrFields d (s, no, fromFileOffset o))
  where Just no = Map.lookup (elfSectionName s) name_map
        base =  l^.elfOutputSize
        o    = base `alignOffset` elfSectionAddrAlign s

------------------------------------------------------------------------
-- elfLayout

addRelroToLayout :: Num w => Maybe (Range w) -> ElfLayout w -> ElfLayout w
addRelroToLayout Nothing l = l
addRelroToLayout (Just (f,c)) l = l & phdrs %~ (Seq.|> (s, (f,c)))
  where s = ElfSegment { elfSegmentType = PT_GNU_RELRO
                       , elfSegmentFlags = pf_r
                       , elfSegmentVirtAddr = f
                       , elfSegmentPhysAddr = f
                       , elfSegmentAlign = 1
                       , elfSegmentMemSize = c
                       , elfSegmentData = Seq.empty
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

-- | Return layout information from elf file.
elfLayout' :: forall w . ElfWidth w => Elf w -> ElfLayout w
elfLayout' e = initl & flip (foldl impl) (e^.elfFileData)
                     & addRelroToLayout (elfRelroRange e)
  where c = elfClass e
        d = elfData e
        (name_data,name_map) = stringTable $
          elfSectionName <$> toListOf elfSections' e

        phdr_cnt = elfSegmentCount e
        shdr_cnt = elfSectionCount e

        initl = ElfLayout { elfLayoutHeader = elfHeader e
                          , elfLayoutRegions = e^.elfFileData
                          , elfLayoutSectionNameData = name_data
                          , _elfOutputSize = startOfFile
                          , _phdrTableOffset = startOfFile
                          , _preLoadPhdrs = Seq.empty
                          , _phdrs = Seq.empty
                          , _shdrTableOffset = startOfFile
                          , _shstrndx = 0
                          , _shdrs = Seq.empty
                          }

        -- Process element.
        impl :: ElfWidth w => ElfLayout w -> ElfDataRegion w -> ElfLayout w
        impl l ElfDataElfHeader =
             l & elfOutputSize %~ (`incOffset` (fromIntegral (sizeOfEhdr c)))
        impl l ElfDataSegmentHeaders =
             l & elfOutputSize %~ (`incOffset` phdr_size)
               & phdrTableOffset .~ l^.elfOutputSize
          where phdr_size = fromIntegral phdr_cnt * fromIntegral (sizeOfPhdr c)
        impl l (ElfDataSegment s) = l3
          where cnt = phdr_padding_count s (l^.elfOutputSize)

                -- Add padding so that offset will be congruent to virtual address
                -- This will be zero if segment is not loadable.
                l1 = l & elfOutputSize %~ (`incOffset` cnt)

                -- Update layout by folding over segment data.
                l2 :: ElfLayout w
                l2 = l1 & flip (foldl impl) (elfSegmentData s)
                -- Get bytes at start of elf
                seg_offset = l1^.elfOutputSize
                seg_size   = rangeSize seg_offset (l2^.elfOutputSize)
                -- Add segment to appropriate
                l3 :: ElfLayout w
                l3 | isPreloadPhdr (elfSegmentType s)
                   = l2 & preLoadPhdrs %~ (Seq.|> (s, (fromFileOffset seg_offset, seg_size)))
                   | otherwise
                   = l2 & phdrs        %~ (Seq.|> (s, (fromFileOffset seg_offset, seg_size)))
        impl l ElfDataSectionHeaders =
             l & elfOutputSize   %~ (`incOffset` shdr_size)
               & shdrTableOffset .~ l^.elfOutputSize
          where shdr_size = fromIntegral shdr_cnt * fromIntegral (sizeOfShdr c)
        impl l ElfDataSectionNameTable =
            addSectionToLayout d name_map l' s
          where l' = l & shstrndx .~ shnum l
                s  = elfNameTableSection name_data
        impl l (ElfDataGOT g) = addSectionToLayout d name_map l (elfGotSection g)
        impl l (ElfDataSection s) = addSectionToLayout d name_map l s
        impl l (ElfDataRaw b) = l & elfOutputSize %~ (`incOffset` fromIntegral (B.length b))

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

------------------------------------------------------------------------
-- Elf Width instances

elfMagic :: B.ByteString
elfMagic = B.fromString "\DELELF"

elfIdentBuilder :: ElfHeader w -> Builder
elfIdentBuilder e =
  mconcat [ U.fromByteString elfMagic
          , U.singleton (fromElfClass (headerClass e))
          , U.singleton (fromElfData  (headerData e))
          , U.singleton expectedElfVersion
          , U.singleton (fromElfOSABI (headerOSABI e))
          , U.singleton (fromIntegral (headerABIVersion e))
          , mconcat (replicate 7 (U.singleton 0))
          ]

sizeOfEhdr32 :: Word16
sizeOfEhdr32 = sizeOfRecord ehdr32Fields

sizeOfEhdr64 :: Word16
sizeOfEhdr64 = sizeOfRecord ehdr64Fields

sizeOfPhdr32 :: Word16
sizeOfPhdr32 = sizeOfRecord phdr32Fields

sizeOfPhdr64 :: Word16
sizeOfPhdr64 = sizeOfRecord phdr64Fields

sizeOfShdr32 :: Word16
sizeOfShdr32 = sizeOfRecord shdr32Fields

sizeOfShdr64 :: Word16
sizeOfShdr64 = sizeOfRecord shdr64Fields

sizeOfEhdr :: ElfClass w -> Word16
sizeOfEhdr ELFCLASS32 = sizeOfEhdr32
sizeOfEhdr ELFCLASS64 = sizeOfEhdr64

sizeOfPhdr :: ElfClass w -> Word16
sizeOfPhdr ELFCLASS32 = sizeOfPhdr32
sizeOfPhdr ELFCLASS64 = sizeOfPhdr64

sizeOfShdr :: ElfClass w -> Word16
sizeOfShdr ELFCLASS32 = sizeOfShdr32
sizeOfShdr ELFCLASS64 = sizeOfShdr64

ehdr32Fields :: ElfRecord (Ehdr Word32)
ehdr32Fields =
  [ ("e_ident",     EFBS 16  $ \(e,_) -> elfIdentBuilder e)
  , ("e_type",      EFWord16 $ \(e,_) -> fromElfType    $ headerType e)
  , ("e_machine",   EFWord16 $ \(e,_) -> fromElfMachine $ headerMachine e)
  , ("e_version",   EFWord32 $ \_     -> fromIntegral expectedElfVersion)
  , ("e_entry",     EFWord32 $ \(e,_) -> headerEntry e)
  , ("e_phoff",     EFWord32 $ \(_,l) -> fromFileOffset $ l^.phdrTableOffset)
  , ("e_shoff",     EFWord32 $ \(_,l) -> fromFileOffset $ l^.shdrTableOffset)
  , ("e_flags",     EFWord32 $ \(e,_) -> headerFlags e)
  , ("e_ehsize",    EFWord16 $ \_     -> sizeOfEhdr32)
  , ("e_phentsize", EFWord16 $ \_     -> sizeOfPhdr32)
  , ("e_phnum",     EFWord16 $ \(_,l) -> phnum l)
  , ("e_shentsize", EFWord16 $ \_     -> sizeOfShdr32)
  , ("e_shnum",     EFWord16 $ \(_,l) -> shnum l)
  , ("e_shstrndx",  EFWord16 $ \(_,l) -> l^.shstrndx)
  ]

ehdr64Fields :: ElfRecord (Ehdr Word64)
ehdr64Fields =
  [ ("e_ident",     EFBS 16  $ \(e,_) -> elfIdentBuilder e)
  , ("e_type",      EFWord16 $ \(e,_) -> fromElfType $ headerType e)
  , ("e_machine",   EFWord16 $ \(e,_) -> fromElfMachine $ headerMachine e)
  , ("e_version",   EFWord32 $ \_     -> fromIntegral expectedElfVersion)
  , ("e_entry",     EFWord64 $ \(e,_) -> headerEntry e)
  , ("e_phoff",     EFWord64 $ \(_,l) -> fromFileOffset $ l^.phdrTableOffset)
  , ("e_shoff",     EFWord64 $ \(_,l) -> fromFileOffset $ l^.shdrTableOffset)
  , ("e_flags",     EFWord32 $ \(e,_) -> headerFlags e)
  , ("e_ehsize",    EFWord16 $ \_     -> sizeOfEhdr64)
  , ("e_phentsize", EFWord16 $ \_     -> sizeOfPhdr64)
  , ("e_phnum",     EFWord16 $ \(_,l) -> phnum l)
  , ("e_shentsize", EFWord16 $ \_     -> sizeOfShdr64)
  , ("e_shnum",     EFWord16 $ \(_,l) -> shnum l)
  , ("e_shstrndx",  EFWord16 $ \(_,l) -> l^.shstrndx)
  ]

phdr32Fields :: ElfRecord (Phdr Word32)
phdr32Fields =
  [ ("p_type",   EFWord32 $ view $ _1 . to elfSegmentType . to fromElfSegmentType)
  , ("p_offset", EFWord32 $ view $ _2 . _1)
  , ("p_vaddr",  EFWord32 $ view $ _1 . to elfSegmentVirtAddr)
  , ("p_paddr",  EFWord32 $ view $ _1 . to elfSegmentPhysAddr)
  , ("p_filesz", EFWord32 $ view $ _2 . _2)
  , ("p_memsz",  EFWord32 $ view $ _1 . to elfSegmentMemSize)
  , ("p_flags",  EFWord32 $ view $ _1 . to elfSegmentFlags . to fromElfSegmentFlags)
  , ("p_align",  EFWord32 $ view $ _1 . to elfSegmentAlign)
  ]

phdr64Fields :: ElfRecord (Phdr Word64)
phdr64Fields =
  [ ("p_type",   EFWord32 $ view $ _1 . to elfSegmentType . to fromElfSegmentType)
  , ("p_flags",  EFWord32 $ view $ _1 . to elfSegmentFlags . to fromElfSegmentFlags)
  , ("p_offset", EFWord64 $ view $ _2 . _1)
  , ("p_vaddr",  EFWord64 $ view $ _1 . to elfSegmentVirtAddr)
  , ("p_paddr",  EFWord64 $ view $ _1 . to elfSegmentPhysAddr)
  , ("p_filesz", EFWord64 $ view $ _2 . _2)
  , ("p_memsz",  EFWord64 $ view $ _1 . to elfSegmentMemSize)
  , ("p_align",  EFWord64 $ view $ _1 . to elfSegmentAlign)
  ]

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

instance ElfWidth Word32 where
  ehdrFields = ehdr32Fields
  phdrFields = phdr32Fields
  shdrFields = shdr32Fields

-- | Gets a single entry from the symbol table, use with runGetMany.
instance ElfWidth Word64 where
  ehdrFields = ehdr64Fields
  phdrFields = phdr64Fields
  shdrFields = shdr64Fields

elfClassElfWidthInstance :: ElfClass w -> (ElfWidth w => a) -> a
elfClassElfWidthInstance ELFCLASS32 a = a
elfClassElfWidthInstance ELFCLASS64 a = a

-- | Return the bytes in the Elf file as a lazy bytestring.
elfLayoutBytes :: ElfLayout w -> L.ByteString
elfLayoutBytes l = elfClassElfWidthInstance (elfLayoutClass l) $
    Bld.toLazyByteString $ elfLayoutBytes2 l startOfFile regions
  where regions = F.toList (elfLayoutRegions l)


------------------------------------------------------------------------
-- elfLayout

-- | Traverse sections in Elf file and modify or delete them.
updateSections :: Traversal (Elf w) (Elf w) (ElfSection w) (Maybe (ElfSection w))
updateSections fn e0 = elfClassElfWidthInstance (elfClass e0) $
  updateSections' fn e0

-- | Traverse elf sections
elfSections :: Simple Traversal (Elf w) (ElfSection w)
elfSections f = updateSections (fmap Just . f)

-- | Return layout information from elf file.
elfLayout :: Elf w -> ElfLayout w
elfLayout e = elfClassElfWidthInstance (elfClass e) $ elfLayout' e

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
