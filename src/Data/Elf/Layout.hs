{-# LANGUAGE GADTs #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Data.Elf.Layout
  ( -- * ElfLayout
    ElfLayout
  , elfLayoutClass
  , elfOutput
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
  ) where

import           Control.Lens hiding (enum)
import           Control.Monad
import           Data.Bits
import qualified Data.ByteString as B
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

------------------------------------------------------------------------
-- Phdr

-- | An elf segment and its layout.
type Phdr w = (ElfSegment w, Range w)

-- | Returns true if the segment should appear before a loadable segment.
isPreloadPhdr :: ElfSegmentType -> Bool
isPreloadPhdr PT_PHDR = True
isPreloadPhdr PT_INTERP = True
isPreloadPhdr _ = False

-- | Compute number of bytes of padding to add to file.
phdr_padding_count :: (Integral w, Ord w) => ElfSegment w -> w -> w
phdr_padding_count s file_pos
    | n <= 1 = 0
      -- Increment addr_mod up to file_mod if it can be.
    | file_mod <= addr_mod = addr_mod - file_mod
      -- Otherwise add padding to We
    | otherwise = (n - file_mod) + addr_mod
  where mem_addr = elfSegmentVirtAddr s
        n = elfSegmentAlign s
        file_mod  = file_pos `mod` n
        addr_mod = mem_addr `mod` n

------------------------------------------------------------------------
-- ElfLayout

-- | This provides information about the layout of an Elf file.
--
-- It can be used to obtain precise information about Elf file layout.
data ElfLayout w = ElfLayout {
        elfLayoutClass :: !(ElfClass w)
        -- ^ Class for elf layout
      , _elfOutput :: Builder
        -- ^ Elf output
      , _phdrTableOffset :: w
        -- ^ Offset to phdr table.
      , _preLoadPhdrs :: Seq.Seq (Phdr w)
        -- ^ Phdrs that must appear before loadable segments.
      , _phdrs :: Seq.Seq (Phdr w)
        -- ^ Phdrs that not required to appear before loadable segments.
      , _shdrTableOffset :: w
        -- ^ Offset to section header table.
      , _shstrndx :: Word16
        -- ^ Index of section for string table.
      , _shdrs :: Seq.Seq Builder
        -- ^ List of section headers found so far.
      }

-- | Lens containing all data for an Elf file.
elfOutput :: Simple Lens (ElfLayout w) Builder
elfOutput = lens _elfOutput (\s v -> s { _elfOutput = v })

phdrTableOffset :: Simple Lens (ElfLayout w) w
phdrTableOffset = lens _phdrTableOffset (\s v -> s { _phdrTableOffset = v })

preLoadPhdrs :: Simple Lens (ElfLayout w) (Seq.Seq (Phdr w))
preLoadPhdrs = lens _preLoadPhdrs (\s v -> s { _preLoadPhdrs = v })

phdrs :: Simple Lens (ElfLayout w) (Seq.Seq (Phdr w))
phdrs = lens _phdrs (\s v -> s { _phdrs = v })

shdrTableOffset :: Simple Lens (ElfLayout w) w
shdrTableOffset = lens _phdrTableOffset (\s v -> s { _phdrTableOffset = v })

shstrndx :: Simple Lens (ElfLayout w) Word16
shstrndx = lens _shstrndx (\s v -> s { _shstrndx = v })

shdrs :: Simple Lens (ElfLayout w) (Seq.Seq Builder)
shdrs = lens _shdrs (\s v -> s { _shdrs = v })

-- | Return the bytes in the Elf file as a lazy bytestring.
elfLayoutBytes :: ElfLayout w -> L.ByteString
elfLayoutBytes l = U.toLazyByteString (l^.elfOutput)

-- | Return total size of elf file.
elfLayoutSize :: ElfLayout w -> w
elfLayoutSize l = elfClassIntegralInstance (elfLayoutClass l) $
  case safeFromIntegral (U.length (l^.elfOutput)) of
    Just r -> r
    Nothing -> error "Output is too large."

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

------------------------------------------------------------------------
-- ElfRecord

-- | A record to be written to the Elf file.
type ElfRecord v = [(String, ElfField v)]

sizeOfRecord :: ElfRecord v -> Word16
sizeOfRecord = sum . map (sizeOfField . snd)

writeRecord :: ElfRecord v -> ElfData -> v -> Builder
writeRecord fields d v =
  mconcat $ map (\(_,f) -> writeField f d v) fields

------------------------------------------------------------------------
-- ElfWidth


-- | Contains elf file, program header offset, section header offset.
type Ehdr w = (Elf w, ElfLayout w)
-- | Contains Elf section data, name offset, and data offset.
type Shdr w = (ElfSection w, Word32, w)

-- | @ElfWidth w@ is used to capture the constraint that Elf files are
-- either 32 or 64 bit.  It is not meant to be implemented by others.
class (Bits w, Integral w, Show w) => ElfWidth w where
  ehdrFields :: ElfRecord (Ehdr w)
  phdrFields :: ElfRecord (Phdr w)
  shdrFields :: ElfRecord (Shdr w)

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
          concatMap regionNames (F.toList (s^.elfSegmentData))
        regionNames ElfDataSectionNameTable = [shstrtab]
        regionNames (ElfDataGOT g)          = [elfGotName g]
        regionNames (ElfDataSection s)      = [elfSectionName s]
        regionNames _                       = []

-- | Traverse sections in Elf file and modify or delete them.
updateSections' :: (Bits w, Num w)
                => Traversal (Elf w) (Elf w) (ElfSection w) (Maybe (ElfSection w))
updateSections' fn e0 = elfFileData (updateSeq impl) e0
  where (t,_) = stringTable $ elfSectionNames e0
        norm :: (Bits w, Num w) => ElfSection w -> ElfDataRegion w
        norm s
          | elfSectionName s == shstrtab = ElfDataSectionNameTable
          | elfSectionName s `elem` [".got", ".got.plt"] =
            case elfSectionAsGOT s of
              Left e -> error $ "Error in Data.Elf.updateSections: " ++ e
              Right v -> ElfDataGOT v
          | otherwise = ElfDataSection s

        impl (ElfDataSegment s) = Just . ElfDataSegment <$> s'
          where s' = s & elfSegmentData (updateSeq impl)
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
    l & elfOutput <>~ pad <> fn
      & shdrs %~ (Seq.|> writeRecord shdrFields d (s,no, o))
  where Just no = Map.lookup (elfSectionName s) name_map
        base = elfLayoutSize l
        o = fixAlignment base (elfSectionAddrAlign s)
        pad = U.fromByteString (B.replicate (fromIntegral (o - base)) 0)
        fn  = U.fromByteString (elfSectionData s)

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
                       , _elfSegmentData = Seq.empty
                       }

-- | Return layout information from elf file.
elfLayout' :: forall w . ElfWidth w => Elf w -> ElfLayout w
elfLayout' e = final
  where d = elfData e
        section_names = map elfSectionName $ toListOf elfSections' e
        (name_data,name_map) = stringTable section_names
        initl = ElfLayout { elfLayoutClass = elfClass e
                          , _elfOutput = mempty
                          , _phdrTableOffset = 0
                          , _preLoadPhdrs = Seq.empty
                          , _phdrs = Seq.empty
                          , _shdrTableOffset = 0
                          , _shstrndx = 0
                          , _shdrs = Seq.empty
                          }
        -- Get final elf layout after processing elements.
        final0 = foldl impl initl (e^.elfFileData)
        -- Add relro information if needed.
        final = addRelroToLayout (elfRelroRange e) final0

        -- Process element.
        impl :: ElfWidth w => ElfLayout w -> ElfDataRegion w -> ElfLayout w
        impl l ElfDataElfHeader =
             l & elfOutput <>~ writeRecord ehdrFields d (e,final)
        impl l ElfDataSegmentHeaders =
             l & elfOutput <>~ headers
               & phdrTableOffset .~ elfLayoutSize l
          where headers = mconcat (writeRecord phdrFields d <$> F.toList (allPhdrs final))
        impl l (ElfDataSegment s) = l3
          where l1 = case elfSegmentType s of
                       -- Add padding so that offset will be congruent to virtual address.
                       PT_LOAD | cnt > 0 -> l & elfOutput <>~ padding
                         where cnt = phdr_padding_count s (elfLayoutSize l1)
                               Just cnt' = safeFromIntegral cnt
                               padding = U.fromLazyByteString $ L.replicate cnt' 0
                       -- No padding is needed.
                       _ -> l

                -- Update layout by folding over segment data.
                l2 :: ElfLayout w
                l2 = l1 & flip (foldl impl) (s^.elfSegmentData)
                -- Get bytes at start of elf
                seg_offset = elfLayoutSize l1
                seg_size   = elfLayoutSize l2 - seg_offset
                -- Add segment to appropriate
                l3 :: ElfLayout w
                l3 | isPreloadPhdr (elfSegmentType s)
                   = l2 & preLoadPhdrs %~ (Seq.|> (s, (seg_offset, seg_size)))
                   | otherwise
                   = l2 & phdrs        %~ (Seq.|> (s, (seg_offset, seg_size)))
        impl l ElfDataSectionHeaders =
             l & elfOutput <>~ mconcat (F.toList (final^.shdrs))
               & shdrTableOffset .~ elfLayoutSize l
        impl l ElfDataSectionNameTable = impl l' (ElfDataSection s)
          where l' = l & shstrndx .~ shnum l
                s  = elfNameTableSection name_data
        impl l (ElfDataGOT g) = addSectionToLayout d name_map l (elfGotSection g)
        impl l (ElfDataSection s) = addSectionToLayout d name_map l s
        impl l (ElfDataRaw b) = l & elfOutput <>~ U.fromByteString b

------------------------------------------------------------------------
-- Elf Width instances

elfMagic :: B.ByteString
elfMagic = B.fromString "\DELELF"

elfIdentBuilder :: ElfWidth w  => Elf w -> Builder
elfIdentBuilder e =
  mconcat [ U.fromByteString elfMagic
          , U.singleton (fromElfClass (elfClass e))
          , U.singleton (fromElfData (elfData e))
          , U.singleton (elfVersion e)
          , U.singleton (fromElfOSABI (elfOSABI e))
          , U.singleton (fromIntegral (elfABIVersion e))
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

ehdr32Fields :: ElfRecord (Ehdr Word32)
ehdr32Fields =
  [ ("e_ident",     EFBS 16  (\(e,_) -> elfIdentBuilder e))
  , ("e_type",      EFWord16 (\(e,_) -> fromElfType    $ elfType e))
  , ("e_machine",   EFWord16 (\(e,_) -> fromElfMachine $ elfMachine e))
  , ("e_version",   EFWord32 (\(e,_) -> fromIntegral   $ elfVersion e))
  , ("e_entry",     EFWord32 (\(e,_) -> elfEntry e))
  , ("e_phoff",     EFWord32 (view (_2.phdrTableOffset)))
  , ("e_shoff",     EFWord32 (view (_2.shdrTableOffset)))
  , ("e_flags",     EFWord32 (\(e,_) -> elfFlags e))
  , ("e_ehsize",    EFWord16 (\(_,_) -> sizeOfEhdr32))
  , ("e_phentsize", EFWord16 (\(_,_) -> sizeOfPhdr32))
  , ("e_phnum",     EFWord16 (\(_,l) -> phnum l))
  , ("e_shentsize", EFWord16 (\(_,_) -> sizeOfShdr32))
  , ("e_shnum",     EFWord16 (\(_,l) -> shnum l))
  , ("e_shstrndx",  EFWord16 (view $ _2.shstrndx))
  ]

ehdr64Fields :: ElfRecord (Ehdr Word64)
ehdr64Fields =
  [ ("e_ident",     EFBS 16  $ elfIdentBuilder . fst)
  , ("e_type",      EFWord16 $ fromElfType . elfType . fst)
  , ("e_machine",   EFWord16 $ fromElfMachine . elfMachine . fst)
  , ("e_version",   EFWord32 $ fromIntegral . elfVersion . fst)
  , ("e_entry",     EFWord64 $ view $ _1.to elfEntry)
  , ("e_phoff",     EFWord64 $ view $ _2.phdrTableOffset)
  , ("e_shoff",     EFWord64 $ view $ _2.shdrTableOffset)
  , ("e_flags",     EFWord32 $ view $ _1.to elfFlags)
  , ("e_ehsize",    EFWord16 $ const sizeOfEhdr64)
  , ("e_phentsize", EFWord16 $ const sizeOfPhdr64)
  , ("e_phnum",     EFWord16 $ view $ _2.to phnum)
  , ("e_shentsize", EFWord16 $ const sizeOfShdr64)
  , ("e_shnum",     EFWord16 $ view $ _2.to shnum)
  , ("e_shstrndx",  EFWord16 $ view $ _2.shstrndx)
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
