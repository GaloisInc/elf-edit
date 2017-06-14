{-|
Module           : Data.ElfEdit.Layout
Copyright        : (c) Galois, Inc 2016
Maintainer       : Joe Hendrix <jhendrix@galois.com>
License          : BSD3

This defines the 'ElfLayout' class which is used for writing elf files.
-}
{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE Trustworthy #-} -- Use Control.Lens and Data.Vector
{-# LANGUAGE UndecidableInstances #-}
module Data.ElfEdit.Layout
  ( -- * ElfLayout
    ElfLayout
  , elfLayoutClass
  , elfLayoutData
  , Phdr(..)
  , phdrFileRange
  , phdrs
  , allPhdrs
  , Shdr
  , shdrs
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
  , traverseElfDataRegions
  , updateSegments
    -- * Low level constants
  , elfMagic
  , ehdrSize
  , phdrEntrySize
  , shdrEntrySize
  , FileOffset(..)
  , stringTable
  , strtabSection
  , symbolTableEntrySize
  , symbolTableSize
    -- * Utilities
  , putWord16
  , putWord32
  , putWord64
  ) where

import           Control.Exception (assert)
import           Control.Lens hiding (enum)
import           Control.Monad
import           Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Builder as Bld
import qualified Data.ByteString.Lazy as L
import qualified Data.Foldable as F
import           Data.List (sort)
import           Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import           Data.Maybe
import           Data.Monoid
import qualified Data.Sequence as Seq
import qualified Data.Vector as V
import           Data.Word
import           Numeric

import           Data.ElfEdit.Enums
import           Data.ElfEdit.Types

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
                   , phdrFileStart :: !(FileOffset (ElfWordType w))
                   , phdrFileSize  :: !(ElfWordType w)
                   , phdrMemSize   :: !(ElfWordType w)
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
fixedHex n v | v >= 0    = alignRight n '0' s
             | otherwise = error "fixedHex given negative value"
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

instance (Integral (ElfWordType w)) => Show (Phdr w) where
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
                 , fixedHex 0 (toInteger (elfSegmentAlign seg))
                 ]

phdrFileRange :: Phdr w -> Range (ElfWordType w)
phdrFileRange phdr = (fromFileOffset (phdrFileStart phdr), phdrFileSize phdr)

------------------------------------------------------------------------
-- Shdr

-- | Contains Elf section data, name offset, and data offset.
type Shdr w = (ElfSection (ElfWordType w), Word32, ElfWordType w)

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
      , elfLayoutSectionNameData :: !B.ByteString
        -- ^ Contents of section name table data.
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
      , _shdrs :: !(Map Word16 (Shdr w))
        -- ^ Map each section index to the section header entry for that section.
      }

elfLayoutClass :: ElfLayout w -> ElfClass w
elfLayoutClass = headerClass . elfLayoutHeader

elfLayoutData :: ElfLayout w -> ElfData
elfLayoutData = headerData . elfLayoutHeader

-- | Lens containing size of sections processed so far in layout.
elfOutputSize :: Simple Lens (ElfLayout w) (FileOffset (ElfWordType w))
elfOutputSize = lens _elfOutputSize (\s v -> s { _elfOutputSize = v })

phdrTableOffset :: Simple Lens (ElfLayout w) (FileOffset (ElfWordType w))
phdrTableOffset = lens _phdrTableOffset (\s v -> s { _phdrTableOffset = v })

phdrs :: Simple Lens (ElfLayout w) (Map Word16 (Phdr w))
phdrs = lens _phdrs (\s v -> s { _phdrs = v })

shdrTableOffset :: Simple Lens (ElfLayout w) (FileOffset (ElfWordType w))
shdrTableOffset = lens _shdrTableOffset (\s v -> s { _shdrTableOffset = v })

shstrndx :: Simple Lens (ElfLayout w) Word16
shstrndx = lens _shstrndx (\s v -> s { _shstrndx = v })

shdrs :: Simple Lens (ElfLayout w) (Map Word16 (Shdr w))
shdrs = lens _shdrs (\s v -> s { _shdrs = v })

-- | Return total size of elf file.
elfLayoutSize :: ElfLayout w -> ElfWordType w
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
  where r = Map.size $ l^.shdrs

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
writeField2 (EFBS _   f) _ = f
writeField2 (EFWord16 f) d = putWord16 d . f
writeField2 (EFWord32 f) d = putWord32 d . f
writeField2 (EFWord64 f) d = putWord64 d . f

-- | Convert 'Word16' to data using appropriate endianess.
putWord16 :: ElfData -> Word16 -> Bld.Builder
putWord16 ELFDATA2LSB = Bld.word16LE
putWord16 ELFDATA2MSB = Bld.word16BE

-- | Convert 'Word32' to data using appropriate endianess.
putWord32 :: ElfData -> Word32 -> Bld.Builder
putWord32 ELFDATA2LSB = Bld.word32LE
putWord32 ELFDATA2MSB = Bld.word32BE

-- | Convert 'Word64' to data using appropriate endianess.
putWord64 :: ElfData -> Word64 -> Bld.Builder
putWord64 ELFDATA2LSB = Bld.word64LE
putWord64 ELFDATA2MSB = Bld.word64BE

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

------------------------------------------------------------------------
-- Symbol table

symbolTableEntrySize :: ElfClass w -> ElfWordType w
symbolTableEntrySize ELFCLASS32 = 16
symbolTableEntrySize ELFCLASS64 = 24

-- | Get size of symbol table
symbolTableSize :: ElfClass w -> ElfSymbolTable (ElfWordType w) -> ElfWordType w
symbolTableSize c symtab = elfClassInstances c $
  let cnt = fromIntegral $ V.length $ elfSymbolTableEntries symtab
   in symbolTableEntrySize c * cnt

-- | Write a symbol table entry to a builder
renderSymbolTableEntry :: ElfClass w
                       -> ElfData
                       -> (B.ByteString -> Word32)
                          -- ^ Function that maps a bytestring to the index associated with it.
                       -> ElfSymbolTableEntry (ElfWordType w)
                       -> Bld.Builder
renderSymbolTableEntry ELFCLASS32 d = \nameFn s ->
    putWord32 d (nameFn (steName s))
    <> putWord32 d (steValue s)
    <> putWord32 d (steSize  s)
    <> Bld.word8 (typeAndBindToInfo (steType s) (steBind s))
    <> Bld.word8 (steOther s)
    <> putWord16 d (fromElfSectionIndex (steIndex s))
renderSymbolTableEntry ELFCLASS64 d = \nameFn s ->
  putWord32 d (nameFn (steName s))
  <> Bld.word8 (typeAndBindToInfo (steType s) (steBind s))
  <> Bld.word8 (steOther s)
  <> putWord16 d (fromElfSectionIndex (steIndex s))
  <> putWord64 d (steValue s)
  <> putWord64 d (steSize  s)


-- | Create an elf section for symbol table and string table of symbol names.
symtabData :: ElfClass w
           -> ElfData
           -> Map B.ByteString Word32
              -- ^ Maps symbol table names to offset.
           -> ElfSymbolTable (ElfWordType w) -- ^ The symbol table
           -> Bld.Builder
symtabData cl d name_map symtab = bld
  where entries = elfSymbolTableEntries symtab
        nameFn nm =
          case Map.lookup nm name_map of
            Just name_idx -> name_idx
            Nothing -> error "internal: symtabData given undefined symbol name."
        bld = mconcat $ V.toList $ renderSymbolTableEntry cl d nameFn <$> entries

-- | Create an elf section for symbol table and string table of symbol names.
symtabSection :: ElfClass w
              -> ElfData
              -> Map B.ByteString Word32
              -> Word16 -- ^ Index of string table for symbol names
              -> ElfSymbolTable (ElfWordType w) -- ^ The symbol table
              -> ElfSection (ElfWordType w)
symtabSection cl d name_map this_strtab_idx symtab = s
  where bld = symtabData cl d name_map symtab
        dta = L.toStrict $ Bld.toLazyByteString bld
        s = elfClassInstances cl $
            ElfSection { elfSectionIndex = elfSymbolTableIndex symtab
                       , elfSectionName  = ".symtab"
                       , elfSectionType  = SHT_SYMTAB
                       , elfSectionFlags = shf_none
                       , elfSectionAddr  = 0
                       , elfSectionSize  = fromIntegral (B.length dta)
                       , elfSectionLink  = fromIntegral this_strtab_idx
                       , elfSectionInfo  = elfSymbolTableLocalEntries symtab
                       , elfSectionAddrAlign = 8
                       , elfSectionEntSize = symbolTableEntrySize cl
                       , elfSectionData = dta
                       }

------------------------------------------------------------------------
-- elfLayoutBytes

-- | Render the main ELF header.
buildElfHeader :: ElfLayout w -> Bld.Builder
buildElfHeader l = writeRecord2 (ehdrFields (headerClass hdr)) d l
  where hdr = elfLayoutHeader l
        d = headerData hdr

-- | Render the ELF segment header table.
buildElfSegmentHeaderTable :: ElfLayout w -> Bld.Builder
buildElfSegmentHeaderTable l =
    mconcat $ writeRecord2 (phdrFields (headerClass hdr)) d <$> allPhdrs l
  where hdr = elfLayoutHeader l
        d = headerData hdr

-- | Render the ELF section header table.
buildElfSectionHeaderTable :: ElfLayout w -> Bld.Builder
buildElfSectionHeaderTable l = mconcat (f <$> Map.elems (l^.shdrs))
  where f  = writeRecord2 (shdrFields cl) d
        d  = headerData (elfLayoutHeader l)
        cl = headerClass (elfLayoutHeader l)

-- | Render the given list of regions at a particular file offeset.
buildRegions :: ElfWidthConstraints w
             => ElfLayout w
             -> FileOffset (ElfWordType w)
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
    ElfDataSectionNameTable _ ->
      Bld.byteString (elfLayoutSectionNameData l)
        <> buildRegions l o' rest
    ElfDataGOT g ->
      Bld.byteString (elfGotData g)
        <> buildRegions l o' rest
    ElfDataStrtab _ ->
      Bld.byteString (strtab_data l)
        <> buildRegions l o' rest
    ElfDataSymtab symtab ->
        symtabData (headerClass h) (headerData h) (strtab_map l) symtab
          <> buildRegions l o' rest
      where h = elfLayoutHeader l
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
nextRegionOffset :: ElfLayout w
                 -> FileOffset (ElfWordType w)
                 -> ElfDataRegion w
                 -> FileOffset (ElfWordType w)
nextRegionOffset l o reg = elfClassInstances (elfLayoutClass l) $ do
  let e = elfLayoutHeader l
  let c = headerClass e
  case reg of
    ElfDataElfHeader      -> o `incOffset` fromIntegral (ehdrSize c)
    ElfDataSegmentHeaders -> o `incOffset` phdr_size
      where phdr_size = fromIntegral (phnum l) * fromIntegral (phdrEntrySize c)
    ElfDataSegment _ -> o
    ElfDataSectionHeaders -> o `incOffset` sz
      where sz = fromIntegral (shnum l) * fromIntegral (shdrEntrySize c)
    ElfDataSectionNameTable _ -> o `incOffset` fromIntegral (B.length dta)
      where dta = elfLayoutSectionNameData l
    ElfDataGOT g -> o `incOffset` fromIntegral (B.length dta)
      where dta = elfGotData g
    ElfDataStrtab _ -> o `incOffset` fromIntegral (B.length dta)
      where dta = strtab_data l
    ElfDataSymtab symtab -> o `incOffset` symbolTableSize c symtab
    ElfDataSection s -> o `incOffset` fromIntegral (B.length dta)
      where dta = elfSectionData s
    ElfDataRaw b -> o `incOffset` sz
      where sz = fromIntegral (B.length b)

------------------------------------------------------------------------
-- strtabSection

-- | Create a section for the section name table from the data.
strtabSection :: Num w
              => B.ByteString
                 -- ^ Name of section
              -> Word16
                 -- ^ Index of section
              -> B.ByteString
                 -- ^ Data for name information
              -> ElfSection w
strtabSection name idx name_data =
  ElfSection {
      elfSectionIndex = idx
    , elfSectionName = name
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
  return ElfGOT { elfGotIndex = elfSectionIndex s
                , elfGotName  = elfSectionName s
                , elfGotAddr  = elfSectionAddr s
                , elfGotAddrAlign = elfSectionAddrAlign s
                , elfGotEntSize = elfSectionEntSize s
                , elfGotData = d
                }


------------------------------------------------------------------------
-- StringTable

-- | Name of shstrtab (used to reduce spelling errors).
shstrtab :: B.ByteString
shstrtab = ".shstrtab"

-- | A string table contains a  map from offsets, the number of elements,
-- and a builder with the current string.
type StringTable = (Map B.ByteString Word32, Word32, Bld.Builder)

insertTail :: B.ByteString
           -> Word32
           -> Map B.ByteString Word32
           -> Map B.ByteString Word32
insertTail bs base  m
  | B.null bs = m
  | otherwise =
    insertTail (B.tail bs) (base + 1) $!
      Map.insertWith (\_ -> id) bs base m

-- | Insert bytestring in list of strings.
insertString :: StringTable -> B.ByteString -> StringTable
insertString a@(m, base, b) bs
    | Map.member bs m = a
    | otherwise = seq m' $ seq base' $ seq b' $ (m', base',  b')
  where -- Insert all tails of the bytestring into the map so that
        -- we can find the index later if needed.
        l = B.length bs
        m' = insertTail bs base m
        b' = b `mappend` Bld.byteString bs `mappend` Bld.word8 0
        base' = base + fromIntegral l + 1

-- | Create a string table from the list of strings, and return list of offsets.
stringTable :: [B.ByteString] -> (B.ByteString, Map B.ByteString Word32)
stringTable strings = (res, stringMap)
  where -- Compress entries by removing a string if it is the prefiex of
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
        entries = compress $ fmap B.reverse $ sort $ fmap B.reverse strings

        -- Insert strings into map (first string must be empty string)
        empty_table = (Map.singleton B.empty 0
                      , 1
                      , Bld.word8 0
                      )

        -- We insert strings in order so that they will appear in sorted
        -- order in the bytestring.  This is likely not essential, but
        -- corresponds to ld's behavior.
        (m,_,b) = F.foldl' insertString empty_table entries

        myFind bs =
          case Map.lookup bs m of
            Just v -> v
            Nothing -> error $ "internal: stringTable missing entry:\n"
              ++ unlines (show <$> strings)
              ++ show bs ++ "\n"
              ++ show entries ++ "\n"
              ++ show m
        stringMap = Map.fromList $ strings `zip` map myFind strings

        res = L.toStrict (Bld.toLazyByteString b)

------------------------------------------------------------------------
-- Section traversal

-- | Return name of all elf sections.
elfSectionNames :: forall w . Elf w -> [B.ByteString]
elfSectionNames e = concatMap regionNames (F.toList (e^.elfFileData))
  where regionNames :: ElfDataRegion w -> [B.ByteString]
        regionNames (ElfDataSegment s) =
          concatMap regionNames (F.toList (elfSegmentData s))
        regionNames (ElfDataSectionNameTable _) = [shstrtab]
        regionNames (ElfDataGOT g)              = [elfGotName g]
        regionNames (ElfDataStrtab _)           = [".strtab"]
        regionNames (ElfDataSymtab _)           = [".symtab"]
        regionNames (ElfDataSection s)          = [elfSectionName s]
        regionNames _                           = []

-- | Traverse sections in Elf file and modify or delete them.
updateSections' :: forall w
                .  Traversal (Elf w) (Elf w) (ElfSection (ElfWordType w)) (Maybe (ElfSection (ElfWordType w)))
updateSections' fn0 e0 = elfClassInstances (elfClass e0) $ elfFileData (updateSeq (impl fn0)) e0
  where t = fst $ stringTable $ elfSectionNames e0
        norm :: ElfWidthConstraints w => ElfSection (ElfWordType w) -> ElfDataRegion w
        norm s
          | elfSectionName s == shstrtab = ElfDataSectionNameTable (elfSectionIndex s)
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
        impl fn (ElfDataSectionNameTable idx) = fmap norm <$> fn (strtabSection shstrtab idx t)
        impl fn (ElfDataGOT g) = fmap norm <$> fn (elfGotSection g)
        impl fn (ElfDataSection s) = fmap norm <$> fn s
        impl _  d = pure (Just d)

updateSegments' :: forall w f . Monad f
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

updateDataRegions' :: forall w f
                   .  Monad f
                   => (ElfDataRegion w -> f (Maybe (ElfDataRegion w)))
                   -> Elf w
                   -> f (Elf w)
updateDataRegions' fn = elfFileData (updateSeq impl)
  where
    impl (ElfDataSegment seg) =
      let inner = updateSeq impl (elfSegmentData seg)
          updateData s d = s { elfSegmentData = d }
      in fmap (updateData seg) inner >>= (fn . ElfDataSegment)
    impl d = fn d

------------------------------------------------------------------------
-- Section Elf Layout

-- | Return a section corresponding to the initial elf section at index 0.
emptyElfSection :: Num w => ElfSection w
emptyElfSection =
  ElfSection { elfSectionIndex = 0
             , elfSectionName  = ""
             , elfSectionType  = SHT_NULL
             , elfSectionFlags = shf_none
             , elfSectionAddr  = 0
             , elfSectionSize  = 0
             , elfSectionLink  = 0
             , elfSectionInfo  = 0
             , elfSectionAddrAlign = 0
             , elfSectionEntSize   = 0
             , elfSectionData      = B.empty
             }

-- | Add section information to layout.
addSectionToLayout :: Map B.ByteString Word32 -- ^ Name to offset map.
                   -> ElfLayout w
                   -> ElfSection (ElfWordType w)
                   -> ElfLayout w
addSectionToLayout name_map l s
    | Map.member (elfSectionIndex s) (l^.shdrs) =
      error $ "Section index " ++ show (elfSectionIndex s) ++ " already exists; cannot add "
        ++ show (elfSectionName s) ++ "."
    | otherwise = elfClassInstances (elfLayoutClass l) $
     let Just no = Map.lookup (elfSectionName s) name_map
         base =  l^.elfOutputSize
         data_size = elfSectionFileSize s
         idx = elfSectionIndex s
      in l & elfOutputSize %~ (`incOffset` data_size)
           & shdrs %~ Map.insert idx (s, no, fromFileOffset base)

------------------------------------------------------------------------
-- elfLayout

addRelroToLayout :: Maybe (Range (ElfWordType w)) -> ElfLayout w -> ElfLayout w
addRelroToLayout Nothing l = l
addRelroToLayout (Just (f,c)) l = l & phdrs %~ Map.insert idx phdr
  where idx = fromIntegral (Map.size (l^.phdrs))
        s = elfClassInstances (elfLayoutClass l) $
            ElfSegment { elfSegmentType     = PT_GNU_RELRO
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


-- | Return index for .strtab if defined or '0' if undefined.
elfStrtabSectionIndex :: Elf w -> Word16
elfStrtabSectionIndex e = fromMaybe 0 $ asumDataRegions f e
  where f (ElfDataStrtab idx) = Just idx
        f _ = Nothing

-- | Return symbol table names in elf.
elfSymtabNames :: Elf w -> [B.ByteString]
elfSymtabNames = asumDataRegions f
  where f (ElfDataSymtab symtab) = V.toList $ steName <$> elfSymbolTableEntries symtab
        f _ = []

-- | Return the size of a region given the elf region data.
elfRegionFileSize :: ElfLayout w -> ElfDataRegion w -> ElfWordType w
elfRegionFileSize l reg = elfClassInstances c $ do
    case reg of
      ElfDataElfHeader          -> fromIntegral (ehdrSize c)
      ElfDataSegmentHeaders     -> fromIntegral (phnum l) * fromIntegral (phdrEntrySize c)
      ElfDataSegment s          -> sum (elfRegionFileSize l <$> elfSegmentData s)
      ElfDataSectionHeaders     -> fromIntegral (shnum l) * fromIntegral (shdrEntrySize c)
      ElfDataSectionNameTable _ -> fromIntegral $ B.length $ elfLayoutSectionNameData l
      ElfDataGOT g              -> elfGotSize g
      ElfDataStrtab _           -> fromIntegral $ B.length $ strtab_data l
      ElfDataSymtab symtab      -> symbolTableSize c symtab
      ElfDataSection s          -> elfSectionFileSize s
      ElfDataRaw b              -> fromIntegral (B.length b)
  where c = elfLayoutClass l

-- | Return layout information from elf file.
elfLayout' :: forall w . ElfWidthConstraints w => Elf w -> ElfLayout w
elfLayout' e = final
  where c = elfClass e
        d = elfData e
        sec_names = elfSectionNames e
        (name_data,name_map) = stringTable sec_names

        (this_strtab_data, this_strtab_map) = stringTable (elfSymtabNames e)

        has_relro = isJust (elfRelroRange e)

        phdr_cnt = elfSegmentCount e
                 + (if has_relro then 1 else 0)

        -- Section names can be determed from counter
        shdr_cnt = length sec_names + 1

        initl = ElfLayout { elfLayoutHeader = elfHeader e
                          , elfLayoutRegions = e^.elfFileData
                          , elfLayoutSectionNameData = name_data
                          , strtab_idx  = elfStrtabSectionIndex e
                          , strtab_data = this_strtab_data
                          , strtab_map  = this_strtab_map
                          , _elfOutputSize = startOfFile
                          , _phdrTableOffset = startOfFile
                          , _phdrs = Map.empty
                          , _shdrTableOffset = startOfFile
                          , _shstrndx = 0
                          , _shdrs = Map.singleton 0 $ (emptyElfSection, 0, 0)
                          }

        -- Process element.
        layoutRegion :: ElfWidthConstraints w
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
                -- Get memory size of segment
                mem_size =
                  case elfSegmentMemSize s of
                    -- Absolute sizes are lower bounds
                    ElfAbsoluteSize sz -> max seg_size sz
                    -- Relative sizes are offsets of the computed sizes.
                    ElfRelativeSize o  -> seg_size + o
                phdr = Phdr { phdrSegment = s
                            , phdrFileStart = seg_offset
                            , phdrFileSize  = seg_size
                            , phdrMemSize   = mem_size
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
        layoutRegion l (ElfDataSectionNameTable idx) =
            addSectionToLayout name_map l' s
          where l' = l & shstrndx .~ idx
                s  = strtabSection shstrtab idx name_data
        layoutRegion l (ElfDataGOT g) = addSectionToLayout name_map l (elfGotSection g)
        layoutRegion l (ElfDataStrtab idx) = addSectionToLayout name_map l s
          where s = strtabSection ".strtab" idx (strtab_data l)
        layoutRegion l (ElfDataSymtab symtab) = addSectionToLayout name_map l s
          where s = symtabSection c d (strtab_map l) (strtab_idx l) symtab
        layoutRegion l (ElfDataSection s) = addSectionToLayout name_map l s
        layoutRegion l (ElfDataRaw b) =
          l & elfOutputSize %~ (`incOffset` fromIntegral (B.length b))

        final = initl & flip (foldl layoutRegion) (e^.elfFileData)
                      & addRelroToLayout (elfRelroRange e)

------------------------------------------------------------------------
-- Elf Width instances

-- | The 4-byte strict expected at the start of an Elf file '(0x7f)ELF'
elfMagic :: B.ByteString
elfMagic = "\DELELF"

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

-- | Size of the main elf header table for given width.
ehdrSize :: ElfClass w -> Word16
ehdrSize ELFCLASS32 = ehdrSize32
ehdrSize ELFCLASS64 = ehdrSize64

-- | Size of entry in Elf program header table for given width.
phdrEntrySize :: ElfClass w -> Word16
phdrEntrySize ELFCLASS32 = phdrEntrySize32
phdrEntrySize ELFCLASS64 = phdrEntrySize64

-- | Size of entry in Elf section header table for given width.
shdrEntrySize :: ElfClass w -> Word16
shdrEntrySize ELFCLASS32 = shdrEntrySize32
shdrEntrySize ELFCLASS64 = shdrEntrySize64

ehdr32Fields :: ElfRecord (Ehdr 32)
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

ehdr64Fields :: ElfRecord (Ehdr 64)
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

phdr32Fields :: ElfRecord (Phdr 32)
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

phdr64Fields :: ElfRecord (Phdr 64)
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

shdr32Fields :: ElfRecord (Shdr 32)
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
shdr64Fields :: ElfRecord (Shdr 64)
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

-- | Return the bytes in the Elf file as a lazy bytestring.
elfLayoutBytes :: ElfLayout w -> L.ByteString
elfLayoutBytes l = elfClassInstances (elfLayoutClass l) $
    Bld.toLazyByteString $ buildRegions l startOfFile regions
  where regions = F.toList (elfLayoutRegions l)


------------------------------------------------------------------------
-- elfLayout

-- | Traverse sections in Elf file and modify or delete them.
updateSections :: Traversal (Elf w) (Elf w) (ElfSection (ElfWordType w)) (Maybe (ElfSection (ElfWordType w)))
updateSections fn e0 = elfClassInstances (elfClass e0) $
  updateSections' fn e0

-- | Traverse segments in an ELF file and modify or delete them
updateSegments :: (Monad f) => (ElfSegment w -> f (Maybe (ElfSegment w))) -> Elf w -> f (Elf w)
updateSegments fn e0 = elfClassInstances (elfClass e0) $
  updateSegments' fn e0

-- | Traverse the data regions in an ELF file and modify or delete them
updateDataRegions :: (Monad f) => (ElfDataRegion w -> f (Maybe (ElfDataRegion w))) -> Elf w -> f (Elf w)
updateDataRegions fn e0 = elfClassInstances (elfClass e0) $
  updateDataRegions' fn e0

-- | Traverse elf sections
elfSections :: Simple Traversal (Elf w) (ElfSection (ElfWordType w))
elfSections f = updateSections (fmap Just . f)

-- | Traverse elf segments
traverseElfSegments :: Monad f => (ElfSegment w -> f (ElfSegment w)) -> Elf w -> f (Elf w)
traverseElfSegments f = updateSegments (fmap Just . f)

-- | Traverse elf data regions
traverseElfDataRegions :: Monad f => (ElfDataRegion w -> f (ElfDataRegion w)) -> Elf w -> f (Elf w)
traverseElfDataRegions f = updateDataRegions (fmap Just . f)


-- | Return layout information from elf file.
elfLayout :: Elf w -> ElfLayout w
elfLayout e = elfClassInstances  (elfClass e) $ elfLayout' e
