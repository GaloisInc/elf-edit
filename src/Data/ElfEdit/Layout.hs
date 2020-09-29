{-|
Module           : Data.ElfEdit.Layout
Copyright        : (c) Galois, Inc 2016-18
Maintainer       : Joe Hendrix <jhendrix@galois.com>
License          : BSD3

This defines the 'ElfLayout' class which is used for writing elf files.
-}
{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE Trustworthy #-} -- Use Control.Lens and Data.Vector
{-# LANGUAGE TupleSections #-}
{-# LANGUAGE UndecidableInstances #-}
module Data.ElfEdit.Layout
  ( -- * ElfLayout
    ElfLayout(..)
--  , elfLayoutHeader
  , elfLayoutClass
  , elfLayoutData
--  , elfLayoutRegions
  , Phdr(..)
  , phdrFileRange
  , phdrs
  , allPhdrs
  , shdrs
  , elfLayout
  , elfLayoutBytes
  , elfLayoutSize
  , Ehdr(..)
  , layoutEhdr
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
  -- * FileOffset
  , FileOffset(..)
    -- * Low level constants
  , elfMagic
  , ehdrSize
  , phdrEntrySize
  , stringTable
  , strtabSection
  , symbolTableEntrySize
  , symbolTableSize
  , renderSymbolTableEntry
    -- * Special section header defines
  , strtabShdr
  , symtabShdr
    -- * Utilities
  , putWord16
  , putWord32
  , putWord64
    -- * Misc
  , startOfFile
  , emptyElfSection
  , layoutRegion
  , gnuStackPhdr
  , addPhdrToLayout
  , buildRegions
  , addSectionHeadersToLayout
  , addSectionToLayout
  , symtabSection
  , sectionContents
  , incOffset
  , alignFileOffset
  , shdrAlign
  , incOutputSize
  , alignmentPadding
  , symtabAlign
  ) where

import           Control.Exception (assert)
import           Control.Lens hiding (enum)
import           Control.Monad
import           Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Builder as Bld
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Lazy as L
import qualified Data.Foldable as F
import           Data.List (sort)
import           Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import           Data.Maybe
import qualified Data.Sequence as Seq
import qualified Data.Vector as V
import           Data.Word
import           Numeric

import           Data.ElfEdit.Enums
import           Data.ElfEdit.ShdrEntry
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
  deriving (Eq, Ord, Enum, Integral, Num, Real)

instance Show w => Show (FileOffset w) where
  show (FileOffset o) = show o

startOfFile :: Num w => FileOffset w
startOfFile = FileOffset 0

incOffset :: Num w => FileOffset w -> w -> FileOffset w
incOffset (FileOffset b) o = FileOffset (b + o)

rangeSize :: (Ord w, Num w) => FileOffset w -> FileOffset w -> w
rangeSize (FileOffset s) (FileOffset e) = assert (e >= s) $ e - s

-- | `alignFileOffset align off` rounds `off` to the smallest multiple
-- of `align` not less than `offset`.
alignFileOffset :: (Bits w, Num w) => w -> FileOffset w -> FileOffset w
alignFileOffset align (FileOffset o) = FileOffset $ (o + (align - 1)) .&. complement (align - 1)

-- | `isAligned off align` checks that `off` is an
-- of `align` not less than `offset`.
--
-- Note. This throws an error is the alignment is not a power of two.
isAligned :: (Bits w, Num w) => FileOffset w -> w -> Bool
isAligned (FileOffset o) align
  | align .&. (align - 1) /= 0 = error "alignments must be power of two."
  | otherwise = (o .&. (align - 1)) == 0


-- | `alignFileOffset align off` rounds `off` to the smallest multiple
-- of `align` not less than `offset`.
alignmentPadding :: Integral w => FileOffset w -> FileOffset w -> Bld.Builder
alignmentPadding (FileOffset o) (FileOffset o') = Bld.byteString $ B.replicate (fromIntegral (o' - o)) 0

------------------------------------------------------------------------
-- Phdr

-- | Provides concrete information about an elf segment and its layout.
data Phdr w = Phdr { phdrSegmentIndex :: !SegmentIndex
                   , phdrSegmentType  :: !ElfSegmentType
                   , phdrSegmentFlags :: !ElfSegmentFlags
                   , phdrSegmentVirtAddr  :: !(ElfWordType w)
                   , phdrSegmentPhysAddr  :: !(ElfWordType w)
                   , phdrSegmentAlign     :: !(ElfWordType w)
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
    where col1 = [ alignLeft 15 (show (phdrSegmentType p)) ' '
                 , "0x" ++ fixedHex 16 (fromFileOffset (phdrFileStart p))
                 , "0x" ++ fixedHex 16 (phdrSegmentVirtAddr p)
                 , "0x" ++ fixedHex 16 (phdrSegmentPhysAddr p)
                 ]
          col2 = [ replicate 14 ' '
                 , "0x" ++ fixedHex 16 (phdrFileSize p)
                 , "0x" ++ fixedHex 16 (phdrMemSize  p)
                 , alignLeft 7 (showSegFlags (phdrSegmentFlags p)) ' '
                 , fixedHex 0 (toInteger (phdrSegmentAlign p))
                 ]

phdrFileRange :: Phdr w -> Range (ElfWordType w)
phdrFileRange phdr = (fromFileOffset (phdrFileStart phdr), phdrFileSize phdr)

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

------------------------------------------------------------------------
-- ElfRecord

-- | A record to be written to the Elf file.
type ElfRecord v = [(String, ElfField v)]

sizeOfRecord :: ElfRecord v -> Word16
sizeOfRecord = sum . map (sizeOfField . snd)

writeRecord :: ElfRecord v -> ElfData -> v -> Bld.Builder
writeRecord fields d v =
  mconcat $ map (\(_,f) -> writeField2 f d v) fields

------------------------------------------------------------------------
-- Shdr

-- | Contains Elf section data, name offset, and data offset.
type Shdr w = (ElfSection w, Word32, w)

------------------------------------------------------------------------
-- Symbol table

-- | Return the size of a symbol table entry.
symbolTableEntrySize :: ElfClass w -> Int
symbolTableEntrySize ELFCLASS32 = 16
symbolTableEntrySize ELFCLASS64 = 24

-- | Get size of symbol table
symbolTableSize :: ElfClass w -> ElfSymbolTable nm (ElfWordType w) -> ElfWordType w
symbolTableSize c symtab = elfClassInstances c $
  let cnt = fromIntegral $ V.length $ elfSymbolTableEntries symtab
   in fromIntegral (symbolTableEntrySize c) * cnt

-- | Write a symbol table entry to a builder
renderSymbolTableEntry :: ElfClass w
                       -> ElfData
                       -> ElfSymbolTableEntry Word32 (ElfWordType w)
                       -> Bld.Builder
renderSymbolTableEntry ELFCLASS32 d s =
  putWord32 d (steName s)
    <> putWord32 d (steValue s)
    <> putWord32 d (steSize  s)
    <> Bld.word8 (typeAndBindToInfo (steType s) (steBind s))
    <> Bld.word8 (steOther s)
    <> putWord16 d (fromElfSectionIndex (steIndex s))
renderSymbolTableEntry ELFCLASS64 d s =
  putWord32 d (steName s)
  <> Bld.word8 (typeAndBindToInfo (steType s) (steBind s))
  <> Bld.word8 (steOther s)
  <> putWord16 d (fromElfSectionIndex (steIndex s))
  <> putWord64 d (steValue s)
  <> putWord64 d (steSize  s)

-- | Alignment used for symtab sections.
symtabAlign :: ElfClass w -> ElfWordType w
symtabAlign ELFCLASS32 = 4
symtabAlign ELFCLASS64 = 8

-- | Create a section header for a symbol table
symtabShdr :: ElfClass w
           -> nm -- ^ Name of symtab (typically ".symtab")
           -> Word16 -- ^ Index of string table for symbol names
           -> Word32 -- ^ Number of entries that are local
           -> FileOffset (ElfWordType w)
           -- ^ Offset of file that section must be after.
           --
           -- We align section so the actual location may be larger.
           -> ElfWordType w
           -- ^ Size of section
           -> ShdrEntry nm (ElfWordType w)
symtabShdr cl nm strtabIdx localCnt o sz = elfClassInstances cl $
  let align = symtabAlign cl
      o' = alignFileOffset align o
   in ShdrEntry { shdrName = nm
                , shdrType  = SHT_SYMTAB
                , shdrFlags = shf_none
                , shdrAddr  = 0
                , shdrOff   = fromFileOffset o'
                , shdrSize  = sz
                , shdrLink  = fromIntegral strtabIdx
                , shdrInfo  = localCnt
                , shdrAddrAlign = symtabAlign cl
                , shdrEntSize = fromIntegral (symbolTableEntrySize cl)
                }

-- | Create an elf section for symbol table and string table of symbol names.
symtabSection :: ElfClass w
              -> ElfData
              -> Map B.ByteString Word32
              -> Word16 -- ^ Index of string table for symbol names
              -> ElfSymbolTable B.ByteString (ElfWordType w) -- ^ The symbol table
              -> ElfSection (ElfWordType w)
symtabSection cl d nameMap thisStrtabIdx symtab = sec
  where nameFn nm =
          case Map.lookup nm nameMap of
            Just nameIdx -> nameIdx
            Nothing -> error "internal: symtabData given undefined symbol name."
        renderSym s = renderSymbolTableEntry cl d (s { steName = nameFn (steName s) })
        bld = mconcat $ V.toList $ renderSym <$> elfSymbolTableEntries symtab
        dta = L.toStrict $ Bld.toLazyByteString bld
        sec = elfClassInstances cl $
            ElfSection { elfSectionIndex = elfSymbolTableIndex symtab
                       , elfSectionName  = ".symtab"
                       , elfSectionType  = SHT_SYMTAB
                       , elfSectionFlags = shf_none
                       , elfSectionAddr  = 0
                       , elfSectionSize  = fromIntegral (B.length dta)
                       , elfSectionLink  = fromIntegral thisStrtabIdx
                       , elfSectionInfo  = elfSymbolTableLocalEntries symtab
                       , elfSectionAddrAlign = symtabAlign cl
                       , elfSectionEntSize = fromIntegral (symbolTableEntrySize cl)
                       , elfSectionData = dta
                       }


------------------------------------------------------------------------
-- strtabSection

-- | Create a section header for a string tabl.
strtabShdr :: Num w
           => nm
           -- ^ Name of section
           -> w
           -- ^ Offset of section
           -> w
           -- ^ Size of section
           -> ShdrEntry nm w
strtabShdr nm o sz =
  ShdrEntry { shdrName = nm
            , shdrType = SHT_STRTAB
            , shdrFlags = shf_none
            , shdrAddr = 0
            , shdrOff  = o
            , shdrSize = sz
            , shdrLink = 0
            , shdrInfo = 0
            , shdrAddrAlign = 1
            , shdrEntSize = 0
            }


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
      , _shdrs :: !(Map Word16 (ShdrEntry Word32 (ElfWordType w)))
        -- ^ Map each section index to the section header entry for that section.
      }

elfLayoutClass :: ElfLayout w -> ElfClass w
elfLayoutClass = headerClass . elfLayoutHeader

elfLayoutData :: ElfLayout w -> ElfData
elfLayoutData = headerData . elfLayoutHeader

-- | Lens containing size of sections processed so far in layout.
elfOutputSize :: Simple Lens (ElfLayout w) (FileOffset (ElfWordType w))
elfOutputSize = lens _elfOutputSize (\s v -> s { _elfOutputSize = v })

-- | Increment output size
incOutputSize :: Num (ElfWordType w) => ElfWordType w -> ElfLayout w -> ElfLayout w
incOutputSize n l = l & elfOutputSize %~ (`incOffset` n)

phdrTableOffset :: Simple Lens (ElfLayout w) (FileOffset (ElfWordType w))
phdrTableOffset = lens _phdrTableOffset (\s v -> s { _phdrTableOffset = v })

phdrs :: Simple Lens (ElfLayout w) (Map Word16 (Phdr w))
phdrs = lens _phdrs (\s v -> s { _phdrs = v })

shdrTableOffset :: Simple Lens (ElfLayout w) (FileOffset (ElfWordType w))
shdrTableOffset = lens _shdrTableOffset (\s v -> s { _shdrTableOffset = v })

shstrndx :: Simple Lens (ElfLayout w) Word16
shstrndx = lens _shstrndx (\s v -> s { _shstrndx = v })

shdrs :: Simple Lens (ElfLayout w) (Map Word16 (ShdrEntry Word32 (ElfWordType w)))
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
-- Adding to elf layout

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

initShdrEntry :: Num w => nm -> ShdrEntry nm w
initShdrEntry nm =
  ShdrEntry { shdrName = nm
            , shdrType = SHT_NULL
            , shdrFlags = shf_none
            , shdrAddr = 0
            , shdrOff  = 0
            , shdrSize = 0
            , shdrLink = 0
            , shdrInfo = 0
            , shdrAddrAlign = 0
            , shdrEntSize = 0
            }


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
          & shdrs %~ Map.insert idx (mkShdrEntry (s, no, fromFileOffset alignedOff))

addSectionHeadersToLayout :: ElfLayout w -> ElfLayout w
addSectionHeadersToLayout l = elfClassInstances  (elfLayoutClass l) $
   let cl = elfLayoutClass l
       shdrCnt = elfLayoutShdrCount l
       o' = alignFileOffset (shdrAlign cl) (l^.elfOutputSize)
       shdrTableSize = shdrCnt * fromIntegral (shdrEntrySize cl)
    in l & shdrTableOffset .~ o'
         & elfOutputSize   .~ incOffset o' shdrTableSize


gnuStackPhdr :: Num (ElfWordType w) => GnuStack -> Phdr w
gnuStackPhdr gnuStack =
  let thisIdx = gnuStackSegmentIndex gnuStack
      perm | gnuStackIsExecutable gnuStack = pf_r .|. pf_w .|. pf_x
           |  otherwise = pf_r .|. pf_w
   in Phdr { phdrSegmentIndex = thisIdx
           , phdrSegmentType  = PT_GNU_STACK
           , phdrSegmentFlags = perm
           , phdrSegmentVirtAddr = 0
           , phdrSegmentPhysAddr = 0
           , phdrSegmentAlign = 0x8
           , phdrFileStart = startOfFile
           , phdrFileSize  = 0
           , phdrMemSize   = 0
           }

addPhdrToLayout :: String -> ElfLayout w -> Phdr w -> ElfLayout w
addPhdrToLayout nm l phdr
  | Map.member (phdrSegmentIndex phdr) (l^.phdrs) =
      error $ nm ++ " " ++ show (phdrSegmentIndex phdr) ++ " already exists."
  | otherwise =
      l & phdrs %~ Map.insert (phdrSegmentIndex phdr) phdr

addRelroToLayout :: ElfLayout w -> GnuRelroRegion w -> ElfLayout w
addRelroToLayout l r
  | otherwise = elfClassInstances (elfLayoutClass l) $ do
      let refIdx = relroRefSegmentIndex r
      case Map.lookup refIdx (l^.phdrs) of
        Nothing -> error $ "Error segment index " ++ show refIdx ++ " could not be found."
        Just refPhdr ->
          let thisIdx = relroSegmentIndex r
              vaddr = relroAddrStart r
              fstart = phdrFileStart refPhdr `incOffset` (vaddr - phdrSegmentVirtAddr refPhdr)
              phdr = Phdr { phdrSegmentIndex = thisIdx
                          , phdrSegmentType  = PT_GNU_RELRO
                          , phdrSegmentFlags = pf_r
                          , phdrSegmentVirtAddr = vaddr
                          , phdrSegmentPhysAddr = vaddr
                          , phdrSegmentAlign = 1
                          , phdrFileStart = fstart
                          , phdrFileSize  = relroSize r
                          , phdrMemSize   = relroSize r
                          }
           in addPhdrToLayout "Relro segment index" l phdr

------------------------------------------------------------------------
-- Layout information

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

-- | Size of the main elf header table for given width.
ehdrSize :: ElfClass w -> Word16
ehdrSize ELFCLASS32 = ehdrSize32
ehdrSize ELFCLASS64 = ehdrSize64

-- | Size of entry in Elf program header table for given width.
phdrEntrySize :: ElfClass w -> Word16
phdrEntrySize ELFCLASS32 = phdrEntrySize32
phdrEntrySize ELFCLASS64 = phdrEntrySize64

-- | Return alignment constraint on elf
phdrAlign :: ElfClass w -> ElfWordType w
phdrAlign ELFCLASS32 = 4
phdrAlign ELFCLASS64 = 8

-- | Return alignment constraint on elf
shdrAlign :: ElfClass w -> ElfWordType w
shdrAlign ELFCLASS32 = 4
shdrAlign ELFCLASS64 = 8

-- | Information to be rendered into Elf header record at start of file.
data Ehdr w = Ehdr { ehdrHeader :: !(ElfHeader w)
                   , ehdrPhoff :: !(FileOffset (ElfWordType w))
                   , ehdrShoff :: !(FileOffset (ElfWordType w))
                   , ehdrPhnum :: !Word16
                   , ehdrShnum :: !Word16
                   , ehdrShstrndx :: !Word16
                   }

-- | Get ehdr from elf layout
layoutEhdr :: ElfLayout w -> Ehdr w
layoutEhdr l = Ehdr { ehdrHeader   = elfLayoutHeader l
                    , ehdrPhoff    = l^.phdrTableOffset
                    , ehdrShoff    = l^.shdrTableOffset
                    , ehdrPhnum    = phnum l
                    , ehdrShnum    = shnum l
                    , ehdrShstrndx = l^.shstrndx
                    }

ehdr32Fields :: ElfRecord (Ehdr 32)
ehdr32Fields =
  [ ("e_ident",     EFBS 16  $ elfIdentBuilder . ehdrHeader)
  , ("e_type",      EFWord16 $ fromElfType     . headerType    . ehdrHeader)
  , ("e_machine",   EFWord16 $ fromElfMachine  . headerMachine . ehdrHeader)
  , ("e_version",   EFWord32 $ \_ -> fromIntegral expectedElfVersion)
  , ("e_entry",     EFWord32 $ headerEntry . ehdrHeader)
  , ("e_phoff",     EFWord32 $ fromFileOffset . ehdrPhoff)
  , ("e_shoff",     EFWord32 $ fromFileOffset . ehdrShoff)
  , ("e_flags",     EFWord32 $ headerFlags . ehdrHeader)
  , ("e_ehsize",    EFWord16 $ \_ -> ehdrSize32)
  , ("e_phentsize", EFWord16 $ \_ -> phdrEntrySize32)
  , ("e_phnum",     EFWord16 $ ehdrPhnum)
  , ("e_shentsize", EFWord16 $ \_ -> 40)
  , ("e_shnum",     EFWord16 $ ehdrShnum)
  , ("e_shstrndx",  EFWord16 $ ehdrShstrndx)
  ]

ehdr64Fields :: ElfRecord (Ehdr 64)
ehdr64Fields =
  [ ("e_ident",     EFBS 16  $ elfIdentBuilder . ehdrHeader)
  , ("e_type",      EFWord16 $ fromElfType    . headerType    . ehdrHeader)
  , ("e_machine",   EFWord16 $ fromElfMachine . headerMachine . ehdrHeader)
  , ("e_version",   EFWord32 $ \_ -> fromIntegral expectedElfVersion)
  , ("e_entry",     EFWord64 $ headerEntry . ehdrHeader)
  , ("e_phoff",     EFWord64 $ fromFileOffset . ehdrPhoff)
  , ("e_shoff",     EFWord64 $ fromFileOffset . ehdrShoff)
  , ("e_flags",     EFWord32 $ headerFlags . ehdrHeader)
  , ("e_ehsize",    EFWord16 $ \_ -> ehdrSize64)
  , ("e_phentsize", EFWord16 $ \_ -> phdrEntrySize64)
  , ("e_phnum",     EFWord16 $ ehdrPhnum)
  , ("e_shentsize", EFWord16 $ \_ -> 64)
  , ("e_shnum",     EFWord16 $ ehdrShnum)
  , ("e_shstrndx",  EFWord16 $ ehdrShstrndx)
  ]

ehdrFields :: ElfClass w -> ElfRecord (Ehdr w)
ehdrFields ELFCLASS32 = ehdr32Fields
ehdrFields ELFCLASS64 = ehdr64Fields

phdr32Fields :: ElfRecord (Phdr 32)
phdr32Fields =
  [ ("p_type",   EFWord32 $ fromElfSegmentType . phdrSegmentType)
  , ("p_offset", EFWord32 $ fromFileOffset . phdrFileStart)
  , ("p_vaddr",  EFWord32 $ phdrSegmentVirtAddr)
  , ("p_paddr",  EFWord32 $ phdrSegmentPhysAddr)
  , ("p_filesz", EFWord32 $ phdrFileSize)
  , ("p_memsz",  EFWord32 $ phdrMemSize)
  , ("p_flags",  EFWord32 $ fromElfSegmentFlags . phdrSegmentFlags)
  , ("p_align",  EFWord32 $ phdrSegmentAlign)
  ]

phdr64Fields :: ElfRecord (Phdr 64)
phdr64Fields =
  [ ("p_type",   EFWord32 $ fromElfSegmentType  . phdrSegmentType)
  , ("p_flags",  EFWord32 $ fromElfSegmentFlags . phdrSegmentFlags)
  , ("p_offset", EFWord64 $ fromFileOffset . phdrFileStart)
  , ("p_vaddr",  EFWord64 $ phdrSegmentVirtAddr)

  , ("p_paddr",  EFWord64 $ phdrSegmentPhysAddr)
  , ("p_filesz", EFWord64 $ phdrFileSize)
  , ("p_memsz",  EFWord64 $ phdrMemSize)
  , ("p_align",  EFWord64 $ phdrSegmentAlign)
  ]

phdrFields :: ElfClass w -> ElfRecord (Phdr w)
phdrFields ELFCLASS32 = phdr32Fields
phdrFields ELFCLASS64 = phdr64Fields

------------------------------------------------------------------------
-- Render Elf layout

-- | Render the main ELF header.
buildElfHeader :: Ehdr w -> Bld.Builder
buildElfHeader e = writeRecord (ehdrFields (headerClass hdr)) d e
  where hdr = ehdrHeader e
        d = headerData hdr

-- | Render the ELF segment header table.
buildElfSegmentHeaderTable :: ElfClass w -> ElfData -> [Phdr w] -> Bld.Builder
buildElfSegmentHeaderTable cl d l = mconcat $ writeRecord (phdrFields cl) d <$> l


mkShdrEntry :: Shdr w -> ShdrEntry Word32 w
mkShdrEntry (s,n,o) = ShdrEntry { shdrName = n
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

-- | Render the ELF section header table.
buildElfSectionHeaderTable :: ElfClass w -> ElfData -> [ShdrEntry Word32 (ElfWordType w)] -> Bld.Builder
buildElfSectionHeaderTable cl d sl = mconcat $ writeShdrEntry d cl <$> sl

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
    ElfDataSymtab _           -> False
    ElfDataSection s          -> B.null (elfSectionData s)
    ElfDataRaw b              -> B.null b

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
        buildElfHeader (layoutEhdr l)
        <> doRest (fromIntegral (ehdrSize cl))
    ElfDataSegmentHeaders
      | not (isAligned o (phdrAlign cl)) ->
          error $ "internal error: buildRegions phdr alignment check failed; Fix layoutRegion."
      | otherwise ->
          let phdrSize = fromIntegral (phnum l) * fromIntegral (phdrEntrySize cl)
           in buildElfSegmentHeaderTable (headerClass hdr) (headerData hdr) (allPhdrs l)
              <> buildRegions l (o `incOffset` phdrSize) rest
    ElfDataSegment s -> do
      buildRegions l o $ ((,True) <$> F.toList (elfSegmentData s)) ++ rest
    ElfDataSectionHeaders ->
      let o' = alignFileOffset (shdrAlign cl) o
          sz = fromIntegral (shnum l) * fromIntegral (shdrEntrySize cl)
       in alignmentPadding o o'
            <> buildElfSectionHeaderTable (headerClass hdr) (headerData hdr) (Map.elems (l^.shdrs))
            <> buildRegions l (o' `incOffset` sz) rest
    ElfDataSectionNameTable idx -> do
      let s = strtabSection shstrtab idx (elfLayoutSectionNameData l)
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
    ElfDataSymtab symtab ->
      let s = symtabSection cl d (strtab_map l) (strtab_idx l) symtab
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
  where regions = F.toList (elfLayoutRegions l)

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
          ElfDataSymtab symtab      -> symbolTableSize c symtab
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
  where f (ElfDataSymtab symtab) = V.toList $ steName <$> elfSymbolTableEntries symtab
        f _ = []

elfSegmentCount :: Elf w -> Int
elfSegmentCount e = F.foldl' f 0 (e^.elfFileData)
  where f c (ElfDataSegment s) = F.foldl' f (c + 1) (elfSegmentData s)
        f c _ = c

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
      | not (isAligned o (phdrAlign cl)) ->
          error $ "Segment header table file offset " ++ show o
               ++ " must be a multiple of " ++ show (phdrAlign cl) ++ "."
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
          s  = strtabSection shstrtab idx (elfLayoutSectionNameData l)
       in addSectionToLayout l' s inLoad
    ElfDataGOT g ->
      let s = elfGotSection g
       in addSectionToLayout l s inLoad
    ElfDataStrtab idx ->
      let s = strtabSection ".strtab" idx (strtab_data l)
       in addSectionToLayout l s inLoad
    ElfDataSymtab symtab ->
      let s = symtabSection cl d (strtab_map l) (strtab_idx l) symtab
       in addSectionToLayout l s inLoad
    ElfDataSection s ->
      addSectionToLayout l s inLoad
    ElfDataRaw b ->
      l & incOutputSize (fromIntegral (B.length b))

-- | Return layout information from elf file.
elfLayout' :: forall w . ElfWidthConstraints w => Elf w -> ElfLayout w
elfLayout' e = initl & flip (F.foldl' (layoutRegion False)) (e^.elfFileData)
                     & flip (F.foldl' (addPhdrToLayout "GNU stack segment index")) (fmap gnuStackPhdr (elfGnuStackSegment e))
                     & flip (F.foldl' addRelroToLayout)    (elfGnuRelroRegions e)
  where sec_names = elfSectionNames e
        (nameData,nameMap) = stringTable sec_names

        (this_strtab_data, this_strtab_map) = stringTable (elfSymtabNames e)

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
                          , _shdrs = Map.singleton 0 (initShdrEntry 0)
                          }

-- | Return layout information from elf file.
elfLayout :: Elf w -> ElfLayout w
elfLayout e = elfClassInstances  (elfClass e) $ elfLayout' e

------------------------------------------------------------------------
-- Traversing Elf

-- | Traverse sections in Elf file and modify or delete them.
updateSections :: Traversal (Elf w)
                            (Elf w)
                            (ElfSection (ElfWordType w))
                            (Maybe (ElfSection (ElfWordType w)))
updateSections fn0 e0 = elfClassInstances (elfClass e0) $ elfFileData (updateSeq (impl fn0)) e0
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

-- | Traverse elf sections
elfSections :: Simple Traversal (Elf w) (ElfSection (ElfWordType w))
elfSections f = updateSections (fmap Just . f)

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
