{-|
Module           : Data.ElfEdit.Layout
Copyright        : (c) Galois, Inc 2016
Maintainer       : Joe Hendrix <jhendrix@galois.com>
License          : BSD3

This module provides facilities for manipulating ELF files.  It includes
operations for both reading and writing files a well as inspecting their
contents.

To read an existing ELF file, see the documentation for 'parseElf' and the
operations on the 'Elf' datatype.  To write an existing file, see the
documentation for 'renderElf'.  If more control is desired for generating an Elf
file with specific layout constraints, see the documentation for the 'ElfLayout'
datatype.
-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE Trustworthy #-}
{-# LANGUAGE TypeFamilies #-}
module Data.ElfEdit
  ( -- * Top-level definitions
    Elf (..)
  , ElfClass(..)
  , ElfData(..)
  , emptyElf
  , elfFileData
  , elfSegments
  , traverseElfSegments
  , traverseElfDataRegions
  , elfSections
  , findSectionByName
  , removeSectionByName
  , updateSections
  , elfInterpreter
  , elfSymtab
  , module Data.ElfEdit.Enums
    -- * Elf data region
  , ElfDataRegion(..)
    -- * Elf GOT
  , ElfGOT(..)
  , elfGotSection
    -- * Reading Elf files
  , hasElfMagic
  , ElfGetResult(..)
  , ElfParseError(..)
  , ElfInsertError(..)
  , parseElf
  , SomeElf(..)
    -- * Writing Elf files
  , renderElf
    -- ** Layout information
  , ElfLayout
  , elfLayout
  , elfLayoutClass
  , elfLayoutBytes
  , elfLayoutSize
  , elfMagic
  , ehdrSize
  , phdrEntrySize
  , shdrEntrySize
  , buildElfHeader
  , buildElfSegmentHeaderTable
  , buildElfSectionHeaderTable
  , elfRegionFileSize
  , Shdr
  , shdrs
    -- * Sections
  , ElfSection(..)
  , elfSectionFileSize
    -- ** Elf section type
  , ElfSectionType(..)
  , pattern SHT_NULL
  , pattern SHT_PROGBITS
  , pattern SHT_SYMTAB
  , pattern SHT_STRTAB
  , pattern SHT_RELA
  , pattern SHT_HASH
  , pattern SHT_DYNAMIC
  , pattern SHT_NOTE
  , pattern SHT_NOBITS
  , pattern SHT_REL
  , pattern SHT_SHLIB
  , pattern SHT_DYNSYM
    -- ** Elf section flags
  , ElfSectionFlags
  , shf_none
  , shf_write
  , shf_alloc
  , shf_execinstr
  , shf_merge
  , shf_tls
    -- * Segment operations.
  , ElfSegment(..)
    -- ** Elf segment type
  , ElfSegmentType(..)
  , pattern PT_NULL
  , pattern PT_LOAD
  , pattern PT_DYNAMIC
  , pattern PT_INTERP
  , pattern PT_NOTE
  , pattern PT_SHLIB
  , pattern PT_PHDR
  , pattern PT_TLS
  , pattern PT_NUM
  , pattern PT_LOOS
  , pattern PT_GNU_EH_FRAME
  , pattern PT_GNU_STACK
  , pattern PT_GNU_RELRO
  , pattern PT_HIOS
  , pattern PT_LOPROC
  , pattern PT_HIPROC
    -- ** Elf segment flags
  , ElfSegmentFlags
  , pf_none, pf_x, pf_w, pf_r
    -- ** ElfMemSize
  , ElfMemSize(..)
    -- ** Layout information from Elf segments
  , allPhdrs
  , Phdr(..)
  , FileOffset(..)
  , phdrFileRange
    -- * Symbol Table Entries
  , ElfSymbolTable(..)
  , ElfSymbolTableEntry(..)
  , ppSymbolTableEntries
  , symbolTableEntrySize
    -- ** Elf symbol visibility
  , steVisibility
  , ElfSymbolVisibility(..)
  , pattern STV_DEFAULT
  , pattern STV_INTERNAL
  , pattern STV_HIDDEN
  , pattern STV_PROTECTED
    -- * Relocations
  , IsRelocationType(..)
  , RelaWidth(..)
  , RelaEntry(..)
  , ppRelaEntries
  , elfRelaEntries
    -- ** 32-bit x86 relocations
  , module Data.ElfEdit.Relocations.I386
    -- * 64-bit x86 relocations
  , module Data.ElfEdit.Relocations.X86_64
    -- ** Relocation utilities
  , ElfWordType
  , ElfIntType
    -- * Dynamic symbol table and relocations
  , DynamicSection(..)
  , module Data.ElfEdit.DynamicArrayTag
  , VersionDef(..)
  , VersionReq(..)
  , VersionReqAux
  , DynamicMap
  , dynamicEntries
    -- * Common definitions
  , Range
  , hasPermissions
  , stringTable
  ) where

import           Control.Lens ((^.), (^..), filtered, over)
import           Control.Monad
import           Data.Binary
import           Data.Binary.Get
import           Data.Bits
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Lazy.UTF8 as L (toString)
import qualified Data.ByteString.UTF8 as B (toString)
import qualified Data.Foldable as F
import           Data.Int
import qualified Data.Map.Strict as Map
import           Data.Maybe
import           Text.PrettyPrint.ANSI.Leijen hiding ((<>), (<$>))

import           Data.ElfEdit.DynamicArrayTag
import           Data.ElfEdit.Enums
import           Data.ElfEdit.Get
import           Data.ElfEdit.Layout
import           Data.ElfEdit.Relocations
import           Data.ElfEdit.Relocations.I386
import           Data.ElfEdit.Relocations.X86_64
import           Data.ElfEdit.Types

------------------------------------------------------------------------
-- Utilities

-- | Returns null-terminated string at given index in bytestring.
lookupStringL :: Int64 -> L.ByteString -> L.ByteString
lookupStringL o b = L.takeWhile (/= 0) $ L.drop o b

------------------------------------------------------------------------
-- Elf Layout

-- | Return true if section has the given name.
hasSectionName :: ElfSection w -> String -> Bool
hasSectionName section name = elfSectionName section == name

-- | Given a section name, returns sections matching that name.
--
-- Section names in elf are not necessarily unique.
findSectionByName :: String -> Elf w -> [ElfSection w]
findSectionByName name e  = e^..elfSections.filtered (`hasSectionName` name)

-- | Remove section with given name.
removeSectionByName :: String -> Elf w -> Elf w
removeSectionByName nm = over updateSections fn
  where fn s | s `hasSectionName` nm = Nothing
             | otherwise = Just s

-- | List of segments in the file.
elfSegments :: Elf w -> [ElfSegment w]
elfSegments e = concatMap impl (e^.elfFileData)
  where impl (ElfDataSegment s) = s : concatMap impl (F.toList (elfSegmentData s))
        impl _ = []

-- | Return true if this bytestring has the 4 bytes "\DELELF" at the start.
hasElfMagic :: L.ByteString -> Bool
hasElfMagic l = either (const False) (const True) $ flip runGetOrFail l $ do
  ei_magic    <- getByteString 4
  unless (ei_magic == elfMagic) $
    fail "Invalid magic number for ELF"

------------------------------------------------------------------------
-- ElfLayout

-- | Write elf file out to bytestring.
renderElf :: Elf w -> L.ByteString
renderElf = elfLayoutBytes . elfLayout

------------------------------------------------------------------------
-- ElfSymbolVisibility

-- | Visibility for elf symbol
newtype ElfSymbolVisibility = ElfSymbolVisibility { fromElfSymbolVisibility :: Word8 }

-- | Visibility is specified by binding type
pattern STV_DEFAULT = ElfSymbolVisibility 0

-- | OS specific version of STV_HIDDEN.
pattern STV_INTERNAL = ElfSymbolVisibility 1

-- | Can only be seen inside current component.
pattern STV_HIDDEN = ElfSymbolVisibility 2

-- | Can only be seen inside current component.
pattern STV_PROTECTED = ElfSymbolVisibility 3

instance Show ElfSymbolVisibility where
  show v =
    case v of
      STV_DEFAULT   -> "DEFAULT"
      STV_INTERNAL  -> "INTERNAL"
      STV_HIDDEN    -> "HIDDEN"
      STV_PROTECTED -> "PROTECTED"
      _ -> "BadVis"

------------------------------------------------------------------------
-- ElfSymbolTableEntry


steVisibility :: ElfSymbolTableEntry w -> ElfSymbolVisibility
steVisibility e = ElfSymbolVisibility (steOther e .&. 0x3)

-- | Pretty print symbol table entries in format used by readelf.
ppSymbolTableEntries :: (Integral w, Bits w, Show w) => [ElfSymbolTableEntry w] -> Doc
ppSymbolTableEntries l = fix_table_columns (snd <$> cols) (fmap fst cols : entries)
  where entries = zipWith ppSymbolTableEntry [0..] l
        cols = [ ("Num:",     alignRight 6)
               , ("Value",    alignLeft 0)
               , ("Size",     alignRight 5)
               , ("Type",     alignLeft  7)
               , ("Bind",     alignLeft  6)
               , ("Vis",      alignLeft 8)
               , ("Ndx",      alignLeft 3)
               , ("Name",     id)
               ]

ppSymbolTableEntry :: (Integral w, Bits w, Show w) => Int -> ElfSymbolTableEntry w -> [String]
ppSymbolTableEntry i e =
  [ show i ++ ":"
  , ppHex (steValue e)
  , show (steSize e)
  , show (steType e)
  , show (steBind e)
  , show (steVisibility e)
    -- Ndx
  , show (steIndex e)
  , B.toString (steName e)
  ]

-- | Return symbol tables in Elf file.
--
-- These are sections labeled, ".symtab" with type SHT_SYMTAB.
-- There should be at most one symbol table, but we return a list in case the
-- elf file happens to contain multiple symbol tables.
elfSymtab :: Elf w -> [ElfSymbolTable w]
elfSymtab = asumDataRegions f
  where f (ElfDataSymtab s) = [s]
        f _ = []

------------------------------------------------------------------------
-- Dynamic information

-- | Dynamic array entry
data Dynamic w
   = Dynamic { dynamicTag :: !ElfDynamicArrayTag
             , _dynamicVal :: !w
             }
  deriving (Show)

-- | Read dynamic array entry.
getDynamic :: forall w . RelaWidth w -> ElfData -> Get (Dynamic (ElfWordType w))
getDynamic w d = elfWordInstances w $ do
  tag <- getRelaWord w d :: Get (ElfWordType w)
  v   <- getRelaWord w d
  return $! Dynamic (ElfDynamicArrayTag (fromIntegral tag)) v

dynamicList :: RelaWidth w -> ElfData -> Get [Dynamic (ElfWordType w)]
dynamicList w d = go []
  where go l = do
          done <- isEmpty
          if done then
            return l
           else do
            e <- getDynamic w d
            case dynamicTag e of
              DT_NULL -> return (reverse l)
              _ -> go (e:l)

type DynamicMap w = Map.Map ElfDynamicArrayTag [w]

insertDynamic :: Dynamic w -> DynamicMap w -> DynamicMap w
insertDynamic (Dynamic tag v) = Map.insertWith (++) tag [v]

dynamicEntry :: ElfDynamicArrayTag -> DynamicMap w -> [w]
dynamicEntry tag m = fromMaybe [] (Map.lookup tag m)

-- | Get the mandatory entry with the given tag from the map.
-- It is required that there is exactly one tag with this type.
optionalDynamicEntry :: Monad m => ElfDynamicArrayTag -> DynamicMap w -> m (Maybe w)
optionalDynamicEntry tag m =
  case dynamicEntry tag m of
    [w] -> return (Just w)
    [] -> return Nothing
    _ -> fail $ "Dynamic information contains multiple " ++ show tag ++ " entries."

-- | Get the mandatory entry with the given tag from the map.
-- It is required that there is exactly one tag with this type.
mandatoryDynamicEntry :: Monad m => ElfDynamicArrayTag -> DynamicMap w -> m w
mandatoryDynamicEntry tag m =
  case dynamicEntry tag m of
    [w] -> return w
    [] -> fail $ "Dynamic information missing " ++ show tag
    _ -> fail $ "Dynamic information contains multiple " ++ show tag ++ " entries."

-- | Return ranges in file containing the given address range.
-- In a well-formed file, the list should contain at most one element.
fileOffsetOfAddr :: (Ord w, Num w) => w -> ElfLayout w -> [Range w]
fileOffsetOfAddr w l =
  [ (dta + offset, n-offset)
  | phdr <- F.toList (l^.phdrs)
  , let seg            = phdrSegment phdr
  , let FileOffset dta = phdrFileStart phdr
  , let n              = phdrFileSize phdr
  , elfSegmentType seg == PT_LOAD
  , let base = elfSegmentVirtAddr seg
  , inRange w (base, n)
  , let offset = w - base
  ]

addressToFile :: Monad m
              => ElfLayout w -- ^ Layout of Elf file
              -> L.ByteString -- ^ Bytestring with contents.
              -> String
              -> w -- ^ Address in memory.
              -> m L.ByteString
addressToFile l b nm w = elfClassInstances (elfLayoutClass l) $
  case fileOffsetOfAddr w l of
    [] -> fail $ "Could not find " ++ nm ++ "."
    [r] -> return (sliceL r b)
    _ -> fail $ "Multiple overlapping segments containing " ++ nm ++ "."

-- | Return  ranges in file containing the given address range.
-- In a well-formed file, the list should contain at most one element.
fileOffsetOfRange :: (Ord w, Num w) => Range w -> ElfLayout w -> [Range w]
fileOffsetOfRange (w,sz) l =
  [ (dta + offset, sz)
  | phdr <- F.toList (l^.phdrs)
  , let seg = phdrSegment phdr
  , let FileOffset dta = phdrFileStart phdr
  , let n = phdrFileSize phdr
  , elfSegmentType seg == PT_LOAD
  , let base = elfSegmentVirtAddr seg
  , inRange w (base, n)
  , let offset = w - base
  , n-offset >= sz
  ]

addressRangeToFile :: Monad m
                   => ElfLayout w -- ^ Layout of Elf file
                   -> L.ByteString -- ^ Bytestring with contents.
                   -> String
                   -> Range w
                   -> m L.ByteString
addressRangeToFile l b nm rMem = elfClassInstances (elfLayoutClass l) $
  case fileOffsetOfRange rMem l of
    [] -> fail $ "Could not find " ++ nm ++ "."
    [r] -> return (sliceL r b)
    _ -> fail $ "Multiple overlapping segments containing " ++ nm ++ "."

-- | Return contents of dynamic string tab.
dynStrTab :: Monad m
          => ElfLayout w -> L.ByteString -> DynamicMap w -> m L.ByteString
dynStrTab l b m = do
  w <-  mandatoryDynamicEntry DT_STRTAB m
  sz <- mandatoryDynamicEntry DT_STRSZ m
  addressRangeToFile l b "dynamic string table" (w,sz)

getDynNeeded :: Integral w => L.ByteString -> DynamicMap w -> [FilePath]
getDynNeeded strTab m =
  let entries = dynamicEntry DT_NEEDED m
      getName w = L.toString $ lookupStringL (fromIntegral w) strTab
   in getName <$> entries

nameFromIndex :: L.ByteString -> Int64 -> String
nameFromIndex strTab o = L.toString $ lookupStringL o strTab

-- | Get string from strTab read by 32-bit offset.
getOffsetString :: ElfData -> L.ByteString -> Get String
getOffsetString d strTab = do
  nameFromIndex strTab . fromIntegral <$> getWord32 d

gnuLinkedList :: Monad m
              => (L.ByteString -> Get a) -- ^ Function for reading.
              -> ElfData
              -> Int -- ^ Number of entries expected.
              -> L.ByteString -- ^ Buffer to read.
              -> m [a]
gnuLinkedList readFn d cnt0 b0 = do
  let readNextVal b = (,) <$> readFn b <*> getWord32 d
  let go 0 _ prev = return (reverse prev)
      go cnt b prev = do
        case runGetOrFail (readNextVal b) b of
          Left (_,_,msg) -> fail msg
          Right (_,_,(d',next)) -> do
            go (cnt-1) (L.drop (fromIntegral next) b) (d':prev)
  go cnt0 b0 []

dynSymTab :: Monad m
          => Elf w
          -> ElfLayout w
          -> L.ByteString
          -> DynamicMap w
          -> m [ElfSymbolTableEntry w]
dynSymTab e l file m = elfClassInstances (elfClass e) $ do
  let cl = elfClass e
  -- Get string table.
  strTab <- L.toStrict <$> dynStrTab l file m

  sym_off <- mandatoryDynamicEntry DT_SYMTAB m
  -- According to a comment in GNU Libc 2.19 (dl-fptr.c:175), you get the
  -- size of the dynamic symbol table by assuming that the string table follows
  -- immediately afterwards.
  str_off <- mandatoryDynamicEntry DT_STRTAB m
  when (str_off < sym_off) $ do
    fail $ "The string table offset is before the symbol table offset."
  -- Size of each symbol table entry.
  syment <- mandatoryDynamicEntry DT_SYMENT m
  when (syment /= symbolTableEntrySize cl) $ do
    fail "Unexpected symbol table entry size"
  let sym_sz = str_off - sym_off
  symtab <- addressRangeToFile l file "dynamic symbol table" (sym_off,sym_sz)
  let nameFn idx = lookupString idx strTab
  return $ runGetMany (getSymbolTableEntry (elfClass e) (elfData e) nameFn) symtab

------------------------------
-- Dynamic relocations

checkPLTREL :: (Integral u, Monad m) => DynamicMap u -> m ()
checkPLTREL dm = do
  mw <- optionalDynamicEntry DT_PLTREL dm
  case mw of
    Nothing -> return ()
    Just w -> do
      when (fromIntegral w /= fromElfDynamicArrayTag DT_RELA) $ do
        fail $ "Only DT_RELA entries are supported."

-- | Return range for ".rela.plt" from DT_JMPREL and DT_PLTRELSZ if
-- defined.
dynRelaPLT :: Monad m => DynamicMap u -> m (Maybe (Range u))
dynRelaPLT dm = do
  mrelaplt <- optionalDynamicEntry DT_JMPREL dm
  case mrelaplt of
    Nothing -> return Nothing
    Just relaplt -> do
      sz <- mandatoryDynamicEntry DT_PLTRELSZ dm
      return $ Just (relaplt, sz)

dynRelaArray :: forall m tp
              . (IsRelocationType tp, Monad m)
             => ElfData
             -> ElfLayout (ElfWordType (RelocationWidth tp))
             -> L.ByteString
             -> DynamicMap (ElfWordType (RelocationWidth tp))
             -> m [RelaEntry tp]
dynRelaArray d l file dm = do
  let w = relaWidth (error "dynRelaEntry temp evaluated" :: tp)
  elfWordInstances w $ checkPLTREL dm
  mrela_offset <- optionalDynamicEntry DT_RELA dm
  case mrela_offset of
    Nothing -> return []
    Just rela_offset -> do
      ent <- mandatoryDynamicEntry DT_RELAENT dm
      sz  <- mandatoryDynamicEntry DT_RELASZ dm
      when (elfWordInstances w $ ent /= relaEntSize w) $
        fail "Unexpected size for relocation entry."
      rela <- addressRangeToFile l file "relocation array" (rela_offset,sz)
      return $! runGetMany (getRelaEntry d) rela

checkRelaCount :: forall tp m
                . (IsRelocationType tp, Monad m)
               => [RelaEntry tp]
               -> DynamicMap (ElfWordType (RelocationWidth tp))
               -> m ()
checkRelaCount relocations dm = do
  elfWordInstances (relaWidth (undefined :: tp))  $ do
  let relaCount = length (filter isRelativeRelaEntry relocations)
  mexpRelaCount <- optionalDynamicEntry DT_RELACOUNT dm
  let correctCount = case mexpRelaCount of
                       Just c -> c == fromIntegral relaCount
                       Nothing -> True
  when (not correctCount) $ do
    fail $ "Incorrect DT_RELACOUNT"

-- | Version definition
data VersionDef = VersionDef { vd_flags :: !Word16
                               -- ^ Version information flags bitmask.
                             , vd_ndx  :: !Word16
                               -- ^ Index in SHT_GNU_versym section of this version.
                             , vd_hash :: !Word32
                               -- ^ Version name hash value.
                             , vd_aux  :: ![String]
                               -- ^ Version or dependency names.
                             } deriving (Show)

gnuVersionDefs :: (Integral w, Show w, Monad m)
               => ElfData
               -> ElfLayout w
               -> L.ByteString
                  -- ^ Contents of file.
               -> L.ByteString
                  -- ^ Dynamic string table.
               -> DynamicMap w
               -> m [VersionDef]
gnuVersionDefs d l file strTab dm = do
  mvd <- optionalDynamicEntry DT_VERDEF dm
  case mvd of
    Nothing -> return []
    Just vd -> do
      vdnum <- mandatoryDynamicEntry DT_VERDEFNUM dm
      def_buffer <- addressToFile l file "symbol version definitions" vd
      gnuLinkedList (readVersionDef d strTab) d (fromIntegral vdnum) def_buffer

readVersionDef :: ElfData -> L.ByteString -> L.ByteString -> Get VersionDef
readVersionDef d strTab b = do
  ver   <- getWord16 d
  when (ver /= 1) $
    fail $ "Unexpected version definition version: " ++ show ver
  flags <- getWord16 d
  ndx   <- getWord16 d
  cnt   <- getWord16 d
  hash  <- getWord32 d
  aux   <- getWord32 d
  let entry_cnt = fromIntegral cnt
  let entry_buffer = L.drop (fromIntegral aux) b
  entries <- gnuLinkedList (\_ -> getOffsetString d strTab) d entry_cnt entry_buffer
  return VersionDef { vd_flags = flags
                    , vd_ndx   = ndx
                    , vd_hash  = hash
                    , vd_aux   = entries
                    }

-- | Version requirement informaito.nx
data VersionReq = VersionReq { vn_file :: String
                             , vn_aux :: [VersionReqAux]
                             } deriving (Show)

readVersionReq :: ElfData -> L.ByteString -> L.ByteString -> Get VersionReq
readVersionReq d strTab b = do
  ver <- getWord16 d
  when (ver /= 1) $ do
    fail $ "Unexpected version need version: " ++ show ver
  cnt  <- getWord16 d
  file <- getOffsetString d strTab
  aux  <- getWord32 d
  let entry_buffer = L.drop (fromIntegral aux) b
  entries <- gnuLinkedList (readVersionReqAux d strTab) d (fromIntegral cnt) entry_buffer
  return VersionReq { vn_file = file
                    , vn_aux = entries
                    }

-- | Version requirement information.
data VersionReqAux = VersionReqAux { vna_hash :: !Word32
                                   , vna_flags :: !Word16
                                   , vna_other :: !Word16
                                   , vna_name :: !String
                                   } deriving (Show)

readVersionReqAux :: ElfData -> L.ByteString -> L.ByteString -> Get VersionReqAux
readVersionReqAux d strTab _ = do
  hash <- getWord32 d
  flags <- getWord16 d
  other   <- getWord16 d
  name <- getOffsetString d strTab
  return VersionReqAux { vna_hash  = hash
                       , vna_flags = flags
                       , vna_other = other
                       , vna_name  = name
                       }

gnuVersionReqs :: (Integral w, Show w, Monad m)
               => ElfData
               -> ElfLayout w
               -> L.ByteString
                  -- ^ Contents of file.
               -> L.ByteString
                  -- ^ Dynamic string table.
               -> DynamicMap w
               -> m [VersionReq]
gnuVersionReqs d l file strTab dm = do
  mvn <- optionalDynamicEntry DT_VERNEED dm
  case mvn of
    Nothing -> return []
    Just vn -> do
      vnnum <- mandatoryDynamicEntry DT_VERNEEDNUM dm
      req_buffer <- addressToFile l file "symbol version requirements" vn
      gnuLinkedList (readVersionReq d strTab) d (fromIntegral vnnum) req_buffer

data DynamicSection u s tp
   = DynSection { dynNeeded :: ![FilePath]
                , dynSOName :: Maybe String
                , dynInit :: [u]
                , dynFini :: [u]
                , dynSymbols :: [ElfSymbolTableEntry u]
                , dynRelocations :: ![RelaEntry tp]
                , dynSymVersionTable :: ![Word16]
                , dynVersionDefs :: ![VersionDef]
                , dynVersionReqs :: ![VersionReq]
                  -- | Address of GNU Hash address.
                , dynGNUHASH_Addr :: !(Maybe u)
                  -- | Address of PLT in memory.
                , dynPLTAddr :: !(Maybe u)
                , dynRelaPLTRange :: !(Maybe (Range u))
                  -- | Value of DT_DEBUG.
                , dynDebug :: !(Maybe u)
                , dynUnparsed :: !(DynamicMap u)
                }
  deriving (Show)

gnuSymVersionTable :: (Monad m)
                   => ElfData
                   -> ElfLayout w
                   -> L.ByteString
                   -> DynamicMap w
                   -> Int -- ^ Number of symbols
                   -> m [Word16]
gnuSymVersionTable d l file dm symcnt = do
  mvs <- optionalDynamicEntry DT_VERSYM dm
  case mvs of
    Nothing -> return []
    Just vs -> do
      buffer <- addressToFile l file "symbol version requirements" vs
      return $ runGet (replicateM symcnt (getWord16 d)) buffer

parsed_dyntags :: [ElfDynamicArrayTag]
parsed_dyntags =
  [ DT_NEEDED
  , DT_PLTRELSZ
  , DT_PLTGOT

  , DT_STRTAB
  , DT_SYMTAB
  , DT_RELA
  , DT_RELASZ
  , DT_RELAENT
  , DT_STRSZ
  , DT_SYMENT
  , DT_INIT
  , DT_FINI
  , DT_SONAME

  , DT_PLTREL
  , DT_DEBUG

  , DT_JMPREL

  , DT_GNU_HASH

  , DT_VERSYM
  , DT_RELACOUNT

  , DT_VERDEF
  , DT_VERDEFNUM
  , DT_VERNEED
  , DT_VERNEEDNUM
  ]

-- | This returns information about the dynamic segment in a elf file
-- if it exists.
--
-- The code assumes that there is at most one segment with type PT_Dynamic.
dynamicEntries :: forall s tp m
                . (IsRelocationType tp, Monad m)
               => Elf (ElfWordType (RelocationWidth tp))
               -> m (Maybe (DynamicSection (ElfWordType (RelocationWidth tp)) s tp))
dynamicEntries e = elfClassInstances (elfClass e) $ do
  let w :: RelaWidth (RelocationWidth tp)
      w = relaWidth (undefined :: tp)
  let l :: ElfLayout (ElfWordType (RelocationWidth tp))
      l = elfLayout e
  let file = elfLayoutBytes l
  case filter (\p -> elfSegmentType (phdrSegment p) == PT_DYNAMIC) (F.toList (l^.phdrs)) of
    [] -> return Nothing
    [phdr] -> do
      let p = phdrFileRange phdr
      let elts :: [Dynamic (ElfWordType (RelocationWidth tp))]
          elts = runGet (dynamicList w (elfData e)) (sliceL p file)
      let m :: DynamicMap (ElfWordType (RelocationWidth tp))
          m = F.foldl' (flip insertDynamic) Map.empty elts

      strTab <- dynStrTab l file m

      mnm_index <- optionalDynamicEntry DT_SONAME m
      let mnm = nameFromIndex strTab . fromIntegral <$> mnm_index

      symbols <- dynSymTab e l file m

      let isUnparsed tag _ = not (tag `elem` parsed_dyntags)
      sym_versions <- gnuSymVersionTable (elfData e) l file m (length symbols)
      version_defs <- elfWordInstances w $
        gnuVersionDefs (elfData e) l file strTab m
      version_reqs <- elfWordInstances w $
        gnuVersionReqs (elfData e) l file strTab m

      relocations <- dynRelaArray (elfData e) l file m
      checkRelaCount relocations m

      gnuhashAddr <- optionalDynamicEntry DT_GNU_HASH m
      pltAddr     <- optionalDynamicEntry DT_PLTGOT m
      relaPLTRange <- dynRelaPLT m
      mdebug <- optionalDynamicEntry DT_DEBUG m

      return $ Just DynSection { dynNeeded = getDynNeeded strTab m
                               , dynSOName = mnm
                               , dynInit = dynamicEntry DT_INIT m
                               , dynFini = dynamicEntry DT_FINI m
                               , dynSymbols = symbols
                               , dynRelocations = relocations
                               , dynSymVersionTable = sym_versions
                               , dynVersionDefs = version_defs
                               , dynVersionReqs = version_reqs
                               , dynGNUHASH_Addr = gnuhashAddr
                               , dynPLTAddr = pltAddr
                               , dynRelaPLTRange = relaPLTRange
                               , dynDebug = mdebug
                               , dynUnparsed = Map.filterWithKey isUnparsed m
                               }
    _ -> fail "Multiple dynamic segments."

------------------------------------------------------------------------
-- Elf interpreter

-- | Return elf interpreter in a PT_INTERP segment if one exists, or Nothing is no interpreter
-- is defined.  This will call the Monad fail operation if the contents of the data cannot be
-- parsed.
elfInterpreter :: Monad m => Elf w -> m (Maybe FilePath)
elfInterpreter e =
  case filter (\s -> elfSegmentType s == PT_INTERP) (elfSegments e) of
    [] -> return Nothing
    seg:_ ->
      case F.toList (elfSegmentData seg) of
        [ElfDataSection s] -> return (Just (B.toString (elfSectionData s)))
        _ -> fail "Could not parse elf section."
