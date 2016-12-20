{-
Copyright        : (c) Galois, Inc 2016
Maintainer       : Joe Hendrix <jhendrix@galois.com>

Defines function for parsing dynamic section.
-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE UndecidableInstances #-}
module Data.ElfEdit.Dynamic
  ( module Data.ElfEdit.Dynamic.Tag
  , DynamicSection(..)
  , VersionDef(..)
  , VersionReq(..)
  , VersionReqAux(..)
  , VirtAddrMap
  , virtAddrMap
  , DynamicMap
  , dynamicEntries
  ) where

import           Control.Monad
import           Control.Monad.Except
import           Control.Monad.Reader
import           Data.Binary.Get hiding (runGet)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import qualified Data.Foldable as F
import           Data.Int
import qualified Data.Map.Strict as Map
import           Data.Maybe
import           Data.Word

import           Data.ElfEdit.Dynamic.Tag
import           Data.ElfEdit.Get
import           Data.ElfEdit.Layout
import           Data.ElfEdit.Relocations
import           Data.ElfEdit.Types

------------------------------------------------------------------------
-- Utilities

-- | Returns null-terminated string at given index in bytestring.
lookupStringL :: Int64 -> L.ByteString -> B.ByteString
lookupStringL o b = L.toStrict (L.takeWhile (/= 0) $ L.drop o b)

-- | Maps the start of memory segment addresses to the file contents backing that
-- memory
type VirtAddrMap w = Map.Map w L.ByteString

-- | Creates a virtual address map from bytestring and list of program headers.
virtAddrMap :: Integral w
            => L.ByteString -- ^ File contents
            -> [Phdr w] -- ^ Program headers
            -> Maybe (VirtAddrMap w)
virtAddrMap file = F.foldlM ins Map.empty
  where ins m phdr
          | elfSegmentType seg /= PT_LOAD = pure m
          | otherwise =
            case Map.lookupLE addr m of
              Just (prev, old) | addr - prev < fromIntegral (L.length old) -> Nothing
              _ -> pure $! Map.insert addr new_contents m
          where seg = phdrSegment phdr
                addr = elfSegmentVirtAddr seg
                FileOffset dta = phdrFileStart phdr
                n              = phdrFileSize phdr
                new_contents   = sliceL (dta,n) file

------------------------------------------------------------------------
-- DynamicError

data DynamicError
   = MandatoryEntryMissing    !ElfDynamicTag
   | EntryDuplicated          !ElfDynamicTag
   | EntryAddressNotFound     !ElfDynamicTag
   | EntrySizeTooSmall        !ElfDynamicTag
   | BadSymbolTableEntrySize
   | StrtabNotAfterSymtab
   | ErrorParsingDynamicEntries !String
   | ErrorParsingVerDefs !String
   | ErrorParsingVerReqs !String
   | ErrorParsingVerSym  !String
   | ErrorParsingSymTab  !String
   | ErrorParsingRelaEntries !String
   | IncorrectRelaCount
   | IncorrectRelaSize


instance Show DynamicError where
  show (MandatoryEntryMissing tag) =
    "Dynamic information missing " ++ show tag
  show (EntryDuplicated tag) =
    "Dynamic information contains multiple " ++ show tag ++ " entries."
  show (EntryAddressNotFound tag) =
    "Could not find " ++ show tag ++ " address."
  show (EntrySizeTooSmall tag) =
    show tag ++ "refers past end of memory segment."
  show BadSymbolTableEntrySize = "Unexpected symbol table entry size."
  show (ErrorParsingDynamicEntries msg) = "Invalid dynamic entries: " ++ msg
  show (ErrorParsingVerDefs msg) = "Invalid version defs: " ++ msg
  show (ErrorParsingVerReqs msg) = "Invalid version reqs: " ++ msg
  show (ErrorParsingVerSym msg) = "Invalid DT_VERSYM: " ++ msg
  show (ErrorParsingSymTab msg) = "Invalid symbol table: " ++ msg
  show (ErrorParsingRelaEntries msg) = "Could not parse rela entries: " ++ msg
  show StrtabNotAfterSymtab = "The dynamic string table did not appear just after symbol table."
  show IncorrectRelaCount = "Incorrect DT_RELACOUNT"
  show IncorrectRelaSize = "DT_RELAENT has unexpected size"

------------------------------------------------------------------------
-- DynamicMap

type DynamicMap w = Map.Map ElfDynamicTag [w]

insertDynamic :: Dynamic w -> DynamicMap w -> DynamicMap w
insertDynamic (Dynamic tag v) = Map.insertWith (++) tag [v]

dynamicEntry :: ElfDynamicTag -> DynamicMap w -> [w]
dynamicEntry tag m = fromMaybe [] (Map.lookup tag m)

------------------------------------------------------------------------
-- DynamicParser

data DynamicParseContext w = DynamicParseContext { fileData  :: !ElfData
                                                 , fileClass :: !(ElfClass w)
                                                   -- ^ Class for Elf file.
                                                 , fileAddrMap :: !(VirtAddrMap w)
                                                   -- ^ Map from virtual address to file
                                                   -- contents at that range.
                                                 }

type DynamicParser w = ExceptT DynamicError (Reader (DynamicParseContext w))

runDynamicParser :: ElfData
                 -> ElfClass w
                 -> VirtAddrMap w
                 -> DynamicParser w a
                 -> Either DynamicError a
runDynamicParser dta cl m p = elfClassInstances cl $
  let ctx = DynamicParseContext { fileData  = dta
                                , fileClass = cl
                                , fileAddrMap = m
                                }
   in runReader (runExceptT p) ctx

-- | Get the mandatory entry with the given tag from the map.
-- It is required that there is exactly one tag with this type.
optionalDynamicEntry :: ElfDynamicTag -> DynamicMap w -> DynamicParser w (Maybe w)
optionalDynamicEntry tag m =
  case dynamicEntry tag m of
    [w] -> return (Just w)
    [] -> return Nothing
    _   -> throwError $ EntryDuplicated tag

-- | Get the mandatory entry with the given tag from the map.
-- It is required that there is exactly one tag with this type.
mandatoryDynamicEntry :: ElfDynamicTag -> DynamicMap w -> DynamicParser w w
mandatoryDynamicEntry tag m =
  case dynamicEntry tag m of
    [w] -> return w
    []  -> throwError $ MandatoryEntryMissing tag
    _   -> throwError $ EntryDuplicated tag

------------------------------------------------------------------------
-- Lookup address

addressToFile :: ElfDynamicTag -- ^ Tag this address was defined in
              -> w -- ^ Address in memory.
              -> DynamicParser w L.ByteString
addressToFile tag addr = do
  cl       <- asks fileClass
  m        <- asks fileAddrMap
  elfClassInstances cl $ do
  case Map.lookupLE addr m of
    Just (prev, contents) | addr - prev <= fromIntegral (L.length contents) -> do
      let seg_offset = addr - prev
      return $ L.drop (fromIntegral seg_offset) contents
    _ -> throwError $ EntryAddressNotFound tag

addressRangeToFile :: (ElfDynamicTag, ElfDynamicTag)
                   -> Range w
                   -> DynamicParser w L.ByteString
addressRangeToFile (tag_off, tag_size) (off, sz) = do
  cl <- asks fileClass
  elfClassInstances cl $ do
  bs <- addressToFile tag_off off
  when (L.length bs < fromIntegral sz) $ do
    throwError $ EntrySizeTooSmall tag_size
  pure $! L.take (fromIntegral sz) bs

------------------------------------------------------------------------
-- Dynamic

-- | Dynamic array entry
data Dynamic w
   = Dynamic { dynamicTag :: !ElfDynamicTag
             , _dynamicVal :: !w
             }
  deriving (Show)

-- | Read dynamic array entry.
getDynamic :: forall w . RelaWidth w -> ElfData -> Get (Dynamic (ElfWordType w))
getDynamic w d = elfWordInstances w $ do
  tag <- getRelaWord w d :: Get (ElfWordType w)
  v   <- getRelaWord w d
  return $! Dynamic (ElfDynamicTag (fromIntegral tag)) v

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

------------------------------------------------------------------------
-- GNU extension

-- | Parses a linked list
gnuLinkedList :: (L.ByteString -> Get a) -- ^ Function for reading.
              -> ElfData
              -> Int -- ^ Number of entries expected.
              -> L.ByteString -- ^ Buffer to read.
              -> Either String [a]
gnuLinkedList readFn d = go []
  where readNextVal b = (,) <$> readFn b <*> getWord32 d
        go prev 0 _ = return (reverse prev)
        go prev cnt b =
          case runGetOrFail (readNextVal b) b of
            Left (_,_,msg) -> Left msg
            Right (_,_,(d',next)) -> do
              go (d':prev) (cnt-1) (L.drop (fromIntegral next) b)

------------------------------------------------------------------------
-- VersionDef

-- | Version definition
data VersionDef = VersionDef { vd_flags :: !Word16
                               -- ^ Version information flags bitmask.
                             , vd_ndx  :: !Word16
                               -- ^ Index in SHT_GNU_versym section of this version.
                             , vd_hash :: !Word32
                               -- ^ Version name hash value.
                             , vd_aux  :: ![B.ByteString]
                               -- ^ Version or dependency names.
                             } deriving (Show)

-- | Get string from strTab read by 32-bit offset.
getOffsetString :: ElfData -> L.ByteString -> Get B.ByteString
getOffsetString d strTab = do
  (`lookupStringL` strTab) . fromIntegral <$> getWord32 d

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
  entries <-
    either fail pure $
    gnuLinkedList (\_ -> getOffsetString d strTab) d entry_cnt entry_buffer
  return VersionDef { vd_flags = flags
                    , vd_ndx   = ndx
                    , vd_hash  = hash
                    , vd_aux   = entries
                    }

gnuVersionDefs :: L.ByteString
                  -- ^ Dynamic string table.
               -> DynamicMap w
               -> DynamicParser w [VersionDef]
gnuVersionDefs strTab dm = do
  ctx <- ask
  let d = fileData ctx
  mvd <- optionalDynamicEntry DT_VERDEF dm
  case mvd of
    Nothing -> return []
    Just vd -> do
      vdnum <- mandatoryDynamicEntry DT_VERDEFNUM dm
      def_buffer <- addressToFile DT_VERDEF vd
      elfClassInstances (fileClass ctx) $
        either (throwError . ErrorParsingVerDefs) pure $
        gnuLinkedList (readVersionDef d strTab) d (fromIntegral vdnum) def_buffer

------------------------------------------------------------------------
-- VersionReq

-- | Version requirement auxillery information.
data VersionReqAux = VersionReqAux { vna_hash :: !Word32
                                   , vna_flags :: !Word16
                                   , vna_other :: !Word16
                                   , vna_name :: !B.ByteString
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

-- | Version requirement information.
data VersionReq = VersionReq { vn_file :: B.ByteString
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
  entries <- either fail pure $
    gnuLinkedList (readVersionReqAux d strTab) d (fromIntegral cnt) entry_buffer
  return VersionReq { vn_file = file
                    , vn_aux = entries
                    }

gnuVersionReqs :: L.ByteString
                  -- ^ Dynamic string table.
               -> DynamicMap w
               -> DynamicParser w [VersionReq]
gnuVersionReqs strTab dm = do
  ctx <- ask
  let d = fileData ctx
  mvn <- optionalDynamicEntry DT_VERNEED dm
  case mvn of
    Nothing -> return []
    Just vn -> do
      req_buffer <- addressToFile DT_VERNEED vn
      vnnum <- mandatoryDynamicEntry DT_VERNEEDNUM dm
      elfClassInstances (fileClass ctx) $ do
      either (throwError . ErrorParsingVerReqs) pure $
        gnuLinkedList (readVersionReq d strTab) d (fromIntegral vnnum) req_buffer

------------------------------------------------------------------------
-- DynamicSection

data DynamicSection tp
   = DynSection { dynNeeded :: ![B.ByteString]
                , dynSOName :: Maybe B.ByteString
                , dynInit :: [RelocationWord tp]
                , dynFini :: [RelocationWord tp]
                , dynSymbols :: [ElfSymbolTableEntry (RelocationWord tp)]
                , dynRelocations :: ![RelaEntry tp]
                , dynSymVersionTable :: ![Word16]
                , dynVersionDefs :: ![VersionDef]
                , dynVersionReqs :: ![VersionReq]
                  -- | Address of GNU Hash address.
                , dynGNUHASH_Addr :: !(Maybe (RelocationWord tp))
                  -- | Address of PLT in memory.
                , dynPLTAddr :: !(Maybe (RelocationWord tp))
                , dynRelaPLTRange :: !(Maybe (Range (RelocationWord tp)))
                  -- | Value of DT_DEBUG.
                , dynDebug :: !(Maybe (RelocationWord tp))
                , dynUnparsed :: !(DynamicMap (RelocationWord tp))
                }

deriving instance (Show (RelocationWord tp), IsRelocationType tp)
  => Show (DynamicSection tp)


------------------------------------------------------------------------
-- Parsing dynamic section

-- | Lookup 'DY
getDynNeeded :: Integral w => L.ByteString -> DynamicMap w -> [B.ByteString]
getDynNeeded strTab m =
  let entries = dynamicEntry DT_NEEDED m
      getName w = lookupStringL (fromIntegral w) strTab
   in getName <$> entries

checkRelaCount :: forall tp
                . IsRelocationType tp
               => [RelaEntry tp]
               -> DynamicMap (RelocationWord tp)
               -> DynamicParser (RelocationWord tp) ()
checkRelaCount relocations dm = do
  elfWordInstances (relaWidth (undefined :: tp))  $ do
  let relaCount = length (filter isRelativeRelaEntry relocations)
  mexpRelaCount <- optionalDynamicEntry DT_RELACOUNT dm
  let correctCount = case mexpRelaCount of
                       Just c -> c == fromIntegral relaCount
                       Nothing -> True
  when (not correctCount) $ do
    throwError IncorrectRelaCount

gnuSymVersionTable :: DynamicMap w
                   -> Int -- ^ Number of symbols
                   -> DynamicParser w [Word16]
gnuSymVersionTable dm symcnt = do
  dta <- asks fileData
  mvs <- optionalDynamicEntry DT_VERSYM dm
  case mvs of
    Nothing -> return []
    Just vs -> do
      buffer <- addressToFile DT_VERSYM vs
      case runGetOrFail (replicateM symcnt (getWord16 dta)) buffer of
        Right (_,_,l) -> pure l
        Left (_,_,msg) -> throwError (ErrorParsingVerSym msg)

-- | Return contents of dynamic string tab.
dynStrTab :: DynamicMap w
          -> DynamicParser w L.ByteString
dynStrTab m = do
  w <-  mandatoryDynamicEntry DT_STRTAB m
  sz <- mandatoryDynamicEntry DT_STRSZ m
  addressRangeToFile (DT_STRTAB, DT_STRSZ) (w,sz)

dynSymTab :: L.ByteString
             -- ^ String table
          -> DynamicMap w
          -> DynamicParser w [ElfSymbolTableEntry w]
dynSymTab strTab m = do
  cl  <- asks fileClass
  dta <- asks fileData
  elfClassInstances cl $ do

  sym_off <- mandatoryDynamicEntry DT_SYMTAB m
  -- According to a comment in GNU Libc 2.19 (dl-fptr.c:175), you get the
  -- size of the dynamic symbol table by assuming that the string table follows
  -- immediately afterwards.
  str_off <- mandatoryDynamicEntry DT_STRTAB m
  -- Size of each symbol table entry.
  syment <- mandatoryDynamicEntry DT_SYMENT m
  when (syment /= symbolTableEntrySize cl) $ do
    throwError BadSymbolTableEntrySize
  symtab <- do
    symtab_full <- addressToFile DT_SYMTAB sym_off
    let sym_sz = fromIntegral $ str_off - sym_off
    when (str_off < sym_off || L.length symtab_full < sym_sz) $ do
      throwError StrtabNotAfterSymtab
    pure $! L.take sym_sz symtab_full

  let nameFn idx = lookupStringL (fromIntegral idx) strTab
  case runGetMany (getSymbolTableEntry cl dta nameFn) symtab of
    Left msg -> throwError $ ErrorParsingSymTab msg
    Right entries -> return entries

parsed_dyntags :: [ElfDynamicTag]
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

checkPLTREL :: DynamicMap w -> DynamicParser w ()
checkPLTREL dm = do
  mw <- optionalDynamicEntry DT_PLTREL dm
  cl <- asks fileClass
  case mw of
    Nothing -> return ()
    Just w -> elfClassInstances cl $ do
      when (ElfDynamicTag (fromIntegral w) /= DT_RELA) $ do
        fail $ "Only DT_RELA entries are supported."

dynRelaArray :: forall tp
              . IsRelocationType tp
             => DynamicMap (RelocationWord tp)
             -> DynamicParser (RelocationWord tp) [RelaEntry tp]
dynRelaArray dm = do
  ctx <- ask :: DynamicParser (RelocationWord tp) (DynamicParseContext (RelocationWord tp))
  let d = fileData ctx
  checkPLTREL dm
  mrela_offset <- optionalDynamicEntry DT_RELA dm
  case mrela_offset of
    Nothing -> return []
    Just rela_offset -> do
      sz  <- mandatoryDynamicEntry DT_RELASZ dm
      rela <- addressRangeToFile (DT_RELA, DT_RELASZ) (rela_offset,sz)

      ent <- mandatoryDynamicEntry DT_RELAENT dm
      let w = relaWidth (error "relaWidth evaluated" :: tp)
      when (elfClassInstances (fileClass ctx) $ ent /= relaEntSize w) $
        throwError IncorrectRelaSize
      case runGetMany (getRelaEntry d) rela of
        Left msg -> throwError (ErrorParsingRelaEntries msg)
        Right entries -> return entries

-- | Return range for ".rela.plt" from DT_JMPREL and DT_PLTRELSZ if
-- defined.
dynRelaPLT :: DynamicMap u -> DynamicParser u (Maybe (Range u))
dynRelaPLT dm = do
  mrelaplt <- optionalDynamicEntry DT_JMPREL dm
  case mrelaplt of
    Nothing -> return Nothing
    Just relaplt -> do
      sz <- mandatoryDynamicEntry DT_PLTRELSZ dm
      return $ Just (relaplt, sz)

-- | This returns information about the dynamic segment in a elf file
-- if it exists.
--
-- The code assumes that there is at most one segment with type 'PT_DYNAMIC'.
dynamicEntries :: forall tp
                . IsRelocationType tp
               => ElfData
                  -- ^ Elf data
               -> ElfClass (RelocationWord tp)
                  -- ^ Elf class
               -> VirtAddrMap (RelocationWord tp)
                  -- ^ Virtual address map
               -> L.ByteString
                  -- ^ Dynamic section contents
               -> Either DynamicError (DynamicSection tp)
dynamicEntries d cl virtMap dynamic = elfClassInstances cl $
 runDynamicParser d cl virtMap $ do
  let w :: RelaWidth (RelocationWidth tp)
      w = relaWidth (error "relaWidth evaluated" :: tp)
  m <-
    case runGetOrFail (dynamicList w d) dynamic of
      Left  (_,_,msg)  -> throwError (ErrorParsingDynamicEntries msg)
      Right (_,_,elts) -> pure (F.foldl' (flip insertDynamic) Map.empty elts)

  strTab <- dynStrTab m

  mnm_index <- optionalDynamicEntry DT_SONAME m
  let mnm = (`lookupStringL` strTab) . fromIntegral <$> mnm_index

  symbols <- dynSymTab strTab m

  let isUnparsed tag _ = not (tag `elem` parsed_dyntags)
  sym_versions <- gnuSymVersionTable m (length symbols)
  version_defs <- gnuVersionDefs strTab m
  version_reqs <- gnuVersionReqs strTab m

  relocations <- dynRelaArray m
  checkRelaCount relocations m

  gnuhashAddr  <- optionalDynamicEntry DT_GNU_HASH m
  pltAddr      <- optionalDynamicEntry DT_PLTGOT m
  relaPLTRange <- dynRelaPLT m
  mdebug       <- optionalDynamicEntry DT_DEBUG m

  return $ DynSection { dynNeeded = getDynNeeded strTab m
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
