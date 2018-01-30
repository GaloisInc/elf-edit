{-
Copyright        : (c) Galois, Inc 2016
Maintainer       : Joe Hendrix <jhendrix@galois.com>

Defines function for parsing dynamic section.
-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE UndecidableInstances #-}
module Data.ElfEdit.Dynamic
  ( module Data.ElfEdit.Dynamic.Tag
  , DynamicSection(..)
  , dynNeeded
  , dynInit
  , dynFini
  , dynUnparsed
  , dynRelocations
  , dynPLTRel
  , dynamicEntries
  , dynamicEntriesFromSegment
  , DynamicMap
  , VersionedSymbol
  , VersionId(..)
  , dynSymTable
    -- * Virtual address map
  , VirtAddrMap
  , virtAddrMap
  , VersionDef(..)
  , VersionDefFlags
  , ver_flg_base
  , ver_flg_weak
  , VersionReq(..)
  , VersionReqAux(..)
  , VersionTableValue(..)
  ) where

import           Control.Monad
import           Control.Monad.Except
import           Control.Monad.Reader
import           Control.Monad.State
import           Data.Binary.Get hiding (runGet)
import           Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Char8 as BSC
import           Data.Foldable
import qualified Data.Map.Strict as Map
import           Data.Maybe
import qualified Data.Vector as V
import           Data.Word
import           Numeric (showHex)

import           Data.ElfEdit.Dynamic.Tag
import           Data.ElfEdit.Get
import           Data.ElfEdit.Layout
import           Data.ElfEdit.Relocations
import           Data.ElfEdit.Types

------------------------------------------------------------------------
-- Utilities

-- | Maps the start of memory segment addresses to the file contents backing that
-- memory
type VirtAddrMap w = Map.Map (ElfWordType w) L.ByteString

-- | Creates a virtual address map from bytestring and list of program headers.
--
-- Returns 'Nothing' if the map could not be created due to overlapping segments.
virtAddrMap :: Integral (ElfWordType w)
            => L.ByteString -- ^ File contents
            -> [Phdr w] -- ^ Program headers
            -> Maybe (VirtAddrMap w)
virtAddrMap file = foldlM ins Map.empty
  where -- Insert phdr into map if it is loadable
        ins m phdr
            -- If segment is not loadable or empty, leave map unchanged
          | elfSegmentType seg /= PT_LOAD || n == 0 = pure m
            -- If segment overlaps with a previous segment, then return
            -- 'Nothing' to indicate an error.
          | Just (prev, old) <- Map.lookupLE addr m
          , addr - prev < fromIntegral (L.length old) = Nothing
            -- Insert phdr into map
          | otherwise =
            pure $! Map.insert addr new_contents m
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
   | VerSymTooSmall
   | ErrorParsingSymTab  !String
   | ErrorParsingRelaEntries !String
   | IncorrectRelaSize
   | IllegalNameIndex
   | ErrorParsingPLTRelaEntries !String
   | DupVersionReqAuxIndex !Word16
   | UnresolvedVersionReqAuxIndex !B.ByteString !Word16
   | MultipleDynamicSegments
   | OverlappingLoadableSegments


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
  show (ErrorParsingSymTab msg) = "Invalid symbol table: " ++ msg
  show (ErrorParsingRelaEntries msg) = "Could not parse relocation entries: " ++ msg
  show IncorrectRelaSize = "DT_RELAENT has unexpected size"
  show (ErrorParsingPLTRelaEntries msg) = "Could not parse plt relocation entries: " ++ msg
  show IllegalNameIndex = "The index of the DT_SONAME is illegal."
  show StrtabNotAfterSymtab = "The dynamic string table did not appear just after symbol table."
  show (DupVersionReqAuxIndex idx) = "The version requirement index " ++ show idx ++ " is not unique."
  show (UnresolvedVersionReqAuxIndex sym idx) =
    "Symbol " ++ BSC.unpack sym ++ " has unresolvable version requirement index " ++ show idx ++ "."
  show VerSymTooSmall = "File ends before end of symbol version table."
  show MultipleDynamicSegments = "File contained multiple dynamic segments."
  show OverlappingLoadableSegments = "File contained overlapping loadable segments."

------------------------------------------------------------------------
-- DynamicMap

type DynamicMap w = Map.Map ElfDynamicTag [ElfWordType w]

insertDynamic :: Dynamic v ->  Map.Map ElfDynamicTag [v] -> Map.Map ElfDynamicTag [v]
insertDynamic (Dynamic tag v) = Map.insertWith (++) tag [v]

-- | Return entries in the dynamic map.
dynamicEntry :: ElfDynamicTag -> Map.Map ElfDynamicTag [v] -> [v]
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
optionalDynamicEntry :: ElfDynamicTag -> DynamicMap w -> DynamicParser w (Maybe (ElfWordType w))
optionalDynamicEntry tag m =
  case dynamicEntry tag m of
    [w] -> return (Just w)
    [] -> return Nothing
    _   -> throwError $ EntryDuplicated tag

-- | Get the mandatory entry with the given tag from the map.
-- It is required that there is exactly one tag with this type.
mandatoryDynamicEntry :: ElfDynamicTag -> DynamicMap w -> DynamicParser w (ElfWordType w)
mandatoryDynamicEntry tag m =
  case dynamicEntry tag m of
    [w] -> return w
    []  -> throwError $ MandatoryEntryMissing tag
    _   -> throwError $ EntryDuplicated tag

-- | Parse a word16 with the given data.
word16 :: ElfData -> L.ByteString -> DynamicParser w Word16
word16 d s = do
  let idx i = fromIntegral (s `L.index` i)
  case d of
    _ | L.length s < 2 -> throwError VerSymTooSmall
    ELFDATA2LSB -> pure $ (idx 1 `shiftL` 8) .|. idx 0
    ELFDATA2MSB -> pure $ (idx 0 `shiftL` 8) .|. idx 1

------------------------------------------------------------------------
-- Lookup address

addressToFile :: ElfDynamicTag -- ^ Tag this address was defined in
              -> ElfWordType w -- ^ Address in memory.
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
                   -> Range (ElfWordType w)
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
getDynamic :: forall w . ElfClass w -> ElfData -> Get (Dynamic (ElfWordType w))
getDynamic w d = elfClassInstances w $ do
  tag <- getRelaWord w d :: Get (ElfWordType w)
  v   <- getRelaWord w d
  return $! Dynamic (ElfDynamicTag (fromIntegral tag)) v

dynamicList :: ElfClass w -> ElfData -> Get [Dynamic (ElfWordType w)]
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

newtype VersionDefFlags = VersionDefFlags Word16
  deriving (Bits, Eq)

ver_flg_base :: VersionDefFlags
ver_flg_base = VersionDefFlags 1

ver_flg_weak :: VersionDefFlags
ver_flg_weak = VersionDefFlags 2

instance Show VersionDefFlags where
  show (VersionDefFlags 0) = "none"
  show (VersionDefFlags 1) = "BASE"
  show (VersionDefFlags 2) = "weak"
  show (VersionDefFlags w) = showHex w ""


-- | Version definition
data VersionDef = VersionDef { vd_flags :: !VersionDefFlags
                               -- ^ Version information flags bitmask.
                             , vd_ndx  :: !Word16
                               -- ^ Index in SHT_GNU_versym section of this version.
                             , vd_hash :: !Word32
                               -- ^ Version name hash value.
                             , vd_string  :: !B.ByteString
                               -- ^ Name of this version def.
                             , vd_parents  :: ![B.ByteString]
                               -- ^ Name of parent version definitions.
                             } deriving (Show)

-- | Get string from strTab read by 32-bit offset.
getOffsetString :: ElfData -> B.ByteString -> Get B.ByteString
getOffsetString d strTab = do
  o <- getWord32 d
  either (fail . show) pure $
    lookupString o strTab

readVersionDef :: ElfData -> B.ByteString -> L.ByteString -> Get VersionDef
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
  case entries of
    [] -> fail "Expected version definition name"
    nm:par -> do
      return VersionDef { vd_flags   = VersionDefFlags flags
                        , vd_ndx     = ndx
                        , vd_hash    = hash
                        , vd_string  = nm
                        , vd_parents = par
                        }

gnuVersionDefs :: B.ByteString
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
                                     -- ^ Identifier used to flag version
                                   , vna_name :: !B.ByteString
                                   } deriving (Show)

readVersionReqAux :: ElfData -> B.ByteString -> Get VersionReqAux
readVersionReqAux d strTab = do
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


readVersionReq :: ElfData -> B.ByteString -> L.ByteString -> Get VersionReq
readVersionReq d strTab b = do
  ver <- getWord16 d
  when (ver /= 1) $ do
    fail $ "Unexpected version need version: " ++ show ver
  cnt  <- getWord16 d
  file <- getOffsetString d strTab
  aux  <- getWord32 d
  let entry_buffer = L.drop (fromIntegral aux) b
  entries <- either fail pure $
    gnuLinkedList (\_ -> readVersionReqAux d strTab) d (fromIntegral cnt) entry_buffer
  return VersionReq { vn_file = file
                    , vn_aux = entries
                    }

gnuVersionReqs :: B.ByteString
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
   = DynSection { dynData :: !ElfData
                , dynClass :: !(ElfClass (RelocationWidth tp))
                , dynAddrMap :: !(VirtAddrMap (RelocationWidth tp))
                , dynMap :: !(DynamicMap (RelocationWidth tp))

                , dynSOName :: Maybe B.ByteString
                , dynStrTab  :: B.ByteString
                  -- ^ Dynamic string table contents
                , dynSymbols :: !(V.Vector (ElfSymbolTableEntry (RelocationWord tp)))
                , dynVersionDefs :: ![VersionDef]
                , dynVersionReqs :: ![VersionReq]
                  -- | Address of GNU Hash address.
                , dynGNUHASH_Addr :: !(Maybe (RelocationWord tp))
                , dynPLTAddr :: !(Maybe (RelocationWord tp))
                -- | Value of DT_DEBUG.
                , dynDebug :: !(Maybe (RelocationWord tp))
                }

deriving instance (Show (RelocationWord tp), IsRelocationType tp)
  => Show (DynamicSection tp)

-- | Get values of DT_NEEDED entries
dynNeeded :: DynamicSection tp -> Either LookupStringError [B.ByteString]
dynNeeded d = elfClassInstances (dynClass d) $
  let entries = dynamicEntry DT_NEEDED (dynMap d)
      strtab = dynStrTab d
   in traverse ((`lookupString` strtab) . fromIntegral) entries

dynInit :: DynamicSection tp -> [RelocationWord tp]
dynInit = dynamicEntry DT_INIT . dynMap

dynFini :: DynamicSection tp -> [RelocationWord tp]
dynFini = dynamicEntry DT_FINI . dynMap

-- | Return unparsed entries
dynUnparsed :: DynamicSection tp -> DynamicMap (RelocationWidth tp)
dynUnparsed = Map.filterWithKey isUnparsed . dynMap
  where isUnparsed tag _ = not (tag `elem` parsed_dyntags)

------------------------------------------------------------------------
-- Parsing dynamic section

-- | Return contents of dynamic string tab.
getDynStrTab :: DynamicMap w -> DynamicParser w B.ByteString
getDynStrTab m = do
  w <-  mandatoryDynamicEntry DT_STRTAB m
  sz <- mandatoryDynamicEntry DT_STRSZ m
  L.toStrict <$> addressRangeToFile (DT_STRTAB, DT_STRSZ) (w,sz)

dynSymTab :: B.ByteString
             -- ^ String table
          -> DynamicMap w
          -> DynamicParser w [ElfSymbolTableEntry (ElfWordType w)]
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

  case runGetMany (getSymbolTableEntry cl dta strTab) symtab of
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

  , DT_VERDEF
  , DT_VERDEFNUM
  , DT_VERNEED
  , DT_VERNEEDNUM
  ]

-- | This returns information about the dynamic segment in a elf file
-- if it exists.
--
-- The code assumes that there is at most one segment with type 'PT_DYNAMIC'.
dynamicEntries :: forall tp
                . IsRelocationType tp
               => ElfData
                  -- ^ Elf data
               -> ElfClass (RelocationWidth tp)
                  -- ^ Elf class
               -> VirtAddrMap (RelocationWidth tp)
                  -- ^ Virtual address map
               -> L.ByteString
                  -- ^ Dynamic section contents
               -> Either DynamicError (DynamicSection tp)
dynamicEntries d cl virtMap dynamic = elfClassInstances cl $
 runDynamicParser d cl virtMap $ do
  m <-
    case runGetOrFail (dynamicList cl d) dynamic of
      Left  (_,_,msg)  -> throwError (ErrorParsingDynamicEntries msg)
      Right (_,_,elts) -> pure (foldl' (flip insertDynamic) Map.empty elts)

  strTab <- getDynStrTab m

  mnm_index <- optionalDynamicEntry DT_SONAME m
  mnm <- case mnm_index of
           Nothing -> pure Nothing
           Just idx -> either (\_ -> throwError IllegalNameIndex) (pure . Just) $
             lookupString (fromIntegral idx) strTab

  symbols <- dynSymTab strTab m

  version_defs <- gnuVersionDefs strTab m
  version_reqs <- gnuVersionReqs strTab m


  gnuhashAddr  <- optionalDynamicEntry DT_GNU_HASH m
  pltAddr      <- optionalDynamicEntry DT_PLTGOT m
  mdebug       <- optionalDynamicEntry DT_DEBUG m

  return $ DynSection { dynData    = d
                      , dynClass   = cl
                      , dynAddrMap = virtMap
                      , dynMap     = m
                      , dynStrTab  = strTab
                      , dynSOName  = mnm
                      , dynSymbols = V.fromList symbols
                      , dynVersionDefs = version_defs
                      , dynVersionReqs = version_reqs
                      , dynGNUHASH_Addr = gnuhashAddr
                      , dynPLTAddr = pltAddr
                      , dynDebug = mdebug
                      }

-- | Returns information from dynamic segment in elf file if it exists.
dynamicEntriesFromSegment :: forall tp
                         .  IsRelocationType tp
                         => Elf (RelocationWidth tp)
                         -> Maybe (Either DynamicError (DynamicSection tp))
dynamicEntriesFromSegment e = do
   elfClassInstances (elfClass e) $ do
   let l = elfLayout e
   let contents = elfLayoutBytes l
   let ph = allPhdrs l
   case filter (\phdr -> elfSegmentType (phdrSegment phdr) == PT_DYNAMIC) ph of
     [] -> Nothing
     [dynPhdr] -> do
       let dynContents = sliceL (phdrFileRange dynPhdr) contents
       case virtAddrMap contents ph of
         Just virtMap -> do
           Just $ dynamicEntries (elfData e) (elfClass e) virtMap dynContents
         Nothing -> do
           Just $ Left OverlappingLoadableSegments
     _ -> Just $ Left MultipleDynamicSegments

------------------------------------------------------------------------
-- Symbol version information

-- | Identifies a version in an Elf file
data VersionId
   = VersionId { verFile :: !B.ByteString
                 -- ^ Name of file symbol is expected in
               , verName :: !B.ByteString
                 -- ^ Name of version this belongs to.
               } deriving (Show)

data VersionTableValue
   = VersionLocal
     -- ^ Symbol is local and not available outside object
   | VersionGlobal
     -- ^ Symbol is defined in object and globally available
   | VersionSpecific !VersionId
     -- ^ Symbol version information

-- | Identifies a symbol entry along with a possible version constraint for the symbol.
type VersionedSymbol w = (ElfSymbolTableEntry w, VersionTableValue)


-- | Maps the version requirement index to the appropriate version.
type VersionReqMap = Map.Map Word16 VersionId

insVersionReq :: VersionReqMap -> VersionReq -> Either DynamicError VersionReqMap
insVersionReq m0 r = foldlM ins m0 (vn_aux r)
  where file = vn_file r
        ins m a =
          case Map.lookup (vna_other a) m of
            Nothing -> Right $! Map.insert (vna_other a) (VersionId file (vna_name a)) m
            Just{}  -> Left $! DupVersionReqAuxIndex (vna_other a)

versionReqMap :: [VersionReq] -> Either DynamicError VersionReqMap
versionReqMap = foldlM insVersionReq Map.empty

-- | Return the symbols in this section with version information added.
dynSymTable :: DynamicSection tp
            -> Either DynamicError (V.Vector (VersionedSymbol (RelocationWord tp)))
dynSymTable ds = runParser ds $ do
  let dm = dynMap ds
  let symbols = dynSymbols ds
  let dta = dynData ds
  mvs <- optionalDynamicEntry DT_VERSYM dm
  case mvs of
    Nothing ->
      return $! (\s -> (s, VersionGlobal)) <$> symbols
    Just vs -> do
      verMap <- either throwError pure $ versionReqMap (dynVersionReqs ds)

      -- Extract the version symbol infirnation.
      fileRest <- addressToFile DT_VERSYM vs
      -- This takes each symbol table entry and associated it with the version indices
      -- by the next two bytes in the bytestring.
      let resolveSymVer :: ElfSymbolTableEntry a
                        -> StateT L.ByteString (DynamicParser w) (VersionedSymbol a)
          resolveSymVer sym = do
            bs <- get
            put (L.drop 2 bs)
            idx <- lift $ word16 dta bs
            case idx of
              0 -> pure (sym, VersionLocal)
              1 -> pure (sym, VersionGlobal)
              _ | Just verId <- Map.lookup idx verMap -> do
                    pure (sym, VersionSpecific verId)
                | otherwise -> do
                    throwError $ UnresolvedVersionReqAuxIndex (steName sym) idx
      evalStateT (traverse resolveSymVer symbols) fileRest

------------------------------------------------------------------------
-- Relocations

runParser :: DynamicSection tp
          -> DynamicParser (RelocationWidth tp) a
          -> Either DynamicError a
runParser ds m = runDynamicParser (dynData ds) (dynClass ds) (dynAddrMap ds) m

-- | Parse the relocation entries using the dynamic tags for start and size.
getRelaRange :: ElfDynamicTag -- ^ Tag for reading start of entries
             -> ElfDynamicTag -- ^ Tag for reading size of entries
             -> DynamicMap w
             -> DynamicParser w (Maybe L.ByteString)
getRelaRange startTag sizeTag dm = do
  mrela_offset <- optionalDynamicEntry startTag dm
  case mrela_offset of
    Nothing -> return Nothing
    Just rela_offset -> do
      sz  <- mandatoryDynamicEntry sizeTag dm
      Just <$> addressRangeToFile (startTag, sizeTag) (rela_offset,sz)

-- | Return the runtime relocation entries
dynRelocations :: forall tp
               .  IsRelocationType tp
               => DynamicSection tp
               -> Either DynamicError [RelaEntry tp]
dynRelocations ds = do
  runParser ds $ do
    mr <- getRelaRange DT_RELA DT_RELASZ (dynMap ds)
    case mr of
      Nothing -> pure []
      Just rela -> do
        ent <- mandatoryDynamicEntry DT_RELAENT (dynMap ds)
        let w = relaWidth (error "relaWidth evaluated" :: tp)
        when (elfClassInstances (dynClass ds) $ ent /= relaEntSize w) $
          throwError IncorrectRelaSize
        either (throwError . ErrorParsingRelaEntries) pure $
          elfRelaEntries (dynData ds) rela


-- | Parse the PLT location and relocation entries.
--
-- These may be applied immediately upon load, or done later if lazy binding is
-- enabled.
dynPLTRel :: IsRelocationType tp
          => DynamicSection tp
          -> Either DynamicError [RelaEntry tp]
dynPLTRel ds = do
  runParser ds $ do
    mr <- getRelaRange DT_JMPREL DT_PLTRELSZ (dynMap ds)
    case mr of
      Nothing -> pure []
      Just rela -> do
        w <- elfClassInstances (dynClass ds) $
          ElfDynamicTag . fromIntegral <$> mandatoryDynamicEntry DT_PLTREL (dynMap ds)
        when (w /= DT_RELA) $ do
          fail $ "Only DT_RELA entries are supported."

        either (throwError . ErrorParsingPLTRelaEntries) pure $
          elfRelaEntries (dynData ds) rela
