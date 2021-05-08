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
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE UndecidableInstances #-}
module Data.ElfEdit.Dynamic
  ( DynamicSection(..)
  , dynNeeded
  , dynInit
  , dynFini
  , dynUnparsed
  , dynSOName
  , dynRelBuffer
  , dynRelaBuffer
  , dynRelaEntries
  , dynVersionDefs
  , PLTEntries(..)
  , dynPLTRel
  , dynamicEntries
  , DynamicMap
  , parseDynamicMap
  , DynamicError(..)
    -- ** Tag
  , module Data.ElfEdit.Dynamic.Tag
    -- ** Version information
  , VersionReqMap
  , dynVersionReqMap
  , VersionedSymbol
  , dynSymEntry
  , VersionId(..)
  , VersionDef(..)
  , VersionDefFlags
  , ver_flg_base
  , ver_flg_weak
  , VersionReq(..)
  , VersionReqAux(..)
  , VersionTableValue(..)
    -- ** Virtual address map
  , VirtAddrMap
  , virtAddrMap
  , lookupVirtAddrContents
  ) where

import           Control.Monad
import           Control.Monad.Except
import           Control.Monad.Reader
import           Data.Binary.Get ( Get )
import           Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BSC
import           Data.Foldable
import qualified Data.Map.Strict as Map
import           Data.Word
import           Numeric (showHex)

import           Data.ElfEdit.ByteString
import           Data.ElfEdit.Dynamic.Tag
import           Data.ElfEdit.Prim.Ehdr
import           Data.ElfEdit.Prim.File
import           Data.ElfEdit.Prim.Phdr
import           Data.ElfEdit.Prim.StringTable
import           Data.ElfEdit.Prim.SymbolTable
import           Data.ElfEdit.Relocations.Common
import           Data.ElfEdit.Utils (strictRunGetOrFail)

------------------------------------------------------------------------
-- Utilities

-- | Maps the start of memory offsets in Elf file to the file contents backing that
-- memory
newtype VirtAddrMap w = VAM (Map.Map (ElfWordType w) B.ByteString)

instance Show (ElfWordType w) => Show (VirtAddrMap w) where
  show (VAM m) = "VAM (" ++ show m ++ ")"

-- | Creates a virtual address map from bytestring and list of program headers.
--
-- Returns 'Nothing' if the map could not be created due to overlapping segments.
virtAddrMap :: (Foldable t, Integral (ElfWordType w))
            => B.ByteString -- ^ File contents
            -> t (Phdr w) -- ^ Program headers
            -> Maybe (VirtAddrMap w)
virtAddrMap file phdrList = VAM <$> foldlM ins Map.empty phdrList
  where -- Insert phdr into map if it is loadable
        ins m phdr
            -- If segment is not loadable or empty, leave map unchanged
          | phdrSegmentType phdr /= PT_LOAD || phdrFileSize phdr == 0 = pure m
            -- If segment overlaps with a previous segment, then return
            -- 'Nothing' to indicate an error.
          | Just (prev, old) <- Map.lookupLE addr m
          , addr - prev < fromIntegral (B.length old) = Nothing
            -- Insert phdr into map
          | otherwise =
            pure $! Map.insert addr newContents m
          where addr = phdrSegmentVirtAddr phdr
                newContents    = slice (phdrFileRange phdr) file

-- | Return the contents in the Elf file starting from the given address
-- offset.
lookupVirtAddrContents :: Integral (ElfWordType w)
                       => ElfWordType w
                       -> VirtAddrMap w
                       -> Maybe B.ByteString
lookupVirtAddrContents addr (VAM m) =
  case Map.lookupLE addr m of
    Just (prev, contents) | addr - prev <= fromIntegral (B.length contents) -> do
      let seg_offset = addr - prev
      Just $! B.drop (fromIntegral seg_offset) contents
    _ -> Nothing

------------------------------------------------------------------------
-- DynamicError

-- | Errors found when parsing dynamic section
data DynamicError
   = UnexpectedEndOfDynamicEntries
   | ErrorParsingSymTabEntry !SymtabError
   | BadValuePltRel !Integer
     -- ^ DT_PLTREL entry contained a bad value
   | ErrorParsingPLTEntries !String
   | ErrorRelaBufferNotMultiple
   | IncorrectRelSize
   | IncorrectRelaSize
   | UnresolvedVersionReqAuxIndex !B.ByteString !Word16
   | VerSymTooSmall
   | InvalidDynamicSegmentFileRange
   | MultipleDynamicSegments
   | BadSymbolTableEntrySize
   | DupVersionReqAuxIndex !Word16
   | DtSonameIllegal !LookupStringError
   | ErrorParsingVerDefs !String
   | ErrorParsingVerReqs !String
   | MandatoryEntryMissing    !ElfDynamicTag
   | EntryDuplicated          !ElfDynamicTag
   | EntryAddressNotFound     !ElfDynamicTag
   | EntrySizeTooSmall        !ElfDynamicTag
     -- ^ We could not parse the given symbol table entry.

instance Show DynamicError where
  show UnexpectedEndOfDynamicEntries =
    "Dynamic section ended before DT_NULL entry."
  show (ErrorParsingSymTabEntry e) = show e
  show (MandatoryEntryMissing tag) =
    "Dynamic information missing " ++ show tag
  show (EntryDuplicated tag) =
    "Dynamic information contains multiple " ++ show tag ++ " entries."
  show (EntryAddressNotFound tag) =
    "Could not find " ++ show tag ++ " address."
  show (EntrySizeTooSmall tag) =
    show tag ++ "refers past end of memory segment."
  show BadSymbolTableEntrySize = "Unexpected symbol table entry size."
  show (ErrorParsingVerDefs msg) = "Invalid version defs: " ++ msg
  show (ErrorParsingVerReqs msg) = "Invalid version reqs: " ++ msg
  show ErrorRelaBufferNotMultiple =
    "Rela buffer must be a multiple of rela entry size."
  show IncorrectRelSize = "DT_RELENT has unexpected size"
  show IncorrectRelaSize = "DT_RELAENT has unexpected size"
  show (ErrorParsingPLTEntries msg) = "Could not parse PLT relocation entries: " ++ msg
  show (DtSonameIllegal idx) = "Error parsing DT_SONAME: " ++ show idx
  show (DupVersionReqAuxIndex idx) = "The version requirement index " ++ show idx ++ " is not unique."
  show (UnresolvedVersionReqAuxIndex sym idx) =
    "Symbol " ++ BSC.unpack sym ++ " has unresolvable version requirement index " ++ show idx ++ "."
  show VerSymTooSmall = "File ends before end of symbol version table."
  show InvalidDynamicSegmentFileRange = "Dynamic segment file range is out of range of file."
  show MultipleDynamicSegments = "File contained multiple dynamic segments."
  show (BadValuePltRel v) = "DT_PLTREL entry contained an unexpected value " ++ show v ++ "."

------------------------------------------------------------------------
-- DynamicMap

-- | Dynamic array entry
data Dynamic w
   = Dynamic { dynamicTag :: !ElfDynamicTag
             , _dynamicVal :: !w
             }
  deriving (Show)

-- | Map tags to the values associated with that tag.
type DynamicMap w = Map.Map ElfDynamicTag [ElfWordType w]

insertDynamic :: Dynamic v ->  Map.Map ElfDynamicTag [v] -> Map.Map ElfDynamicTag [v]
insertDynamic (Dynamic tag v) = Map.insertWith (++) tag [v]

-- | Return entries in the dynamic map.
dynamicEntry :: ElfDynamicTag -> Map.Map ElfDynamicTag [v] -> [v]
dynamicEntry = Map.findWithDefault []

------------------------------------------------------------------------
-- DynamicParser

data DynamicParseContext w = DynamicParseContext { fileData  :: !ElfData
                                                 , fileClass :: !(ElfClass w)
                                                   -- ^ Class for Elf file.
                                                 }

type DynamicParser w = ExceptT DynamicError (Reader (DynamicParseContext w))

runDynamicParser :: ElfData
                 -> ElfClass w
                 -> DynamicParser w a
                 -> Either DynamicError a
runDynamicParser dta cl p = elfClassInstances cl $
  let ctx = DynamicParseContext { fileData  = dta
                                , fileClass = cl
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

------------------------------------------------------------------------
-- Lookup address

addressToFile :: VirtAddrMap w
              -> ElfDynamicTag -- ^ Tag this address was defined in
              -> ElfWordType w -- ^ Address in memory.
              -> DynamicParser w B.ByteString
addressToFile virtMap tag addr = do
  cl       <- asks fileClass
  elfClassInstances cl $ do
  case lookupVirtAddrContents addr virtMap of
    Just contents ->
      return $ contents
    _ ->
      throwError $ EntryAddressNotFound tag

addressRangeToFile :: VirtAddrMap w
                   -> ElfDynamicTag -- ^ Tag for offset
                   -> ElfDynamicTag -- ^ Tag for size
                   -> ElfWordType w -- ^ Address
                   -> ElfWordType w -- ^ Size
                   -> DynamicParser w B.ByteString
addressRangeToFile virtMap tagOff tagSize off sz = do
  cl <- asks fileClass
  elfClassInstances cl $ do
  bs <- addressToFile virtMap tagOff off
  when (B.length bs < fromIntegral sz) $ do
    throwError $ EntrySizeTooSmall tagSize
  pure $! B.take (fromIntegral sz) bs

------------------------------------------------------------------------
-- Dynamic

relaWord :: ElfClass w -> ElfData -> B.ByteString -> ElfWordType w
relaWord ELFCLASS32 ELFDATA2LSB = bsWord32le
relaWord ELFCLASS32 ELFDATA2MSB = bsWord32be
relaWord ELFCLASS64 ELFDATA2LSB = bsWord64le
relaWord ELFCLASS64 ELFDATA2MSB = bsWord64be

relaWordSize :: ElfClass w -> Int
relaWordSize ELFCLASS32 = 4
relaWordSize ELFCLASS64 = 8

buildDynamicMap :: ElfClass w
                -> ElfData
                -> DynamicMap w
                -> B.ByteString
                -> Maybe (DynamicMap w)
buildDynamicMap cl d m bs
    | B.length bs == 0 = Just m
    | B.length bs < 2*sz = Nothing
    | otherwise =
      let tag = elfClassInstances cl $ ElfDynamicTag (fromIntegral (relaWord cl d bs))
          v   = relaWord cl d (B.drop sz bs)
          m' = insertDynamic (Dynamic tag v) m
          bs' = B.drop (2*sz) bs
       in case tag of
            DT_NULL -> Just m'
            _ -> seq m' $ seq bs' $ buildDynamicMap cl d m' bs'
  where sz = relaWordSize cl

parseDynamicMap :: ElfClass w
                -> ElfData
                -> B.ByteString
                -> Maybe (DynamicMap w)
parseDynamicMap cl d b = buildDynamicMap cl d Map.empty b

------------------------------------------------------------------------
-- GNU extension

-- | Parses a linked list
gnuLinkedList :: (B.ByteString -> Get a) -- ^ Function for reading.
              -> ElfData
              -> Int -- ^ Number of entries expected.
              -> B.ByteString -- ^ Buffer to read.
              -> Either String [a]
gnuLinkedList readFn d = go []
  where readNextVal b = (,) <$> readFn b <*> getWord32 d
        go prev 0 _ = return (reverse prev)
        go prev cnt b =
          case strictRunGetOrFail (readNextVal b) b of
            Left (_,_,msg) -> Left msg
            Right (_,_,(d',next)) -> do
              go (d':prev) (cnt-1) (B.drop (fromIntegral next) b)

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

readVersionDef :: ElfData -> B.ByteString -> B.ByteString -> Get VersionDef
readVersionDef d strTab b = do
  ver   <- getWord16 d
  when (ver /= 1) $
    fail $ "Unexpected version definition version: " ++ show ver
  flags <- getWord16 d
  ndx   <- getWord16 d
  cnt   <- getWord16 d
  hash  <- getWord32 d
  aux   <- getWord32 d
  let entryCnt = fromIntegral cnt
  let entryBuffer = B.drop (fromIntegral aux) b
  entries <-
    either fail pure $
    gnuLinkedList (\_ -> getOffsetString d strTab) d entryCnt entryBuffer
  case entries of
    [] -> fail "Expected version definition name"
    nm:par -> do
      return VersionDef { vd_flags   = VersionDefFlags flags
                        , vd_ndx     = ndx
                        , vd_hash    = hash
                        , vd_string  = nm
                        , vd_parents = par
                        }

------------------------------------------------------------------------
-- VersionReq

-- | Version requirement auxillery information.
data VersionReqAux =
  VersionReqAux { vna_hash :: !Word32
                , vna_flags :: !Word16
                , vna_other :: !Word16
                  -- ^ Index used to identify version in version
                  -- symbol table (@DT_VERSYM@)
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


readVersionReq :: ElfData -> B.ByteString -> B.ByteString -> Get VersionReq
readVersionReq d strTab b = do
  ver <- getWord16 d
  when (ver /= 1) $ do
    fail $ "Unexpected version need version: " ++ show ver
  cnt  <- getWord16 d
  file <- getOffsetString d strTab
  aux  <- getWord32 d
  let entryBuffer = B.drop (fromIntegral aux) b
  entries <- either fail pure $
    gnuLinkedList (\_ -> readVersionReqAux d strTab) d (fromIntegral cnt) entryBuffer
  return VersionReq { vn_file = file
                    , vn_aux = entries
                    }

gnuVersionReqs :: VirtAddrMap w
               -> B.ByteString
                  -- ^ Dynamic string table.
               -> DynamicMap w
               -> DynamicParser w [VersionReq]
gnuVersionReqs virtMap strTab m = do
  ctx <- ask
  let d = fileData ctx
  mvn <- optionalDynamicEntry DT_VERNEED m
  case mvn of
    Nothing -> return []
    Just vn -> do
      reqBuffer <- addressToFile virtMap DT_VERNEED vn
      vnnum <- mandatoryDynamicEntry DT_VERNEEDNUM m
      elfClassInstances (fileClass ctx) $ do
      either (throwError . ErrorParsingVerReqs) pure $
        gnuLinkedList (readVersionReq d strTab) d (fromIntegral vnnum) reqBuffer

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
type VersionedSymbol w = (SymtabEntry B.ByteString w, VersionTableValue)

-- | Maps the version requirement index to the appropriate version.
type VersionReqMap = Map.Map Word16 VersionId

insVersionReq :: VersionReqMap -> VersionReq -> Either DynamicError VersionReqMap
insVersionReq m0 r = foldlM ins m0 (vn_aux r)
  where file = vn_file r
        ins m a =
          case Map.lookup (vna_other a) m of
            Nothing -> do
              let vid = VersionId { verFile = file
                                  , verName = vna_name a
                                  }
              Right $! Map.insert (vna_other a) vid m
            Just{}  -> Left $! DupVersionReqAuxIndex (vna_other a)

versionReqMap :: [VersionReq] -> Either DynamicError VersionReqMap
versionReqMap = foldlM insVersionReq Map.empty

------------------------------------------------------------------------
-- DynamicSection

data DynamicSection w
   = DynSection { dynData :: !ElfData
                , dynClass :: !(ElfClass w)
                , dynMap :: !(DynamicMap w)
                , dynVersymAddr :: !(Maybe (ElfWordType w))
                  -- ^ Address of .gnu.version section
                , dynSONameStringOffset :: !(Maybe (ElfWordType w))
                  -- ^ Offset of string for soname in dynamic section.
                  -- | Address of GNU Hash address.
                , dynGNUHASH_Addr :: !(Maybe (ElfWordType w))
                , dynPLTAddr :: !(Maybe (ElfWordType w))
                -- | Value of DT_DEBUG.
                , dynDebug :: !(Maybe (ElfWordType w))
                }

runParser :: DynamicSection w
          -> DynamicParser w a
          -> Either DynamicError a
runParser ds m = runDynamicParser (dynData ds) (dynClass ds) m

-- | Get the mandatory entry with the given tag from the map.
-- It is required that there is exactly one tag with this type.
findEntry :: ElfDynamicTag -> DynamicSection w -> Either DynamicError (ElfWordType w)
findEntry tag ds =
  case dynamicEntry tag (dynMap ds) of
    [w] -> return w
    []  -> Left $ MandatoryEntryMissing tag
    _   -> Left $ EntryDuplicated tag



dynStrtabAddr :: DynamicSection w -> Either DynamicError (ElfWordType w)
dynStrtabAddr = findEntry DT_STRTAB

dynStrtabSize :: DynamicSection w -> Either DynamicError (ElfWordType w)
dynStrtabSize = findEntry DT_STRSZ

dynSymtabAddr :: DynamicSection w -> Either DynamicError (ElfWordType w)
dynSymtabAddr = findEntry DT_SYMTAB

dynStrtabContents :: DynamicSection w ->  VirtAddrMap w -> Either DynamicError B.ByteString
dynStrtabContents ds virtMap = do
  addr <- dynStrtabAddr ds
  size <- dynStrtabSize ds
  runParser ds $ addressRangeToFile virtMap DT_STRTAB DT_STRSZ addr size

dynSOName :: DynamicSection w -> VirtAddrMap w -> Maybe (Either DynamicError B.ByteString)
dynSOName ds virtMap =
  case dynSONameStringOffset ds of
    Nothing -> Nothing
    Just idx -> Just $ elfClassInstances (dynClass ds) $ do
      strtab <- dynStrtabContents ds virtMap
      case lookupString (fromIntegral idx) strtab of
        Left e -> Left (DtSonameIllegal e)
        Right r -> Right r

dynVersionDefs :: DynamicSection w -> VirtAddrMap w -> Either DynamicError [VersionDef]
dynVersionDefs ds virtMap = do
  strtab <- dynStrtabContents ds virtMap
  let dm = dynMap ds
  runParser ds $ do
    ctx <- ask
    let d = fileData ctx
    mvd <- optionalDynamicEntry DT_VERDEF dm
    case mvd of
      Nothing -> return []
      Just vd -> do
        vdnum <- mandatoryDynamicEntry DT_VERDEFNUM dm
        def_buffer <- addressToFile virtMap DT_VERDEF vd
        elfClassInstances (fileClass ctx) $
          either (throwError . ErrorParsingVerDefs) pure $
          gnuLinkedList (readVersionDef d strtab) d (fromIntegral vdnum) def_buffer

-- | Version requirement map
dynVersionReqMap :: DynamicSection w -> VirtAddrMap w -> Either DynamicError VersionReqMap
dynVersionReqMap ds virtMap = do
  strtab <- dynStrtabContents ds virtMap
  runParser ds $ either throwError pure . versionReqMap =<< gnuVersionReqs virtMap strtab (dynMap ds)


deriving instance Show (ElfWordType w)
  => Show (DynamicSection w)

-- | Get values of DT_NEEDED entries
dynNeeded :: forall w . DynamicSection w -> VirtAddrMap w -> Either String [B.ByteString]
dynNeeded ds virtMap = elfClassInstances (dynClass ds) $ do
  addr <- either (Left . show) pure (dynStrtabAddr ds)
  size <- either (Left . show) pure (dynStrtabSize ds)
  bs <-
    case lookupVirtAddrContents addr virtMap of
      Just bs -> pure bs
      Nothing -> Left $ "Could not resolve DT_STRTAB index."
  when (toInteger (B.length bs) < toInteger size) $ do
    Left $ "Dynamic string table end offset " ++ showHex (addr + size) "Invalid."
  let strtab = B.take (fromIntegral size) bs
  let entries = dynamicEntry DT_NEEDED (dynMap ds)
  let go :: ElfWordType w -> Either String B.ByteString
      go off = case lookupString (fromIntegral off) strtab of
                  Left e -> Left (show e)
                  Right r -> Right r
  traverse go entries

dynInit :: DynamicSection w -> [ElfWordType w]
dynInit = dynamicEntry DT_INIT . dynMap

dynFini :: DynamicSection w -> [ElfWordType w]
dynFini = dynamicEntry DT_FINI . dynMap

-- | Return unparsed entries
dynUnparsed :: DynamicSection w -> DynamicMap w
dynUnparsed = Map.filterWithKey isUnparsed . dynMap
  where isUnparsed tag _ = not (tag `elem` parsed_dyntags)

------------------------------------------------------------------------
-- Get symbol

-- | Return the symbol with the given index.
dynSymEntry :: forall w
            .  DynamicSection w -- ^ Dynamic section information
            -> VirtAddrMap w -- ^ Virtual address map
            -> VersionReqMap -- ^ GNU verison requirements
            -> Word32 -- ^ Index of symbol table entry.
            -> Either DynamicError (VersionedSymbol (ElfWordType w))
dynSymEntry ds virtMap verMap i = do
  strtab <- dynStrtabContents ds virtMap
  symtabAddr <- dynSymtabAddr ds
  runParser ds $ elfClassInstances (dynClass ds) $ do
    symtab <- addressToFile virtMap DT_SYMTAB symtabAddr
    -- Parse symbol table entry
    sym <-
      case decodeSymtabEntry (dynClass ds) (dynData ds) strtab symtab i of
        Left e -> throwError (ErrorParsingSymTabEntry e)
        Right sym -> pure sym
    -- Parse version information if present.
    case dynVersymAddr ds of
      Nothing -> do
        return $! (sym, VersionGlobal)
      Just versymAddr -> do
        verBuffer <- addressToFile virtMap DT_VERSYM versymAddr
        -- Parse the version index
        let verOffset :: Int
            verOffset = 2 * fromIntegral i
        -- Check the version offset is larger enough
        when (verOffset + 2 > B.length verBuffer) $ throwError VerSymTooSmall
        let verIdx =
              let g :: Int -> Word16
                  g j = fromIntegral (B.index verBuffer (verOffset + j))
               in case dynData ds of
                    ELFDATA2LSB -> (g 1 `shiftL` 8) .|. g 0
                    ELFDATA2MSB -> (g 0 `shiftL` 8) .|. g 1
        case verIdx of
          0 -> pure (sym, VersionLocal)
          1 -> pure (sym, VersionGlobal)
          _ ->
            case Map.lookup verIdx verMap of
              Just verId -> pure (sym, VersionSpecific verId)
              Nothing -> do
                throwError $ UnresolvedVersionReqAuxIndex (steName sym) verIdx

------------------------------------------------------------------------
-- Relocations

-- | Parse the relocation entries using the dynamic tags for start and size.
getRelaRange :: VirtAddrMap w
             -> ElfDynamicTag -- ^ Tag for reading start of entries
             -> ElfDynamicTag -- ^ Tag for reading size of entries
             -> DynamicMap w
             -> DynamicParser w (Maybe B.ByteString)
getRelaRange virtMap startTag sizeTag dm = do
  mrelaOffset <- optionalDynamicEntry startTag dm
  case mrelaOffset of
    Nothing -> return Nothing
    Just relaOff -> do
      sz  <- mandatoryDynamicEntry sizeTag dm
      Just <$> addressRangeToFile virtMap startTag sizeTag relaOff sz

-- | Return the buffer containing rel entries from the dynamic section if any.
dynRelBuffer :: DynamicSection w
             -> VirtAddrMap w
             -> Either DynamicError (Maybe B.ByteString)
dynRelBuffer ds virtMap = do
  runParser ds $ do
    mr <- getRelaRange virtMap DT_REL DT_RELSZ (dynMap ds)
    -- Check entry size
    case mr of
      Nothing -> pure ()
      Just{} -> do
        ent <- mandatoryDynamicEntry DT_RELENT (dynMap ds)
        let w = dynClass ds
        when (elfClassInstances (dynClass ds) $ ent /= relEntSize w) $
          throwError IncorrectRelSize
    pure mr

-- | Return the buffer containing rela entries from the dynamic section if any.
dynRelaBuffer :: DynamicSection w
              -> VirtAddrMap w
              -> Either DynamicError (Maybe B.ByteString)
dynRelaBuffer ds virtMap = do
  runParser ds $ do
    mr <- getRelaRange virtMap DT_RELA DT_RELASZ (dynMap ds)
    -- Check entry size
    case mr of
      Nothing -> pure ()
      Just{} -> do
        ent <- mandatoryDynamicEntry DT_RELAENT (dynMap ds)
        let w = dynClass ds
        when (elfClassInstances (dynClass ds) $ ent /= relaEntSize w) $
          throwError IncorrectRelaSize
    pure mr

-- | Return the runtime relocation entries
dynRelaEntries :: forall tp
               .  IsRelocationType tp
               => DynamicSection (RelocationWidth tp)
               -> VirtAddrMap (RelocationWidth tp)
               -> Either DynamicError [RelaEntry tp]
dynRelaEntries ds virtMap = do
  dynRelaBuf <- dynRelaBuffer ds virtMap
  let cl :: ElfClass (RelocationWidth tp)
      cl = relaWidth (undefined :: tp)
  case dynRelaBuf of
    Nothing -> pure []
    Just buf ->
      case B.length buf `quotRem` relaEntSize cl of
        (n, 0) ->
          Right $ decodeRelaEntry (dynData ds) buf <$> [0..fromIntegral n-1]
        _ -> Left ErrorRelaBufferNotMultiple

-- | Information about the PLT relocations in a dynamic section.
data PLTEntries tp
  = PLTRel [RelEntry tp]
  | PLTRela [RelaEntry tp]
  | PLTEmpty

-- | Parse the PLT location and relocation entries.
--
-- These may be applied immediately upon load, or done later if lazy binding is
-- enabled.  They may be either all `DT_REL` entries or `DT_RELA` entries
dynPLTRel :: IsRelocationType tp
          => DynamicSection (RelocationWidth tp)
          -> VirtAddrMap (RelocationWidth  tp)
          -> Either DynamicError (PLTEntries tp)
dynPLTRel ds virtMap = do
  runParser ds $ elfClassInstances (dynClass ds) $ do
    mr <- getRelaRange virtMap DT_JMPREL DT_PLTRELSZ (dynMap ds)
    case mr of
      Nothing -> pure PLTEmpty
      Just contents -> do
        w <- mandatoryDynamicEntry DT_PLTREL (dynMap ds)
        case () of
          _ | w == fromIntegral (fromElfDynamicTag DT_RELA) ->
              case decodeRelaEntries (dynData ds) contents of
                Left err -> throwError $ ErrorParsingPLTEntries err
                Right l -> pure $ PLTRela l
            | w == fromIntegral (fromElfDynamicTag DT_REL) ->
              case decodeRelEntries (dynData ds) contents of
                Left err -> throwError $ ErrorParsingPLTEntries err
                Right l -> pure $ PLTRel l
            | otherwise ->
              throwError $ BadValuePltRel (toInteger w)

------------------------------------------------------------------------
-- Decoding

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
--
-- Note. This code previously parsed all the dynamic symbol table entries.  It
-- inferred the size of the dynamic symbol table by assuming that the string
-- table immediately followed the symbol table.  This was chosen because
-- this is what GNU Libc 2.19 (see comment in dl-fptr.c:175).  It turns out
-- Android does not follow this convention, and so we now defer parsing
-- dynamic symbol tables here, but rather provide a function `dynSymEntry`
-- for parsing them later (e.g. when resolving relocations that refer to
-- symbol table entries).
dynamicEntries :: forall w
                . ElfData
                  -- ^ Elf data
               -> ElfClass w
                  -- ^ Elf class
               -> B.ByteString
                  -- ^ Dynamic section contents
               -> Either DynamicError (DynamicSection w)
dynamicEntries d cl dynamic = elfClassInstances cl $ runDynamicParser d cl $ do
  m <-
    case parseDynamicMap cl d dynamic of
      Nothing -> throwError $ UnexpectedEndOfDynamicEntries
      Just m -> pure m

  mnmIndex   <- optionalDynamicEntry DT_SONAME m

  -- Get buffer that points to beginnig of symbol table
  gnuhashAddr  <- optionalDynamicEntry DT_GNU_HASH m
  pltAddr      <- optionalDynamicEntry DT_PLTGOT m
  mdebug       <- optionalDynamicEntry DT_DEBUG m
  mVersymAddr  <- optionalDynamicEntry DT_VERSYM m
  return $ DynSection { dynData    = d
                      , dynClass   = cl
                      , dynMap     = m
                      , dynVersymAddr = mVersymAddr
                      , dynSONameStringOffset = mnmIndex
                      , dynGNUHASH_Addr = gnuhashAddr
                      , dynPLTAddr = pltAddr
                      , dynDebug = mdebug
                      }