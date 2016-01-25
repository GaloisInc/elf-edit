{-# LANGUAGE CPP #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE DoAndIfThenElse #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
-- | Data.Elf provides an interface for querying and manipulating Elf files.
module Data.Elf ( -- * Top-level definitions
                  Elf (..)
                , emptyElf
                , elfFileData
                , elfSegments
                , elfSections
                , findSectionByName
                , removeSectionByName
                , updateSections
                , elfInterpreter
                  -- ** Top-level Elf information
                , ElfClass(..)
                , ElfData(..)
                , ElfOSABI(..)
                , ElfType(..)
                , ElfMachine(..)
                , ElfDataRegion(..)
                , ElfGOT(..)
                  -- ** Reading and Writing Elf files
                , hasElfMagic
                , SomeElf(..)
                , parseElf
                , renderElf
                  -- ** Layout information
                , ElfLayout
                , elfLayout
                , elfLayoutBytes
                , elfLayoutSize
                  -- * Sections
                , ElfSection(..)
                  -- ** Elf section type
                , ElfSectionType(..)
                  -- ** Elf section flags
                , ElfSectionFlags
                , shf_none, shf_write, shf_alloc, shf_execinstr
                  -- * Segment operations.
                , ElfSegment(..)
                , elfSegmentData
                  -- ** Elf segment type
                , ElfSegmentType(..)
                  -- ** Elf segment flags
                , ElfSegmentFlags
                , pf_none, pf_x, pf_w, pf_r
                  -- ** Getting data from Elf segments
                , RenderedElfSegment
                , renderedElfSegments
                  -- * Symbol Table Entries
                , ElfSymbolTableEntry(..)
                , ppSymbolTableEntries
                , parseSymbolTables
                , findSymbolDefinition
                  -- ** Elf symbol visibility
                , steVisibility
                , ElfSymbolVisibility
                , stv_default
                , stv_internal
                , stv_hidden
                , stv_protected
                  -- ** Elf symbol type
                , ElfSymbolType(..)
                , fromElfSymbolType
                , toElfSymbolType
                  -- ** Elf symbol binding
                , ElfSymbolBinding(..)
                , ElfSectionIndex(..)
                  -- * Dynamic symbol table and relocations
                , DynamicSection(..)
                , VersionDef(..)
                , VersionReq(..)
                , VersionReqAux
                , DynamicMap
                , ElfDynamicArrayTag
                , IsRelocationType(..)
                , IsElfData(..)
                , dynamicEntries
                , RelaEntry(..)
                , ppRelaEntries
                , I386_RelocationType
                , X86_64_RelocationType
                  -- * Common definitions
                , Range
                , hasPermissions
                ) where

#if !MIN_VERSION_base(4,8,0)
import           Control.Applicative
#endif
import           Control.Exception ( assert )
import           Control.Lens hiding (enum)
import           Control.Monad
import           Data.Binary
import           Data.Binary.Get as G
import           Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Lazy.UTF8 as L (toString)
import qualified Data.ByteString.UTF8 as B (toString)
import qualified Data.Foldable as F
import           Data.Int
import           Data.List (genericDrop, foldl', transpose)
import qualified Data.Map as Map
import           Data.Maybe
import qualified Data.Sequence as Seq
import           Numeric (showHex)
import           Text.PrettyPrint.ANSI.Leijen hiding ((<>), (<$>))

import           Data.Elf.Layout
import qualified Data.Elf.SizedBuilder as U
import           Data.Elf.TH
import           Data.Elf.Types

------------------------------------------------------------------------
-- Utilities

-- | @tryParse msg f v@ returns @fromJust (f v)@ is @f v@ returns a value,
-- and calls @fail@ otherwise.
tryParse :: Monad m => String -> (a -> Maybe b) -> a -> m b
tryParse desc toFn = maybe (fail ("Invalid " ++ desc)) return . toFn

runGetMany :: forall a . Get a -> L.ByteString -> [a]
runGetMany g0 bs0 = start g0 (L.toChunks bs0)
  where go :: Get a -> [B.ByteString] -> Decoder a -> [a]
        go _ _ (Fail _ _ msg)  = error $ "runGetMany: " ++ msg
        go g [] (Partial f)    = go g [] (f Nothing)
        go g (h:r) (Partial f) = go g r (f (Just h))
        go g l (Done bs _ v)   = v : start g (bs:l)

        start _ [] = []
        start g (h:r) | B.null h = start g r
        start g l = go g l (runGetIncremental g)

elfDataRegionName :: ElfDataRegion w -> String
elfDataRegionName ElfDataElfHeader = "elf header"
elfDataRegionName ElfDataSegmentHeaders = "phdr table"
elfDataRegionName (ElfDataSegment s) = show (elfSegmentType s) ++ " segment"
elfDataRegionName ElfDataSectionHeaders = "shdr table"
elfDataRegionName ElfDataSectionNameTable = "section name table"
elfDataRegionName (ElfDataGOT g) = elfGotName g
elfDataRegionName (ElfDataSection s) = elfSectionName s
elfDataRegionName (ElfDataRaw _) = "elf raw"

-- | @p `hasPermissions` req@ returns true if all bits set in 'req' are set in 'p'.
hasPermissions :: Bits b => b -> b -> Bool
hasPermissions p req = (p .&. req) == req
{-# INLINE hasPermissions #-}

------------------------------------------------------------------------
-- StringTable

-- | Returns null-terminated string at given index in bytestring.
lookupString :: Word32 -> B.ByteString -> B.ByteString
lookupString o b = B.takeWhile (/= 0) $ B.drop (fromIntegral o) b

-- | Returns null-terminated string at given index in bytestring.
lookupStringL :: Int64 -> L.ByteString -> L.ByteString
lookupStringL o b = L.takeWhile (/= 0) $ L.drop o b

-- | Given a section name, returns sections matching that name.
--
-- Section names in elf are not necessarily unique.
findSectionByName :: String -> Elf w -> [ElfSection w]
findSectionByName name e  = e^..elfSections.filtered byName
  where byName section = elfSectionName section == name

-- | Remove section with given name.
removeSectionByName :: String -> Elf w -> Elf w
removeSectionByName nm = over updateSections fn
  where fn s | elfSectionName s == nm = Nothing
             | otherwise = Just s

-- | List of segments in the file.
elfSegments :: Elf w -> [ElfSegment w]
elfSegments e = concatMap impl (e^.elfFileData)
  where impl (ElfDataSegment s) = s : concatMap impl (F.toList (s^.elfSegmentData))
        impl _ = []
-- | Returns length of section in file.
sectionFileLen :: Num w => ElfSectionType -> w -> w
sectionFileLen SHT_NOBITS _ = 0
sectionFileLen _ s = s

sectionData :: Integral w => ElfSectionType -> w -> w -> B.ByteString -> B.ByteString
sectionData SHT_NOBITS _ _ _ = B.empty
sectionData _ o s b = slice (o,s) b

type GetShdrFn w = B.ByteString
                 -> B.ByteString
                 -> Get (Range w, ElfSection w)

getShdr32 :: ElfData -> GetShdrFn Word32
getShdr32 d file string_section = do
  sh_name      <- getWord32 d
  sh_type      <- toElfSectionType <$> getWord32 d
  sh_flags     <- ElfSectionFlags  <$> getWord32 d
  sh_addr      <- getWord32 d
  sh_offset    <- getWord32 d
  sh_size      <- getWord32 d
  sh_link      <- getWord32 d
  sh_info      <- getWord32 d
  sh_addralign <- getWord32 d
  sh_entsize   <- getWord32 d
  let s = ElfSection
           { elfSectionName      = B.toString $ lookupString sh_name string_section
           , elfSectionType      = sh_type
           , elfSectionFlags     = sh_flags
           , elfSectionAddr      = sh_addr
           , elfSectionSize      = sh_size
           , elfSectionLink      = sh_link
           , elfSectionInfo      = sh_info
           , elfSectionAddrAlign = sh_addralign
           , elfSectionEntSize   = sh_entsize
           , elfSectionData      = sectionData sh_type sh_offset sh_size file
           }
  return ((sh_offset, sectionFileLen sh_type sh_size), s)

getShdr64 :: ElfData -> GetShdrFn Word64
getShdr64 er file string_section = do
  sh_name      <- getWord32 er
  sh_type      <- toElfSectionType <$> getWord32 er
  sh_flags     <- ElfSectionFlags  <$> getWord64 er
  sh_addr      <- getWord64 er
  sh_offset    <- getWord64 er
  sh_size      <- getWord64 er
  sh_link      <- getWord32 er
  sh_info      <- getWord32 er
  sh_addralign <- getWord64 er
  sh_entsize   <- getWord64 er
  let s = ElfSection
           { elfSectionName      = B.toString $ lookupString sh_name string_section
           , elfSectionType      = sh_type
           , elfSectionFlags     = sh_flags
           , elfSectionAddr      = sh_addr
           , elfSectionSize      = sh_size
           , elfSectionLink      = sh_link
           , elfSectionInfo      = sh_info
           , elfSectionAddrAlign = sh_addralign
           , elfSectionEntSize   = sh_entsize
           , elfSectionData = sectionData sh_type sh_offset sh_size file
    }
  return ((sh_offset, sectionFileLen sh_type sh_size), s)

-- | Type for reading a elf segment from binary data.
type GetPhdrFn w = Get (ElfSegment w, (Range w))

getPhdr32 :: ElfData -> GetPhdrFn Word32
getPhdr32 d = do
  p_type   <- toElfSegmentType  <$> getWord32 d
  p_offset <- getWord32 d
  p_vaddr  <- getWord32 d
  p_paddr  <- getWord32 d
  p_filesz <- getWord32 d
  p_memsz  <- getWord32 d
  p_flags  <- ElfSegmentFlags <$> getWord32 d
  p_align  <- getWord32 d
  let s = ElfSegment
          { elfSegmentType      = p_type
          , elfSegmentFlags     = p_flags
          , elfSegmentVirtAddr  = p_vaddr
          , elfSegmentPhysAddr  = p_paddr
          , elfSegmentAlign     = p_align
          , elfSegmentMemSize   = p_memsz
          , _elfSegmentData     = Seq.empty
          }
  return $! (s, (p_offset, p_filesz))

getPhdr64 :: ElfData -> GetPhdrFn Word64
getPhdr64 d = do
  p_type   <- toElfSegmentType  <$> getWord32 d
  p_flags  <- ElfSegmentFlags <$> getWord32 d
  p_offset <- getWord64 d
  p_vaddr  <- getWord64 d
  p_paddr  <- getWord64 d
  p_filesz <- getWord64 d
  p_memsz  <- getWord64 d
  p_align  <- getWord64 d
  let s = ElfSegment
         { elfSegmentType     = p_type
         , elfSegmentFlags    = p_flags
         , elfSegmentVirtAddr = p_vaddr
         , elfSegmentPhysAddr = p_paddr
         , elfSegmentAlign    = p_align
         , elfSegmentMemSize  = p_memsz
         , _elfSegmentData    = Seq.empty
         }
  return $! (s, (p_offset, p_filesz))

-- | Defines the layout of a table with elements of a fixed size.
data TableLayout w =
  TableLayout { tableOffset :: w
                -- ^ Offset where table starts relative to start of file.
              , entrySize :: Word16
                -- ^ Size of entries in bytes.
              , entryNum :: Word16
                -- ^ Number of entries in bytes.
              }

mkTableLayout :: w -> Word16 -> Word16 -> TableLayout w
mkTableLayout o s n = TableLayout o s n

-- | Returns offset of entry in table.
tableEntry :: Integral w => TableLayout w -> Word16 -> B.ByteString -> L.ByteString
tableEntry l i b = L.fromChunks [B.drop (fromIntegral o) b]
  where sz = fromIntegral (entrySize l)
        o = tableOffset l + fromIntegral i * sz

-- | Returns size of table.
tableSize :: Integral w => TableLayout w -> w
tableSize l = fromIntegral (entryNum l) * fromIntegral (entrySize l)

-- | Returns range in memory of table.
tableRange :: Integral w => TableLayout w -> Range w
tableRange l = (tableOffset l, tableSize l)

-- | Returns size of region.
type RegionSizeFn w = ElfDataRegion w -> w

-- | Function that transforms list of regions into new list.
type RegionPrefixFn w = Seq.Seq (ElfDataRegion w) -> Seq.Seq (ElfDataRegion w)

-- | Create a singleton list with a raw data region if one exists
insertRawRegion :: B.ByteString -> RegionPrefixFn w
insertRawRegion b r | B.length b == 0 = r
                     | otherwise = ElfDataRaw b Seq.<| r

data InsertError w
   = OverlapSegment (ElfDataRegion w)
   | OutOfRange

-- | Insert an elf data region at a given offset.
insertAtOffset :: Integral w
               => RegionSizeFn w   -- ^ Function for getting size of a region.
               -> Range w          -- ^ Range to insert in.
               -> RegionPrefixFn w -- ^ Insert function
               -> Seq.Seq (ElfDataRegion w)
               -> Either (InsertError w) (Seq.Seq (ElfDataRegion w))
insertAtOffset sizeOf (o,c) fn r0 =
  case Seq.viewl r0 of
    Seq.EmptyL
      | (o,c) == (0,0) ->
        pure $ fn Seq.empty
      | otherwise ->
        Left OutOfRange

    p Seq.:< r
      -- Go to next segment if offset to insert is after p.
      | o >= sz ->
        (p Seq.<|) <$> insertAtOffset sizeOf (o-sz,c) fn r
        -- Recurse inside segment if p is a segment that contains region to insert.
      | o + c <= sz
      , ElfDataSegment s <- p -> do
        -- New region ends before p ends and p is a segment.
        s' <- s & elfSegmentData (insertAtOffset sizeOf (o,c) fn)
        pure $! ElfDataSegment s' Seq.<| r
        -- Insert into current region is offset is 0.
      | o == 0 ->
        pure $! fn (p Seq.<| r)
        -- Split a raw segment into prefix and post.
      | ElfDataRaw b <- p ->
          -- We know offset is less than length of bytestring as otherwise we would
          -- have gone to next segment
          assert (fromIntegral o < B.length b) $ do
            let (pref,post) = B.splitAt (fromIntegral o) b
            pure $! insertRawRegion pref $ fn $ insertRawRegion post r
      | otherwise ->
        Left (OverlapSegment p)
     where sz = sizeOf p

-- | Insert a leaf region into the region.
insertSpecialRegion :: Integral w
                    => RegionSizeFn w -- ^ Returns size of region.
                    -> Range w
                    -> ElfDataRegion w -- ^ New region
                    -> Seq.Seq (ElfDataRegion w)
                    -> Seq.Seq (ElfDataRegion w)
insertSpecialRegion sizeOf r n segs =
    case insertAtOffset sizeOf r fn segs of
      Left (OverlapSegment prev) ->
        error $ "insertSpecialRegion: attempt to insert "
          ++ elfDataRegionName n
          ++ " overlapping Elf region into "
          ++ elfDataRegionName prev
          ++ "."
      Left OutOfRange -> error "insertSpecialRegion: Invalid region"
      Right result -> result
  where c = snd r
        -- Insert function
        fn l | c == 0 = n Seq.<| l
        fn l0
          | ElfDataRaw b Seq.:< l <- Seq.viewl l0
          , fromIntegral c <= B.length b =
            n Seq.<| insertRawRegion (B.drop (fromIntegral c) b) l
        fn _ = error $ "Elf file contained a non-empty header that overlapped with another.\n"
                       ++ "  This is not supported by the Elf parser."

insertSegment :: forall w
               . (Bits w, Integral w, Show w)
              => RegionSizeFn w
              -> Phdr w
              -> Seq.Seq (ElfDataRegion w)
              -> Seq.Seq (ElfDataRegion w)
insertSegment sizeOf (d,rng) segs =
    case insertAtOffset sizeOf rng (gather szd Seq.empty) segs of
      Left (OverlapSegment _) -> error "Attempt to insert overlapping segments."
      Left OutOfRange -> error "Invalid segment region"
      Right result -> result
  where (_,szd) = rng
        -- | @gather@ inserts new segment into head of list after collecting existings
        -- data it contains.
        gather :: w -- ^ Number of bytes to insert.
               -> Seq.Seq (ElfDataRegion w)
                  -- ^ Subsegments that occur before this segment. segment.
               -> Seq.Seq (ElfDataRegion w)
                  -- ^ Segments after insertion point.
               -> Seq.Seq (ElfDataRegion w)
        -- Insert segment if there are 0 bytes left to process.
        gather 0 l r = ElfDataSegment (d & elfSegmentData .~ l) Seq.<| r
        -- Collect p if it is contained within segment we are inserting.
        gather cnt l r0 =
          case Seq.viewl r0 of
            p Seq.:< r
              | sizeOf p <= cnt ->
                gather (cnt - sizeOf p) (l Seq.|> p) r
                -- Split raw bytes into contiguous segments.
              | ElfDataRaw b <- p ->
                  let pref = B.take (fromIntegral cnt) b
                      post = B.drop (fromIntegral cnt) b
                      newData = l Seq.>< insertRawRegion pref Seq.empty
                      d' = d & elfSegmentData .~ newData
                   in ElfDataSegment d' Seq.<| insertRawRegion post r
              | otherwise ->
                error $ "insertSegment: Inserted segments overlaps a previous segment.\n"
                     ++ "  Previous segment: " ++ show p ++ "\n"
                     ++ "  Previous segment size: " ++ show (sizeOf p) ++ "\n"
                     ++ "  New segment:\n" ++ show (indent 2 (ppSegment d)) ++ "\n"
                     ++ "  Remaining bytes: " ++ show cnt
            Seq.EmptyL -> error "insertSegment: Data ended before completion"

-- | Contains information needed to parse elf files.
data ElfParseInfo w = ElfParseInfo {
       -- | Size of ehdr table
       ehdrSize :: !Word16
       -- | Layout of segment header table.
     , phdrTable :: !(TableLayout w)
       -- | Function for reading elf segments.
     , getPhdr :: !(GetPhdrFn w)
       -- | Index of section for storing section names.
     , shdrNameIdx :: !Word16
       -- | Layout of section header table.
     , shdrTable :: !(TableLayout w)
       -- | Function for reading elf sections.
     , getShdr   :: !(GetShdrFn w)
       -- | Contents of file as a bytestring.
     , fileContents :: !B.ByteString
     }

-- | Return size of region given parse information.
regionSize :: Integral w
           => ElfParseInfo w
           -> w -- ^ Contains size of name table
           -> RegionSizeFn w
regionSize epi nameSize = sizeOf
  where sizeOf ElfDataElfHeader        = fromIntegral $ ehdrSize epi
        sizeOf ElfDataSegmentHeaders   = tableSize $ phdrTable epi
        sizeOf (ElfDataSegment s)      = sum $ sizeOf <$> (s^.elfSegmentData)
        sizeOf ElfDataSectionHeaders   = tableSize $ shdrTable epi
        sizeOf ElfDataSectionNameTable = nameSize
        sizeOf (ElfDataGOT g)          = elfGotSize g
        sizeOf (ElfDataSection s)      = fromIntegral $ B.length (elfSectionData s)
        sizeOf (ElfDataRaw b)          = fromIntegral $ B.length b

-- | Parse segment at given index.
segmentByIndex :: Integral w
               => ElfParseInfo w -- ^ Information for parsing
               -> Word16 -- ^ Index
               -> Phdr w
segmentByIndex epi i =
  runGet (getPhdr epi) (tableEntry (phdrTable epi) i (fileContents epi))

-- | Return list of segments with contents.
rawSegments :: Integral w => ElfParseInfo w -> [Phdr w]
rawSegments epi = segmentByIndex epi <$> enumCnt 0 (entryNum (phdrTable epi))

isRelroPhdr :: Phdr w -> Bool
isRelroPhdr (s,_) = elfSegmentType s == PT_GNU_RELRO

-- | Extract relro information.
asRelroInfo :: [Phdr w] -> Maybe (Range w)
asRelroInfo l =
  case filter isRelroPhdr l of
    [] -> Nothing
    [(_,r)] -> Just r
    _ -> error "Multiple relro segments."

-- | Parse elf region.
parseElfRegions :: (Bits w, Integral w, Show w)
                => ElfParseInfo w -- ^ Information for parsing.
                -> [Phdr w]
                -> Seq.Seq (ElfDataRegion w)
parseElfRegions epi segments = final
  where file = fileContents epi
        getSection i = runGet (getShdr epi file names)
                              (tableEntry (shdrTable epi) i file)
        nameRange = fst $ getSection (shdrNameIdx epi)
        sizeOf = regionSize epi (snd nameRange)
        names = slice nameRange file
        -- Define table with special data regions.
        headers = [ ((0, fromIntegral (ehdrSize epi)), ElfDataElfHeader)
                  , (tableRange (phdrTable epi), ElfDataSegmentHeaders)
                  , (tableRange (shdrTable epi), ElfDataSectionHeaders)
                  , (nameRange, ElfDataSectionNameTable)
                  ]
        -- Define table with regions for sections.
        dataSection (r,s) = (r, ElfDataSection s)
        sections = map (dataSection . getSection)
                 $ filter (/= shdrNameIdx epi)
                 $ enumCnt 0 (entryNum (shdrTable epi))
        -- Define initial region list without segments.
        initial  = foldr (uncurry (insertSpecialRegion sizeOf))
                         (insertRawRegion file Seq.empty)
                         (headers ++ sections)
        final = foldr (insertSegment sizeOf) initial
                -- Strip out relro segment (stored in `elfRelroRange')
              $ filter (not . isRelroPhdr) segments

-- | Either a 32-bit or 64-bit elf file.
data SomeElf
   = Elf32 (Elf Word32)
   | Elf64 (Elf Word64)

parseElfResult :: Either (L.ByteString, ByteOffset, String) (L.ByteString, ByteOffset, a)
               -> Either (ByteOffset,String) a
parseElfResult (Left (_,o,e)) = Left (o,e)
parseElfResult (Right (_,_,v)) = Right v

-- | Return true if this bytestring has the 4 bytes "\DELELF" at the start.
hasElfMagic :: L.ByteString -> Bool
hasElfMagic l = either (const False) (const True) $ flip runGetOrFail l $ do
  ei_magic    <- getByteString 4
  unless (ei_magic == elfMagic) $
    fail "Invalid magic number for ELF"

-- | Parses a ByteString into an Elf record. Parse failures call error. 32-bit ELF objects hav
-- their fields promoted to 64-bit so that the 32- and 64-bit ELF records can be the same.
parseElf :: B.ByteString -> Either (ByteOffset,String) SomeElf
parseElf b = parseElfResult $ flip runGetOrFail (L.fromChunks [b]) $ do
  ei_magic    <- getByteString 4
  unless (ei_magic == elfMagic) $
    fail $ "Invalid magic number for ELF: " ++ show (ei_magic, elfMagic)
  ei_class   <- tryParse "ELF class" toSomeElfClass =<< getWord8
  d          <- tryParse "ELF data"  toElfData =<< getWord8
  ei_version <- getWord8
  unless (ei_version == 1) $
    fail "Invalid version number for ELF"
  ei_osabi    <- toElfOSABI <$> getWord8
  ei_abiver   <- getWord8
  skip 7
  case ei_class of
    SomeElfClass ELFCLASS32 ->
      Elf32 <$> parseElf32 d ei_version ei_osabi ei_abiver b
    SomeElfClass ELFCLASS64 ->
      Elf64 <$> parseElf64 d ei_version ei_osabi ei_abiver b

-- | Parse a 32-bit elf.
parseElf32 :: ElfData -> Word8 -> ElfOSABI -> Word8 -> B.ByteString -> Get (Elf Word32)
parseElf32 d ei_version ei_osabi ei_abiver b = do
  e_type      <- toElfType    <$> getWord16 d
  e_machine   <- toElfMachine <$> getWord16 d
  e_version   <- getWord32 d
  unless (fromIntegral ei_version == e_version) $
    fail "ELF Version mismatch"
  e_entry     <- getWord32 d
  e_phoff     <- getWord32 d
  e_shoff     <- getWord32 d
  e_flags     <- getWord32 d
  e_ehsize    <- getWord16 d
  e_phentsize <- getWord16 d
  unless (e_phentsize == sizeOfPhdr32) $
    fail $ "Invalid segment entry size"
  e_phnum     <- getWord16 d
  e_shentsize <- getWord16 d
  unless (e_shentsize == sizeOfShdr32) $
    fail $ "Invalid section entry size"
  e_shnum     <- getWord16 d
  e_shstrndx  <- getWord16 d
  let epi = ElfParseInfo
                  { ehdrSize = e_ehsize
                  , phdrTable = mkTableLayout e_phoff e_phentsize e_phnum
                  , getPhdr = getPhdr32 d
                  , shdrNameIdx = e_shstrndx
                  , shdrTable = mkTableLayout e_shoff e_shentsize e_shnum
                  , getShdr = getShdr32 d
                  , fileContents = b
                  }
  let segments = rawSegments epi
  return Elf { elfData       = d
             , elfClass      = ELFCLASS32
             , elfVersion    = ei_version
             , elfOSABI      = ei_osabi
             , elfABIVersion = ei_abiver
             , elfType       = e_type
             , elfMachine    = e_machine
             , elfEntry      = e_entry
             , elfFlags      = e_flags
             , _elfFileData  = parseElfRegions epi segments
             , elfRelroRange = asRelroInfo segments
             }

-- | Parse a 32-bit elf.
parseElf64 :: ElfData -> Word8 -> ElfOSABI -> Word8 -> B.ByteString -> Get (Elf Word64)
parseElf64 d ei_version ei_osabi ei_abiver b = do
  e_type      <- toElfType    <$> getWord16 d
  e_machine   <- toElfMachine <$> getWord16 d
  e_version   <- getWord32 d
  unless (fromIntegral ei_version == e_version) $
    fail "ELF Version mismatch"
  e_entry     <- getWord64 d
  e_phoff     <- getWord64 d
  e_shoff     <- getWord64 d
  e_flags     <- getWord32 d
  e_ehsize    <- getWord16 d
  e_phentsize <- getWord16 d
  e_phnum     <- getWord16 d
  e_shentsize <- getWord16 d
  e_shnum     <- getWord16 d
  e_shstrndx  <- getWord16 d
  let epi = ElfParseInfo
                  { ehdrSize    = e_ehsize
                  , phdrTable   = mkTableLayout e_phoff e_phentsize e_phnum
                  , getPhdr     = getPhdr64 d
                  , shdrNameIdx = e_shstrndx
                  , shdrTable   = mkTableLayout e_shoff e_shentsize e_shnum
                  , getShdr     = getShdr64 d
                  , fileContents = b
                  }
  let segments = rawSegments epi
  return Elf { elfData       = d
             , elfClass      = ELFCLASS64
             , elfVersion    = ei_version
             , elfOSABI      = ei_osabi
             , elfABIVersion = ei_abiver
             , elfType       = e_type
             , elfMachine    = e_machine
             , elfEntry      = e_entry
             , elfFlags      = e_flags
             , _elfFileData  = parseElfRegions epi segments
             , elfRelroRange = asRelroInfo segments
             }


------------------------------------------------------------------------
-- ElfLayout

-- | Write elf file out to bytestring.
renderElf :: Elf w -> L.ByteString
renderElf = elfLayoutBytes . elfLayout

type RenderedElfSegment w = (ElfSegment w, B.ByteString)

-- | Returns elf segments with data in them.
renderedElfSegments :: Elf w -> [RenderedElfSegment w]
renderedElfSegments e = elfClassIntegralInstance (elfClass e) $
  let l = elfLayout e
      b = U.toStrictByteString (l^.elfOutput)
      segFn (s,rng) = (s, slice rng b)
   in segFn <$> F.toList (allPhdrs l)

------------------------------------------------------------------------
-- ElfSymbolVisibility

-- | Visibility for elf symbol
newtype ElfSymbolVisibility = ElfSymbolVisibility { _visAsWord :: Word8 }

-- | Visibility is specified by binding type
stv_default :: ElfSymbolVisibility
stv_default = ElfSymbolVisibility 0

-- | OS specific version of STV_HIDDEN.
stv_internal :: ElfSymbolVisibility
stv_internal = ElfSymbolVisibility 1

-- | Can only be seen inside currect component.
stv_hidden :: ElfSymbolVisibility
stv_hidden = ElfSymbolVisibility 2

-- | Can only be seen inside currect component.
stv_protected :: ElfSymbolVisibility
stv_protected = ElfSymbolVisibility 3

instance Show ElfSymbolVisibility where
  show (ElfSymbolVisibility w) =
    case w of
      0 -> "DEFAULT"
      1 -> "INTERNAL"
      2 -> "HIDDEN"
      3 -> "PROTECTED"
      _ -> "BadVis"

------------------------------------------------------------------------
-- ElfSymbolTableEntry

class (Integral w) => ElfSymbolTableWidth w where
  symbolTableEntrySize :: w

  getSymbolTableEntry :: Elf w
                      -> (Word32 -> String)
                         -- ^ Function for mapping offset in string table
                         -- to bytestring.
                      -> Get (ElfSymbolTableEntry w)


-- | The symbol table entries consist of index information to be read from other
-- parts of the ELF file. Some of this information is automatically retrieved
-- for your convenience (including symbol name, description of the enclosing
-- section, and definition).
data ElfSymbolTableEntry w = EST
    { steName             :: String
    , steType             :: ElfSymbolType
    , steBind             :: ElfSymbolBinding
    , steOther            :: Word8
    , steIndex            :: ElfSectionIndex  -- ^ Section in which the def is held
    , steValue            :: w
    , steSize             :: w
    } deriving (Eq, Show)

steEnclosingSection :: Elf w -> ElfSymbolTableEntry w -> Maybe (ElfSection w)
steEnclosingSection e s = sectionByIndex e (steIndex s)

steVisibility :: ElfSymbolTableEntry w -> ElfSymbolVisibility
steVisibility e = ElfSymbolVisibility (steOther e .&. 0x3)

type ColumnAlignmentFn = [String] -> [String]

alignLeft :: Int -> ColumnAlignmentFn
alignLeft minw l = ar <$> l
  where w = maximum $ minw : (length <$> l)
        ar s = s ++ replicate (w-n) ' '
          where n = length s

alignRight :: Int -> ColumnAlignmentFn
alignRight minw l = ar <$> l
  where w = maximum $ minw : (length <$> l)
        ar s = replicate (w-n) ' ' ++ s
          where n = length s

-- | Function for pretty printing a row of tables according to
-- rules for each column.
fix_table_columns :: [ColumnAlignmentFn]
                     -- ^ Functions for modifying each column
                  -> [[String]]
                  -> Doc
fix_table_columns colFns rows = vcat (hsep . fmap text <$> fixed_rows)
  where cols = transpose rows
        fixed_cols = zipWith ($) colFns cols
        fixed_rows = transpose fixed_cols

-- | Pretty print symbol table entries in format used by readelf.
ppSymbolTableEntries :: (Integral w, Bits w, Show w) => [ElfSymbolTableEntry w] -> Doc
ppSymbolTableEntries l = fix_table_columns (snd <$> cols) (fmap fst cols : entries)
  where entries = zipWith ppSymbolTableEntry [0..] l
        cols = [ ("Num:",     alignRight 6)
               , ("   Value", alignLeft 0)
               , ("Size",     alignRight 5)
               , ("Type",     alignLeft  7)
               , ("Bind",     alignLeft  6)
               , ("Vis",      alignLeft 8)
               , ("Ndx",      alignLeft 3)
               , ("Name", id)
               ]

ppSymbolTableEntry :: (Integral w, Bits w, Show w) => Int -> ElfSymbolTableEntry w -> [String]
ppSymbolTableEntry i e =
  [ show i ++ ":"
  , ppHex (steValue e)
  , show (steSize e)
  , ppElfSymbolType (steType e)
  , ppElfSymbolBinding (steBind e)
  , show (steVisibility e)
    -- Ndx
  , show (steIndex e)
  , steName e
  ]

-- | Parse the symbol table section into a list of symbol table entries. If
-- no symbol table is found then an empty list is returned.
-- This function does not consult flags to look for SHT_STRTAB (when naming symbols),
-- it just looks for particular sections of ".strtab" and ".shstrtab".
parseSymbolTables :: Elf w -> [[ElfSymbolTableEntry w]]
parseSymbolTables e =
  getSymbolTableEntries e <$> symbolTableSections e

-- | Assumes the given section is a symbol table, type SHT_SYMTAB
-- (guaranteed by parseSymbolTables).
getSymbolTableEntries :: Elf w -> ElfSection w -> [ElfSymbolTableEntry w]
getSymbolTableEntries e s = elfSymbolTableWidthInstance (elfClass e) $
  let link   = elfSectionLink s
      strtab = lookup link (zip [0..] (toListOf elfSections e))
      strs = fromMaybe B.empty (elfSectionData <$> strtab)
      nameFn idx = B.toString (lookupString idx strs)
   in runGetMany (getSymbolTableEntry e nameFn) (L.fromChunks [elfSectionData s])

-- | Use the symbol offset and size to extract its definition
-- (in the form of a ByteString).
-- If the size is zero, or the offset larger than the 'elfSectionData',
-- then 'Nothing' is returned.
findSymbolDefinition :: Elf w -> ElfSymbolTableEntry w -> Maybe B.ByteString
findSymbolDefinition elf e = elfClassIntegralInstance (elfClass elf) $
    let enclosingData = elfSectionData <$> steEnclosingSection elf e
        start = steValue e
        len = steSize e
        def = slice (start, len) <$> enclosingData
    in if def == Just B.empty then Nothing else def

hasSectionType :: ElfSectionType -> ElfSection w -> Bool
hasSectionType tp s = elfSectionType s == tp

symbolTableSections :: Elf w -> [ElfSection w]
symbolTableSections = toListOf $ elfSections.filtered (hasSectionType SHT_SYMTAB)

instance ElfSymbolTableWidth Word32 where
  symbolTableEntrySize = 16
  getSymbolTableEntry e nameFn = do
    let d = elfData e
    nameIdx <- getWord32 d
    value <- getWord32 d
    size  <- getWord32 d
    info  <- getWord8
    other <- getWord8
    sTlbIdx <- ElfSectionIndex <$> getWord16 d
    let (typ,bind) = infoToTypeAndBind info
    return $ EST { steName = nameFn nameIdx
                 , steType  = typ
                 , steBind  = bind
                 , steOther = other
                 , steIndex = sTlbIdx
                 , steValue = value
                 , steSize  = size
                 }

instance ElfSymbolTableWidth Word64 where
  symbolTableEntrySize = 24
  getSymbolTableEntry e nameFn = do
    let d = elfData e
    nameIdx <- getWord32 d
    info <- getWord8
    other <- getWord8
    sTlbIdx <- ElfSectionIndex <$> getWord16 d
    symVal <- getWord64 d
    size <- getWord64 d
    let (typ,bind) = infoToTypeAndBind info
    return $ EST { steName = nameFn nameIdx
                 , steType = typ
                 , steBind = bind
                 , steOther = other
                 , steIndex = sTlbIdx
                 , steValue = symVal
                 , steSize = size
                 }

sectionByIndex :: Elf w
               -> ElfSectionIndex
               -> Maybe (ElfSection w)
sectionByIndex e si = do
  i <- asSectionIndex si
  listToMaybe $ genericDrop i (e^..elfSections)

------------------------------------------------------------------------
-- Dynamic information

[enum|
 ElfDynamicArrayTag :: Word32
 DT_NULL          0
 DT_NEEDED        1
 DT_PLTRELSZ      2
 DT_PLTGOT        3
 DT_HASH          4
 DT_STRTAB        5
 DT_SYMTAB        6
 DT_RELA          7
 DT_RELASZ        8
 DT_RELAENT       9
 DT_STRSZ        10
 DT_SYMENT       11
 DT_INIT         12
 DT_FINI         13
 DT_SONAME       14
 DT_RPATH        15
 DT_SYMBOLIC     16
 DT_REL          17
 DT_RELSZ        18
 DT_RELENT       19
 DT_PLTREL       20
 DT_DEBUG        21
 DT_TEXTREL      22
 DT_JMPREL       23
 DT_BIND_NOW     24
 DT_INIT_ARRAY   25
 DT_FINI_ARRAY   26
 DT_INIT_ARRAYSZ    27
 DT_FINI_ARRAYSZ    28
 DT_RUNPATH         29 -- Library search path
 DT_FLAGS           30 -- Flags for the object being loaded
 DT_PREINIT_ARRAY   32 -- Start of encoded range (also DT_PREINIT_ARRAY)
 DT_PREINIT_ARRAYSZ 33 -- Size in bytes of DT_PREINIT_ARRAY

 -- DT_LOOS   0x60000000
 -- DT_VALRNGLO    0x6ffffd00
 DT_GNU_PRELINKED  0x6ffffdf5 -- Prelinking timestamp
 DT_GNU_CONFLICTSZ 0x6ffffdf6 -- Size of conflict section.
 DT_GNU_LIBLISTSZ  0x6ffffdf7 -- Size of lbirary list
 DT_CHECKSUM       0x6ffffdf8
 DT_PLTPADSZ       0x6ffffdf9
 DT_MOVEENT        0x6ffffdfa
 DT_MOVESZ         0x6ffffdfb
 DT_FEATURE_1      0x6ffffdfc -- Feature selection (DTF_*).
 DT_POSFLAG_1      0x6ffffdfd -- Flags for DT_* entries, effecting the following DT_* entry.
 DT_SYMINSZ        0x6ffffdfe -- Size of syminfo table (in bytes)
 DT_SYMINENT       0x6ffffdff -- Entry size of syminfo
 -- DT_VALRNGHI    0x6ffffdff


-- DT_* entries between DT_ADDRRNGHI & DT_ADDRRNGLO use the
-- d_ptr field
 -- DT_ADDRRNGLO   0x6ffffe00
 DT_GNU_HASH       0x6ffffef5 -- GNU-style hash table.
 DT_TLSDESC_PLT	   0x6ffffef6
 DT_TLSDESC_GOT	   0x6ffffef7
 DT_GNU_CONFLICT   0x6ffffef8 -- Start of conflict section
 DT_GNU_LIBLIST	   0x6ffffef9 -- Library list
 DT_CONFIG	   0x6ffffefa -- Configuration information
 DT_DEPAUDIT       0x6ffffefb -- Dependency auditing
 DT_AUDIT          0x6ffffefc -- Object auditing
 DT_PLTPAD         0x6ffffefd -- PLT padding
 DT_MOVETAB        0x6ffffefe -- Move table
 DT_SYMINFO        0x6ffffeff -- Syminfo table
  -- DT_ADDRRNGHI  0x6ffffeff

 DT_VERSYM         0x6ffffff0
 DT_RELACOUNT      0x6ffffff9
 DT_RELCOUNT       0x6ffffffa
 DT_FLAGS_1        0x6ffffffb -- State flags
 DT_VERDEF         0x6ffffffc -- Address of version definition.
 DT_VERDEFNUM      0x6ffffffd
 DT_VERNEED        0x6ffffffe
 DT_VERNEEDNUM     0x6fffffff -- Number of needed versions.
 -- DT_HIOS        0x6FFFFFFF

 -- DT_LOPROC 0x70000000
 -- DT_HIPROC 0x7FFFFFFF
 DT_Other         _
|]

-- | Dynamic array entry
data Dynamic w
   = Dynamic { dynamicTag :: !ElfDynamicArrayTag
             , _dynamicVal :: !w
             }
  deriving (Show)

-- | Read dynamic array entry.
getDynamic :: forall w . (Integral w, IsElfData w) => ElfData -> Get (Dynamic w)
getDynamic d = do
  tag <- getData d :: Get w
  v <- getData d
  return $! Dynamic (toElfDynamicArrayTag (fromIntegral tag)) v


dynamicList :: (Integral w, IsElfData w) => ElfData -> Get [Dynamic w]
dynamicList d = go []
  where go l = do
          done <- isEmpty
          if done then
            return l
          else do
            e <- getDynamic d
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
  | (seg, (dta,n)) <- F.toList (l^.phdrs)
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
addressToFile l b nm w = elfClassIntegralInstance (elfLayoutClass l) $
  case fileOffsetOfAddr w l of
    [] -> fail $ "Could not find " ++ nm ++ "."
    [r] -> return (sliceL r b)
    _ -> fail $ "Multiple overlapping segments containing " ++ nm ++ "."

-- | Return  ranges in file containing the given address range.
-- In a well-formed file, the list should contain at most one element.
fileOffsetOfRange :: (Ord w, Num w) => Range w -> ElfLayout w -> [Range w]
fileOffsetOfRange (w,sz) l =
  [ (dta + offset, sz)
  | (seg, (dta,n)) <- F.toList (l^.phdrs)
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
addressRangeToFile l b nm rMem = elfClassIntegralInstance (elfLayoutClass l) $
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
dynSymTab e l file m = elfSymbolTableWidthInstance (elfClass e) $ do
  -- Get string table.
  strTab <- dynStrTab l file m

  sym_off <- mandatoryDynamicEntry DT_SYMTAB m
  -- According to a comment in GNU Libc 2.19 (dl-fptr.c:175), you get the
  -- size of the dynamic symbol table by assuming that the string table follows
  -- immediately afterwards.
  str_off <- mandatoryDynamicEntry DT_STRTAB m
  when (str_off < sym_off) $ do
    fail $ "The string table offset is before the symbol table offset."
  -- Size of each symbol table entry.
  syment <- mandatoryDynamicEntry DT_SYMENT m
  when (syment /= symbolTableEntrySize) $ do
    fail "Unexpected symbol table entry size"
  let sym_sz = str_off - sym_off
  symtab <- addressRangeToFile l file "dynamic symbol table" (sym_off,sym_sz)
  let nameFn idx = L.toString $ lookupStringL (fromIntegral idx) strTab
  return $ runGetMany (getSymbolTableEntry e nameFn) symtab

------------------------------------------------------------------------
-- Low level getters

getWord16 :: ElfData -> Get Word16
getWord16 ELFDATA2LSB = getWord16le
getWord16 ELFDATA2MSB = getWord16be

getWord32 :: ElfData -> Get Word32
getWord32 ELFDATA2LSB = getWord32le
getWord32 ELFDATA2MSB = getWord32be

getWord64 :: ElfData -> Get Word64
getWord64 ELFDATA2LSB = getWord64le
getWord64 ELFDATA2MSB = getWord64be

------------------------------------------------------------------------
-- IsElfData

-- | @IsElfData s@ indicates that @s@ is a type that can be read from an
-- Elf file given its endianess
class Show s => IsElfData s where
  getData :: ElfData -> Get s

instance IsElfData Int32 where
  getData d = fromIntegral <$> getWord32 d

instance IsElfData Int64 where
  getData d = fromIntegral <$> getWord64 d

instance IsElfData Word32 where
  getData = getWord32

instance IsElfData Word64 where
  getData = getWord64

class Integral w => IsRelaWidth w where
  -- | Size of one relocation entry.
  relaEntSize :: w

  -- | Convert info paramter to relocation sym.
  relaSym :: w -> Word32

  -- | Get relocation entry element.
  getRelaEntryElt :: ElfData -> Get w

instance IsRelaWidth Word32 where
  relaEntSize = 12
  relaSym info = info `shiftR` 8
  getRelaEntryElt = getWord32

instance IsRelaWidth Word64 where
  relaEntSize = 24
  relaSym info = fromIntegral (info `shiftR` 32)
  getRelaEntryElt = getWord64

elfRelaWidthInstance :: ElfClass w -> (IsRelaWidth w => a) -> a
elfRelaWidthInstance c a =
  case c of
    ELFCLASS32 -> a
    ELFCLASS64 -> a

-- | @IsRelocationType u s tp@ indicates that @tp@ is a tagged union of
-- relocation entries that encodes signed values as type @s@ and unsigned
-- values as type @u@.
class (IsRelaWidth u, IsElfData u, IsElfData s, Show tp)
   => IsRelocationType u s tp | tp -> u, tp -> s where

  -- | Convert unsigned value to type.
  relaType :: u -> Maybe tp

  -- | Return true if this is a relative relocation type.
  isRelative :: tp -> Bool

-- | A relocation entry
data RelaEntry u s tp
   = Rela { r_offset :: !u
            -- ^ The location to apply the relocation action.
          , r_sym    :: !Word32
            -- ^ Symbol table entry relocation refers to.
          , r_type   :: !tp
            -- ^ The type of relocation entry
          , r_addend :: !s
            -- ^ The constant addend to apply.
          } deriving (Show)

-- | Return true if this is a relative relocation entry.
isRelativeRelaEntry :: IsRelocationType u s tp => RelaEntry u s tp -> Bool
isRelativeRelaEntry r = isRelative (r_type r)

-- | Pretty-print a table of relocation entries.
ppRelaEntries :: (Bits u, IsRelocationType u s tp) => [RelaEntry u s tp] -> Doc
ppRelaEntries l = fix_table_columns (snd <$> cols) (fmap fst cols : entries)
  where entries = zipWith ppRelaEntry [0..] l
        cols = [ ("Num", alignRight 0)
               , ("Offset", alignLeft 0)
               , ("Symbol", alignLeft 0)
               , ("Type", alignLeft 0)
               , ("Addend", alignLeft 0)
               ]

ppRelaEntry :: (Bits u, IsRelocationType u s tp) => Int -> RelaEntry u s tp -> [String]
ppRelaEntry i e =
  [ shows i ":"
  , ppHex (r_offset e)
  , show (r_sym e)
  , show (r_type e)
  , show (r_addend e)
  ]

-- | Read a relocation entry.
getRelaEntry :: IsRelocationType u s tp => ElfData -> Get (RelaEntry u s tp)
getRelaEntry d = do
  offset <- getData d
  info   <- getData d
  addend <- getData d
  let msg = "Could not parse relocation type: " ++ showHex info ""
  tp <- maybe (fail msg) return $ relaType info
  return Rela { r_offset = offset
              , r_sym = relaSym info
              , r_type = tp
              , r_addend = addend
              }

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

dynRelaArray :: (IsRelocationType u s tp, Monad m)
             => ElfData
             -> ElfLayout u
             -> L.ByteString
             -> DynamicMap u
             -> m [RelaEntry u s tp]
dynRelaArray d l file dm = elfRelaWidthInstance (elfLayoutClass l) $ do
  checkPLTREL dm
  mrela_offset <- optionalDynamicEntry DT_RELA dm
  case mrela_offset of
    Nothing -> return []
    Just rela_offset -> do
      --cnt <- mandatoryDynamicEntry DT_RELACOUNT dm
      ent <- mandatoryDynamicEntry DT_RELAENT dm
      sz  <- mandatoryDynamicEntry DT_RELASZ dm
      --when (cnt * ent /= sz) $ do
      --  fail $ "Unexpected size of relocation array:" ++ show (cnt,ent,sz)
      when (ent /= relaEntSize) $ fail "Unexpected size for relocation entry."
      rela <- addressRangeToFile l file "relocation array" (rela_offset,sz)
      return $ runGetMany (getRelaEntry d) rela

checkRelaCount :: (IsRelocationType u s tp, Monad m)
               => [RelaEntry u s tp]
               -> DynamicMap u
               -> m ()
checkRelaCount relocations dm = do
  let relaCount = length (filter isRelativeRelaEntry relocations)
  mexpRelaCount <- optionalDynamicEntry DT_RELACOUNT dm
  let correctCount = case mexpRelaCount of
                       Just c -> c == fromIntegral relaCount
                       Nothing -> True
  when (not correctCount) $ do
    fail $ "Incorrect DT_RELACOUNT"

[enum|
  I386_RelocationType :: Word32
  R_386_NONE      0
  R_386_32        1
  R_386_PC32      2
  R_386_GOT32     3
  R_386_PLT32     4
  R_386_COPY      5
  R_386_GLOB_DAT  6
  R_386_JMP_SLOT  7
  R_386_RELATIVE  8
  R_386_GOTOFF    9
  R_386_GOTPC    10
|]

instance IsRelocationType Word32 Int32 I386_RelocationType where
  relaType = toI386_RelocationType

  isRelative R_386_RELATIVE = True
  isRelative _ = False

[enum|
 X86_64_RelocationType :: Word32
 R_X86_64_NONE           0  -- No reloc
 R_X86_64_64             1  -- Direct 64 bit
 R_X86_64_PC32           2  -- PC relative 32 bit signed
 R_X86_64_GOT32          3  -- 32 bit GOT entry
 R_X86_64_PLT32          4  -- 32 bit PLT address
 R_X86_64_COPY           5  -- Copy symbol at runtime
 R_X86_64_GLOB_DAT       6  -- Create GOT entry
 R_X86_64_JUMP_SLOT      7  -- Create PLT entry
 R_X86_64_RELATIVE       8  -- Adjust by program base
 R_X86_64_GOTPCREL       9  -- 32 bit signed pc relative offset to GOT
 R_X86_64_32             10 -- Direct 32 bit zero extended
 R_X86_64_32S            11 -- Direct 32 bit sign extended
 R_X86_64_16             12 -- Direct 16 bit zero extended
 R_X86_64_PC16           13 -- 16 bit sign extended pc relative
 R_X86_64_8              14 -- Direct 8 bit sign extended
 R_X86_64_PC8            15 -- 8 bit sign extended pc relative
|]

instance IsRelocationType Word64 Int64 X86_64_RelocationType where
  relaType = toX86_64_RelocationType . fromIntegral

  isRelative R_X86_64_RELATIVE = True
  isRelative _ = False

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
                , dynRelocations :: ![RelaEntry u s tp]
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

elfSymbolTableWidthInstance :: ElfClass w -> (ElfSymbolTableWidth w => a) -> a
elfSymbolTableWidthInstance c a =
  case c of
    ELFCLASS32 -> a
    ELFCLASS64 -> a

-- | This returns information about the dynamic segment in a elf file
-- if it exists.
--
-- The code assumes that there is at most one segment with type PT_Dynamic.
dynamicEntries :: (IsRelocationType u s tp, Monad m)
               => Elf u
               -> m (Maybe (DynamicSection u s tp))
dynamicEntries e = elfSymbolTableWidthInstance (elfClass e) $ do
  let l = elfLayout e
  let file = U.toLazyByteString $ l^.elfOutput
  case filter (\(s,_) -> elfSegmentType s == PT_DYNAMIC) (F.toList (l^.phdrs)) of
    [] -> return Nothing
    [(_,p)] -> do
      let elts = runGet (dynamicList (elfData e)) (sliceL p file)
      let m = foldl' (flip insertDynamic) Map.empty elts

      strTab <- dynStrTab l file m

      mnm_index <- optionalDynamicEntry DT_SONAME m
      let mnm = nameFromIndex strTab . fromIntegral <$> mnm_index

      symbols <- dynSymTab e l file m

      let isUnparsed tag _ = not (tag `elem` parsed_dyntags)
      sym_versions <- gnuSymVersionTable (elfData e) l file m (length symbols)
      version_defs <- gnuVersionDefs (elfData e) l file strTab m
      version_reqs <- gnuVersionReqs (elfData e) l file strTab m

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
-- Elf symbol information

[enum|
  ElfSymbolBinding :: Word8
  STB_LOCAL 0 -- Symbol not visible outside obj
  STB_GLOBAL 1 -- Symbol visible outside obj
  STB_WEAK 2 -- Like globals, lower precedence
  STB_GNU_UNIQUE 10 --Symbol is unique in namespace
  STB_Other w
|]

ppElfSymbolBinding :: ElfSymbolBinding -> String
ppElfSymbolBinding b =
  case b of
    STB_LOCAL -> "LOCAL"
    STB_GLOBAL -> "GLOBAL"
    STB_WEAK   -> "WEAK"
    STB_GNU_UNIQUE -> "UNIQUE"
    STB_Other w | 11 <= w && w <= 12 -> "<OS specific>: " ++ show w
                | 13 <= w && w <= 15 -> "<processor specific>: " ++ show w
                | otherwise -> "<unknown>: " ++ show w

infoToTypeAndBind :: Word8 -> (ElfSymbolType,ElfSymbolBinding)
infoToTypeAndBind i =
  let tp = toElfSymbolType (i .&. 0x0F)
      b = (i `shiftR` 4) .&. 0xF
   in (tp, toElfSymbolBinding b)

[enum|
 ElfSymbolType :: Word8
 STT_NOTYPE     0 -- Symbol type is unspecified
 STT_OBJECT     1 -- Symbol is a data object
 STT_FUNC       2 -- Symbol is a code object
 STT_SECTION    3 -- Symbol associated with a section.
 STT_FILE       4 -- Symbol gives a file name.
 STT_COMMON     5 -- An uninitialised common block.
 STT_TLS        6 -- Thread local data object.
 STT_RELC       8 -- Complex relocation expression.
 STT_SRELC      9 -- Signed Complex relocation expression.
 STT_GNU_IFUNC 10 -- Symbol is an indirect code object.
 STT_Other      _
|]

-- | Returns true if this is an OF specififc symbol type.
isOSSpecificSymbolType :: ElfSymbolType -> Bool
isOSSpecificSymbolType tp =
  case tp of
    STT_GNU_IFUNC -> True
    STT_Other w | 10 <= w && w <= 12 -> True
    _ -> False

isProcSpecificSymbolType :: ElfSymbolType -> Bool
isProcSpecificSymbolType tp =
  case tp of
    STT_Other w | 13 <= w && w <= 15 -> True
    _ -> False

ppElfSymbolType :: ElfSymbolType -> String
ppElfSymbolType tp =
  case tp of
    STT_NOTYPE  -> "NOTYPE"
    STT_OBJECT  -> "OBJECT"
    STT_FUNC    -> "FUNC"
    STT_SECTION -> "SECTION"
    STT_FILE    -> "FILE"
    STT_COMMON  -> "COMMON"
    STT_TLS     -> "TLS"
    STT_RELC    -> "RELC"
    STT_SRELC   -> "SRELC"
    STT_GNU_IFUNC -> "IFUNC"
    STT_Other w | isOSSpecificSymbolType tp -> "<OS specific>: " ++ show w
                | isProcSpecificSymbolType tp -> "<processor specific>: " ++ show w
                | otherwise -> "<unknown>: " ++ show w


newtype ElfSectionIndex = ElfSectionIndex Word16
  deriving (Eq, Ord)

asSectionIndex :: ElfSectionIndex -> Maybe Word16
asSectionIndex si@(ElfSectionIndex w)
  | shn_undef < si && si < shn_loreserve = Just (w-1)
  | otherwise = Nothing

-- | Undefined section
shn_undef :: ElfSectionIndex
shn_undef = ElfSectionIndex 0

-- | Associated symbol is absolute.
shn_abs :: ElfSectionIndex
shn_abs = ElfSectionIndex 0xfff1

-- | Associated symbol is common.
shn_common :: ElfSectionIndex
shn_common = ElfSectionIndex 0xfff2

-- | Start of reserved indices.
shn_loreserve :: ElfSectionIndex
shn_loreserve = ElfSectionIndex 0xff00

-- | Start of processor specific.
shn_loproc :: ElfSectionIndex
shn_loproc = shn_loreserve

-- | Like SHN_COMMON but symbol in .lbss
shn_x86_64_lcommon :: ElfSectionIndex
shn_x86_64_lcommon = ElfSectionIndex 0xff02

-- | Only used by HP-UX, because HP linker gives
-- weak symbols precdence over regular common symbols.
shn_ia_64_ansi_common :: ElfSectionIndex
shn_ia_64_ansi_common = shn_loreserve

-- | Small common symbols
shn_mips_scommon :: ElfSectionIndex
shn_mips_scommon = ElfSectionIndex 0xff03

-- | Small undefined symbols
shn_mips_sundefined  :: ElfSectionIndex
shn_mips_sundefined = ElfSectionIndex 0xff04

-- | Small data area common symbol.
shn_tic6x_scommon :: ElfSectionIndex
shn_tic6x_scommon = shn_loreserve

-- | End of processor specific.
shn_hiproc :: ElfSectionIndex
shn_hiproc = ElfSectionIndex 0xff1f

-- | Start of OS-specific.
shn_loos :: ElfSectionIndex
shn_loos = ElfSectionIndex 0xff20

-- | End of OS-specific.
shn_hios :: ElfSectionIndex
shn_hios = ElfSectionIndex 0xff3f

instance Show ElfSectionIndex where
  show i = ppElfSectionIndex EM_NONE ELFOSABI_SYSV maxBound i

ppElfSectionIndex :: ElfMachine
                  -> ElfOSABI
                  -> Word16 -- ^ Number of sections.
                  -> ElfSectionIndex
                  -> String
ppElfSectionIndex m abi this_shnum tp@(ElfSectionIndex w)
  | tp == shn_undef  = "UND"
  | tp == shn_abs    = "ABS"
  | tp == shn_common = "COM"
  | tp == shn_ia_64_ansi_common
  , m == EM_IA_64
  , abi == ELFOSABI_HPUX = "ANSI_COM"
  | tp == shn_x86_64_lcommon
  , m `elem` [ EM_X86_64, EM_L1OM, EM_K1OM]
  = "LARGE_COM"
  | (tp,m) == (shn_mips_scommon, EM_MIPS)
    || (tp,m) == (shn_tic6x_scommon, EM_TI_C6000)
  = "SCOM"
  | (tp,m) == (shn_mips_sundefined, EM_MIPS)
  = "SUND"
  | tp >= shn_loproc && tp <= shn_hiproc
  = "PRC[0x" ++ showHex w "]"
  | tp >= shn_loos && tp <= shn_hios
  = "OS [0x" ++ showHex w "]"
  | tp >= shn_loreserve
  = "RSV[0x" ++ showHex w "]"
  | w >= this_shnum = "bad section index[" ++ show w ++ "]"
  | otherwise = show w

-- | Return elf interpreter in a PT_INTERP segment if one exists, or Nothing is no interpreter
-- is defined.  This will call the Monad fail operation if the contents of the data cannot be
-- parsed.
elfInterpreter :: Monad m => Elf w -> m (Maybe FilePath)
elfInterpreter e =
  case filter (\s -> elfSegmentType s == PT_INTERP) (elfSegments e) of
    [] -> return Nothing
    seg:_ ->
      case F.toList (seg^.elfSegmentData) of
        [ElfDataSection s] -> return (Just (B.toString (elfSectionData s)))
        _ -> fail "Could not parse elf section."

_unused :: a
_unused = undefined fromElfSymbolBinding fromI386_RelocationType fromX86_64_RelocationType
