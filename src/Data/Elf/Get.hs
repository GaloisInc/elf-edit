{-# LANGUAGE GADTs #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Data.Elf.Get
  ( SomeElf(..)
  , parseElf
    -- * Low level utilities
  , getWord16
  , getWord32
  , getWord64
  , lookupString
  ) where

import           Control.Exception ( assert )
import           Control.Lens
import           Control.Monad
import           Data.Binary.Get as G
import           Data.Bits
import qualified Data.ByteString.UTF8 as B (toString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import qualified Data.Sequence as Seq
import           Data.Word
import           Text.PrettyPrint.ANSI.Leijen hiding ((<>), (<$>))

import           Data.Elf.Layout (Phdr, elfMagic, sizeOfPhdr32, sizeOfShdr32)
import           Data.Elf.Types

------------------------------------------------------------------------
-- Utilities

-- | Returns null-terminated string at given index in bytestring.
lookupString :: Word32 -> B.ByteString -> B.ByteString
lookupString o b = B.takeWhile (/= 0) $ B.drop (fromIntegral o) b

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


-- | @tryParse msg f v@ returns @fromJust (f v)@ is @f v@ returns a value,
-- and calls @fail@ otherwise.
tryParse :: Monad m => String -> (a -> Maybe b) -> a -> m b
tryParse desc toFn = maybe (fail ("Invalid " ++ desc)) return . toFn

isRelroPhdr :: Phdr w -> Bool
isRelroPhdr (s,_) = elfSegmentType s == PT_GNU_RELRO

-- | Extract relro information.
asRelroInfo :: [Phdr w] -> Maybe (Range w)
asRelroInfo l =
  case filter isRelroPhdr l of
    [] -> Nothing
    [(_,r)] -> Just r
    _ -> error "Multiple relro segments."

------------------------------------------------------------------------
-- TableLayout

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

-- | Returns size of table.
tableSize :: Integral w => TableLayout w -> w
tableSize l = fromIntegral (entryNum l) * fromIntegral (entrySize l)

-- | Returns range in memory of table.
tableRange :: Integral w => TableLayout w -> Range w
tableRange l = (tableOffset l, tableSize l)

-- | Returns offset of entry in table.
tableEntry :: Integral w => TableLayout w -> Word16 -> B.ByteString -> L.ByteString
tableEntry l i b = L.fromChunks [B.drop (fromIntegral o) b]
  where sz = fromIntegral (entrySize l)
        o = tableOffset l + fromIntegral i * sz

------------------------------------------------------------------------
-- Section

sectionData :: Integral w => ElfSectionType -> w -> w -> B.ByteString -> B.ByteString
sectionData SHT_NOBITS _ _ _ = B.empty
sectionData _ o s b = slice (o,s) b

-- | Returns length of section in file.
sectionFileLen :: Num w => ElfSectionType -> w -> w
sectionFileLen SHT_NOBITS _ = 0
sectionFileLen _ s = s

------------------------------------------------------------------------
-- GetPhdr

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

------------------------------------------------------------------------
-- GetShdr

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

------------------------------------------------------------------------
-- ElfParseInfo

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

-- | Return list of segments with contents.
rawSegments :: Integral w => ElfParseInfo w -> [Phdr w]
rawSegments epi = segmentByIndex epi <$> enumCnt 0 (entryNum (phdrTable epi))

-- | Returns size of region.
type RegionSizeFn w = ElfDataRegion w -> w

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

------------------------------------------------------------------------
-- Region name

elfDataRegionName :: ElfDataRegion w -> String
elfDataRegionName ElfDataElfHeader = "elf header"
elfDataRegionName ElfDataSegmentHeaders = "phdr table"
elfDataRegionName (ElfDataSegment s) = show (elfSegmentType s) ++ " segment"
elfDataRegionName ElfDataSectionHeaders = "shdr table"
elfDataRegionName ElfDataSectionNameTable = "section name table"
elfDataRegionName (ElfDataGOT g) = elfGotName g
elfDataRegionName (ElfDataSection s) = elfSectionName s
elfDataRegionName (ElfDataRaw _) = "elf raw"

------------------------------------------------------------------------
-- Region parsing

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

-- | Either a 32-bit or 64-bit elf file.
data SomeElf
   = Elf32 (Elf Word32)
   | Elf64 (Elf Word64)

parseElfResult :: Either (L.ByteString, ByteOffset, String) (L.ByteString, ByteOffset, a)
               -> Either (ByteOffset,String) a
parseElfResult (Left (_,o,e)) = Left (o,e)
parseElfResult (Right (_,_,v)) = Right v

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
