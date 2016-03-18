{-# LANGUAGE GADTs #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Data.Elf.Get
  ( -- * parseElf
    parseElf
  , SomeElf(..)
    -- * elfHeaderInfo low-level interface
  , ElfHeaderInfo
  , header
  , parseElfHeaderInfo
  , getElf
  , getSectionTable
    -- * Utilities
  , getWord16
  , getWord32
  , getWord64
  , lookupString
  ) where

import           Control.Exception ( assert )
import           Control.Lens
import           Control.Monad
import           Data.Binary.Get
  ( getWord8
  , ByteOffset
  , skip
  , Get
  )
import qualified Data.Binary.Get as Get
import           Data.Bits
import qualified Data.ByteString.UTF8 as B (toString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import           Data.Foldable (foldl')
import qualified Data.Sequence as Seq
import qualified Data.Vector as V
import           Data.Word
import           Text.PrettyPrint.ANSI.Leijen hiding ((<>), (<$>))

import           Data.Elf.Layout
  ( FileOffset(..)
  , Phdr(..)
  , phdrFileRange
  , elfMagic
  , phdrEntrySize
  , shdrEntrySize
  )
import           Data.Elf.Types

------------------------------------------------------------------------
-- Utilities

-- | Returns null-terminated string at given index in bytestring.
lookupString :: Word32 -> B.ByteString -> B.ByteString
lookupString o b = B.takeWhile (/= 0) $ B.drop (fromIntegral o) b

------------------------------------------------------------------------
-- Low level getters

getWord16 :: ElfData -> Get Word16
getWord16 ELFDATA2LSB = Get.getWord16le
getWord16 ELFDATA2MSB = Get.getWord16be

getWord32 :: ElfData -> Get Word32
getWord32 ELFDATA2LSB = Get.getWord32le
getWord32 ELFDATA2MSB = Get.getWord32be

getWord64 :: ElfData -> Get Word64
getWord64 ELFDATA2LSB = Get.getWord64le
getWord64 ELFDATA2MSB = Get.getWord64be

-- | @tryParse msg f v@ returns @fromJust (f v)@ is @f v@ returns a value,
-- and calls @fail@ otherwise.
tryParse :: Monad m => String -> (a -> Maybe b) -> a -> m b
tryParse desc toFn = maybe (fail ("Invalid " ++ desc)) return . toFn

isRelroPhdr :: Phdr w -> Bool
isRelroPhdr p = elfSegmentType (phdrSegment p) == PT_GNU_RELRO

-- | Extract relro information.
asRelroInfo :: [Phdr w] -> Maybe (Range w)
asRelroInfo l =
  case filter isRelroPhdr l of
    [] -> Nothing
    [p] -> Just (fromFileOffset (phdrFileStart p), phdrFileSize p)
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
-- GetPhdr

-- | Given a
getPhdr32 :: ElfData -> Word16 -> Get (Phdr Word32)
getPhdr32 d idx = do
  p_type   <- ElfSegmentType  <$> getWord32 d
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
          , elfSegmentIndex     = idx
          , elfSegmentVirtAddr  = p_vaddr
          , elfSegmentPhysAddr  = p_paddr
          , elfSegmentAlign     = p_align
          , elfSegmentMemSize   = ElfAbsoluteSize p_memsz
          , elfSegmentData      = Seq.empty
          }
  return $! Phdr { phdrSegment   = s
                 , phdrFileStart = FileOffset p_offset
                 , phdrFileSize  = p_filesz
                 , phdrMemSize   = p_memsz
                 }

getPhdr64 :: ElfData -> Word16 -> Get (Phdr Word64)
getPhdr64 d idx = do
  p_type   <- ElfSegmentType  <$> getWord32 d
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
         , elfSegmentIndex    = idx
         , elfSegmentVirtAddr = p_vaddr
         , elfSegmentPhysAddr = p_paddr
         , elfSegmentAlign    = p_align
         , elfSegmentMemSize  = ElfAbsoluteSize p_memsz
         , elfSegmentData     = Seq.empty
         }
  return $! Phdr { phdrSegment   = s
                 , phdrFileStart = FileOffset p_offset
                 , phdrFileSize  = p_filesz
                 , phdrMemSize   = p_memsz
                 }

------------------------------------------------------------------------
-- GetShdr

type GetShdrFn w = (Word32 -> String) -- ^ String lookup function
                 -> Get (Range w, ElfSection w)

-- | Returns length of section in file.
sectionFileLen :: Num w => ElfSectionType -> w -> w
sectionFileLen SHT_NOBITS _ = 0
sectionFileLen _ s = s

getShdr32 :: ElfData -> B.ByteString -> GetShdrFn Word32
getShdr32 d file name_fn = do
  sh_name      <- getWord32 d
  sh_type      <- ElfSectionType  <$> getWord32 d
  sh_flags     <- ElfSectionFlags <$> getWord32 d
  sh_addr      <- getWord32 d
  sh_offset    <- getWord32 d
  sh_size      <- getWord32 d
  sh_link      <- getWord32 d
  sh_info      <- getWord32 d
  sh_addralign <- getWord32 d
  sh_entsize   <- getWord32 d
  let file_sz = sectionFileLen sh_type sh_size
  let s = ElfSection
           { elfSectionName      = name_fn sh_name
           , elfSectionType      = sh_type
           , elfSectionFlags     = sh_flags
           , elfSectionAddr      = sh_addr
           , elfSectionSize      = sh_size
           , elfSectionLink      = sh_link
           , elfSectionInfo      = sh_info
           , elfSectionAddrAlign = sh_addralign
           , elfSectionEntSize   = sh_entsize
           , elfSectionData      = slice (sh_offset, file_sz) file
           }
  return ((sh_offset, file_sz), s)

getShdr64 :: ElfData -> B.ByteString -> GetShdrFn Word64
getShdr64 er file name_fn = do
  sh_name      <- getWord32 er
  sh_type      <- ElfSectionType  <$> getWord32 er
  sh_flags     <- ElfSectionFlags <$> getWord64 er
  sh_addr      <- getWord64 er
  sh_offset    <- getWord64 er
  sh_size      <- getWord64 er
  sh_link      <- getWord32 er
  sh_info      <- getWord32 er
  sh_addralign <- getWord64 er
  sh_entsize   <- getWord64 er
  let file_sz = sectionFileLen sh_type sh_size
  let s = ElfSection
           { elfSectionName      = name_fn sh_name
           , elfSectionType      = sh_type
           , elfSectionFlags     = sh_flags
           , elfSectionAddr      = sh_addr
           , elfSectionSize      = sh_size
           , elfSectionLink      = sh_link
           , elfSectionInfo      = sh_info
           , elfSectionAddrAlign = sh_addralign
           , elfSectionEntSize   = sh_entsize
           , elfSectionData      = slice (sh_offset, file_sz) file
           }
  return ((sh_offset, file_sz), s)

------------------------------------------------------------------------
-- ElfHeaderInfo

-- | Contains information needed to parse elf files.
data ElfHeaderInfo w = ElfHeaderInfo {
       header :: !(ElfHeader w)
       -- ^ Elf header information
     , ehdrSize :: !Word16
       -- ^ Size of ehdr table
     , phdrTable :: !(TableLayout w)
       -- ^ Layout of segment header table.
     , getPhdr :: !(Word16 -> Get (Phdr w))
       -- ^ Function for reading elf segments.
     , shdrNameIdx :: !Word16
       -- ^ Index of section for storing section names.
     , shdrTable :: !(TableLayout w)
       -- ^ Layout of section header table.
     , getShdr   :: !(GetShdrFn w)
       -- ^ Function for reading elf sections.
     , fileContents :: !B.ByteString
       -- ^ Contents of file as a bytestring.
     }

-- | Return list of segments with contents.
rawSegments :: Integral w => ElfHeaderInfo w -> [Phdr w]
rawSegments epi = segmentByIndex epi <$> enumCnt 0 (entryNum (phdrTable epi))

-- | Returns size of region.
type RegionSizeFn w = ElfDataRegion w -> w

-- | Return size of region given parse information.
regionSize :: Integral w
           => ElfHeaderInfo w
           -> w -- ^ Contains size of name table
           -> RegionSizeFn w
regionSize epi nameSize = sizeOf
  where sizeOf ElfDataElfHeader        = fromIntegral $ ehdrSize epi
        sizeOf ElfDataSegmentHeaders   = tableSize $ phdrTable epi
        sizeOf (ElfDataSegment s)      = sum $ sizeOf <$> elfSegmentData s
        sizeOf ElfDataSectionHeaders   = tableSize $ shdrTable epi
        sizeOf ElfDataSectionNameTable = nameSize
        sizeOf (ElfDataGOT g)          = elfGotSize g
        sizeOf (ElfDataSection s)      = fromIntegral $ B.length (elfSectionData s)
        sizeOf (ElfDataRaw b)          = fromIntegral $ B.length b

-- | Parse segment at given index.
segmentByIndex :: Integral w
               => ElfHeaderInfo w -- ^ Information for parsing
               -> Word16 -- ^ Index
               -> Phdr w
segmentByIndex epi i =
  Get.runGet (getPhdr epi i) (tableEntry (phdrTable epi) i (fileContents epi))

-- Return section
getSection' :: ElfHeaderInfo w
            -> (Word32 -> String) -- ^ Maps section index to name to use for section.
            -> Word16 -- ^ Index of section.
            -> (Range w, ElfSection w)
getSection' epi name_fn i =
    elfClassInstances (headerClass (header epi)) $
      Get.runGet (getShdr epi name_fn)
                 (tableEntry (shdrTable epi) i file)
  where file = fileContents epi

nameSectionInfo :: ElfHeaderInfo w
                -> (Range w, B.ByteString)
nameSectionInfo epi =
  over _2 elfSectionData $ getSection' epi (\_ -> "") (shdrNameIdx epi)

------------------------------------------------------------------------
-- Region name

elfDataRegionName :: ElfDataRegion w -> String
elfDataRegionName reg =
  case reg of
    ElfDataElfHeader        -> "elf header"
    ElfDataSegmentHeaders   -> "phdr table"
    ElfDataSegment s        -> show (elfSegmentType s) ++ " segment"
    ElfDataSectionHeaders   -> "shdr table"
    ElfDataSectionNameTable -> "section name table"
    ElfDataGOT g            -> elfGotName g
    ElfDataSection s        -> elfSectionName s
    ElfDataRaw _            -> "elf raw"

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
        seg_data' <- insertAtOffset sizeOf (o,c) fn (elfSegmentData s)
        let s' = s { elfSegmentData = seg_data' }
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

-- | Insert a segment/phdr into a sequence of elf regions, returning the new sequence.
insertSegment :: forall w
               . (Bits w, Integral w, Show w)
              => RegionSizeFn w
              -> Seq.Seq (ElfDataRegion w)
              -> Phdr w
              -> Seq.Seq (ElfDataRegion w)
insertSegment sizeOf segs phdr =
    case insertAtOffset sizeOf rng (gather szd Seq.empty) segs of
      Left (OverlapSegment _) -> error "Attempt to insert overlapping segments."
      Left OutOfRange -> error "Invalid segment region"
      Right result -> result
  where d = phdrSegment phdr
        rng = phdrFileRange phdr
        szd = phdrFileSize  phdr
        -- | @gather@ inserts new segment into head of list after collecting existings
        -- data it contains.
        gather :: w -- ^ Number of bytes to insert.
               -> Seq.Seq (ElfDataRegion w)
                  -- ^ Subsegments that occur before this segment.
               -> Seq.Seq (ElfDataRegion w)
                  -- ^ Segments after insertion point.
               -> Seq.Seq (ElfDataRegion w)
        -- Insert segment if there are 0 bytes left to process.
        gather 0 l r =
          ElfDataSegment (d { elfSegmentData = l}) Seq.<| r
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
                      d' = d { elfSegmentData = newData }
                   in ElfDataSegment d' Seq.<| insertRawRegion post r
              | otherwise ->
                error $ "insertSegment: Inserted segments overlaps a previous segment.\n"
                     ++ "  Previous segment: " ++ show p ++ "\n"
                     ++ "  Previous segment size: " ++ show (sizeOf p) ++ "\n"
                     ++ "  New segment:\n" ++ show (indent 2 (ppSegment d)) ++ "\n"
                     ++ "  Remaining bytes: " ++ show cnt
            Seq.EmptyL -> error "insertSegment: Data ended before completion"

getSectionName :: B.ByteString -> Word32 -> String
getSectionName names idx = B.toString $ lookupString idx names

-- | Get list of sections from Elf parse info.
-- This includes the initial section
getSectionTable :: forall w . ElfHeaderInfo w -> V.Vector (ElfSection w)
getSectionTable epi = V.generate cnt $ getSection
  where cnt = fromIntegral (entryNum (shdrTable epi)) :: Int

        c = headerClass (header epi)

        -- Return range used to store name index.
        names :: B.ByteString
        names = snd $ nameSectionInfo epi

        getSection :: Int -> ElfSection w
        getSection i = elfClassInstances c $
          snd $ getSection' epi (getSectionName names) (fromIntegral i)

-- | Parse elf region.
parseElfRegions :: forall w
                .  (Bits w, Integral w, Show w)
                => ElfHeaderInfo w -- ^ Information for parsing.
                -> [Phdr w] -- ^ List of segments
                -> Seq.Seq (ElfDataRegion w)
parseElfRegions epi segments = final
  where -- Return range used to store name index.
        nameRange :: Range w
        nameRange = fst $ nameSectionInfo epi

        -- Get list of all sections other than the first section (which is skipped)
        sections :: [(Range w, ElfSection w)]
        sections = fmap (getSection' epi (getSectionName names))
                 $ filter (\i -> i /= shdrNameIdx epi && i /= 0)
                 $ enumCnt 0 (entryNum (shdrTable epi))
          where names = slice nameRange (fileContents epi)

        -- Define table with special data regions.
        headers :: [(Range w, ElfDataRegion w)]
        headers = [ ((0, fromIntegral (ehdrSize epi)), ElfDataElfHeader)
                  , (tableRange (phdrTable epi), ElfDataSegmentHeaders)
                  , (tableRange (shdrTable epi), ElfDataSectionHeaders)
                  , (nameRange,                  ElfDataSectionNameTable)
                  ]

        -- | Returns size of a given data region.
        sizeOf :: ElfDataRegion w -> w
        sizeOf = regionSize epi (snd nameRange)

        -- Define table with regions for sections.
        -- TODO: Modify this so that it correctly recognizes the GOT section
        -- and generate the appropriate type.
        dataSection = over _2 ElfDataSection

        -- Define initial region list without segments.
        initial  = foldr (uncurry (insertSpecialRegion sizeOf))
                         (insertRawRegion (fileContents epi) Seq.empty)
                         (headers ++ fmap dataSection sections)

        -- Add in segments
        final = foldl' (insertSegment sizeOf) initial
                -- Strip out relro segment (stored in `elfRelroRange')
              $ filter (not . isRelroPhdr) segments

getElf :: (Bits w, Integral w, Show w)
       => ElfHeaderInfo w
       -> Elf w
getElf epi =
    Elf { elfData       = headerData       (header epi)
        , elfClass      = headerClass      (header epi)
        , elfOSABI      = headerOSABI      (header epi)
        , elfABIVersion = headerABIVersion (header epi)
        , elfType       = headerType       (header epi)
        , elfMachine    = headerMachine    (header epi)
        , elfEntry      = headerEntry      (header epi)
        , elfFlags      = headerFlags      (header epi)
        , _elfFileData  = parseElfRegions epi segments
        , elfRelroRange = asRelroInfo segments
        }
  where segments = rawSegments epi

-- | Parse a 32-bit elf.
parseElf32ParseInfo :: ElfData
                    -> ElfOSABI
                    -> Word8 -- ^ ABI Version
                    -> B.ByteString
                    -> Get (ElfHeaderInfo Word32)
parseElf32ParseInfo d ei_osabi ei_abiver b = do
  e_type      <- ElfType      <$> getWord16 d
  e_machine   <- ElfMachine   <$> getWord16 d
  e_version   <- getWord32 d
  when (fromIntegral expectedElfVersion /= e_version) $
    fail "ELF Version mismatch"
  e_entry     <- getWord32 d
  e_phoff     <- getWord32 d
  e_shoff     <- getWord32 d
  e_flags     <- getWord32 d
  e_ehsize    <- getWord16 d
  e_phentsize <- getWord16 d
  e_phnum     <- getWord16 d
  e_shentsize <- getWord16 d
  e_shnum     <- getWord16 d
  e_shstrndx  <- getWord16 d
  let expected_phdr_entry_size = phdrEntrySize ELFCLASS64
  let expected_shdr_entry_size = shdrEntrySize ELFCLASS64
  when (e_phnum /= 0 && e_phentsize /= expected_phdr_entry_size) $ do
    fail $ "Invalid segment entry size"
  when (e_shnum /= 0 && e_shentsize /= expected_shdr_entry_size) $ do
    fail $ "Invalid section entry size"
  let hdr = ElfHeader { headerData       = d
                      , headerClass      = ELFCLASS32
                      , headerOSABI      = ei_osabi
                      , headerABIVersion = ei_abiver
                      , headerType       = e_type
                      , headerMachine    = e_machine
                      , headerFlags      = e_flags
                      , headerEntry      = e_entry
                      }
  return $! ElfHeaderInfo
                  { header       = hdr
                  , ehdrSize     = e_ehsize
                  , phdrTable    = TableLayout e_phoff expected_phdr_entry_size e_phnum
                  , getPhdr      = getPhdr32 d
                  , shdrNameIdx  = e_shstrndx
                  , shdrTable    = TableLayout e_shoff expected_shdr_entry_size e_shnum
                  , getShdr      = getShdr32 d b
                  , fileContents = b
                  }


-- | Parse a 32-bit elf.
parseElf64ParseInfo :: ElfData
                    -> ElfOSABI
                    -> Word8 -- ^ ABI Version
                    -> B.ByteString
                    -> Get (ElfHeaderInfo Word64)
parseElf64ParseInfo d ei_osabi ei_abiver b = do
  e_type      <- ElfType    <$> getWord16 d
  e_machine   <- ElfMachine <$> getWord16 d
  e_version   <- getWord32 d
  when (fromIntegral expectedElfVersion /= e_version) $
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
  let expected_phdr_entry_size = phdrEntrySize ELFCLASS64
  let expected_shdr_entry_size = shdrEntrySize ELFCLASS64

  when (e_phnum /= 0 && e_phentsize /= expected_phdr_entry_size) $ do
    fail $ "Invalid segment entry size"
  when (e_shnum /= 0 && e_shentsize /= expected_shdr_entry_size) $ do
    fail $ "Invalid section entry size"
  let hdr = ElfHeader { headerData       = d
                      , headerClass      = ELFCLASS64
                      , headerOSABI      = ei_osabi
                      , headerABIVersion = ei_abiver
                      , headerType       = e_type
                      , headerMachine    = e_machine
                      , headerFlags      = e_flags
                      , headerEntry      = e_entry
                      }
  return $! ElfHeaderInfo
                  { header       = hdr
                  , ehdrSize     = e_ehsize
                  , phdrTable    = TableLayout e_phoff expected_phdr_entry_size e_phnum
                  , getPhdr      = getPhdr64 d
                  , shdrNameIdx  = e_shstrndx
                  , shdrTable    = TableLayout e_shoff expected_shdr_entry_size e_shnum
                  , getShdr      = getShdr64 d b
                  , fileContents = b
                  }

-- | Either a 32-bit or 64-bit tpyed value.
data SomeElf f
   = Elf32 (f Word32)
   | Elf64 (f Word64)

parseElfResult :: Either (L.ByteString, ByteOffset, String) (L.ByteString, ByteOffset, a)
               -> Either (ByteOffset,String) a
parseElfResult (Left (_,o,e)) = Left (o,e)
parseElfResult (Right (_,_,v)) = Right v

-- | Parses a ByteString into an Elf record. Parse failures call error. 32-bit ELF objects hav
-- their fields promoted to 64-bit so that the 32- and 64-bit ELF records can be the same.
parseElfHeaderInfo :: B.ByteString -> Either (ByteOffset,String) (SomeElf ElfHeaderInfo)
parseElfHeaderInfo b = parseElfResult $ flip Get.runGetOrFail (L.fromChunks [b]) $ do
  ei_magic    <- Get.getByteString 4
  unless (ei_magic == elfMagic) $
    fail $ "Invalid magic number for ELF: " ++ show (ei_magic, elfMagic)
  ei_class   <- tryParse "ELF class" toSomeElfClass =<< getWord8
  d          <- tryParse "ELF data"  toElfData =<< getWord8
  ei_version <- getWord8
  unless (ei_version == expectedElfVersion) $
    fail "Invalid version number for ELF"
  ei_osabi    <- ElfOSABI <$> getWord8
  ei_abiver   <- getWord8
  skip 7
  case ei_class of
    SomeElfClass ELFCLASS32 -> do
      Elf32 <$> parseElf32ParseInfo d ei_osabi ei_abiver b
    SomeElfClass ELFCLASS64 -> do
      Elf64 <$> parseElf64ParseInfo d ei_osabi ei_abiver b

-- | Parses a ByteString into an Elf record. Parse failures call error. 32-bit ELF objects hav
-- their fields promoted to 64-bit so that the 32- and 64-bit ELF records can be the same.
parseElf :: B.ByteString -> Either (ByteOffset,String) (SomeElf Elf)
parseElf b = do
  some_header <- parseElfHeaderInfo b
  return $!
    case some_header of
      Elf32 hdr -> Elf32 (getElf hdr)
      Elf64 hdr -> Elf64 (getElf hdr)
