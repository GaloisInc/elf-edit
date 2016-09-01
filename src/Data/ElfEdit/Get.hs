{-# LANGUAGE GADTs #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE Trustworthy #-}
module Data.ElfEdit.Get
  ( -- * parseElf
    parseElf
  , ElfGetResult(..)
    -- * elfHeaderInfo low-level interface
  , ElfHeaderInfo
  , header
  , parseElfHeaderInfo
  , SomeElf(..)
  , getElf
  , ElfParseError(..)
  , ElfInsertError(..)
  , getSectionTable
  , getSymbolTableEntry
    -- * Utilities
  , getWord16
  , getWord32
  , getWord64
  , lookupString
  , runGetMany
  ) where

import           Control.Exception ( assert )
import           Control.Lens
import           Control.Monad
import           Data.Binary
import           Data.Binary.Get
import qualified Data.Binary.Get as Get
import           Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.UTF8 as B (toString)
import           Data.Foldable (foldl', foldlM, foldrM)
import qualified Data.Sequence as Seq
import qualified Data.Vector as V
import           Text.PrettyPrint.ANSI.Leijen hiding ((<>), (<$>))

import           Data.ElfEdit.Enums
import           Data.ElfEdit.Layout
  ( FileOffset(..)
  , Phdr(..)
  , phdrFileRange
  , elfMagic
  , phdrEntrySize
  , shdrEntrySize
  , symbolTableSize
  )
import           Data.ElfEdit.Types

------------------------------------------------------------------------
-- Utilities

-- | Returns null-terminated string at given index in bytestring.
lookupString :: Word32 -> B.ByteString -> B.ByteString
lookupString o b = B.takeWhile (/= 0) $ B.drop (fromIntegral o) b

-- | Apply the get operation repeatedly to bystring until all bits are done.
--
-- This returns a list contain all the values read, and calls 'error' if
-- a failure occurs.
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

type GetShdrFn w = Word16 -- ^ Index of section
                 -> (Word32 -> String) -- ^ String lookup function
                 -> Get (Range w, ElfSection w)

-- | Returns length of section in file.
sectionFileLen :: Num w => ElfSectionType -> w -> w
sectionFileLen SHT_NOBITS _ = 0
sectionFileLen _ s = s

getShdr32 :: ElfData -> B.ByteString -> GetShdrFn Word32
getShdr32 d file idx name_fn = do
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
           { elfSectionIndex     = idx
           , elfSectionName      = name_fn sh_name
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
getShdr64 er file idx name_fn = do
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
           { elfSectionIndex     = idx
           , elfSectionName      = name_fn sh_name
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

-- | Information parsed from the ELF header need to parse the
-- segments and sections.
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
rawSegments ehi = segmentByIndex ehi <$> enumCnt 0 (entryNum (phdrTable ehi))

-- | Returns size of region.
type RegionSizeFn w = ElfDataRegion w -> w

-- | Information needed to compute region sizes.
data ElfSizingInfo w
   = ElfSizingInfo
     { esiHeaderInfo :: !(ElfHeaderInfo w)
       -- ^ Header info
     , esiSectionNameTableSize :: !w
       -- ^ Contains size of name table
     , esiStrtabSize :: !w
       -- ^ Return string table size
     }

-- | Return filesize of region given parse information.
regionSize :: Integral w
           => ElfSizingInfo w
           -> RegionSizeFn w
regionSize esi = sizeOf
  where ehi = esiHeaderInfo esi
        sizeOf ElfDataElfHeader            = fromIntegral $ ehdrSize ehi
        sizeOf ElfDataSegmentHeaders       = tableSize $ phdrTable ehi
        sizeOf (ElfDataSegment s)          = sum $ sizeOf <$> elfSegmentData s
        sizeOf ElfDataSectionHeaders       = tableSize $ shdrTable ehi
        sizeOf (ElfDataSectionNameTable _) = esiSectionNameTableSize esi
        sizeOf (ElfDataGOT g)              = elfGotSize g
        sizeOf (ElfDataStrtab _)           = esiStrtabSize esi
        sizeOf (ElfDataSymtab s)           = symbolTableSize c s
          where c = headerClass (header ehi)
        sizeOf (ElfDataSection s)          = fromIntegral $ B.length (elfSectionData s)
        sizeOf (ElfDataRaw b)              = fromIntegral $ B.length b

-- | Parse segment at given index.
segmentByIndex :: Integral w
               => ElfHeaderInfo w -- ^ Information for parsing
               -> Word16 -- ^ Index
               -> Phdr w
segmentByIndex ehi i =
  Get.runGet (getPhdr ehi i) (tableEntry (phdrTable ehi) i (fileContents ehi))

-- Return section
getSection' :: ElfHeaderInfo w
            -> (Word32 -> String) -- ^ Maps section index to name to use for section.
            -> Word16 -- ^ Index of section.
            -> (Range w, ElfSection w)
getSection' ehi name_fn i =
    elfClassInstances (headerClass (header ehi)) $
      Get.runGet (getShdr ehi i name_fn)
                 (tableEntry (shdrTable ehi) i file)
  where file = fileContents ehi

nameSectionInfo :: ElfHeaderInfo w
                -> (Range w, B.ByteString)
nameSectionInfo ehi =
  over _2 elfSectionData $ getSection' ehi (\_ -> "") (shdrNameIdx ehi)

------------------------------------------------------------------------
-- Symbol table entries

-- | Create a symbol table entry from a Get monad
getSymbolTableEntry :: ElfClass w
                    -> ElfData
                    -> (Word32 -> B.ByteString)
                         -- ^ Function for mapping offset in string table
                         -- to bytestring.
                      -> Get (ElfSymbolTableEntry w)
getSymbolTableEntry ELFCLASS32 d nameFn = do
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
getSymbolTableEntry ELFCLASS64 d nameFn = do
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

------------------------------------------------------------------------
-- Region name

elfDataRegionName :: ElfDataRegion w -> String
elfDataRegionName reg =
  case reg of
    ElfDataElfHeader          -> "elf header"
    ElfDataSegmentHeaders     -> "phdr table"
    ElfDataSegment s          -> show (elfSegmentType s) ++ " segment"
    ElfDataSectionHeaders     -> "shdr table"
    ElfDataSectionNameTable _ -> "section name table"
    ElfDataGOT g              -> elfGotName g
    ElfDataStrtab _           -> ".strtab"
    ElfDataSymtab _           -> ".symtab"
    ElfDataSection s          -> elfSectionName s
    ElfDataRaw _              -> "elf raw"

------------------------------------------------------------------------
-- Region parsing

-- | Function that transforms the sequence regions into new list.
--
--
type RegionPrefixFn w = Seq.Seq (ElfDataRegion w) -> Seq.Seq (ElfDataRegion w)

-- | Create a singleton list with a raw data region if one exists
insertRawRegion :: B.ByteString -> RegionPrefixFn w
insertRawRegion b r | B.length b == 0 = r
                    | otherwise = ElfDataRaw b Seq.<| r

-- | Describes reason an insertion failed.
data ElfInsertError w
   = OverlapSegment (ElfDataRegion w) (Range w)
     -- ^ The inserted segment overlaps with another, and we needed to insert
     -- it in the given range.
     -- the end.
   | OutOfRange
     -- ^ This segment is out of range.

-- | This is a type that captures an insertion error, but returns a result
-- anyways.
data GetResult e a
   = GetResult { _getErrors :: ![e]
               , _getValue :: !a
               }

errorPair :: GetResult e a -> ([e], a)
errorPair (GetResult e a) = (e, a)

mapError :: (e -> f) -> GetResult e a -> GetResult f a
mapError f (GetResult l x) = GetResult (f <$> l) x

insError :: e -> a -> GetResult e a
insError e a = seq e $ GetResult [e] a

noInsError :: a -> GetResult e a
noInsError = GetResult []

instance Functor (GetResult e) where
  fmap f (GetResult e a) = GetResult e (f a)

instance Applicative (GetResult e) where
  pure = return
  GetResult j f <*> GetResult k x = GetResult (j ++ k) (f x)

instance Monad (GetResult e) where
  return = GetResult []
  GetResult l x >>= f =
    case f x of
      GetResult l' y -> GetResult (l ++ l') y

-- | Insert an elf data region at a given offset.
insertAtOffset :: Integral w
               => RegionSizeFn w
                  -- ^ Function for getting size of a region.
               -> (Range w -> RegionPrefixFn w)
                  -- ^ Insert function
               -> Range w
                  -- ^ Range to insert in.
               -> Seq.Seq (ElfDataRegion w)
               -> GetResult (ElfInsertError w) (Seq.Seq (ElfDataRegion w))
insertAtOffset sizeOf fn rng@(o,c) r0 =
  case Seq.viewl r0 of
    Seq.EmptyL
      | rng == (0,0) ->
        noInsError $ fn rng Seq.empty
      | otherwise ->
        insError OutOfRange $ fn rng Seq.empty
    p Seq.:< r
      -- Go to next segment if offset to insert is after p.
      | o >= sz ->
        (p Seq.<|) <$> insertAtOffset sizeOf fn (o-sz,c) r
        -- Recurse inside segment if p is a segment that contains region to insert.
        -- New region ends before p ends and p is a segment.
      | o + c <= sz, ElfDataSegment s <- p ->
        let combine seg_data' = ElfDataSegment s' Seq.<| r
                where s' = s { elfSegmentData = seg_data' }
         in combine <$> insertAtOffset sizeOf fn rng (elfSegmentData s)
        -- Insert into current region is offset is 0.
      | o == 0 -> noInsError $! fn rng (p Seq.<| r)
        -- Split a raw segment into prefix and post.
      | ElfDataRaw b <- p ->
          -- We know offset is less than length of bytestring as otherwise we would
          -- have gone to next segment
          assert (fromIntegral o < B.length b) $ do
            let (pref,post) = B.splitAt (fromIntegral o) b
            noInsError $! insertRawRegion pref $ fn rng $ insertRawRegion post r
        --
      | otherwise ->
        insError (OverlapSegment p rng) $! ((p Seq.<|) $! fn (o,c) r)
     where sz = sizeOf p

-- | A parse error
data ElfParseError w
  = ElfInsertError !(ElfDataRegion w) !(ElfInsertError w)
    -- ^ Attempt to insert region failed.

instance Show (ElfParseError w) where
  show (ElfInsertError n (OverlapSegment prev _)) =
    "Attempt to insert "
    ++ elfDataRegionName n
    ++ " overlapping Elf region into "
    ++ elfDataRegionName prev
    ++ "."
  show (ElfInsertError n OutOfRange) =
    "Invalid region " ++ elfDataRegionName n ++ "."

-- | Insert a leaf region into the region.
insertSpecialRegion :: Integral w
                    => ElfSizingInfo w -- ^ Returns size of region.
                    -> Range w
                    -> ElfDataRegion w -- ^ New region
                    -> Seq.Seq (ElfDataRegion w)
                    -> GetResult (ElfInsertError w) (Seq.Seq (ElfDataRegion w))
insertSpecialRegion esi r n segs =
    insertAtOffset (regionSize esi) fn r segs
  where c = snd r
        -- Insert function
        fn _ l | c == 0 = n Seq.<| l
        fn _ l0
          | ElfDataRaw b Seq.:< l <- Seq.viewl l0
          , fromIntegral c <= B.length b =
            n Seq.<| insertRawRegion (B.drop (fromIntegral c) b) l
        fn _ _ = error $ "Elf file contained a non-empty header that overlapped with another.\n"
                       ++ "  This is not supported by the Elf parser."

regionName :: ElfDataRegion w -> String
regionName reg =
  case reg of
    ElfDataSegment s -> "segment " ++ show (elfSegmentIndex s)
    ElfDataSectionHeaders -> "section header table"
    ElfDataSectionNameTable _ -> "section header name table"
    ElfDataGOT g -> elfGotName g
    ElfDataStrtab _ -> ".strtab"
    ElfDataSymtab _ -> ".symtab"
    ElfDataSection s -> elfSectionName s
    ElfDataRaw{} -> "unassigned bits"

-- | Insert a segment/phdr into a sequence of elf regions, returning the new sequence.
insertSegment :: forall w
               . (Bits w, Integral w, Show w)
              => ElfSizingInfo w
              -> Seq.Seq (ElfDataRegion w)
              -> Phdr w
              -> GetResult (ElfParseError w) (Seq.Seq (ElfDataRegion w))
insertSegment esi segs phdr = do
    -- TODO: See if we can do better than dropping the segment.
    mapError (ElfInsertError (ElfDataSegment (phdrSegment phdr))) $
      insertAtOffset (regionSize esi) (\_ -> gather szd Seq.empty) rng segs
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
          ElfDataSegment (d { elfSegmentData = l }) Seq.<| r
        -- Collect p if it is contained within segment we are inserting.
        gather cnt l r0 =
          case Seq.viewl r0 of
            p Seq.:< r
              | regionSize esi p <= cnt ->
                gather (cnt - regionSize esi p) (l Seq.|> p) r
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
                     ++ "  Previous segment size: " ++ show (regionSize esi p) ++ "\n"
                     ++ "  New segment:\n" ++ show (indent 2 (ppSegment d)) ++ "\n"
                     ++ "  Remaining bytes: " ++ show cnt
            Seq.EmptyL -> error "insertSegment: Data ended before completion"

getSectionName :: B.ByteString -> Word32 -> String
getSectionName names idx = B.toString $ lookupString idx names

-- | Get list of sections from Elf parse info.
-- This includes the initial section
getSectionTable :: forall w . ElfHeaderInfo w -> V.Vector (ElfSection w)
getSectionTable ehi = V.generate cnt $ getSection
  where cnt = fromIntegral (entryNum (shdrTable ehi)) :: Int

        c = headerClass (header ehi)

        -- Return range used to store name index.
        names :: B.ByteString
        names = snd $ nameSectionInfo ehi

        getSection :: Int -> ElfSection w
        getSection i = elfClassInstances c $
          snd $ getSection' ehi (getSectionName names) (fromIntegral i)

isSymtabSection :: ElfSection w -> Bool
isSymtabSection s
  =  elfSectionName s == ".symtab"
  && elfSectionType s == SHT_SYMTAB


-- | Parse the section as a list of symbol table entries.
getSymbolTableEntries :: ElfHeader w
                      -> V.Vector (Range w, ElfSection w)
                      -> ElfSection w
                      -> [ElfSymbolTableEntry w]
getSymbolTableEntries hdr sections s =
  let link   = elfSectionLink s
      strs | 0 <= link && link < fromIntegral (V.length sections)  =
             elfSectionData (snd (sections V.! fromIntegral link))
           | otherwise = error "Could not find section string table."
      nameFn = (`lookupString` strs)
   in runGetMany (getSymbolTableEntry (headerClass hdr) (headerData hdr) nameFn)
                 (L.fromChunks [elfSectionData s])

-- | Parse elf region.
parseElfRegions :: forall w
                .  (Bits w, Integral w, Show w)
                => ElfHeaderInfo w -- ^ Information for parsing.
                -> [Phdr w] -- ^ List of segments
                -> GetResult (ElfParseError w) (Seq.Seq (ElfDataRegion w))
parseElfRegions info segments = addSegs =<< minitial
  where addSegs initial =
          -- Add in segments
          foldlM (insertSegment esi) initial $
            -- Strip out relro segment (stored in `elfRelroRange')
            filter (not . isRelroPhdr) segments

        -- Return range used to store name index.
        nameRange :: Range w
        nameRange = fst $ nameSectionInfo info

        section_cnt :: Word16
        section_cnt = entryNum $ shdrTable info

        section_names = slice nameRange $ fileContents info

        -- Get vector with section information
        section_vec :: V.Vector (Range w, ElfSection w)
        section_vec = V.generate (fromIntegral section_cnt) $
          getSection' info (getSectionName section_names) . fromIntegral

        msymtab :: Maybe (Range w, ElfSection w)
        msymtab = V.find (\(_,s) -> isSymtabSection s) section_vec

        mstrtab_index  = elfSectionLink . snd <$> msymtab

        -- Return size of section at given index.
        section_size :: Word32 -> w
        section_size i =
          case section_vec V.!? fromIntegral i of
            Just ((_,n),_) -> n
            Nothing -> 0

        -- Get information needed to compute region sizes.
        esi_size = maybe 0 section_size mstrtab_index
        esi = ElfSizingInfo { esiHeaderInfo = info
                            , esiSectionNameTableSize = snd nameRange
                            , esiStrtabSize = esi_size
                            }

        -- Define table with special data regions.
        headers :: [(Range w, ElfDataRegion w)]
        headers = [ ((0, fromIntegral (ehdrSize info)), ElfDataElfHeader)
                  , (tableRange (phdrTable info), ElfDataSegmentHeaders)
                  , (tableRange (shdrTable info), ElfDataSectionHeaders)
                  , (nameRange,                  ElfDataSectionNameTable (shdrNameIdx info))
                  ]

        -- Get list of all sections other than the first section (which is skipped)
        sections :: [(Range w, ElfSection w)]
        sections = fmap (\i -> section_vec V.! fromIntegral i)
                 $ filter (\i -> i /= shdrNameIdx info && i /= 0)
                 $ enumCnt 0 section_cnt

        -- Define table with regions for sections.
        -- TODO: Modify this so that it correctly recognizes the GOT section
        -- and generate the appropriate type.
        dataSection :: ElfSection w -> ElfDataRegion w
        dataSection s
          | Just (fromIntegral (elfSectionIndex s)) == mstrtab_index
          , elfSectionName s == ".strtab"
          , elfSectionType s == SHT_STRTAB =
            ElfDataStrtab (elfSectionIndex s)
          | isSymtabSection s =
              let idx = elfSectionIndex s
                  entries = getSymbolTableEntries (header info) section_vec s
                  symtab = ElfSymbolTable { elfSymbolTableIndex = idx
                                          , elfSymbolTableEntries = V.fromList entries
                                          , elfSymbolTableLocalEntries = elfSectionInfo s
                                          }
               in ElfDataSymtab symtab
          | otherwise = ElfDataSection s

        insertRegion :: (Range w, ElfDataRegion w)
                      -> Seq.Seq (ElfDataRegion w)
                      -> GetResult (ElfParseError w) (Seq.Seq (ElfDataRegion w))
        insertRegion (r, n) segs =
          mapError (ElfInsertError n) $ insertSpecialRegion esi r n segs

        -- Define initial region list without segments.
        minitial  = foldrM insertRegion
                           (insertRawRegion (fileContents info) Seq.empty)
                           (headers ++ fmap (over _2 dataSection) sections)

-- | This returns an elf from the header information along with
-- and errors that occured when generating it.
--
-- Note that this may call 'error' in some cases,
getElf :: (Bits w, Integral w, Show w)
       => ElfHeaderInfo w
       -> ([ElfParseError w], Elf w)
getElf ehi = errorPair $ f <$> parseElfRegions ehi segments
  where segments = rawSegments ehi
        f dta = Elf { elfData       = headerData       (header ehi)
                    , elfClass      = headerClass      (header ehi)
                    , elfOSABI      = headerOSABI      (header ehi)
                    , elfABIVersion = headerABIVersion (header ehi)
                    , elfType       = headerType       (header ehi)
                    , elfMachine    = headerMachine    (header ehi)
                    , elfEntry      = headerEntry      (header ehi)
                    , elfFlags      = headerFlags      (header ehi)
                    , _elfFileData  = dta
                    , elfRelroRange = asRelroInfo segments
                    }

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
  let expected_phdr_entry_size = phdrEntrySize ELFCLASS32
  let expected_shdr_entry_size = shdrEntrySize ELFCLASS32
  when (e_phnum /= 0 && e_phentsize /= expected_phdr_entry_size) $ do
    fail $ "Expected segment entry size of " ++ show expected_phdr_entry_size
      ++ " and found size of " ++ show e_phentsize ++ " instead."
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

-- | Wraps a either a 32-bit or 64-bit typed value.
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

data ElfGetResult
   = Elf32Res !([ElfParseError Word32]) (Elf Word32)
   | Elf64Res !([ElfParseError Word64]) (Elf Word64)
   | ElfHeaderError !ByteOffset !String
     -- ^ Attempt to parse header failed.
     --
     -- First argument is byte offset, second is string.

-- | Parses a ByteString into an Elf record. Parse failures call error. 32-bit ELF objects hav
-- their fields promoted to 64-bit so that the 32- and 64-bit ELF records can be the same.
parseElf :: B.ByteString -> ElfGetResult
parseElf b = do
  case parseElfHeaderInfo b of
    Left (o, m) -> ElfHeaderError o m
    Right (Elf32 hdr) -> Elf32Res l e
      where (l, e) = getElf hdr
    Right (Elf64 hdr) -> Elf64Res l e
      where (l, e) = getElf hdr
