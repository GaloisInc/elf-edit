{-# LANGUAGE CPP #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}
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
                , ElfWidth
                  -- ** Reading Elf files
                , hasElfMagic
                , parseElf
                , SomeElf(..)
                , ElfHeaderInfo
                , parseElfHeaderInfo
                , getElf
                , getSectionTable
                , G.ByteOffset
                  -- ** Writing Elf files
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
                , getSymbolTableEntries
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
                , pattern STT_NOTYPE
                , pattern STT_OBJECT
                , pattern STT_FUNC
                , pattern STT_SECTION
                , pattern STT_FILE
                , pattern STT_COMMON
                , pattern STT_TLS
                , pattern STT_RELC
                , pattern STT_SRELC
                , pattern STT_GNU_IFUNC
                  -- ** Elf symbol binding
                , ElfSymbolBinding(..)
                , ElfSectionIndex(..)
                  -- * Relocations
                , IsRelocationType(..)
                , RelaWidth(..)
                , RelaEntry(..)
                , ppRelaEntries
                  -- ** 32-bit x86 relocations
                , I386_RelocationType(..)
                , elfRelaEntries
                  -- ** 64-bit 386 relocations
                , X86_64_RelocationType(..)
                , pattern R_X86_64_NONE
                , pattern R_X86_64_64
                , pattern R_X86_64_PC32
                , pattern R_X86_64_GOT32
                , pattern R_X86_64_PLT32
                , pattern R_X86_64_COPY
                , pattern R_X86_64_GLOB_DAT
                , pattern R_X86_64_JUMP_SLOT
                , pattern R_X86_64_RELATIVE
                , pattern R_X86_64_GOTPCREL
                , pattern R_X86_64_32
                , pattern R_X86_64_32S
                , pattern R_X86_64_16
                , pattern R_X86_64_PC16
                , pattern R_X86_64_8
                , pattern R_X86_64_PC8
                , pattern R_X86_64_DTPMOD64
                , pattern R_X86_64_DTPOFF64
                , pattern R_X86_64_TPOFF64
                , pattern R_X86_64_TLSGD
                , pattern R_X86_64_TLSLD
                , pattern R_X86_64_DTPOFF32
                , pattern R_X86_64_GOTTPOFF
                , pattern R_X86_64_TPOFF32
                , pattern R_X86_64_PC64
                , pattern R_X86_64_GOTOFF64
                , pattern R_X86_64_GOTPC32
                , pattern R_X86_64_SIZE32
                , pattern R_X86_64_SIZE64
                , pattern R_X86_64_GOTPC32_TLSDESC
                , pattern R_X86_64_TLSDESC_CALL
                , pattern R_X86_64_TLSDESC
                , pattern R_X86_64_IRELATIVE
                  -- ** Relocation utilitis
                , ElfWordType
                , ElfIntType
                  -- * Dynamic symbol table and relocations
                , DynamicSection(..)
                , VersionDef(..)
                , VersionReq(..)
                , VersionReqAux
                , DynamicMap
                , ElfDynamicArrayTag
                , dynamicEntries
                  -- * Common definitions
                , Range
                , hasPermissions
                ) where

#if !MIN_VERSION_base(4,8,0)
import           Control.Applicative
#endif
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
import           Data.List (genericDrop, foldl')
import qualified Data.Map as Map
import           Data.Maybe
import           Numeric (showHex)
import           Text.PrettyPrint.ANSI.Leijen hiding ((<>), (<$>))

import           Data.Elf.Get
import           Data.Elf.Layout
import           Data.Elf.Relocations
import qualified Data.Elf.SizedBuilder as U
import           Data.Elf.TH
import           Data.Elf.Types

------------------------------------------------------------------------
-- Utilities


-- | @p `hasPermissions` req@ returns true if all bits set in 'req' are set in 'p'.
hasPermissions :: Bits b => b -> b -> Bool
hasPermissions p req = (p .&. req) == req
{-# INLINE hasPermissions #-}

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
  where impl (ElfDataSegment s) = s : concatMap impl (F.toList (s^.elfSegmentData))
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

-- | A pair containing an elf segment and the underlying bytestring content.
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

symbolTableEntrySize :: ElfClass w -> w
symbolTableEntrySize ELFCLASS32 = 16
symbolTableEntrySize ELFCLASS64 = 24

getSymbolTableEntry :: ElfClass w
                    -> ElfData
                    -> (Word32 -> String)
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
    , steValue            :: w -- ^ Value associated with symbol.
    , steSize             :: w
    } deriving (Eq, Show)

steEnclosingSection :: Elf w -> ElfSymbolTableEntry w -> Maybe (ElfSection w)
steEnclosingSection e s = sectionByIndex e (steIndex s)

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
getSymbolTableEntries e s =
  let link   = elfSectionLink s
      strtab = lookup link (zip [0..] (toListOf elfSections e))
      strs = fromMaybe B.empty (elfSectionData <$> strtab)
      nameFn idx = B.toString (lookupString idx strs)
   in runGetMany (getSymbolTableEntry (elfClass e) (elfData e) nameFn)
                 (L.fromChunks [elfSectionData s])

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

sectionByIndex :: Elf w
               -> ElfSectionIndex
               -> Maybe (ElfSection w)
sectionByIndex e si = do
  i <- asSectionIndex si
  listToMaybe $ genericDrop i (e^..elfSections)

------------------------------------------------------------------------
-- I386_RelocationType

-- | Relocation types for 64-bit x86 code.
newtype I386_RelocationType = I386_RelocationType { fromI386_RelocationType :: Word32 }
  deriving (Eq,Ord)

pattern R_386_NONE     = I386_RelocationType  0
pattern R_386_32       = I386_RelocationType  1
pattern R_386_PC32     = I386_RelocationType  2
pattern R_386_GOT32    = I386_RelocationType  3
pattern R_386_PLT32    = I386_RelocationType  4
pattern R_386_COPY     = I386_RelocationType  5
pattern R_386_GLOB_DAT = I386_RelocationType  6
pattern R_386_JMP_SLOT = I386_RelocationType  7
pattern R_386_RELATIVE = I386_RelocationType  8
pattern R_386_GOTOFF   = I386_RelocationType  9
pattern R_386_GOTPC    = I386_RelocationType 10

i386_RelocationTypes :: Map.Map I386_RelocationType String
i386_RelocationTypes = Map.fromList
  [ (,) R_386_NONE     "R_386_NONE"
  , (,) R_386_32       "R_386_32"
  , (,) R_386_PC32     "R_386_PC32"
  , (,) R_386_GOT32    "R_386_GOT32"
  , (,) R_386_PLT32    "R_386_PLT32"
  , (,) R_386_COPY     "R_386_COPY"
  , (,) R_386_GLOB_DAT "R_386_GLOB_DAT"
  , (,) R_386_JMP_SLOT "R_386_JMP_SLOT"
  , (,) R_386_RELATIVE "R_386_RELATIVE"
  , (,) R_386_GOTOFF   "R_386_GOTOFF"
  , (,) R_386_GOTPC    "R_386_GOTPC"
  ]

instance Show I386_RelocationType where
  show i =
    case Map.lookup i i386_RelocationTypes of
      Just s -> s
      Nothing -> "0x" ++ showHex (fromI386_RelocationType i) ""

instance IsRelocationType I386_RelocationType where
  type RelocationWidth I386_RelocationType = 32
  relaWidth _ = Rela32
  relaType = Just . I386_RelocationType
  isRelative R_386_RELATIVE = True
  isRelative _ = False

------------------------------------------------------------------------
-- X86_64_RelocationType

-- | Relocation types for 64-bit x86 code.
newtype X86_64_RelocationType = X86_64_RelocationType { fromX86_64_RelocationType :: Word32 }
  deriving (Eq,Ord)

-- | No relocation
pattern R_X86_64_NONE            = X86_64_RelocationType  0
-- | Direct 64 bit
pattern R_X86_64_64              = X86_64_RelocationType  1
-- | PC relative 32 bit signed
pattern R_X86_64_PC32            = X86_64_RelocationType  2
-- | 32 bit GOT entry
pattern R_X86_64_GOT32           = X86_64_RelocationType  3
-- | 32 bit PLT address
pattern R_X86_64_PLT32           = X86_64_RelocationType  4
-- | Copy symbol at runtime
pattern R_X86_64_COPY            = X86_64_RelocationType  5
-- | Create GOT entry
pattern R_X86_64_GLOB_DAT        = X86_64_RelocationType  6
-- | Create PLT entry
pattern R_X86_64_JUMP_SLOT       = X86_64_RelocationType  7
-- | Adjust by program base
pattern R_X86_64_RELATIVE        = X86_64_RelocationType  8
-- | 32 bit signed pc relative offset to GOT
pattern R_X86_64_GOTPCREL        = X86_64_RelocationType  9
-- | Direct 32 bit zero extended
pattern R_X86_64_32              = X86_64_RelocationType 10

-- | Direct 32 bit sign extended
pattern R_X86_64_32S             = X86_64_RelocationType 11

-- | Direct 16 bit zero extended
pattern R_X86_64_16              = X86_64_RelocationType 12

-- | 16 bit sign extended pc relative
pattern R_X86_64_PC16            = X86_64_RelocationType 13

-- | Direct 8 bit sign extended
pattern R_X86_64_8               = X86_64_RelocationType 14

-- | 8 bit sign extended pc relative
pattern R_X86_64_PC8             = X86_64_RelocationType 15

pattern R_X86_64_DTPMOD64        = X86_64_RelocationType 16
pattern R_X86_64_DTPOFF64        = X86_64_RelocationType 17
pattern R_X86_64_TPOFF64         = X86_64_RelocationType 18
pattern R_X86_64_TLSGD           = X86_64_RelocationType 19
pattern R_X86_64_TLSLD           = X86_64_RelocationType 20
pattern R_X86_64_DTPOFF32        = X86_64_RelocationType 21
pattern R_X86_64_GOTTPOFF        = X86_64_RelocationType 22
pattern R_X86_64_TPOFF32         = X86_64_RelocationType 23

pattern R_X86_64_PC64            = X86_64_RelocationType 24
pattern R_X86_64_GOTOFF64        = X86_64_RelocationType 25
pattern R_X86_64_GOTPC32         = X86_64_RelocationType 26

pattern R_X86_64_SIZE32          = X86_64_RelocationType 32
pattern R_X86_64_SIZE64          = X86_64_RelocationType 33
pattern R_X86_64_GOTPC32_TLSDESC = X86_64_RelocationType 34
pattern R_X86_64_TLSDESC_CALL    = X86_64_RelocationType 35
pattern R_X86_64_TLSDESC         = X86_64_RelocationType 36
pattern R_X86_64_IRELATIVE       = X86_64_RelocationType 37

x86_64_RelocationTypes :: Map.Map X86_64_RelocationType String
x86_64_RelocationTypes = Map.fromList
  [ (,) R_X86_64_NONE            "R_X86_64_NONE"
  , (,) R_X86_64_64              "R_X86_64_64"
  , (,) R_X86_64_PC32            "R_X86_64_PC32"
  , (,) R_X86_64_GOT32           "R_X86_64_GOT32"
  , (,) R_X86_64_PLT32           "R_X86_64_PLT32"
  , (,) R_X86_64_COPY            "R_X86_64_COPY"
  , (,) R_X86_64_GLOB_DAT        "R_X86_64_GLOB_DAT"
  , (,) R_X86_64_JUMP_SLOT       "R_X86_64_JUMP_SLOT"

  , (,) R_X86_64_RELATIVE        "R_X86_64_RELATIVE"
  , (,) R_X86_64_GOTPCREL        "R_X86_64_GOTPCREL"
  , (,) R_X86_64_32              "R_X86_64_32"
  , (,) R_X86_64_32S             "R_X86_64_32S"
  , (,) R_X86_64_16              "R_X86_64_16"
  , (,) R_X86_64_PC16            "R_X86_64_PC16"
  , (,) R_X86_64_8               "R_X86_64_8"
  , (,) R_X86_64_PC8             "R_X86_64_PC8"

  , (,) R_X86_64_DTPMOD64        "R_X86_64_DTPMOD64"
  , (,) R_X86_64_DTPOFF64        "R_X86_64_DTPOFF64"
  , (,) R_X86_64_TPOFF64         "R_X86_64_TPOFF64"
  , (,) R_X86_64_TLSGD           "R_X86_64_TLSGD"
  , (,) R_X86_64_TLSLD           "R_X86_64_TLSLD"
  , (,) R_X86_64_DTPOFF32        "R_X86_64_DTPOFF32"
  , (,) R_X86_64_GOTTPOFF        "R_X86_64_GOTTPOFF"
  , (,) R_X86_64_TPOFF32         "R_X86_64_TPOFF32"

  , (,) R_X86_64_PC64            "R_X86_64_PC64"
  , (,) R_X86_64_GOTOFF64        "R_X86_64_GOTOFF64"
  , (,) R_X86_64_GOTPC32         "R_X86_64_GOTPC32"

  , (,) R_X86_64_SIZE32          "R_X86_64_SIZE32"
  , (,) R_X86_64_SIZE64          "R_X86_64_SIZE64"
  , (,) R_X86_64_GOTPC32_TLSDESC "R_X86_64_GOTPC32_TLSDESC"
  , (,) R_X86_64_TLSDESC_CALL    "R_X86_64_TLSDESC_CALL"
  , (,) R_X86_64_TLSDESC         "R_X86_64_TLSDESC"
  , (,) R_X86_64_IRELATIVE       "R_X86_64_IRELATIVE"
  ]

instance Show X86_64_RelocationType where
  show i =
    case Map.lookup i x86_64_RelocationTypes of
      Just s -> s
      Nothing -> "0x" ++ showHex (fromX86_64_RelocationType i) ""

instance IsRelocationType X86_64_RelocationType where
  type RelocationWidth X86_64_RelocationType = 64

  relaWidth _ = Rela64
  relaType = Just . X86_64_RelocationType . fromIntegral

  isRelative R_X86_64_RELATIVE = True
  isRelative _ = False

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
getDynamic :: forall w . RelaWidth w -> ElfData -> Get (Dynamic (ElfWordType w))
getDynamic w d = elfWordInstances w $ do
  tag <- getRelaWord w d :: Get (ElfWordType w)
  v   <- getRelaWord w d
  return $! Dynamic (toElfDynamicArrayTag (fromIntegral tag)) v

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
dynSymTab e l file m = elfClassIntegralInstance (elfClass e) $ do
  let cl = elfClass e
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
  when (syment /= symbolTableEntrySize cl) $ do
    fail "Unexpected symbol table entry size"
  let sym_sz = str_off - sym_off
  symtab <- addressRangeToFile l file "dynamic symbol table" (sym_off,sym_sz)
  let nameFn idx = L.toString $ lookupStringL (fromIntegral idx) strTab
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
dynamicEntries e = elfClassIntegralInstance (elfClass e) $ do
  let w :: RelaWidth (RelocationWidth tp)
      w = relaWidth (undefined :: tp)
  let l :: ElfLayout (ElfWordType (RelocationWidth tp))
      l = elfLayout e
  let file = U.toLazyByteString $ l^.elfOutput
  case filter (\(s,_) -> elfSegmentType s == PT_DYNAMIC) (F.toList (l^.phdrs)) of
    [] -> return Nothing
    [(_,p)] -> do
      let elts :: [Dynamic (ElfWordType (RelocationWidth tp))]
          elts = runGet (dynamicList w (elfData e)) (sliceL p file)
      let m :: DynamicMap (ElfWordType (RelocationWidth tp))
          m = foldl' (flip insertDynamic) Map.empty elts

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
  let tp = ElfSymbolType (i .&. 0x0F)
      b = (i `shiftR` 4) .&. 0xF
   in (tp, toElfSymbolBinding b)

newtype ElfSymbolType = ElfSymbolType Word8
  deriving (Eq, Ord)

-- | Symbol type is unspecified
pattern STT_NOTYPE = ElfSymbolType 0

-- | Symbol is a data object
pattern STT_OBJECT = ElfSymbolType 1

-- | Symbol is a code object
pattern STT_FUNC   = ElfSymbolType 2

-- | Symbol associated with a section.
pattern STT_SECTION = ElfSymbolType 3

-- | Symbol gives a file name.
pattern STT_FILE = ElfSymbolType 4

-- | An uninitialised common block.
pattern STT_COMMON = ElfSymbolType 5

-- | Thread local data object.
pattern STT_TLS = ElfSymbolType 6

-- | Complex relocation expression.
pattern STT_RELC = ElfSymbolType 8

-- | Signed Complex relocation expression.
pattern STT_SRELC = ElfSymbolType 9

-- | Symbol is an indirect code object.
pattern STT_GNU_IFUNC = ElfSymbolType 10

-- | Returns true if this is an OF specififc symbol type.
isOSSpecificSymbolType :: ElfSymbolType -> Bool
isOSSpecificSymbolType (ElfSymbolType w) = 10 <= w && w <= 12

isProcSpecificSymbolType :: ElfSymbolType -> Bool
isProcSpecificSymbolType (ElfSymbolType w) = 13 <= w && w <= 15

instance Show ElfSymbolType where
   show = ppElfSymbolType

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
    ElfSymbolType w
      | isOSSpecificSymbolType tp   -> "<OS specific>: " ++ show w
      | isProcSpecificSymbolType tp -> "<processor specific>: " ++ show w
      | otherwise -> "<unknown>: " ++ show w


newtype ElfSectionIndex = ElfSectionIndex Word16
  deriving (Eq, Ord, Enum, Num, Real, Integral)

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
_unused = undefined fromElfSymbolBinding
