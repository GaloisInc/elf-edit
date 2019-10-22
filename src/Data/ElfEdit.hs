{-|
Module           : Data.ElfEdit.Layout
Copyright        : (c) Galois, Inc 2016
License          : BSD3
Maintainer       : Joe Hendrix <jhendrix@galois.com>

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
  ( -- * Elf definitions
    Elf(..)
  , ElfData(..)
  , emptyElf
    -- ** Utilities to get information
  , elfHeader
  , elfInterpreter
  , elfSymtab
    -- ** Operations on segments
  , elfSegments
  , elfSegmentCount
  , Data.ElfEdit.Layout.traverseElfSegments
    -- ** Operations on sections
  , elfSections
  , findSectionByName
  , removeSectionByName
  , updateSections
    -- ** Operations all data regions
  , elfFileData
  , Data.ElfEdit.Layout.traverseElfDataRegions
    -- * Header
  , ElfHeader(..)
  , module Data.ElfEdit.Enums
    -- ** ElfClass
  , ElfClass(..)
  , elfClassInstances
  , ElfWidthConstraints
  , elfClassByteWidth
  , elfClassBitWidth
    -- ** Elf data region
  , ElfDataRegion(..)
  , ppRegion
  , module Data.ElfEdit.Sections
    -- ** Elf GOT
  , ElfGOT(..)
  , elfGotSection
    -- * Segments
  , ElfSegment(..)
  , SegmentIndex
  , ppSegment
    -- ** Elf segment type
  , ElfSegmentType(..)
  , hasSegmentType
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
    -- ** Memory size description
  , ElfMemSize(..)
    -- ** Segment Layout information
  , allPhdrs
  , Phdr(..)
  , FileOffset(..)
  , phdrFileRange
  , headerPhdrs
  , headerSections
    -- * Reading Elf files
  , hasElfMagic
  , ElfGetResult(..)
  , ElfParseError(..)
  , parseElf
  , SomeElf(..)
    -- * Writing Elf files
  , renderElf
    -- ** Layout information
  , ElfLayout
  , elfLayout
  , elfLayoutHeader
  , elfLayoutData
  , elfLayoutClass
  , elfLayoutRegions
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
    -- * Symbol Table Entries
  , ElfSymbolTable(..)
  , ElfSymbolTableEntry(..)
  , ppSymbolTableEntries
  , symbolTableEntrySize
  , parseSymbolTableEntry
  , getSymbolTableEntries
  , module Data.ElfEdit.SymbolEnums
    -- ** Elf symbol visibility
  , steVisibility
  , ElfSymbolVisibility(..)
  , pattern STV_DEFAULT
  , pattern STV_INTERNAL
  , pattern STV_HIDDEN
  , pattern STV_PROTECTED
    -- * Relocations
  , IsRelocationType(..)
  , RelocationWord
    -- ** Relocation types
  , RelEntry(..)
  , relOffset
  , RelaEntry(..)
  , relaOffset
  , ppRelaEntries
  , relaToRel
    -- ** Relocation parsing
  , elfRelEntries
  , elfRelaEntries
  , decodeAndroidRelaEntries
  , AndroidDecodeError(..)
    -- ** 32-bit x86 relocations
  , module Data.ElfEdit.Relocations.I386
    -- ** 64-bit x86 relocations
  , module Data.ElfEdit.Relocations.X86_64
    -- ** ARM32 relocations
  , module Data.ElfEdit.Relocations.ARM32
    -- ** ARM64 relocations
  , module Data.ElfEdit.Relocations.AArch64
    -- ** Low-level utilities
  , relocationSymIndex
  , relocationTypeVal
    -- * Dynamic symbol table and relocations
  , DynamicSection(..)
  , module Data.ElfEdit.Dynamic
    -- * Common definitions
  , Range
  , hasPermissions
  , stringTable
  , ElfWordType
  , ElfIntType
    -- * Low level information
  , ElfHeaderInfo
  , parseElfHeaderInfo
  , header
  , getElf
    -- * Gnu-specific extensions
  , GnuStack(..)
  , GnuRelroRegion(..)
  ) where

import           Control.Lens ((^.), (^..), filtered, over)
import           Data.Binary
import           Data.Binary.Get
import           Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.UTF8 as B (toString)
import qualified Data.Foldable as F
import           Data.Maybe (isJust)
import           Text.PrettyPrint.ANSI.Leijen hiding ((<>), (<$>))

import           Data.ElfEdit.Dynamic
import           Data.ElfEdit.Enums
import           Data.ElfEdit.Get
import           Data.ElfEdit.Layout
import           Data.ElfEdit.Relocations
import           Data.ElfEdit.Relocations.Android
import           Data.ElfEdit.Relocations.ARM32
import           Data.ElfEdit.Relocations.AArch64
import           Data.ElfEdit.Relocations.I386
import           Data.ElfEdit.Relocations.X86_64
import           Data.ElfEdit.Sections
import           Data.ElfEdit.SymbolEnums
import           Data.ElfEdit.Types

------------------------------------------------------------------------
-- Elf Layout

-- | Return true if section has the given name.
hasSectionName :: ElfSection w -> B.ByteString -> Bool
hasSectionName section name = elfSectionName section == name

-- | Given a section name, returns sections matching that name.
--
-- Section names in elf are often unique, but the file format does not
-- explicitly enforce this.
findSectionByName :: B.ByteString -> Elf w -> [ElfSection (ElfWordType w)]
findSectionByName name e  = e^..elfSections.filtered (`hasSectionName` name)

-- | Remove all sections with given name.
removeSectionByName :: B.ByteString -> Elf w -> Elf w
removeSectionByName nm = over updateSections fn
  where fn s | s `hasSectionName` nm = Nothing
             | otherwise = Just s

-- | List of segments in the file other than `PT_GNU_RELRO` and `PT_GNU_STACK`.
elfSegments :: Elf w -> [ElfSegment w]
elfSegments e = concatMap impl (e^.elfFileData)
  where impl (ElfDataSegment s) = s : concatMap impl (F.toList (elfSegmentData s))
        impl _ = []

-- | Return total number of segments including `PT_GNU_RELRO` and `PT_GNU_STACK`.
elfSegmentCount :: Elf w -> Int
elfSegmentCount e
  = length (elfSegments e)
  + (if isJust (elfGnuStackSegment e) then 1 else 0)
  + length (elfGnuRelroRegions e)

-- | Return true if this bytestring has the 4 bytes "\DELELF" at the start.
hasElfMagic :: L.ByteString -> Bool
hasElfMagic l = either (\_ -> False) (\(_,_,ei_magic) -> ei_magic == elfMagic) $
  runGetOrFail (getByteString 4) l

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
pattern STV_DEFAULT :: ElfSymbolVisibility
pattern STV_DEFAULT = ElfSymbolVisibility 0

-- | OS specific version of STV_HIDDEN.
pattern STV_INTERNAL :: ElfSymbolVisibility
pattern STV_INTERNAL = ElfSymbolVisibility 1

-- | Can only be seen inside current component.
pattern STV_HIDDEN :: ElfSymbolVisibility
pattern STV_HIDDEN = ElfSymbolVisibility 2

-- | Can only be seen inside current component.
pattern STV_PROTECTED :: ElfSymbolVisibility
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
elfSymtab :: Elf w -> [ElfSymbolTable (ElfWordType w)]
elfSymtab = asumDataRegions f
  where f (ElfDataSymtab s) = [s]
        f _ = []

------------------------------------------------------------------------
-- Elf interpreter

-- | Return true if the segment has the given type.
hasSegmentType :: ElfSegmentType -> ElfSegment w -> Bool
hasSegmentType tp s = elfSegmentType s == tp

-- | Return elf interpreter in a PT_INTERP segment if one exists, or Nothing is no interpreter
-- is defined.  This will call the Monad fail operation if the contents of the data cannot be
-- parsed.
elfInterpreter :: MonadFail m => Elf w -> m (Maybe FilePath)
elfInterpreter e =
  case filter (hasSegmentType PT_INTERP) (elfSegments e) of
    [] -> return Nothing
    seg:_ ->
      case F.toList (elfSegmentData seg) of
        [ElfDataSection s] -> return (Just (B.toString (elfSectionData s)))
        _ -> fail "Could not parse elf section."
