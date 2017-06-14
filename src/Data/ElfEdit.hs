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
    -- * ElfClass
  , ElfClass(..)
  , elfClassInstances
  , elfClassByteWidth
  , elfClassBitWidth
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
  , elfLayoutData
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
  , RelaEntry(..)
  , RelocationWord
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
  , module Data.ElfEdit.Dynamic
    -- * Common definitions
  , Range
  , hasPermissions
  , stringTable
  ) where

import           Control.Lens ((^.), (^..), filtered, over)
import           Data.Binary
import           Data.Binary.Get
import           Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.UTF8 as B (toString)
import qualified Data.Foldable as F
import           Text.PrettyPrint.ANSI.Leijen hiding ((<>), (<$>))

import           Data.ElfEdit.Dynamic
import           Data.ElfEdit.Enums
import           Data.ElfEdit.Get
import           Data.ElfEdit.Layout
import           Data.ElfEdit.Relocations
import           Data.ElfEdit.Relocations.I386
import           Data.ElfEdit.Relocations.X86_64
import           Data.ElfEdit.Types

------------------------------------------------------------------------
-- Elf Layout

-- | Return true if section has the given name.
hasSectionName :: ElfSection w -> B.ByteString -> Bool
hasSectionName section name = elfSectionName section == name

-- | Given a section name, returns sections matching that name.
--
-- Section names in elf are not necessarily unique.
findSectionByName :: B.ByteString -> Elf w -> [ElfSection (ElfWordType w)]
findSectionByName name e  = e^..elfSections.filtered (`hasSectionName` name)

-- | Remove section with given name.
removeSectionByName :: B.ByteString -> Elf w -> Elf w
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
elfInterpreter :: Monad m => Elf w -> m (Maybe FilePath)
elfInterpreter e =
  case filter (hasSegmentType PT_INTERP) (elfSegments e) of
    [] -> return Nothing
    seg:_ ->
      case F.toList (elfSegmentData seg) of
        [ElfDataSection s] -> return (Just (B.toString (elfSectionData s)))
        _ -> fail "Could not parse elf section."
