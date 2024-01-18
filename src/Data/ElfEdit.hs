{-|
This library provides facilities for manipulating ELF files.  It includes
operations for both reading and writing files a well as inspecting their
contents.

This library provides a "high level" interface for manipulating Elf
files as well as a lower level "primitive" interface for more
traditional parsing and serialization.  We think users interested in a
quick application may want to use the more abstract high level
interface while those building an application that needs to understand
many parts of the file use the low level interface.  In particular if
you want to analyze the dynamic section and relocations, you should
get comfortable with the low-level interface for those parts.

To read an existing ELF file, see the documentation for 'parseElf'
and the operations on the 'Elf' datatype.  To generate an Elf file from
`Elf` datatype, see the documentation for 'renderElf'.

The low level interface is described in 'Data.ElfEdit.Prim'.
-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE Trustworthy #-}
{-# LANGUAGE TypeFamilies #-}

module Data.ElfEdit
  ( -- * High-level Elf type
    -- ** Main type
    Data.ElfEdit.HighLevel.Types.Elf(..)
  , Data.ElfEdit.HighLevel.Types.emptyElf
  , Data.ElfEdit.HighLevel.Types.elfHeader
    -- ** Elf data region
  , Data.ElfEdit.HighLevel.Types.ElfDataRegion(..)
  , Data.ElfEdit.HighLevel.Types.ppRegion
  , Data.ElfEdit.HighLevel.Types.elfFileData
  , Data.ElfEdit.HighLevel.Layout.traverseElfDataRegions
    -- ** Segments
  , Data.ElfEdit.HighLevel.Types.ElfSegment(..)
  , Data.ElfEdit.HighLevel.Types.SegmentIndex
  , Data.ElfEdit.HighLevel.Types.ElfMemSize(..)
  , Data.ElfEdit.HighLevel.Types.ppSegment
  , Data.ElfEdit.HighLevel.Types.hasSegmentType
  , Data.ElfEdit.elfSegmentCount
  , Data.ElfEdit.elfSegments
  , Data.ElfEdit.HighLevel.Layout.traverseElfSegments
    -- ** Sections
  , Data.ElfEdit.HighLevel.Sections.ElfSection(..)
  , Data.ElfEdit.HighLevel.Sections.elfSectionFileSize
  , Data.ElfEdit.HighLevel.Layout.elfSections
  , Data.ElfEdit.findSectionByName
  , Data.ElfEdit.removeSectionByName
  , Data.ElfEdit.HighLevel.Layout.updateSections
  , Data.ElfEdit.HighLevel.Get.headerSections
    -- ** Symbol table
  , Data.ElfEdit.elfSymtab
    -- ** Interpreter
  , Data.ElfEdit.elfInterpreter
    -- ** Global offset table
  , Data.ElfEdit.HighLevel.GOT.ElfGOT(..)
    -- ** Gnu-specific extensions
  , Data.ElfEdit.HighLevel.Types.GnuStack(..)
  , Data.ElfEdit.HighLevel.Types.GnuRelroRegion(..)
    -- ** Encoding/decoding
  , Data.ElfEdit.HighLevel.Get.ElfGetResult(..)
  , Data.ElfEdit.HighLevel.Get.ElfParseError(..)
  , Data.ElfEdit.HighLevel.Get.parseElf
  , Data.ElfEdit.HighLevel.Get.getElf
  , Data.ElfEdit.HighLevel.Layout.renderElf
    -- * Primitive Interface
  , module Data.ElfEdit.Prim
    -- * Deprecated
  , ElfSymbolTableEntry
  , ShdrEntry
  , stringTable
  ) where

import           Control.Lens ((^.), (^..), filtered, over)
import qualified Control.Monad.Fail as Fail
import qualified Data.ByteString as B
import qualified Data.ByteString.UTF8 as B (toString)
import qualified Data.Foldable as F
import           Data.Map.Strict (Map)
import           Data.Maybe (isJust)
import           Data.Word

import           Data.ElfEdit.HighLevel.GOT
import           Data.ElfEdit.HighLevel.Get
import           Data.ElfEdit.HighLevel.Layout
import           Data.ElfEdit.HighLevel.Sections
import           Data.ElfEdit.HighLevel.Types
import           Data.ElfEdit.Prim


type ElfSymbolTableEntry = SymtabEntry

{-# DEPRECATED ElfSymbolTableEntry "Use SymtabEntry" #-}

type ShdrEntry = Shdr

{-# DEPRECATED ShdrEntry "Use Shdr" #-}

-- | Create a string table from the list of strings, and return a map
-- from strings in list to their offset for efficient lookup.
stringTable :: [B.ByteString] -> (B.ByteString, Map B.ByteString Word32)
stringTable = encodeStringTable

{-# DEPRECATED stringTable "Use encodeStringTable" #-}

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

------------------------------------------------------------------------
-- ElfLayout

-- | Return symbol tables in Elf file.
--
-- These are sections labeled, ".symtab" with type SHT_SYMTAB.
-- There should be at most one symbol table, but we return a list in case the
-- elf file happens to contain multiple symbol tables.
elfSymtab :: Elf w -> [Symtab w]
elfSymtab = asumDataRegions f
  where f (ElfDataSymtab _ s) = [s]
        f _ = []

------------------------------------------------------------------------
-- Elf interpreter

-- | Return elf interpreter in a PT_INTERP segment if one exists, or Nothing is no interpreter
-- is defined.  This will call the Monad fail operation if the contents of the data cannot be
-- parsed.
elfInterpreter :: Fail.MonadFail m => Elf w -> m (Maybe FilePath)
elfInterpreter e =
  case filter (hasSegmentType PT_INTERP) (elfSegments e) of
    [] -> return Nothing
    seg:_ ->
      case F.toList (elfSegmentData seg) of
        [ElfDataSection s] -> return (Just (B.toString (elfSectionData s)))
        _ -> fail "Could not parse elf section."
