{-
Copyright        : (c) Galois, Inc 2016-2019
Maintainer       : Joe Hendrix <jhendrix@galois.com>

Defines the tags used in the dynamic section.
-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE PatternSynonyms #-}
{-# OPTIONS_GHC -fno-warn-missing-pattern-synonym-signatures #-}
module Data.ElfEdit.Dynamic.Tag
  ( module Data.ElfEdit.Dynamic.Tag
  ) where

import           Data.Foldable
import           Data.Map (Map)
import qualified Data.Map as Map
import           Data.Word (Word32)

newtype ElfDynamicTag = ElfDynamicTag { fromElfDynamicTag :: Word32 }
  deriving (Eq, Ord, Num)

pattern DT_NULL            = ElfDynamicTag 0
pattern DT_NEEDED          = ElfDynamicTag 1
pattern DT_PLTRELSZ        = ElfDynamicTag 2
pattern DT_PLTGOT          = ElfDynamicTag 3
pattern DT_HASH            = ElfDynamicTag 4
pattern DT_STRTAB          = ElfDynamicTag 5
pattern DT_SYMTAB          = ElfDynamicTag 6
pattern DT_RELA            = ElfDynamicTag 7
pattern DT_RELASZ          = ElfDynamicTag 8
pattern DT_RELAENT         = ElfDynamicTag 9
pattern DT_STRSZ           = ElfDynamicTag 10
pattern DT_SYMENT          = ElfDynamicTag 11
pattern DT_INIT            = ElfDynamicTag 12
pattern DT_FINI            = ElfDynamicTag 13
pattern DT_SONAME          = ElfDynamicTag 14
pattern DT_RPATH           = ElfDynamicTag 15
pattern DT_SYMBOLIC        = ElfDynamicTag 16
pattern DT_REL             = ElfDynamicTag 17
pattern DT_RELSZ           = ElfDynamicTag 18
pattern DT_RELENT          = ElfDynamicTag 19
pattern DT_PLTREL          = ElfDynamicTag 20
pattern DT_DEBUG           = ElfDynamicTag 21
pattern DT_TEXTREL         = ElfDynamicTag 22
pattern DT_JMPREL          = ElfDynamicTag 23
pattern DT_BIND_NOW        = ElfDynamicTag 24
pattern DT_INIT_ARRAY      = ElfDynamicTag 25
pattern DT_FINI_ARRAY      = ElfDynamicTag 26
pattern DT_INIT_ARRAYSZ    = ElfDynamicTag 27
pattern DT_FINI_ARRAYSZ    = ElfDynamicTag 28
-- | Library search path
pattern DT_RUNPATH         = ElfDynamicTag 29
-- | Flags for the object being loaded
pattern DT_FLAGS           = ElfDynamicTag 30
-- | Start of encoded range (also DT_PREINIT_ARRAY)
pattern DT_PREINIT_ARRAY   = ElfDynamicTag 32
-- | Size in bytes of DT_PREINIT_ARRAY
pattern DT_PREINIT_ARRAYSZ = ElfDynamicTag 33


pattern OLD_DT_LOOS :: ElfDynamicTag
pattern OLD_DT_LOOS        = ElfDynamicTag 0x60000000

-- | The start of OS specific tags.
--
-- Linux uses this value for DT_LOOS
pattern DT_LOOS :: ElfDynamicTag
pattern DT_LOOS = ElfDynamicTag 0x6000000d

pattern DT_ANDROID_REL :: ElfDynamicTag
pattern DT_ANDROID_REL    = ElfDynamicTag 0x6000000f

pattern DT_ANDROID_RELSZ :: ElfDynamicTag
pattern DT_ANDROID_RELSZ  = ElfDynamicTag 0x60000010

pattern DT_ANDROID_RELA :: ElfDynamicTag
pattern DT_ANDROID_RELA   = ElfDynamicTag 0x60000011

pattern DT_ANDROID_RELASZ :: ElfDynamicTag
pattern DT_ANDROID_RELASZ = ElfDynamicTag 0x60000012

-- | The start of OS specific tags.
--
-- Linux uses this value for DT_HIOS
pattern DT_HIOS :: ElfDynamicTag
pattern DT_HIOS = ElfDynamicTag 0x6ffff000

pattern DT_VALRNGLO        = ElfDynamicTag 0x6ffffd00
-- | Prelinking timestamp
pattern DT_GNU_PRELINKED   = ElfDynamicTag 0x6ffffdf5
-- | Size of conflict section.
pattern DT_GNU_CONFLICTSZ  = ElfDynamicTag 0x6ffffdf6
-- | Size of lbirary list
pattern DT_GNU_LIBLISTSZ   = ElfDynamicTag 0x6ffffdf7
pattern DT_CHECKSUM        = ElfDynamicTag 0x6ffffdf8
pattern DT_PLTPADSZ        = ElfDynamicTag 0x6ffffdf9
pattern DT_MOVEENT         = ElfDynamicTag 0x6ffffdfa
pattern DT_MOVESZ          = ElfDynamicTag 0x6ffffdfb
-- | Feature selection (DTF_*).
pattern DT_FEATURE_1       = ElfDynamicTag 0x6ffffdfc
-- | Flags for DT_* entries, effecting the following DT_* entry.
pattern DT_POSFLAG_1       = ElfDynamicTag 0x6ffffdfd
-- | Size of syminfo table (in bytes)
pattern DT_SYMINSZ         = ElfDynamicTag 0x6ffffdfe
-- | Entry size of syminfo
pattern DT_SYMINENT        = ElfDynamicTag 0x6ffffdff
pattern DT_VALRNGHI        = ElfDynamicTag 0x6ffffdff

-- DT_* entries between DT_ADDRRNGHI & DT_ADDRRNGLO use the
-- d_ptr field
pattern DT_ADDRRNGLO       = ElfDynamicTag 0x6ffffe00
pattern DT_ADDRRNGHI       = ElfDynamicTag 0x6ffffeff

-- | GNU-style hash table.
pattern DT_GNU_HASH        = ElfDynamicTag 0x6ffffef5
pattern DT_TLSDESC_PLT     = ElfDynamicTag 0x6ffffef6
pattern DT_TLSDESC_GOT     = ElfDynamicTag 0x6ffffef7
-- | Start of conflict section
pattern DT_GNU_CONFLICT    = ElfDynamicTag 0x6ffffef8
-- | Library list
pattern DT_GNU_LIBLIST     = ElfDynamicTag 0x6ffffef9
-- | Configuration information
pattern DT_CONFIG          = ElfDynamicTag 0x6ffffefa
-- | Dependency auditing
pattern DT_DEPAUDIT        = ElfDynamicTag 0x6ffffefb
-- | Object auditing
pattern DT_AUDIT           = ElfDynamicTag 0x6ffffefc
-- | PLT padding
pattern DT_PLTPAD          = ElfDynamicTag 0x6ffffefd
-- | Move table
pattern DT_MOVETAB         = ElfDynamicTag 0x6ffffefe
-- | Syminfo table
pattern DT_SYMINFO         = ElfDynamicTag 0x6ffffeff

pattern DT_VERSYM          = ElfDynamicTag 0x6ffffff0
pattern DT_RELACOUNT       = ElfDynamicTag 0x6ffffff9
pattern DT_RELCOUNT        = ElfDynamicTag 0x6ffffffa
-- | State flags
pattern DT_FLAGS_1         = ElfDynamicTag 0x6ffffffb
-- | Address of version definition.
pattern DT_VERDEF          = ElfDynamicTag 0x6ffffffc
pattern DT_VERDEFNUM       = ElfDynamicTag 0x6ffffffd
pattern DT_VERNEED         = ElfDynamicTag 0x6ffffffe
-- | Number of needed versions.
pattern DT_VERNEEDNUM = ElfDynamicTag 0x6fffffff


pattern OLD_DT_HIOS :: ElfDynamicTag
pattern OLD_DT_HIOS = ElfDynamicTag 0x6fffffff


instance Show ElfDynamicTag where
  show = \tag -> case Map.lookup tag elfDynamicTagNameMap of
                   Just r -> r
                   Nothing -> "ElfDynamicTag " ++ show (fromElfDynamicTag tag)
    where
      merge new old = old ++ "|" ++ new
      ins m (k,v) = Map.insertWith merge k v m
      elfDynamicTagNameMap :: Map ElfDynamicTag String
      elfDynamicTagNameMap = foldl' ins Map.empty
        [ (,) DT_NULL            "DT_NULL"
        , (,) DT_NEEDED          "DT_NEEDED"
        , (,) DT_PLTRELSZ        "DT_PLTRELSZ"
        , (,) DT_PLTGOT          "DT_PLTGOT"
        , (,) DT_HASH            "DT_HASH"
        , (,) DT_STRTAB          "DT_STRTAB"
        , (,) DT_SYMTAB          "DT_SYMTAB"
        , (,) DT_RELA            "DT_RELA"
        , (,) DT_RELASZ          "DT_RELASZ"
        , (,) DT_RELAENT         "DT_RELAENT"
        , (,) DT_STRSZ           "DT_STRSZ"
        , (,) DT_SYMENT          "DT_SYMENT"
        , (,) DT_INIT            "DT_INIT"
        , (,) DT_FINI            "DT_FINI"
        , (,) DT_SONAME          "DT_SONAME"
        , (,) DT_RPATH           "DT_RPATH"
        , (,) DT_SYMBOLIC        "DT_SYMBOLIC"
        , (,) DT_REL             "DT_REL"
        , (,) DT_RELSZ           "DT_RELSZ"
        , (,) DT_RELENT          "DT_RELENT"
        , (,) DT_PLTREL          "DT_PLTREL"
        , (,) DT_DEBUG           "DT_DEBUG"
        , (,) DT_TEXTREL         "DT_TEXTREL"
        , (,) DT_JMPREL          "DT_JMPREL"
        , (,) DT_BIND_NOW        "DT_BIND_NOW"
        , (,) DT_INIT_ARRAY      "DT_INIT_ARRAY"
        , (,) DT_FINI_ARRAY      "DT_FINI_ARRAY"
        , (,) DT_INIT_ARRAYSZ    "DT_INIT_ARRAYSZ"
        , (,) DT_FINI_ARRAYSZ    "DT_FINI_ARRAYSZ"
        , (,) DT_RUNPATH         "DT_RUNPATH"
        , (,) DT_FLAGS           "DT_FLAGS"
        , (,) DT_PREINIT_ARRAY   "DT_PREINIT_ARRAY"
        , (,) DT_PREINIT_ARRAYSZ "DT_PREINIT_ARRAYSZ"

        , (,) OLD_DT_LOOS        "OLD_DT_LOOS"
        , (,) DT_LOOS            "DT_LOOS"

        , (,) DT_ANDROID_REL     "DT_ANDROID_REL"
        , (,) DT_ANDROID_RELSZ   "DT_ANDROID_RELSZ"
        , (,) DT_ANDROID_RELA    "DT_ANDROID_RELA"
        , (,) DT_ANDROID_RELSZ   "DT_ANDROID_RELASZ"

        , (,) DT_HIOS            "DT_HIOS"

        , (,) DT_VALRNGLO        "DT_VALRNGLO"
        , (,) DT_GNU_PRELINKED   "DT_GNU_PRELINKED"
        , (,) DT_GNU_CONFLICTSZ  "DT_GNU_CONFLICTSZ"
        , (,) DT_GNU_LIBLISTSZ   "DT_GNU_LIBLISTSZ"
        , (,) DT_CHECKSUM        "DT_CHECKSUM"
        , (,) DT_PLTPADSZ        "DT_PLTPADSZ"
        , (,) DT_MOVEENT         "DT_MOVEENT"
        , (,) DT_MOVESZ          "DT_MOVESZ"
        , (,) DT_FEATURE_1       "DT_FEATURE_1"
        , (,) DT_POSFLAG_1       "DT_POSFLAG_1"
        , (,) DT_SYMINSZ         "DT_SYMINSZ"
        , (,) DT_SYMINENT        "DT_SYMINENT"
        , (,) DT_VALRNGHI        "DT_VALRNGHI"

        , (,) DT_ADDRRNGLO       "DT_ADDRRNGLO"
        , (,) DT_ADDRRNGHI       "DT_ADDRRNGHI"
        , (,) DT_GNU_HASH        "DT_GNU_HASH"
        , (,) DT_TLSDESC_PLT     "DT_TLSDESC_PLT"
        , (,) DT_TLSDESC_GOT     "DT_TLSDESC_GOT"
        , (,) DT_GNU_CONFLICT    "DT_GNU_CONFLICT"
        , (,) DT_GNU_LIBLIST     "DT_GNU_LIBLIST"
        , (,) DT_CONFIG          "DT_CONFIG"
        , (,) DT_DEPAUDIT        "DT_DEPAUDIT"
        , (,) DT_AUDIT           "DT_AUDIT"
        , (,) DT_PLTPAD          "DT_PLTPAD"
        , (,) DT_MOVETAB         "DT_MOVETAB"

        , (,) DT_SYMINFO         "DT_SYMINFO"

        , (,) DT_VERSYM          "DT_VERSYM"
        , (,) DT_RELACOUNT       "DT_RELACOUNT"
        , (,) DT_RELCOUNT        "DT_RELCOUNT"
        , (,) DT_FLAGS_1         "DT_FLAGS_1"
        , (,) DT_VERDEF          "DT_VERDEF"
        , (,) DT_VERDEFNUM       "DT_VERDEFNUM"
        , (,) DT_VERNEED         "DT_VERNEED"
        , (,) DT_VERNEEDNUM      "DT_VERNEEDNUM"
        ]
