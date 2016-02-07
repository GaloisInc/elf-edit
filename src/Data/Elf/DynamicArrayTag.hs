{-# LANGUAGE PatternSynonyms #-}
module Data.Elf.DynamicArrayTag where

import           Data.Foldable
import           Data.Map (Map)
import qualified Data.Map as Map
import           Data.Word (Word32)

newtype ElfDynamicArrayTag = ElfDynamicArrayTag { fromElfDynamicArrayTag :: Word32 }
  deriving (Eq, Ord)

pattern DT_NULL            = ElfDynamicArrayTag 0
pattern DT_NEEDED          = ElfDynamicArrayTag 1
pattern DT_PLTRELSZ        = ElfDynamicArrayTag 2
pattern DT_PLTGOT          = ElfDynamicArrayTag 3
pattern DT_HASH            = ElfDynamicArrayTag 4
pattern DT_STRTAB          = ElfDynamicArrayTag 5
pattern DT_SYMTAB          = ElfDynamicArrayTag 6
pattern DT_RELA            = ElfDynamicArrayTag 7
pattern DT_RELASZ          = ElfDynamicArrayTag 8
pattern DT_RELAENT         = ElfDynamicArrayTag 9
pattern DT_STRSZ           = ElfDynamicArrayTag 10
pattern DT_SYMENT          = ElfDynamicArrayTag 11
pattern DT_INIT            = ElfDynamicArrayTag 12
pattern DT_FINI            = ElfDynamicArrayTag 13
pattern DT_SONAME          = ElfDynamicArrayTag 14
pattern DT_RPATH           = ElfDynamicArrayTag 15
pattern DT_SYMBOLIC        = ElfDynamicArrayTag 16
pattern DT_REL             = ElfDynamicArrayTag 17
pattern DT_RELSZ           = ElfDynamicArrayTag 18
pattern DT_RELENT          = ElfDynamicArrayTag 19
pattern DT_PLTREL          = ElfDynamicArrayTag 20
pattern DT_DEBUG           = ElfDynamicArrayTag 21
pattern DT_TEXTREL         = ElfDynamicArrayTag 22
pattern DT_JMPREL          = ElfDynamicArrayTag 23
pattern DT_BIND_NOW        = ElfDynamicArrayTag 24
pattern DT_INIT_ARRAY      = ElfDynamicArrayTag 25
pattern DT_FINI_ARRAY      = ElfDynamicArrayTag 26
pattern DT_INIT_ARRAYSZ    = ElfDynamicArrayTag 27
pattern DT_FINI_ARRAYSZ    = ElfDynamicArrayTag 28
-- | Library search path
pattern DT_RUNPATH         = ElfDynamicArrayTag 29
-- | Flags for the object being loaded
pattern DT_FLAGS           = ElfDynamicArrayTag 30
-- | Start of encoded range (also DT_PREINIT_ARRAY)
pattern DT_PREINIT_ARRAY   = ElfDynamicArrayTag 32
-- | Size in bytes of DT_PREINIT_ARRAY
pattern DT_PREINIT_ARRAYSZ = ElfDynamicArrayTag 33

pattern DT_LOOS            = ElfDynamicArrayTag 0x60000000
pattern DT_HIOS            = ElfDynamicArrayTag 0x6FFFFFFF

pattern DT_VALRNGLO        = ElfDynamicArrayTag 0x6ffffd00
-- | Prelinking timestamp
pattern DT_GNU_PRELINKED   = ElfDynamicArrayTag 0x6ffffdf5
-- | Size of conflict section.
pattern DT_GNU_CONFLICTSZ  = ElfDynamicArrayTag 0x6ffffdf6
-- | Size of lbirary list
pattern DT_GNU_LIBLISTSZ   = ElfDynamicArrayTag 0x6ffffdf7
pattern DT_CHECKSUM        = ElfDynamicArrayTag 0x6ffffdf8
pattern DT_PLTPADSZ        = ElfDynamicArrayTag 0x6ffffdf9
pattern DT_MOVEENT         = ElfDynamicArrayTag 0x6ffffdfa
pattern DT_MOVESZ          = ElfDynamicArrayTag 0x6ffffdfb
-- | Feature selection (DTF_*).
pattern DT_FEATURE_1       = ElfDynamicArrayTag 0x6ffffdfc
-- | Flags for DT_* entries, effecting the following DT_* entry.
pattern DT_POSFLAG_1       = ElfDynamicArrayTag 0x6ffffdfd
-- | Size of syminfo table (in bytes)
pattern DT_SYMINSZ         = ElfDynamicArrayTag 0x6ffffdfe
-- | Entry size of syminfo
pattern DT_SYMINENT        = ElfDynamicArrayTag 0x6ffffdff
pattern DT_VALRNGHI        = ElfDynamicArrayTag 0x6ffffdff

-- DT_* entries between DT_ADDRRNGHI & DT_ADDRRNGLO use the
-- d_ptr field
pattern DT_ADDRRNGLO       = ElfDynamicArrayTag 0x6ffffe00
pattern DT_ADDRRNGHI       = ElfDynamicArrayTag 0x6ffffeff

-- | GNU-style hash table.
pattern DT_GNU_HASH        = ElfDynamicArrayTag 0x6ffffef5
pattern DT_TLSDESC_PLT     = ElfDynamicArrayTag 0x6ffffef6
pattern DT_TLSDESC_GOT     = ElfDynamicArrayTag 0x6ffffef7
-- | Start of conflict section
pattern DT_GNU_CONFLICT    = ElfDynamicArrayTag 0x6ffffef8
-- | Library list
pattern DT_GNU_LIBLIST     = ElfDynamicArrayTag 0x6ffffef9
-- | Configuration information
pattern DT_CONFIG          = ElfDynamicArrayTag 0x6ffffefa
-- | Dependency auditing
pattern DT_DEPAUDIT        = ElfDynamicArrayTag 0x6ffffefb
-- | Object auditing
pattern DT_AUDIT           = ElfDynamicArrayTag 0x6ffffefc
-- | PLT padding
pattern DT_PLTPAD          = ElfDynamicArrayTag 0x6ffffefd
-- | Move table
pattern DT_MOVETAB         = ElfDynamicArrayTag 0x6ffffefe
-- | Syminfo table
pattern DT_SYMINFO         = ElfDynamicArrayTag 0x6ffffeff

pattern DT_VERSYM          = ElfDynamicArrayTag 0x6ffffff0
pattern DT_RELACOUNT       = ElfDynamicArrayTag 0x6ffffff9
pattern DT_RELCOUNT        = ElfDynamicArrayTag 0x6ffffffa
-- | State flags
pattern DT_FLAGS_1         = ElfDynamicArrayTag 0x6ffffffb
-- | Address of version definition.
pattern DT_VERDEF          = ElfDynamicArrayTag 0x6ffffffc
pattern DT_VERDEFNUM       = ElfDynamicArrayTag 0x6ffffffd
pattern DT_VERNEED         = ElfDynamicArrayTag 0x6ffffffe
-- | Number of needed versions.
pattern DT_VERNEEDNUM      = ElfDynamicArrayTag 0x6fffffff

symbolNameMap :: Ord k => [(k,String)] -> Map k String
symbolNameMap = foldl' ins Map.empty
  where ins m (k,v) = Map.insertWith merge k v m
        merge new old = old ++ "|" ++ new

instance Show ElfDynamicArrayTag where
  show = \tag -> case Map.lookup tag elfDynamicArrayTagNameMap of
                   Just r -> r
                   Nothing -> "ElfDynamicArrayTag " ++ show (fromElfDynamicArrayTag tag)
    where
      elfDynamicArrayTagNameMap :: Map ElfDynamicArrayTag String
      elfDynamicArrayTagNameMap = symbolNameMap
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

        , (,) DT_LOOS            "DT_LOOS"
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
