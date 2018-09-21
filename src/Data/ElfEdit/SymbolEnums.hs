{-
Module           : Data.ElfEdit.SymbolEnums
Copyright        : (c) Galois, Inc 2016
Maintainer       : Joe Hendrix <jhendrix@galois.com>

Defines constants used in the symbol table.
 -}
{-# LANGUAGE PatternSynonyms #-}
module Data.ElfEdit.SymbolEnums
  ( -- ** Elf symbol type
    ElfSymbolType(..)
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
  , pattern STB_LOCAL
  , pattern STB_GLOBAL
  , pattern STB_WEAK
  , pattern STB_NUM
  , pattern STB_LOOS
  , pattern STB_HIOS
  , pattern STB_GNU_UNIQUE
  , pattern STB_LOPROC
  , pattern STB_HIPROC
  ) where

import           Data.Word

------------------------------------------------------------------------
-- ElfSymbolType

-- | The type of an elf symbol table entry
newtype ElfSymbolType = ElfSymbolType Word8
  deriving (Eq, Ord)

-- | Symbol type is unspecified
pattern STT_NOTYPE :: ElfSymbolType
pattern STT_NOTYPE = ElfSymbolType 0

-- | Symbol is a data object
pattern STT_OBJECT :: ElfSymbolType
pattern STT_OBJECT = ElfSymbolType 1

-- | Symbol is a code object
pattern STT_FUNC :: ElfSymbolType
pattern STT_FUNC = ElfSymbolType 2

-- | Symbol associated with a section.
pattern STT_SECTION :: ElfSymbolType
pattern STT_SECTION = ElfSymbolType 3

-- | Symbol gives a file name.
pattern STT_FILE :: ElfSymbolType
pattern STT_FILE = ElfSymbolType 4

-- | An uninitialised common block.
pattern STT_COMMON :: ElfSymbolType
pattern STT_COMMON = ElfSymbolType 5

-- | Thread local data object.
pattern STT_TLS :: ElfSymbolType
pattern STT_TLS = ElfSymbolType 6

-- | Complex relocation expression.
pattern STT_RELC :: ElfSymbolType
pattern STT_RELC = ElfSymbolType 8

-- | Signed Complex relocation expression.
pattern STT_SRELC :: ElfSymbolType
pattern STT_SRELC = ElfSymbolType 9

-- | Symbol is an indirect code object.
pattern STT_GNU_IFUNC :: ElfSymbolType
pattern STT_GNU_IFUNC = ElfSymbolType 10

-- | Returns true if this is an OF specififc symbol type.
isOSSpecificSymbolType :: ElfSymbolType -> Bool
isOSSpecificSymbolType (ElfSymbolType w) = 10 <= w && w <= 12

isProcSpecificSymbolType :: ElfSymbolType -> Bool
isProcSpecificSymbolType (ElfSymbolType w) = 13 <= w && w <= 15

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

instance Show ElfSymbolType where
   show = ppElfSymbolType

------------------------------------------------------------------------
-- ElfSymbolBinding

-- | Symbol binding type
newtype ElfSymbolBinding = ElfSymbolBinding { fromElfSymbolBinding :: Word8 }
  deriving (Eq, Ord)

pattern STB_LOCAL :: ElfSymbolBinding
pattern STB_LOCAL = ElfSymbolBinding  0

pattern STB_GLOBAL :: ElfSymbolBinding
pattern STB_GLOBAL = ElfSymbolBinding  1

pattern STB_WEAK :: ElfSymbolBinding
pattern STB_WEAK = ElfSymbolBinding  2

pattern STB_NUM :: ElfSymbolBinding
pattern STB_NUM = ElfSymbolBinding  3

-- | Lower bound for OS specific symbol bindings.
pattern STB_LOOS :: ElfSymbolBinding
pattern STB_LOOS = ElfSymbolBinding 10

-- | Upper bound for OS specific symbol bindings.
pattern STB_HIOS :: ElfSymbolBinding
pattern STB_HIOS   = ElfSymbolBinding 12

-- | GNU-specific override that makes symbol unique even with local
-- dynamic loading.
pattern STB_GNU_UNIQUE :: ElfSymbolBinding
pattern STB_GNU_UNIQUE = ElfSymbolBinding 10

pattern STB_LOPROC :: ElfSymbolBinding
pattern STB_LOPROC = ElfSymbolBinding 13

pattern STB_HIPROC :: ElfSymbolBinding
pattern STB_HIPROC = ElfSymbolBinding 15

instance Show ElfSymbolBinding where
  show STB_LOCAL  = "STB_LOCAL"
  show STB_GLOBAL = "STB_GLOBAL"
  show STB_WEAK   = "STB_WEAK"
  show STB_NUM    = "STB_NUM"
  show STB_GNU_UNIQUE = "STB_GNU_UNIQUE"
  show b | STB_LOOS   <= b && b <= STB_HIOS   = "<OS specific>: " ++ show w
         | STB_LOPROC <= b && b <= STB_HIPROC = "<processor specific>: " ++ show w
         | otherwise = "<unknown>: " ++ show w
   where w = fromElfSymbolBinding b
