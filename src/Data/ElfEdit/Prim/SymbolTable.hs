{-|
Declares operations for symbol tables.
-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE PatternSynonyms #-}
module Data.ElfEdit.Prim.SymbolTable
  ( -- * Symbol tables
    SymtabEntry(..)
  , steVisibility
    -- ** Symbol type
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
    -- ** Binding
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
    -- ** Visibility
  , ElfSymbolVisibility(..)
  , pattern STV_DEFAULT
  , pattern STV_INTERNAL
  , pattern STV_HIDDEN
  , pattern STV_PROTECTED
  , ppSymbolTableEntries
    -- ** Encoding
  , symtabAlign
  , mkSymtabShdr
  , encodeSymtabEntry
  , decodeSymtab
  , decodeSymtabEntry
  , SymtabError(..)
  , symtabEntrySize
  ) where

import           Control.Monad
import           Data.Binary.Get (Get, getWord8)
import           Data.Bits
import qualified Data.ByteString as B
import qualified Data.ByteString.Builder as Bld
import qualified Data.ByteString.Char8 as BSC
import           Data.ElfEdit.Prim.Shdr
import qualified Data.Vector as V
import           Data.Word
import           Prettyprinter

import           Data.ElfEdit.Prim.Ehdr
import           Data.ElfEdit.Prim.File
import           Data.ElfEdit.Prim.StringTable
import           Data.ElfEdit.Utils

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
-- SymtabEntry

-- | The symbol table entries consist of index information to be read from other
-- parts of the ELF file.
--
-- Some of this information is automatically retrieved
-- for your convenience (including symbol name, description of the enclosing
-- section, and definition).
data SymtabEntry nm w = SymtabEntry
    { steName             :: !nm
      -- ^ This is the name of the symbol.  This is a parameter so we can
      -- support both bytestrings and offsets.
    , steType             :: !ElfSymbolType
    , steBind             :: !ElfSymbolBinding
    , steOther            :: !Word8
    , steIndex            :: !ElfSectionIndex
      -- ^ Section in which the def is held
    , steValue            :: !w
      -- ^ Value associated with symbol.
    , steSize             :: !w
    } deriving (Eq, Show)

-- | Convert 8-bit symbol info to symbol type and binding.
infoToTypeAndBind :: Word8 -> (ElfSymbolType,ElfSymbolBinding)
infoToTypeAndBind i =
  let tp = ElfSymbolType (i .&. 0x0F)
      b = (i `shiftR` 4) .&. 0xF
   in (tp, ElfSymbolBinding b)

-- | Convert type and binding information to symbol info field.
typeAndBindToInfo :: ElfSymbolType -> ElfSymbolBinding -> Word8
typeAndBindToInfo (ElfSymbolType tp) (ElfSymbolBinding b) = tp .|. (b `shiftL` 4)

-- | Get visibility of elf symbol
steVisibility :: SymtabEntry nm w -> ElfSymbolVisibility
steVisibility e = ElfSymbolVisibility (steOther e .&. 0x3)

------------------------------------------------------------------------
-- Pretty printing

ppSymbolTableEntry :: (Integral w, Bits w, Show w) => Int -> SymtabEntry B.ByteString w -> [String]
ppSymbolTableEntry i e =
  [ show i ++ ":"
  , ppHex (steValue e)
  , show (steSize e)
  , show (steType e)
  , show (steBind e)
  , show (steVisibility e)
    -- Ndx
  , show (steIndex e)
  , BSC.unpack (steName e)
  ]

-- | Pretty print symbol table entries in format used by readelf.
ppSymbolTableEntries :: (Integral w, Bits w, Show w) => [SymtabEntry B.ByteString w] -> Doc ann
ppSymbolTableEntries l = fixTableColumns (snd <$> cols) (fmap fst cols : entries)
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

------------------------------------------------------------------------
-- SymtabError

-- | Error from parsing a symbol table
data SymtabError
   = InvalidName !Word32 !LookupStringError
     -- ^ The name of the symbol at the given index could not be obtained.
   | IllegalSymbolIndex !Word32
     -- ^ The index above exceeds the size of the symbol table.
   | InvalidLink !Word32
     -- ^ The link attribute of the section did not refer to a valid
     -- symbol table.
   | MultipleSymtabs
     -- ^ Multiple symbol tables in binary.
     --
     -- Raised in `Data.ElfEdit.Prim.decodeHeaderSymtab`
   | InvalidSymtabFileRange
     -- ^ Invalid symbol table link
     --
     -- Raised in `Data.ElfEdit.Prim.decodeHeaderSymtab`
   | InvalidSymtabLink
     -- ^ Invalid string table file range
     --
     -- Raised in `Data.ElfEdit.Prim.decodeHeaderSymtab`
   | InvalidSymtabLocalCount
     -- ^ Invalid symbol table local count.
     --
     -- Raised in `Data.ElfEdit.Prim.decodeHeaderSymtab`
   | InvalidStrtabFileRange
     -- ^ Invalid string table file range
     --
     -- Raised in `Data.ElfEdit.Prim.decodeHeaderSymtab`

instance Show SymtabError where
  show (InvalidName idx msg) = "Error parsing symbol " ++ show idx ++ " name: " ++ show msg
  show (IllegalSymbolIndex idx) = "Index " ++ show idx ++ " exceeds number of entries."
  show (InvalidLink lnk) = "The link index " ++ show lnk ++ " was invalid."
  show MultipleSymtabs = "Multiple symbol tables defined."
  show InvalidSymtabFileRange = "Symbol table header file offset and size is out of range."
  show InvalidSymtabLink = "Symbol table header had invalid link to string table."
  show InvalidSymtabLocalCount = "Symbol table header had invalid number of local symbols."
  show InvalidStrtabFileRange = "String table file offset and size is out of range."

------------------------------------------------------------------------
-- Reading

-- | Create a symbol table entry from a Get monad
getSymbolTableEntry :: ElfClass w
                    -> ElfData
                    -> Get (SymtabEntry Word32 (ElfWordType w))
getSymbolTableEntry ELFCLASS32 d = do
  nameIdx <- getWord32 d
  value   <- getWord32 d
  size    <- getWord32 d
  info    <- getWord8
  other   <- getWord8
  sTlbIdx <- getWord16 d
  let (typ,bind) = infoToTypeAndBind info
  pure $! SymtabEntry
    { steName  = nameIdx
    , steType  = typ
    , steBind  = bind
    , steOther = other
    , steIndex = ElfSectionIndex sTlbIdx
    , steValue = value
    , steSize  = size
    }
getSymbolTableEntry ELFCLASS64 d = do
  nameIdx <- getWord32 d
  info    <- getWord8
  other   <- getWord8
  sTlbIdx <- getWord16 d
  value   <- getWord64 d
  size    <- getWord64 d
  let (typ,bind) = infoToTypeAndBind info
  pure $! SymtabEntry
    { steName  = nameIdx
    , steType  = typ
    , steBind  = bind
    , steOther = other
    , steIndex = ElfSectionIndex sTlbIdx
    , steValue = value
    , steSize  = size
    }

-- | Parse a symbol table entry
decodeSymtabEntry :: ElfClass w -- ^ Identifies 32 or 64-bit elf.
                       -> ElfData -- ^ Endianness
                       -> B.ByteString
                       -- ^ The string table
                       -> B.ByteString
                       -- ^ Contents of symbol table.
                       -> Word32
                       -- ^ Index of symbol table to retrieve
                       -> Either SymtabError (SymtabEntry B.ByteString (ElfWordType w))
decodeSymtabEntry cl d strTab symTab idx = do
  let symEntSize = elfClassInstances cl $ fromIntegral (symtabEntrySize cl)
  let symOff = fromIntegral idx * symEntSize
  let symEntry = B.drop symOff symTab
  when (symEntSize > B.length symEntry) $ do
    Left (IllegalSymbolIndex idx)
  case strictRunGetOrFail (getSymbolTableEntry cl d) symEntry of
    -- This should never occur.
    Left (_,_,msg) -> error $ "Internal error on symtabEntryByIndex: " ++ msg
    Right (_,_,sym) ->
      case lookupString (steName sym) strTab of
        Left  e  -> Left  $! InvalidName idx e
        Right nm -> Right $! sym { steName = nm }

-- | Parse the section as a list of symbol table entries.
decodeSymtab :: ElfClass w
                  -> ElfData
                  -> BSC.ByteString
                  -- ^ String table for symtab
                  -> BSC.ByteString
                  -- ^ Symtab section
                  -> Either SymtabError
                            (V.Vector (SymtabEntry BSC.ByteString (ElfWordType w)))
decodeSymtab cl dta strtab symtab = do
  let symEntSize :: Int
      symEntSize = elfClassInstances cl $ fromIntegral (symtabEntrySize cl)

  let symDataSize = B.length symtab
  -- Get number of entries (ignore extra bytes as they may be padding)
  let n :: Int
      n = symDataSize `quot` symEntSize

  V.generateM n $ \i->
    decodeSymtabEntry cl dta strtab symtab (fromIntegral i)

------------------------------------------------------------------------
-- Size

-- | Return the size of a symbol table entry.
symtabEntrySize :: ElfClass w -> Int
symtabEntrySize ELFCLASS32 = 16
symtabEntrySize ELFCLASS64 = 24

------------------------------------------------------------------------
-- Encoding

-- | Write a symbol table entry to a builder
encodeSymtabEntry :: ElfClass w
                  -> ElfData
                  -> SymtabEntry Word32 (ElfWordType w)
                  -> Bld.Builder
encodeSymtabEntry ELFCLASS32 d s =
  putWord32 d (steName s)
    <> putWord32 d (steValue s)
    <> putWord32 d (steSize  s)
    <> Bld.word8 (typeAndBindToInfo (steType s) (steBind s))
    <> Bld.word8 (steOther s)
    <> putWord16 d (fromElfSectionIndex (steIndex s))
encodeSymtabEntry ELFCLASS64 d s =
  putWord32 d (steName s)
  <> Bld.word8 (typeAndBindToInfo (steType s) (steBind s))
  <> Bld.word8 (steOther s)
  <> putWord16 d (fromElfSectionIndex (steIndex s))
  <> putWord64 d (steValue s)
  <> putWord64 d (steSize  s)

--------------------------------------------------------------------------------
-- .symtab section

-- | Alignment used for symtab data
symtabAlign :: ElfClass w -> ElfWordType w
symtabAlign ELFCLASS32 = 4
symtabAlign ELFCLASS64 = 8

-- | Create a section header for a symbol table.
--
-- Note symbol tables have an alignment constraint, and this will
-- place the symbol table data on an aligned file offset.
--
-- Callers should check @shdrOff@ of the result to add padding
-- before the symbol table itself.
mkSymtabShdr :: ElfClass w
              -> nm -- ^ Name of symtab (typically ".symtab")
              -> Word16 -- ^ Index of string table for symbol names
              -> Word32 -- ^ Number of entries that are local
              -> FileOffset (ElfWordType w)
              -- ^ Offset of file that section must be after.
              --
              -- We align section so the actual location may be larger.
              -> ElfWordType w
              -- ^ Size of section
              -> Shdr nm (ElfWordType w)
mkSymtabShdr cl nm strtabIdx localCnt o sz = elfClassInstances cl $
  let o' = alignFileOffset (symtabAlign cl) o
   in Shdr { shdrName = nm
                , shdrType  = SHT_SYMTAB
                , shdrFlags = shf_none
                , shdrAddr  = 0
                , shdrOff   = o'
                , shdrSize  = sz
                , shdrLink  = fromIntegral strtabIdx
                , shdrInfo  = localCnt
                , shdrAddrAlign = symtabAlign cl
                , shdrEntSize = fromIntegral (symtabEntrySize cl)
                }
