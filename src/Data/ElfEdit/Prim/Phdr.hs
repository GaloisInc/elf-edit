{-|
Program header
-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE UndecidableInstances #-}
module Data.ElfEdit.Prim.Phdr
  ( -- * Program headers
    Phdr(..)
  , phdrFileRange
  , phdrHasType
  , phdrEntrySize
    -- ** Program header type
  , PhdrType(..)
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
  , pattern PT_PAX_FLAGS
  , pattern PT_HIOS
  , pattern PT_LOPROC
  , pattern PT_ARM_EXIDX
  , pattern PT_HIPROC
    -- ** Program header flags
  , ElfSegmentFlags(..)
  , pf_none, pf_x, pf_w, pf_r
  , hasPermissions
    -- ** Encoding
  , phdrTableAlign
  , encodePhdr
  , encodePhdrTable
  ) where

import           Data.Bits
import qualified Data.ByteString.Builder as Bld
import qualified Data.Map as Map
import qualified Data.Vector as V
import           Data.Word
import           Numeric

import           Data.ElfEdit.Prim.Ehdr
import           Data.ElfEdit.Prim.File
import           Data.ElfEdit.Utils (showFlags)

------------------------------------------------------------------------
-- PhdrType

-- | The type of an elf segment
newtype PhdrType = PhdrType { fromPhdrType :: Word32 }
  deriving (Eq,Ord)

-- | Unused entry
pattern PT_NULL :: PhdrType
pattern PT_NULL    = PhdrType 0
-- | Loadable program segment
pattern PT_LOAD :: PhdrType
pattern PT_LOAD    = PhdrType 1
-- | Dynamic linking information
pattern PT_DYNAMIC :: PhdrType
pattern PT_DYNAMIC = PhdrType 2
-- | Program interpreter path name
pattern PT_INTERP :: PhdrType
pattern PT_INTERP  = PhdrType 3
-- | Note sections
pattern PT_NOTE :: PhdrType
pattern PT_NOTE    = PhdrType 4
-- | Reserved
pattern PT_SHLIB :: PhdrType
pattern PT_SHLIB   = PhdrType 5
-- | Program header table
pattern PT_PHDR :: PhdrType
pattern PT_PHDR    = PhdrType 6
-- | A thread local storage segment
--
-- See 'https://www.akkadia.org/drepper/tls.pdf'
pattern PT_TLS :: PhdrType
pattern PT_TLS     = PhdrType 7
-- | A number of defined types.
pattern PT_NUM :: PhdrType
pattern PT_NUM     = PhdrType 8

-- | Start of OS-specific
pattern PT_LOOS :: PhdrType
pattern PT_LOOS    = PhdrType 0x60000000

-- | The GCC '.eh_frame_hdr' segment
pattern PT_GNU_EH_FRAME :: PhdrType
pattern PT_GNU_EH_FRAME = PhdrType 0x6474e550

-- | Indicates if stack should be executable.
pattern PT_GNU_STACK :: PhdrType
pattern PT_GNU_STACK = PhdrType 0x6474e551

-- | GNU-specific segment type used to indicate that a loadable
-- segment is initially writable, but can be made read-only after
-- relocations have been applied.
pattern PT_GNU_RELRO :: PhdrType
pattern PT_GNU_RELRO = PhdrType 0x6474e552

-- | Indicates this binary uses PAX.
pattern PT_PAX_FLAGS :: PhdrType
pattern PT_PAX_FLAGS = PhdrType 0x65041580

-- | End of OS-specific
pattern PT_HIOS :: PhdrType
pattern PT_HIOS    = PhdrType 0x6fffffff

-- | Start of OS-specific
pattern PT_LOPROC :: PhdrType
pattern PT_LOPROC  = PhdrType 0x70000000

-- | Exception unwinding tables
pattern PT_ARM_EXIDX :: PhdrType
pattern PT_ARM_EXIDX  = PhdrType 0x70000001

-- | End of OS-specific
pattern PT_HIPROC :: PhdrType
pattern PT_HIPROC  = PhdrType 0x7fffffff

phdrTypeNameMap :: Map.Map PhdrType String
phdrTypeNameMap = Map.fromList $
  [ (,) PT_NULL         "NULL"
  , (,) PT_LOAD         "LOAD"
  , (,) PT_DYNAMIC      "DYNAMIC"
  , (,) PT_INTERP       "INTERP"
  , (,) PT_NOTE         "NOTE"
  , (,) PT_SHLIB        "SHLIB"
  , (,) PT_PHDR         "PHDR"
  , (,) PT_TLS          "TLS"
  , (,) PT_GNU_EH_FRAME "GNU_EH_FRAME"
  , (,) PT_GNU_STACK    "GNU_STACK"
  , (,) PT_GNU_RELRO    "GNU_RELRO"
  , (,) PT_PAX_FLAGS    "PAX_FLAGS"
  ]

instance Show PhdrType where
  show tp =
    case Map.lookup tp phdrTypeNameMap of
      Just s -> "PT_" ++ s
      Nothing -> "0x" ++ showHex (fromPhdrType tp) ""

------------------------------------------------------------------------
-- ElfSegmentFlags

-- | The flags (permission bits on an elf segment.
newtype ElfSegmentFlags  = ElfSegmentFlags { fromElfSegmentFlags :: Word32 }
  deriving (Eq, Num, Bits)

instance Show ElfSegmentFlags where
  showsPrec d (ElfSegmentFlags w) = showFlags "pf_none" names d w
    where names = V.fromList [ "pf_x", "pf_w", "pf_r" ]

-- | No permissions
pf_none :: ElfSegmentFlags
pf_none = ElfSegmentFlags 0

-- | Execute permission
pf_x :: ElfSegmentFlags
pf_x = ElfSegmentFlags 1

-- | Write permission
pf_w :: ElfSegmentFlags
pf_w = ElfSegmentFlags 2

-- | Read permission
pf_r :: ElfSegmentFlags
pf_r = ElfSegmentFlags 4

-- | @p `hasPermissions` req@ returns true if all bits set in @req@ are set in @p@.
hasPermissions :: Bits b => b -> b -> Bool
hasPermissions p req = (p .&. req) == req
{-# INLINE hasPermissions #-}

------------------------------------------------------------------------
-- Phdr

-- | Program header information
data Phdr w = Phdr { phdrSegmentIndex :: !Word16
                   , phdrSegmentType  :: !PhdrType
                   , phdrSegmentFlags :: !ElfSegmentFlags
                   , phdrSegmentVirtAddr  :: !(ElfWordType w)
                   , phdrSegmentPhysAddr  :: !(ElfWordType w)
                   , phdrSegmentAlign     :: !(ElfWordType w)
                   , phdrFileStart :: !(FileOffset (ElfWordType w))
                   , phdrFileSize  :: !(ElfWordType w)
                   , phdrMemSize   :: !(ElfWordType w)
                   }

-- | Range of bytes in file for program header.
phdrFileRange :: Phdr w -> FileRange (ElfWordType w)
phdrFileRange p = (phdrFileStart p, phdrFileSize p)

-- | Return true if the program header has the given type.
phdrHasType :: PhdrType -> Phdr w -> Bool
phdrHasType tp p = phdrSegmentType p == tp

------------------------------------------------------------------------
-- Pretty printing

fixedHex :: Integral a => Int -> a -> String
fixedHex n v | v >= 0    = alignRight n '0' s
             | otherwise = error "fixedHex given negative value"
  where s = showHex (toInteger v) ""

showSegFlags :: ElfSegmentFlags -> String
showSegFlags f =
    [ ' '
    , set_if pf_r 'R'
    , set_if pf_w 'W'
    , set_if pf_x 'E'
    ]
  where set_if req c | f `hasPermissions` req = c
                     | otherwise = ' '

-- | @alignLeft n s c@ prints the first @n@-characters in @c@ and pads with
-- @c@ to the end of string if @s@ is shorter than @n@.
alignLeft :: Int -> String -> Char -> String
alignLeft n s c | l < n = s ++ replicate (n - l) c
                | otherwise = take n s
  where l = length s

-- | @alignLeft n s c@ prints the first @n@-characters in @c@ and pads with
-- @c@ at the front of string if @s@ is shorter than @n@.
alignRight :: Int -> Char -> String -> String
alignRight n c s | l < n = replicate (n - l) c ++ s
                 | otherwise = take n s
  where l = length s


instance (Integral (ElfWordType w)) => Show (Phdr w) where
  show p = unlines (unwords <$> [ col1, col2 ])
    where col1 = [ alignLeft 15 (show (phdrSegmentType p)) ' '
                 , "0x" ++ fixedHex 16 (fromFileOffset (phdrFileStart p))
                 , "0x" ++ fixedHex 16 (phdrSegmentVirtAddr p)
                 , "0x" ++ fixedHex 16 (phdrSegmentPhysAddr p)
                 ]
          col2 = [ replicate 14 ' '
                 , "0x" ++ fixedHex 16 (phdrFileSize p)
                 , "0x" ++ fixedHex 16 (phdrMemSize  p)
                 , alignLeft 7 (showSegFlags (phdrSegmentFlags p)) ' '
                 , fixedHex 0 (toInteger (phdrSegmentAlign p))
                 ]

------------------------------------------------------------------------
-- Encoding

-- | Byte alignment expected on start of program header table.
phdrTableAlign :: ElfClass w -> ElfWordType w
phdrTableAlign ELFCLASS32 = 4
phdrTableAlign ELFCLASS64 = 8

-- | Encode a single program header
encodePhdr32 :: ElfData -> Phdr 32 -> Bld.Builder
encodePhdr32 d p
  =  putWord32 d (fromPhdrType (phdrSegmentType p))
  <> putWord32 d (fromFileOffset (phdrFileStart p))
  <> putWord32 d (phdrSegmentVirtAddr p)
  <> putWord32 d (phdrSegmentPhysAddr p)
  <> putWord32 d (phdrFileSize p)
  <> putWord32 d (phdrMemSize p)
  <> putWord32 d (fromElfSegmentFlags (phdrSegmentFlags p))
  <> putWord32 d (phdrSegmentAlign p)

-- | Encode a single program header
encodePhdr64 :: ElfData -> Phdr 64 -> Bld.Builder
encodePhdr64 d p
  =  putWord32 d (fromPhdrType (phdrSegmentType p))
  <> putWord32 d (fromElfSegmentFlags (phdrSegmentFlags p))
  <> putWord64 d (fromFileOffset (phdrFileStart p))
  <> putWord64 d (phdrSegmentVirtAddr p)
  <> putWord64 d (phdrSegmentPhysAddr p)
  <> putWord64 d (phdrFileSize p)
  <> putWord64 d (phdrMemSize p)
  <> putWord64 d (phdrSegmentAlign p)

-- | Encode a single program header
encodePhdr :: ElfClass w -> ElfData -> Phdr w -> Bld.Builder
encodePhdr cl d p =
  case cl of
    ELFCLASS32 -> encodePhdr32 d p
    ELFCLASS64 -> encodePhdr64 d p

-- | Encode program header table
encodePhdrTable :: ElfClass w -> ElfData -> [Phdr w] -> Bld.Builder
encodePhdrTable cl d l = mconcat $ encodePhdr cl d <$> l
