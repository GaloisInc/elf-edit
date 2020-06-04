{-|
Module      : Data.ElfEdit.Relocations
Copyright   : (c) Galois Inc, 2016
License     : BSD
Maintainer  : jhendrix@galois.com

This contains definitions and utilities used for relocations.
-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilies #-}
#if __GLASGOW_HASKELL >= 800
{-# OPTIONS_GHC -fno-warn-missing-pattern-synonym-signatures #-}
#endif
module Data.ElfEdit.Relocations
  ( -- * Relocation types
    IsRelocationType(..)
  , RelocationWord
  , RelEntry(..)
  , RelaEntry(..)
  , relOffset
  , relaOffset
  , relaToRel
  , relocationSymIndex
  , relocationTypeVal
  , isRelativeRelaEntry
  , ppRelaEntries
  , elfRelEntries
  , elfRelaEntries
  , relEntry
  , relaEntry
    -- ** Relocation width
  , relEntSize
  , relaEntSize
  , getRelaWord
    -- * Utilities
    -- ** ElfWordType
  , ElfWordType
    -- ** ElfIntType
  , ElfIntType
  , showElfInt
    -- ** Binary
  , runGetMany
    -- ** Table alignment
  , ColumnAlignmentFn
  , alignLeft
  , alignRight
  , fix_table_columns
  ) where

import           Data.Binary.Get
import           Data.Bits
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as L
import           Data.Int
import           Data.List (transpose)
import           Data.Word
import           GHC.TypeLits (Nat)
import           Text.PrettyPrint.ANSI.Leijen hiding ((<>), (<$>))

import           Data.ElfEdit.ByteString
import           Data.ElfEdit.Get (getWord32, getWord64, runGetMany)
import           Data.ElfEdit.Types (ElfData(..), ppHex, ElfClass(..), ElfWordType)

-------------------------------------------------------------------------
-- ColumnAlignmentFn

type ColumnAlignmentFn = [String] -> [String]

alignLeft :: Int -> ColumnAlignmentFn
alignLeft minw l = ar <$> l
  where w = maximum $ minw : (length <$> l)
        ar s = s ++ replicate (w-n) ' '
          where n = length s

alignRight :: Int -> ColumnAlignmentFn
alignRight minw l = ar <$> l
  where w = maximum $ minw : (length <$> l)
        ar s = replicate (w-n) ' ' ++ s
          where n = length s

-- | Function for pretty printing a row of tables according to
-- rules for each column.
fix_table_columns :: [ColumnAlignmentFn]
                     -- ^ Functions for modifying each column
                  -> [[String]]
                  -> Doc
fix_table_columns colFns rows = vcat (hsep . fmap text <$> fixed_rows)
  where cols = transpose rows
        fixed_cols = zipWith ($) colFns cols
        fixed_rows = transpose fixed_cols


-------------------------------------------------------------------------
-- ElfWordType

ppElfWordHex :: ElfClass w -> ElfWordType w -> String
ppElfWordHex ELFCLASS32 = ppHex
ppElfWordHex ELFCLASS64 = ppHex

{-# INLINE relValueSize #-}
relValueSize :: Num a => ElfClass w -> a
relValueSize ELFCLASS32 = 4
relValueSize ELFCLASS64 = 8

-- | Size of one relocation entry with implicit addend.
relEntSize :: Num a => ElfClass w -> a
relEntSize  cl = 2 * relValueSize cl

-- | Size of one relocation entry with explicit addend.
relaEntSize :: Num a => ElfClass w -> a
relaEntSize cl = 3 * relValueSize cl

-- | Convert info parameter to relocation sym.
relocationSymIndex :: ElfClass w -> ElfWordType w -> Word32
relocationSymIndex ELFCLASS32 info = info `shiftR` 8
relocationSymIndex ELFCLASS64 info = fromIntegral (info `shiftR` 32)

getRelaWord :: ElfClass w -> ElfData -> Get (ElfWordType w)
getRelaWord ELFCLASS32 = getWord32
getRelaWord ELFCLASS64 = getWord64

-------------------------------------------------------------------------
-- ElfIntType

-- | A signed value of a given width
type family ElfIntType (w::Nat) :: *
type instance ElfIntType 32 = Int32
type instance ElfIntType 64 = Int64

-- | Provide a show intance for the ElfIntType
showElfInt :: ElfClass w -> (Show (ElfIntType w) => a) -> a
showElfInt ELFCLASS32 a = a
showElfInt ELFCLASS64 a = a

-------------------------------------------------------------------------
-- IsRelocationType

-- | 'IsRelocationType tp' provide methods associated with
-- relocations on a particular architecture identified by 'tp'.
--
-- Each architecture uses either a 32 or 64-bit Elf encoding, and
-- this is associated via a type family 'RelocationWidth'
class (Show tp, Show (RelocationWord tp)) => IsRelocationType tp where
  -- How many bits are used in encoding relocation type.
  type RelocationWidth tp :: Nat

  -- | Return the width associated with encodings of relocation type.
  --
  -- The argument is used for typing purposes, and should not actually be evaluated.
  relaWidth :: tp -> ElfClass (RelocationWidth tp)

  -- | Return the number of bits that the rel entry should use for the addend.
  --
  -- This is commonly the size of a pointer, but may be smaller for some
  -- relocation types.  This is used for rel entries, where to compute
  -- the addend the next @ceiling (bits/8)@ bytes is read out of memory
  -- as a list of bytes and the low @bits@ are interpreted as a signed
  -- integer (where low uses the elf's endianness) and sign extended.
  relocTargetBits :: tp -> Int

  -- | Convert a word from a relocation entry to the type.
  toRelocType :: Word32 -> tp

  -- | Return true if this is a relative relocation type.
  isRelative :: tp -> Bool

type RelocationWord tp = ElfWordType (RelocationWidth tp)

-------------------------------------------------------------------------
-- RelaEntry

-- | A relocation entry with an implicit addend that is stored in the
-- offset being applied.
data RelEntry tp
   = Rel { relAddr :: !(RelocationWord tp)
           -- ^ Address at link time of location where relocation should be applied.
         , relSym    :: !Word32
           -- ^ Index in symbol table this relocation refers to.
         , relType   :: !tp
           -- ^ The type of relocation entry
         }

-- | Address at link time of location where relocation should be applied.
relOffset :: RelEntry tp -> RelocationWord tp
relOffset = relAddr
{-# DEPRECATED relOffset "Use relAddr" #-}

-- | A relocation entry with an explicit addend
data RelaEntry tp
   = Rela { relaAddr :: !(RelocationWord tp)
            -- ^ Address at link time of location where relocation should be applied.
          , relaSym    :: !Word32
            -- ^ Index in symbol table this relocation refers to.
          , relaType   :: !tp
            -- ^ The type of relocation entry
          , relaAddend :: !(ElfIntType (RelocationWidth tp))
            -- ^ The constant addend to apply.
          }

-- | Address at link time of location where relocation should be applied.
relaOffset :: RelaEntry tp -> RelocationWord tp
relaOffset = relaAddr
{-# DEPRECATED relaOffset "Use relaAddr" #-}

relaToRel :: RelaEntry tp -> RelEntry tp
relaToRel r = Rel { relAddr  = relaAddr r
                  , relSym  = relaSym r
                  , relType = relaType r
                  }

instance IsRelocationType tp => Show (RelaEntry tp) where
  show r =  s ""
    where w :: ElfClass (RelocationWidth tp)
          w = relaWidth (relaType r)
          s = showString "Rela "
            . showString (ppElfWordHex w (relaAddr r))
            . showChar ' '
            . showsPrec 10 (relaSym r)
            . showChar ' '
            . showsPrec 10 (relaType r)
            . showChar ' '
            . showElfInt w (showsPrec 10 (relaAddend r))

-- | Return true if this is a relative relocation entry.
isRelativeRelaEntry :: IsRelocationType tp => RelaEntry tp -> Bool
isRelativeRelaEntry r = isRelative (relaType r)

-- | Convert info parameter to relocation sym.
relocationTypeVal :: ElfClass w -> ElfWordType w -> Word32
relocationTypeVal ELFCLASS32 info = info .&. 0xff
relocationTypeVal ELFCLASS64 info = fromIntegral (info .&. 0xffffffff)

bsRelWord32 :: ElfData -> BS.ByteString -> Word32
bsRelWord32 ELFDATA2LSB = bsWord32le
bsRelWord32 ELFDATA2MSB = bsWord32be

bsRelWord64 :: ElfData -> BS.ByteString -> Word64
bsRelWord64 ELFDATA2LSB = bsWord64le
bsRelWord64 ELFDATA2MSB = bsWord64be

-- | Get a word at a particular offset in a bytestring
relWord :: ElfClass w -- ^ 32/64bit flag
        -> ElfData    -- ^ Endianness
        -> BS.ByteString -- ^ Bytestring
        -> Int        -- ^ Offset in bytes of word.
        -> ElfWordType w
relWord ELFCLASS32 dta bs i = bsRelWord32 dta (BS.take 4 (BS.drop i bs))
relWord ELFCLASS64 dta bs i = bsRelWord64 dta (BS.take 8 (BS.drop i bs))

-- | Get a word at a particular offset in a bytestring
relInt :: ElfClass w -- ^ 32/64bit flag
        -> ElfData    -- ^ Endianness
        -> BS.ByteString -- ^ Bytestring
        -> Int        -- ^ Offset in bytes of word.
        -> ElfIntType w
relInt ELFCLASS32 dta bs i = fromIntegral $ bsRelWord32 dta (BS.take 4 (BS.drop i bs))
relInt ELFCLASS64 dta bs i = fromIntegral $ bsRelWord64 dta (BS.take 8 (BS.drop i bs))

-- | Return the relocation entry at the given index.
relEntry :: forall tp
         .  IsRelocationType tp
         => ElfData
         -> BS.ByteString
         -> Int -- ^ Index of rel entry
         -> RelEntry tp
relEntry dta bs idx =
  let cl :: ElfClass (RelocationWidth tp)
      cl = relaWidth (undefined :: tp)
      sz = relValueSize cl
      off = 2 * sz * idx
      addr = relWord cl dta bs off
      info = relWord cl dta bs (off+sz)
   in Rel { relAddr   = addr
          , relSym    = relocationSymIndex cl info
          , relType   = toRelocType (relocationTypeVal cl info)
          }

-- | Return relocation entries from byte string.
elfRelEntries :: forall tp
              .  IsRelocationType tp
              => ElfData -- ^ Endianess of encodings
              -> L.ByteString -- ^ Relocation entries
              -> Either String [RelEntry tp]
elfRelEntries d bs = do
  let cl :: ElfClass (RelocationWidth tp)
      cl = relaWidth (undefined :: tp)
  case L.length bs `quotRem` relEntSize cl of
    (n, 0) -> Right $ relEntry d (L.toStrict bs) <$> [0..fromIntegral n-1]
    _      -> Left $ "Rel buffer must be a multiple of rel entry size."

-- | Return the rela entr at the given index.
relaEntry :: forall tp
             .  IsRelocationType tp
             => ElfData
             -> BS.ByteString
             -> Int -- ^ Index of rela entry.
             -> RelaEntry tp
relaEntry dta bs idx =
  let cl :: ElfClass (RelocationWidth tp)
      cl = relaWidth (undefined :: tp)
      sz = relValueSize cl
      off = 3 * sz * idx
      addr   = relWord cl dta bs off
      info   = relWord cl dta bs (off+sz)
      addend = relInt cl dta bs (off+2*sz)
   in Rela { relaAddr   = addr
           , relaSym    = relocationSymIndex cl info
           , relaType   = toRelocType (relocationTypeVal cl info)
           , relaAddend = addend
           }

-- | Return relocation entries from byte string.
elfRelaEntries :: forall tp
              .  IsRelocationType tp
              => ElfData -- ^ Endianess of encodings
              -> L.ByteString -- ^ Relocation entries
              -> Either String [RelaEntry tp]
elfRelaEntries d bs = do
  let cl :: ElfClass (RelocationWidth tp)
      cl = relaWidth (undefined :: tp)
  case L.length bs `quotRem` relaEntSize cl of
    (n, 0) -> Right $ relaEntry d (L.toStrict bs) <$> [0..fromIntegral n-1]
    _      -> Left $ "Rela buffer must be a multiple of rela entry size."

-- | Pretty-print a table of relocation entries.
ppRelaEntries :: IsRelocationType tp => [RelaEntry tp] -> Doc
ppRelaEntries l = fix_table_columns (snd <$> cols) (fmap fst cols : entries)
  where entries = zipWith ppRelaEntry [0..] l
        cols = [ ("Num",    alignRight 0)
               , ("Offset", alignLeft  0)
               , ("Symbol", alignLeft  0)
               , ("Type",   alignLeft  0)
               , ("Addend", alignLeft  0)
               ]

-- | Pretty print fields in a relocation entry.
ppRelaEntry :: IsRelocationType tp => Int -> RelaEntry tp -> [String]
ppRelaEntry i e =
  [ shows i ":"
  , ppElfWordHex (relaWidth (relaType e)) (relaAddr e)
  , show (relaSym e)
  , show (relaType e)
  , showElfInt (relaWidth (relaType e)) $ show (relaAddend e)
  ]
