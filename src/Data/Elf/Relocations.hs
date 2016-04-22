{-|
Module      : Data.Elf.Relocations
Copyright   : (c) Galois Inc, 2016
License     : BSD
Maintainer  : jhendrix@galois.com

This contains definitions and utilities used for relocations.
-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}
module Data.Elf.Relocations
  ( -- * Relocation types
    IsRelocationType(..)
  , RelaEntry(..)
  , isRelativeRelaEntry
  , ppRelaEntries
  , elfRelaEntries
  , getRelaEntry
    -- ** Relocation width
  , RelaWidth(..)
  , relaEntSize
  , getRelaWord
    -- * Utilities
    -- ** ElfWordType
  , ElfWordType
  , elfWordInstances
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
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import           Data.Int
import           Data.List (transpose)
import           Data.Word
import           GHC.TypeLits (Nat)
import           Numeric (showHex)
import           Text.PrettyPrint.ANSI.Leijen hiding ((<>), (<$>))

import           Data.Elf.Get (getWord32, getWord64, runGetMany)
import           Data.Elf.Types (ElfData, ppHex)

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

-- | An unsigned value of a given width
type family ElfWordType (w::Nat) :: *
type instance ElfWordType 32 = Word32
type instance ElfWordType 64 = Word64

elfWordInstances :: RelaWidth w
                     -> (( Bits (ElfWordType w)
                        , Integral (ElfWordType w)
                        , Show (ElfWordType w)
                        )
                     => a)
                     -> a
elfWordInstances Rela32 a = a
elfWordInstances Rela64 a = a

-------------------------------------------------------------------------
-- ElfIntType

-- | A signed value of a given width
type family ElfIntType (w::Nat) :: *
type instance ElfIntType 32 = Int32
type instance ElfIntType 64 = Int64

-- | Provide a show intance for the ElfIntType
showElfInt :: RelaWidth w -> (Show (ElfIntType w) => a) -> a
showElfInt Rela32 a = a
showElfInt Rela64 a = a

-------------------------------------------------------------------------
-- RelaWidth

-- | Flags whether relocation uses 32 or 64 bit encoding.
data RelaWidth (n::Nat) where
  Rela32 :: RelaWidth 32
  Rela64 :: RelaWidth 64

-- | Size of one relocation entry.
relaEntSize :: RelaWidth w -> ElfWordType w
relaEntSize Rela32 = 12
relaEntSize Rela64 = 24

-- | Convert info parameter to relocation sym.
relaSym :: RelaWidth w -> ElfWordType w -> Word32
relaSym Rela32 info = info `shiftR` 8
relaSym Rela64 info = fromIntegral (info `shiftR` 32)

getRelaWord :: RelaWidth w -> ElfData -> Get (ElfWordType w)
getRelaWord Rela32 = getWord32
getRelaWord Rela64 = getWord64

-- | Read a signed relocation integer.
getRelaInt :: RelaWidth w -> ElfData -> Get (ElfIntType w)
getRelaInt Rela32 d = fromIntegral <$> getWord32 d
getRelaInt Rela64 d = fromIntegral <$> getWord64 d


-------------------------------------------------------------------------
-- IsRelocationType

-- | @IsRelocationType tp@ is used to provide methods associated with
-- relocations on a particular architecture identified by @tp@.
--
-- Each architecture uses either a 32 or 64-bit Elf encoding, and
-- this is associated via a type family 'RelocationWidth'
class Show tp => IsRelocationType tp where
  -- How many bits are used in encoding relocation type.
  type RelocationWidth tp :: Nat

  -- | Return the width associated with encodings of relocation type.
  --
  -- The argument is used for typing purposes, and should not actually be evaluated.
  relaWidth :: tp -> RelaWidth (RelocationWidth tp)

  -- | Convert unsigned value to type.
  relaType :: ElfWordType (RelocationWidth tp) -> Maybe tp

  -- | Return true if this is a relative relocation type.
  isRelative :: tp -> Bool

-------------------------------------------------------------------------
-- RelaEntry

-- | A relocation entry
data RelaEntry tp
   = Rela { r_offset :: !(ElfWordType (RelocationWidth tp))
            -- ^ Offset in section/segment where relocation should be applied.
          , r_sym    :: !Word32
            -- ^ Offset in symbol table entry relocation refers to.
          , r_type   :: !tp
            -- ^ The type of relocation entry
          , r_addend :: !(ElfIntType (RelocationWidth tp))
            -- ^ The constant addend to apply.
          }


instance IsRelocationType tp => Show (RelaEntry tp) where
  show r =  s ""
    where w :: RelaWidth (RelocationWidth tp)
          w = relaWidth (r_type r)
          s = showString "Rela "
            . elfWordInstances w (showsPrec 10 (r_offset r))
            . showChar ' '
            . showsPrec 10 (r_sym r)
            . showChar ' '
            . showsPrec 10 (r_type r)
            . showChar ' '
            . showElfInt w (showsPrec 10 (r_addend r))

-- | Return true if this is a relative relocation entry.
isRelativeRelaEntry :: IsRelocationType tp => RelaEntry tp -> Bool
isRelativeRelaEntry r = isRelative (r_type r)


-- | Read a relocation entry.
getRelaEntry :: forall tp . IsRelocationType tp => ElfData -> Get (RelaEntry tp)
getRelaEntry d = do
  let w :: RelaWidth (RelocationWidth tp)
      w = relaWidth (undefined :: tp)
  offset <- getRelaWord w d
  info   <- getRelaWord w d
  addend <- getRelaInt  w d
  let msg = elfWordInstances w  $ do
              "Could not parse relocation type: " ++ showHex info ""
  tp <- maybe (fail msg) return $ relaType info
  return Rela { r_offset = offset
              , r_sym    = relaSym w info
              , r_type   = tp
              , r_addend = addend
              }

-- | Return relocation entries from byte string.
elfRelaEntries :: IsRelocationType tp => ElfData -> B.ByteString -> [RelaEntry tp]
elfRelaEntries d entries = runGetMany (getRelaEntry d) (L.fromStrict entries)

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
  , elfWordInstances (relaWidth (r_type e)) $ ppHex (r_offset e)
  , show (r_sym e)
  , show (r_type e)
  , showElfInt (relaWidth (r_type e)) $ show (r_addend e)
  ]
