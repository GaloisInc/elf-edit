{-|
Common types for relocations.
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
module Data.ElfEdit.Relocations.Common
  ( -- ** Class
    IsRelocationType(..)
  , RelocationWord
  , RelocationInt
    -- ** Rel entries
  , RelEntry(..)
  , decodeRelEntries
  , decodeRelEntry
  , relEntSize
    -- ** Rela entries
  , RelaEntry(..)
  , mkRelaEntry
  , ppRelaEntries
  , decodeRelaEntries
  , decodeRelaEntry
  , relaToRel
  , relaEntSize
  ) where

import           Data.Bits
import qualified Data.ByteString as B
import           Data.Word
import           GHC.TypeLits (Nat)
import           Text.PrettyPrint.ANSI.Leijen hiding ((<>), (<$>))

import           Data.ElfEdit.Prim.Ehdr
import           Data.ElfEdit.Utils

-- | Provide a show intance for the ElfIntType
showElfInt :: ElfClass w -> (Show (ElfIntType w) => a) -> a
showElfInt ELFCLASS32 a = a
showElfInt ELFCLASS64 a = a

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

-------------------------------------------------------------------------
-- IsRelocationType

-- | @IsRelocationType tp@ provides methods associated with
-- relocations on a particular architecture identified by @tp@.
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

-- | Synonym for Elf word with width determined by relocation type.
type RelocationWord tp = ElfWordType (RelocationWidth tp)

-- | Synonym for Elf int with width determined by relocation type.
type RelocationInt tp = ElfIntType (RelocationWidth tp)

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

-- | A relocation entry with an explicit addend
data RelaEntry tp
   = Rela { relaAddr :: !(RelocationWord tp)
            -- ^ Address at link time of location where relocation should be applied.
          , relaSym    :: !Word32
            -- ^ Index in symbol table this relocation refers to.
          , relaType   :: !tp
            -- ^ The type of relocation entry
          , relaAddend :: !(RelocationInt tp)
            -- ^ The constant addend to apply.
          }

-- | Make a relocation entry with addend from address, 32-bit info and addend.
mkRelaEntry :: IsRelocationType tp
            => ElfClass (RelocationWidth tp)
            -> RelocationWord tp
            -> RelocationWord tp
            -> RelocationInt tp
            -> RelaEntry tp
mkRelaEntry cl addr info addend =
  Rela { relaAddr = addr
       , relaSym  = relocationSymIndex cl info
       , relaType = toRelocType (relocationTypeVal cl info)
       , relaAddend = addend
       }

relaToRel :: RelaEntry tp -> RelEntry tp
relaToRel r = Rel { relAddr  = relaAddr r
                  , relSym  = relaSym r
                  , relType = relaType r
                  }

instance IsRelocationType tp => Show (RelaEntry tp) where
  show r =  s ""
    where cl :: ElfClass (RelocationWidth tp)
          cl = relaWidth (relaType r)
          s = showString "Rela "
            . showString (ppElfWordHex cl (relaAddr r))
            . showChar ' '
            . showsPrec 10 (relaSym r)
            . showChar ' '
            . showsPrec 10 (relaType r)
            . showChar ' '
            . showElfInt cl (showsPrec 10 (relaAddend r))

-- | Convert info parameter to relocation sym.
relocationTypeVal :: ElfClass w -> ElfWordType w -> Word32
relocationTypeVal ELFCLASS32 info = info .&. 0xff
relocationTypeVal ELFCLASS64 info = fromIntegral (info .&. 0xffffffff)

-- | Get a word at a particular offset in a bytestring
relWord :: ElfClass w -- ^ 32/64bit flag
        -> ElfData    -- ^ Endianness
        -> B.ByteString -- ^ Bytestring
        -> Int        -- ^ Offset in bytes of word.
        -> ElfWordType w
relWord ELFCLASS32 d bs i = decodeWord32 d (B.take 4 (B.drop i bs))
relWord ELFCLASS64 d bs i = decodeWord64 d (B.take 8 (B.drop i bs))

-- | Get a word at a particular offset in a bytestring
relInt :: ElfClass w -- ^ 32/64bit flag
       -> ElfData    -- ^ Endianness
       -> B.ByteString -- ^ Bytestring
       -> Int        -- ^ Offset in bytes of word.
       -> ElfIntType w
relInt ELFCLASS32 d bs i = fromIntegral $ decodeWord32 d (B.take 4 (B.drop i bs))
relInt ELFCLASS64 d bs i = fromIntegral $ decodeWord64 d (B.take 8 (B.drop i bs))

-- | Return the relocation entry at the given index.
decodeRelEntry :: forall tp
               .  IsRelocationType tp
               => ElfData
               -> B.ByteString
               -> Int -- ^ Index of rel entry
               -> RelEntry tp
decodeRelEntry dta bs idx =
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
decodeRelEntries :: forall tp
                 .  IsRelocationType tp
                 => ElfData -- ^ Endianess of encodings
                 -> B.ByteString -- ^ Relocation entries
                 -> Either String [RelEntry tp]
decodeRelEntries d bs = do
  let cl :: ElfClass (RelocationWidth tp)
      cl = relaWidth (undefined :: tp)
  case B.length bs `quotRem` relEntSize cl of
    (n, 0) -> Right $ decodeRelEntry d bs <$> [0..fromIntegral n-1]
    _      -> Left $ "Rel buffer must be a multiple of rel entry size."

-- | Return the rela entr at the given index.
decodeRelaEntry :: forall tp
             .  IsRelocationType tp
             => ElfData
             -> B.ByteString
             -> Int -- ^ Index of rela entry.
             -> RelaEntry tp
decodeRelaEntry dta bs idx =
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
decodeRelaEntries :: forall tp
                  .  IsRelocationType tp
                  => ElfData -- ^ Endianess of encodings
                  -> B.ByteString -- ^ Relocation entries
                  -> Either String [RelaEntry tp]
decodeRelaEntries d bs = do
  let cl :: ElfClass (RelocationWidth tp)
      cl = relaWidth (undefined :: tp)
  case B.length bs `quotRem` relaEntSize cl of
    (n, 0) -> Right $ decodeRelaEntry d bs <$> [0..fromIntegral n-1]
    _      -> Left $ "Rela buffer must be a multiple of rela entry size."

-- | Pretty-print a table of relocation entries.
ppRelaEntries :: IsRelocationType tp => [RelaEntry tp] -> Doc
ppRelaEntries l = fixTableColumns (snd <$> cols) (fmap fst cols : entries)
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
