{-
Copyright        : (c) Galois, Inc 2020
Maintainer       : Joe Hendrix <jhendrix@galois.com>

A datatype for reasoning about the virtual address space.

TODO(lb): Should all the phdrFileSizes be phdrMemSize?
-}

{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE PatternGuards #-}
{-# LANGUAGE UndecidableInstances #-}

module Data.ElfEdit.VirtAddrMap
  ( VirtAddrMap
  , virtAddrMap
  , lookupVirtAddrContents
  ) where

import           Control.Applicative ((<|>))
import           Data.Foldable
import qualified Data.ByteString.Lazy as L
import qualified Data.Map.Strict as Map

import           Data.ElfEdit.Layout
import           Data.ElfEdit.Types

-- | Maps the start of memory offsets in Elf file to the file contents backing that
-- memory
newtype VirtAddrMap w = VAM (Map.Map (ElfWordType w) (Phdr w, L.ByteString))

instance (Show (ElfWordType w), Integral (ElfWordType w)) => Show (VirtAddrMap w) where
  show (VAM m) = "VAM (" ++ show m ++ ")"

-- | Creates a virtual address map from an 'ElfLayout'.
--
-- Returns 'Nothing' if the map could not be created due to overlapping segments.
virtAddrMap :: Integral (ElfWordType w)
            => ElfLayout w
            -> Maybe (VirtAddrMap w)
virtAddrMap layout = VAM <$> foldlM ins Map.empty (allPhdrs layout)
  where -- Insert phdr into map if it is loadable
        ins m phdr
            -- If segment is not loadable or empty, leave map unchanged
          | phdrSegmentType phdr /= PT_LOAD || n == 0 = pure m
            -- If segment overlaps with a previous segment, then return
            -- 'Nothing' to indicate an error.
          | Just (prev, (old, _)) <- Map.lookupLE addr m
          , addr - prev < phdrFileSize old = Nothing
            -- Insert phdr into map
          | otherwise =
            pure $! Map.insert addr (phdr, new_contents) m
          where addr = phdrSegmentVirtAddr phdr
                FileOffset dta = phdrFileStart phdr
                n              = phdrFileSize phdr
                new_contents   = sliceL (dta,n) file
                file = elfLayoutBytes layout

-- | Find a segment that containing this address, if there is one
lookupContaining :: (Num (ElfWordType w), Ord (ElfWordType w))
                 => ElfWordType w
                 -> VirtAddrMap w
                 -> Maybe (Phdr w, L.ByteString)
lookupContaining addr (VAM m) =
  case Map.lookupLE addr m of
    Just (prev, v@(header, _)) | addr - prev <= phdrFileSize header -> Just v
    _ -> Nothing

-- | Find a segment that overlaps with this range, if there is one
lookupRange :: (Num (ElfWordType w), Ord (ElfWordType w))
            => ElfWordType w {-^ Low address -}
            -> ElfWordType w {-^ High address -}
            -> VirtAddrMap w
            -> Maybe (Phdr w, L.ByteString)
lookupRange lowAddr highAddr vam@(VAM m) =
  lookupContaining lowAddr vam <|>
    case Map.lookupLE highAddr m of
      Just (prev, v@(header, _)) | lowAddr < prev + phdrFileSize header -> Just v
      _ -> Nothing

-- | Return the contents in the Elf file starting from the given address
-- offset.
lookupVirtAddrContents :: Integral (ElfWordType w)
                       => ElfWordType w
                       -> VirtAddrMap w
                       -> Maybe L.ByteString
lookupVirtAddrContents addr m =
  case lookupContaining addr m of
    Just (header, contents) -> do
      let seg_offset = addr - phdrSegmentVirtAddr header
      Just $! L.drop (fromIntegral seg_offset) contents
    _ -> Nothing
