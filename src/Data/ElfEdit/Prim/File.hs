{-|
Declarations for working with file offsets and ranges.
-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Data.ElfEdit.Prim.File
  ( -- * FileOffset
    FileOffset(..)
  , startOfFile
  , incOffset
  , isAligned
  , alignFileOffset
    -- * FileRange
  , FileRange
  , inFileRange
  , isValidFileRange
  , slice
  ) where

import           Data.Bits
import qualified Data.ByteString as B

------------------------------------------------------------------------
-- FileOffset

-- | A offset in the file.
--
-- This is just a newtype to avoid confusing with address offsets.
newtype FileOffset w = FileOffset { fromFileOffset :: w }
  deriving (Eq, Ord, Enum, Integral, Num, Real)

instance Show w => Show (FileOffset w) where
  show (FileOffset o) = show o

-- | Initial file offset.
startOfFile :: Num w => FileOffset w
startOfFile = FileOffset 0

-- | Increment file offset.
incOffset :: Num w => FileOffset w -> w -> FileOffset w
incOffset (FileOffset b) o = FileOffset (b + o)

-- | @isAligned off align@ checks that @off@ is an
-- of @align@ not less than @offset@.
--
-- Note. This throws an error is the alignment is not a power of two.
isAligned :: (Bits w, Num w) => FileOffset w -> w -> Bool
isAligned (FileOffset o) align
  | align .&. (align - 1) /= 0 = error "alignments must be power of two."
  | otherwise = (o .&. (align - 1)) == 0

-- | @alignFileOffset align off@ rounds @off@ to the smallest multiple
-- of @align@ not less than  @offset@.
alignFileOffset :: (Bits w, Num w) => w -> FileOffset w -> FileOffset w
alignFileOffset align (FileOffset o) = FileOffset $ (o + (align - 1)) .&. complement (align - 1)


------------------------------------------------------------------------
-- FileRange

-- | A range contains a starting index and a byte count.
type FileRange w = (FileOffset w, w)

inFileRange :: (Ord w, Num w) => w -> FileRange w -> Bool
inFileRange w (FileOffset s,c) = s <= w && (w-s) < c

slice :: Integral w => FileRange w -> B.ByteString -> B.ByteString
slice (i,c) = B.take (fromIntegral c) . B.drop (fromIntegral (fromFileOffset i))

-- | Return true if file range is a region of the file.
isValidFileRange :: Integral w => FileRange w -> B.ByteString -> Bool
isValidFileRange (FileOffset i, c) b =
  c == 0 || (toInteger i + toInteger c <= toInteger (B.length b))
