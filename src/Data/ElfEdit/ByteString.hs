{-|
Declares some basic primitives from extract words/ints from byte
strings.
-}
module Data.ElfEdit.ByteString
  ( bsWord16be
  , bsWord16le
  , bsWord32be
  , bsWord32le
  , bsWord64be
  , bsWord64le
  ) where

import           Data.Bits
import qualified Data.ByteString as BS
import qualified Data.ByteString.Unsafe as BS
import           Data.Word
import           GHC.Stack (HasCallStack)

-- | Extract a big endian Word16 from 2-byte bytestring.
bsWord16be :: HasCallStack => BS.ByteString -> Word16
bsWord16be bs
    | BS.length bs < 2 = error "bsWord16be given bytestring with bad length."
    | otherwise = w 0 1 .|. w 1 0
  where w j i = fromIntegral (BS.unsafeIndex bs j) `shiftL` (i `shiftL` 3)

-- | Extract a little endian Word16 from 2-byte bytestring.
bsWord16le :: HasCallStack => BS.ByteString -> Word16
bsWord16le bs
    | BS.length bs < 2 = error "bsWord16le given bytestring with bad length."
    | otherwise = w 1 .|. w 0
  where w i = fromIntegral (BS.unsafeIndex bs i) `shiftL` (i `shiftL` 3)

-- | Extract a big endian Word32 from 4-byte bytestring.
bsWord32be :: HasCallStack => BS.ByteString -> Word32
bsWord32be bs
    | BS.length bs < 4 = error "bsWord32be given bytestring with bad length."
    | otherwise = w 3 .|. w 2 .|. w 1 .|. w 0
  where w i = fromIntegral (BS.unsafeIndex bs (3-i)) `shiftL` (i `shiftL` 3)

-- | Extract a little endian Word32 from 4-byte bytestring.
bsWord32le :: HasCallStack => BS.ByteString -> Word32
bsWord32le bs
    | BS.length bs < 4 = error "bsWord32le given bytestring with bad length."
    | otherwise = w 3 .|. w 2 .|. w 1 .|. w 0
  where w i = fromIntegral (BS.unsafeIndex bs i) `shiftL` (i `shiftL` 3)

-- | Extract a big endian Word64 from 8-byte bytestring.
bsWord64be :: HasCallStack => BS.ByteString -> Word64
bsWord64be bs
    | BS.length bs < 8 = error "bsWord64be given bytestring with bad length."
    | otherwise = w 7 .|. w 6 .|. w 5 .|. w 4 .|. w 3 .|. w 2 .|. w 1 .|. w 0
  where w i = fromIntegral (BS.unsafeIndex bs (7-i)) `shiftL` (i `shiftL` 3)

-- | Extract a little endian Word64 from 8-byte bytestring.
bsWord64le :: HasCallStack => BS.ByteString -> Word64
bsWord64le bs
    | BS.length bs < 8 = error "bsWord64le given bytestring with bad length."
    | otherwise = w 7 .|. w 6 .|. w 5 .|. w 4 .|. w 3 .|. w 2 .|. w 1 .|. w 0
  where w i = fromIntegral (BS.unsafeIndex bs i) `shiftL` (i `shiftL` 3)
