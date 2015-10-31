-- | Provides an interface similar to Data.Binary.Builder that
-- permits computing the length of the bytes without
-- evaluating the underling ByteString values.
module Data.Binary.Builder.Sized
  ( -- * The Builder type
    Builder
  , toLazyByteString
  , toStrictByteString
  , length
    -- * Constructing Builders
  , empty
  , singleton
  , append
  , fromByteString
  , fromLazyByteString
    -- * Derived Builders
    -- ** Big-endian writes
  , putWord16be
  , putWord32be
  , putWord64be
    -- ** Little-endian writes
  , putWord16le
  , putWord32le
  , putWord64le
    -- ** Host-endian, unaligned writes
  , putWordhost
  , putWord16host
  , putWord32host
  , putWord64host
  ) where

import qualified Data.Binary.Builder as U
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import           Data.Int (Int64)
import           Data.Monoid
import           Data.Word
import           Foreign.Storable
import           Prelude hiding (length)

data Builder = SB !Int64 U.Builder

toLazyByteString :: Builder -> L.ByteString
toLazyByteString (SB _ b) = U.toLazyByteString b

toStrictByteString :: Builder -> B.ByteString
toStrictByteString = B.concat . L.toChunks . toLazyByteString

-- | Returns the number of length of the underlying ByteString.
--
--  * @'length' ('toLazyByteString' b) = 'length' b@
length :: Builder -> Int64
length (SB w _) = w

-- | The empty Builder, satisfying
--
--  * @'toLazyByteString' 'empty' = 'L.empty'@
empty :: Builder
empty = SB 0 U.empty

singleton :: Word8 -> Builder
singleton w = SB 1 (U.singleton w)

append :: Builder -> Builder -> Builder
append (SB sx bx) (SB sy by) = SB (sx + sy) (bx `U.append` by)

instance Monoid Builder where
  mempty = empty
  mappend = append

fromByteString :: B.ByteString -> Builder
fromByteString b = SB (fromIntegral (B.length b)) (U.fromByteString b)

fromLazyByteString :: L.ByteString -> Builder
fromLazyByteString b = SB (L.length b) (U.fromLazyByteString b)

putWord16be :: Word16 -> Builder
putWord16be w = SB 2 (U.putWord16be w)

putWord16le :: Word16 -> Builder
putWord16le w = SB 2 (U.putWord16le w)

putWord32be :: Word32 -> Builder
putWord32be w = SB 4 (U.putWord32be w)

putWord32le :: Word32 -> Builder
putWord32le w = SB 4 (U.putWord32le w)

putWord64be :: Word64 -> Builder
putWord64be w = SB 8 (U.putWord64be w)

putWord64le :: Word64 -> Builder
putWord64le w = SB 8 (U.putWord64le w)

putWordhost :: Word -> Builder
putWordhost = SB sz . U.putWordhost
  where sz = fromIntegral $ sizeOf (undefined :: Word)

putWord16host :: Word16 -> Builder
putWord16host = SB 2 . U.putWord16host

putWord32host :: Word32 -> Builder
putWord32host = SB 4 . U.putWord32host

putWord64host :: Word64 -> Builder
putWord64host = SB 8 . U.putWord64host
