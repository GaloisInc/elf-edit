{-
This contains a parser for the compressed relocation table used in
Android.

-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}
module Data.ElfEdit.Relocations.Android
 ( decodeAndroidRelaEntries
 , AndroidDecodeError(..)
 ) where

import           Control.Monad.Except
import           Control.Monad.Reader
import           Control.Monad.ST
import           Data.Bits
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import           Data.STRef
import qualified Data.Vector as V
import qualified Data.Vector.Mutable as MV
import           Data.Word
import           Numeric.Natural

import Data.ElfEdit.Relocations
       ( ElfWordType, ElfIntType
       , RelocationWidth(..), RelaEntry(..)
       , relocationSymIndex, relocationTypeVal
       )
import Data.ElfEdit.Types (ElfClass)

-- | Decoding errors for relocations
data AndroidDecodeError
   = AndroidUnsupportedFormat !BS.ByteString
   | AndroidEndOfData

instance Show AndroidDecodeError where
  show (AndroidUnsupportedFormat pr) =  "Unsupported relocations format: " ++ BSC.unpack pr
  show AndroidEndOfData = "Data terminated before all entries read"

-- | A parser for reading from a strict bytestring.
newtype Parser s a = Parser (ReaderT (STRef s BS.ByteString) (ExceptT AndroidDecodeError (ST s)) a)
  deriving (Functor, Applicative, Monad)

-- | Run a parse on the bytestring.
runParser :: BS.ByteString -> Parser s a -> ST s (Either AndroidDecodeError a)
runParser s (Parser p) = do
  r <- newSTRef s
  runExceptT $ runReaderT p r


-- | Read next byte from stream
readByte :: Parser s Word8
readByte = Parser $ do
  r <- ask
  s <- lift $ lift $ readSTRef r
  case BS.uncons s of
    Nothing -> do
      throwError $ AndroidEndOfData
    Just (w,t) -> do
      lift $ lift $ writeSTRef r $! t
      pure $! w

readSLEB128' :: Int -> Natural -> Parser s Integer
readSLEB128' w v = seq w $ seq v $ do
  b <- fromIntegral <$> readByte
g  let w' = w+7
  let v' = v .|. (b .&. 0x7f) `shiftL` w
  if b `testBit` 7 then
    readSLEB128' w' v'
   else
    pure $! if b `testBit` 6 then toInteger v' - bit w' else toInteger v'

readSLEB128 :: Parser s Integer
readSLEB128 = do
  b <- fromIntegral <$> readByte
  let v' = b .&. 0x7f
  if b `testBit` 7 then
    readSLEB128' 7 v'
   else
    pure $! if b `testBit` 6 then toInteger v' - bit 7 else toInteger v'

readULEB128' :: Int -> Natural -> Parser s Natural
readULEB128' w v = seq w $ seq v $ do
  b <- fromIntegral <$> readByte
  let v' = v .|. (b .&. 0x7f) `shiftL` w
  if b `testBit` 7 then
    readULEB128' (w+7) v'
   else
    pure $! v'

readULEB128 :: Parser s Natural
readULEB128 = do
  b <- fromIntegral <$> readByte
  let v' = b .&. 0x7f
  if b `testBit` 7 then
    readULEB128' 7 v'
   else
    pure $! v'

readWord :: Num a => Parser s a
readWord = fromIntegral <$> readULEB128

readSWord :: Num a => Parser s a
readSWord = fromIntegral <$> readSLEB128

-- | State maintained while reading the relocation data.
data RelocState w = RS { grCount :: !Int
                       , grOffset :: !(ElfWordType w)
                       , grInfo   :: !(ElfWordType w)
                       , grAddend :: !(ElfIntType w)
                       }

relocationGroupedByInfoFlag :: Word64
relocationGroupedByInfoFlag = 1

relocationGroupedByOffsetDeltaFlag :: Word64
relocationGroupedByOffsetDeltaFlag = 2

relocationGroupedByAddendFlag :: Word64
relocationGroupedByAddendFlag = 4

relocationGroupHasAddendFlag :: Word64
relocationGroupHasAddendFlag = 8

hasFlag :: Word64 -> Word64 -> Bool
hasFlag x y = (x .&. y) /= 0

-- | Run a ST computation in parser.
liftST :: ST s a -> Parser s a
liftST m = Parser $ lift $ lift m

readGroup :: ( IsRelocationType a
             , Num (ElfIntType  (RelocationWidth a))
             , Num (ElfWordType (RelocationWidth a))
             )
          => ElfClass (RelocationWidth a)
          -> MV.MVector s (RelaEntry a)
          -> Int -- ^ Total count when this group ends
          -> Word64 -- ^ Group flags
          -> ElfWordType (RelocationWidth a) -- ^ Offset delta
          -> RelocState (RelocationWidth a)
          -> Parser s (RelocState (RelocationWidth a))
readGroup cl mv groupEndCount groupFlags groupOffsetDelta gr
  | grCount gr >= groupEndCount = do
      return gr
  | otherwise = do
      offset <-
        if groupFlags `hasFlag` relocationGroupedByOffsetDeltaFlag then
          pure $! grOffset gr + groupOffsetDelta
         else
          (grOffset gr +) <$> readWord
      info <-
        if groupFlags `hasFlag` relocationGroupedByInfoFlag then
          pure $! grInfo gr
         else
          readWord
      addend <-
        if (groupFlags `hasFlag` relocationGroupHasAddendFlag)
           && not (groupFlags `hasFlag` relocationGroupedByAddendFlag) then
          (grAddend gr +) <$> readSWord
         else
          pure 0
      let rela = Rela { relaAddr = offset
                      , relaSym  = relocationSymIndex cl info
                      , relaType = toRelocType (relocationTypeVal cl info)
                      , relaAddend = addend
                      }
      liftST $ MV.write mv (grCount gr) rela
      let gr2 = RS { grCount = grCount gr + 1
                   , grOffset = offset
                   , grInfo = info
                   , grAddend = addend
                   }
      readGroup cl mv groupEndCount groupFlags groupOffsetDelta gr2


readGroups :: ( IsRelocationType a
              , Num (ElfIntType  (RelocationWidth a))
              , Num (ElfWordType (RelocationWidth a))
              )
           => ElfClass (RelocationWidth a)
           -> MV.MVector s (RelaEntry a) -- ^ Vector to append elements to.
           -> Int        -- ^ Total number of entries expected
           -> RelocState (RelocationWidth a)
           -- ^ Info value
           -> Parser s ()
readGroups cl mv totalCount gr
  | grCount gr >= totalCount = do
      return ()
  | otherwise = do
      groupSize <- fromIntegral <$> readULEB128
      groupFlags <- readWord
      groupOffsetDelta <-
        if groupFlags `hasFlag` relocationGroupedByOffsetDeltaFlag then
          readWord
         else
          pure 0
      info <-
        if groupFlags `hasFlag` relocationGroupedByInfoFlag then
          readWord
         else
          pure (grInfo gr)
      addend <-
        if not (groupFlags `hasFlag` relocationGroupHasAddendFlag) then
          pure 0
         else if groupFlags `hasFlag` relocationGroupedByAddendFlag then
          (grAddend gr+) <$> readSWord
         else
          pure (grAddend gr)

      let gr1 = gr { grInfo = info, grAddend = addend }
      gr2 <- readGroup cl mv (grCount gr + groupSize) groupFlags groupOffsetDelta gr1
      readGroups cl mv totalCount gr2

-- | Decode a strict bytestring into relocations in the compressed
-- Android format.
decodeAndroidRelaEntries :: forall a
                        .  ( IsRelocationType a
                           , Num (ElfIntType  (RelocationWidth a))
                           , Num (ElfWordType (RelocationWidth a))
                           )
                         => BS.ByteString
                         -> Either AndroidDecodeError (V.Vector (RelaEntry a))
decodeAndroidRelaEntries s = do
  let pr = BS.take 4 s
  let r = BS.drop 4 s
  case pr of
    "APS2" -> V.createT $ runParser r $ do
      totalCount <- fromIntegral <$> readULEB128
      offset <- readWord
      mv <- liftST $ MV.new totalCount
      let gr = RS { grCount = 0
                  , grOffset = offset
                  , grInfo = 0
                  , grAddend = 0
                  }
      readGroups (relaWidth (undefined :: a)) mv totalCount gr
      return mv
    _ -> do
      Left $ AndroidUnsupportedFormat pr
