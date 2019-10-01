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
   | AndroidInvalidValue

instance Show AndroidDecodeError where
  show (AndroidUnsupportedFormat pr) =  "Unsupported relocations format: " ++ show pr
  show AndroidEndOfData = "Data terminated before all entries read"
  show AndroidInvalidValue = "Value read from stream is out of range."

type ReaderFn a = BS.ByteString -> Maybe (a, BS.ByteString)

-- | A parser for reading from a strict bytestring.
newtype Parser s a = Parser (ReaderT (STRef s BS.ByteString, ReaderFn Integer)
                            (ExceptT AndroidDecodeError (ST s)) a)
  deriving (Functor, Applicative, Monad)

-- | Run a parse on the bytestring.
runParser :: ReaderFn Integer
          -> BS.ByteString
          -> Parser s a
          -> ST s (Either AndroidDecodeError a)
runParser f s (Parser p) = do
  r <- newSTRef s
  runExceptT $ runReaderT p (r,f)


doRead :: Parser s Integer
doRead = Parser $ ReaderT $ \(r,f) -> ExceptT $ do
  s <- readSTRef r
  case f s of
    Nothing -> do
      pure (Left AndroidEndOfData)
    Just (v,t) -> seq v $ do
      writeSTRef r $! t
      pure (Right v)

readUBounded :: forall s a . (Integral a, Bounded a) => Parser s a
readUBounded = do
  v <- doRead
  when (v < 0 || v > toInteger (maxBound :: a)) $
    Parser $ throwError AndroidInvalidValue
  pure (fromIntegral v)

readBounded :: Num a => Parser s a
readBounded = fromIntegral <$> doRead

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
             , Integral (ElfIntType  (RelocationWidth a))
             , Bounded  (ElfIntType  (RelocationWidth a))
             , Integral (ElfWordType (RelocationWidth a))
             , Bounded  (ElfWordType (RelocationWidth a))
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
          (grOffset gr +) <$> readBounded
      info <-
        if groupFlags `hasFlag` relocationGroupedByInfoFlag then
          pure $! grInfo gr
         else
          readBounded
      addend <-
        if (groupFlags `hasFlag` relocationGroupHasAddendFlag)
           && not (groupFlags `hasFlag` relocationGroupedByAddendFlag) then
          (grAddend gr +) <$> readBounded
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
              , Integral (ElfIntType  (RelocationWidth a))
              , Bounded  (ElfIntType  (RelocationWidth a))
              , Integral (ElfWordType (RelocationWidth a))
              , Bounded  (ElfWordType (RelocationWidth a))
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
      groupSize <- readUBounded
      groupFlags <- readBounded
      groupOffsetDelta <-
        if groupFlags `hasFlag` relocationGroupedByOffsetDeltaFlag then
          readBounded
         else
          pure 0
      info <-
        if groupFlags `hasFlag` relocationGroupedByInfoFlag then
          readBounded
         else
          pure (grInfo gr)
      addend <-
        if not (groupFlags `hasFlag` relocationGroupHasAddendFlag) then
          pure 0
         else if groupFlags `hasFlag` relocationGroupedByAddendFlag then
          (grAddend gr+) <$> readBounded
         else
          pure (grAddend gr)

      let gr1 = gr { grInfo = info, grAddend = addend }
      gr2 <- readGroup cl mv (grCount gr + groupSize) groupFlags groupOffsetDelta gr1
      readGroups cl mv totalCount gr2

nextSLEB128' :: BS.ByteString
             -> Int
             -> Natural
             -> Maybe (Integer,BS.ByteString)
nextSLEB128' s w v = seq w $ seq v $ do
  (b,t) <- BS.uncons s
  let w' = w+7
  let v' = v .|. (fromIntegral b .&. 0x7f) `shiftL` w
  if b `testBit` 7 then
    nextSLEB128' t w' v'
   else do
    let signedV = if b `testBit` 6 then toInteger v' - bit w' else toInteger v'
    seq signedV $ Just (signedV, t)

nextSLEB128 :: BS.ByteString -> Maybe (Integer, BS.ByteString)
nextSLEB128 s = do
  (b,t) <- BS.uncons s
  let v = fromIntegral b .&. 0x7f
  if b `testBit` 7 then do
    nextSLEB128' t 7 v
   else do
    let signedV = if b `testBit` 6 then toInteger v - bit 7 else toInteger v
    seq signedV $ Just (signedV, t)

nextULEB128' :: BS.ByteString
             -> Int
             -> Natural
             -> Maybe (Integer,BS.ByteString)
nextULEB128' s w v = seq w $ seq v $ do
  (b,t) <- BS.uncons s
  let w' = w+7
  let v' = v .|. (fromIntegral b .&. 0x7f) `shiftL` w
  if b `testBit` 7 then
    nextULEB128' t w' v'
   else do
    let signedV = toInteger v'
    seq signedV $ Just (signedV, t)

nextULEB128 :: BS.ByteString -> Maybe (Integer, BS.ByteString)
nextULEB128 s = do
  (b,t) <- BS.uncons s
  let v = fromIntegral b .&. 0x7f
  if b `testBit` 7 then do
    nextULEB128' t 7 v
   else do
    let signedV = toInteger v
    seq signedV $ Just (signedV, t)

decodeAP :: forall a
         .  ( IsRelocationType a
            , Integral (ElfIntType  (RelocationWidth a))
            , Bounded  (ElfIntType  (RelocationWidth a))
            , Integral (ElfWordType (RelocationWidth a))
            , Bounded (ElfWordType (RelocationWidth a))
            )
         => ReaderFn Integer
         -> BS.ByteString
         -> Either AndroidDecodeError (V.Vector (RelaEntry a))
decodeAP f r = V.createT $ runParser f r $ do
  totalCount <- readUBounded
  offset     <- readBounded
  mv <- liftST $ MV.new totalCount
  let gr = RS { grCount = 0
              , grOffset = offset
              , grInfo = 0
              , grAddend = 0
              }
  readGroups (relaWidth (undefined :: a)) mv totalCount gr
  return mv

-- | Decode a strict bytestring into relocations in the compressed
-- Android format.
decodeAndroidRelaEntries :: forall a
                        .  ( IsRelocationType a
                           , Integral (ElfIntType  (RelocationWidth a))
                           , Bounded  (ElfIntType  (RelocationWidth a))
                           , Integral (ElfWordType (RelocationWidth a))
                           , Bounded (ElfWordType (RelocationWidth a))
                           )
                         => BS.ByteString
                         -> Either AndroidDecodeError (V.Vector (RelaEntry a))
decodeAndroidRelaEntries s = do
  let pr = BS.take 4 s
  let r = BS.drop 4 s
  case pr of
    "APS2" -> decodeAP nextSLEB128 r
    "APU2" -> decodeAP nextULEB128 r
    _ -> do
      Left $ AndroidUnsupportedFormat pr
