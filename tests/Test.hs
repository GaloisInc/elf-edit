{-# LANGUAGE RankNTypes #-}
module Main where

import Control.Applicative
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy as LB
import qualified Data.Map as Map
import Data.Word ( Word32 )
import qualified System.IO as IO
import qualified Test.Tasty as T
import qualified Test.Tasty.HUnit as T
import qualified Test.Tasty.QuickCheck as T

import Prelude

import           Data.Elf

testEmptyElf :: T.Assertion
testEmptyElf = IO.withBinaryFile "./tests/empty.elf" IO.ReadMode $ \h -> do
  fil <- B.hGetContents h
  case parseElf fil of
    Left  _e -> return ()
    Right _a -> T.assertFailure "Empty ELF did not cause an exception."

testIdentityTransform :: FilePath -> T.Assertion
testIdentityTransform fp = do
  bs <- B.readFile fp
  withElf bs $ \e -> do
    int0 <- elfInterpreter e
    withElf (LB.toStrict (renderElf e)) $ \e' -> do
      T.assertEqual "Segment Count" (length (elfSegments e)) (length (elfSegments e'))
      let ex = concat (parseSymbolTables e)
          act = concat (parseSymbolTables e')
      T.assertEqual "Symbol table sizes" (length ex) (length act)
      int1 <- elfInterpreter e'
      T.assertEqual "Interpreter" int0 int1

stringTableConsistencyProp :: [AsciiString] -> Bool
stringTableConsistencyProp strings =
  all (checkStringTableEntry bytes) (Map.toList tab)
  where
    (bytes, tab) = stringTable (map unwrapAsciiString strings)

checkStringTableEntry :: C8.ByteString -> (String, Word32) -> Bool
checkStringTableEntry bytes (str, off) = str == C8.unpack bstr
  where
    bstr = C8.take (length str) $ C8.drop (fromIntegral off) bytes

withElf :: B.ByteString -> (forall w . Elf w -> T.Assertion) -> T.Assertion
withElf bs f =
  case parseElf bs of
    Left e -> T.assertFailure ("Failed to parse elf file: " ++ show e)
    Right (Elf32 e32) -> f e32
    Right (Elf64 e64) -> f e64

tests :: T.TestTree
tests = T.testGroup "ELF Tests"
    [ T.testCase "Empty ELF" testEmptyElf
    , T.testCase "Identity Transformation (simple static)" (testIdentityTransform "./tests/simple.static.elf")
    , T.testCase "Identity Transformation (simple)" (testIdentityTransform "./tests/simple.elf")
    , T.testProperty "stringTable consistency" stringTableConsistencyProp
    ]

main :: IO ()
main = T.defaultMain tests

newtype AsciiString = AsciiString { unwrapAsciiString :: String }
                    deriving (Show)

instance T.Arbitrary AsciiString where
  arbitrary = AsciiString <$> genAsciiString

genAsciiString :: T.Gen String
genAsciiString = T.listOf genAsciiChar

genAsciiChar :: T.Gen Char
genAsciiChar = T.elements (['a'..'z'] ++ ['A'..'Z'])
