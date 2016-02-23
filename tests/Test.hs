{-# LANGUAGE RankNTypes #-}
module Main where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as LB
import           Data.Elf
import           System.IO
import           Test.HUnit

testEmptyElf :: Assertion
testEmptyElf = withBinaryFile "./tests/empty.elf" ReadMode $ \h -> do
  fil <- B.hGetContents h
  case parseElf fil of
    Left  _e -> return ()
    Right _a -> assertFailure "Empty ELF did not cause an exception."

testIdentityTransform :: FilePath -> Assertion
testIdentityTransform fp = do
  bs <- B.readFile fp
  withElf bs $ \e -> do
    int0 <- elfInterpreter e
    assertEqual "Interpreter Name" (Just "/lib64/ld-linux-x86-64.so.2\0") int0
    withElf (LB.toStrict (renderElf e)) $ \e' -> do
      assertEqual "Segment Count" (length (elfSegments e)) (length (elfSegments e'))
      let ex = concat (parseSymbolTables e)
          act = concat (parseSymbolTables e')
      assertEqual "Symbol table sizes" (length ex) (length act)
      int1 <- elfInterpreter e'
      assertEqual "Interpreter" int0 int1

withElf :: B.ByteString -> (forall w . Elf w -> Assertion) -> Assertion
withElf bs f =
  case parseElf bs of
    Left e -> assertFailure ("Failed to parse elf file: " ++ show e)
    Right (Elf32 e32) -> f e32
    Right (Elf64 e64) -> f e64

tests :: Test
tests = TestList
    [ TestLabel "Empty ELF" $ TestCase testEmptyElf
    , TestLabel "Identity Transformation (simple)" $ TestCase (testIdentityTransform "./tests/simple.elf")
    ]

main :: IO Counts
main = runTestTT tests
