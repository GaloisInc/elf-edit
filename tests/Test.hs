module Main where

import qualified Data.ByteString as B
import           Data.Elf
import           System.IO
import           Test.HUnit

testEmptyElf :: IO ()
testEmptyElf = withBinaryFile "./tests/empty.elf" ReadMode $ \h -> do
  fil <- B.hGetContents h
  case parseElf fil of
    Left  _e -> return ()
    Right _a -> assertFailure "Empty ELF did not cause an exception."

tests :: Test
tests = TestList
    [ TestLabel "Empty ELF" $ TestCase testEmptyElf
    ]

main :: IO Counts
main = runTestTT tests
