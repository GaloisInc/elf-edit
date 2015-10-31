module Main where

import qualified Control.Exception as E
import           Control.Monad
import qualified Data.ByteString as B
import           Data.Elf
import           Data.Word
import           System.IO
import           Test.HUnit

testEmptyElf = withBinaryFile "./tests/empty.elf" ReadMode $ \h -> do
  fil <- B.hGetContents h
  case parseElf fil of
    Left  _e -> return ()
    Right _a -> assertFailure "Empty ELF did not cause an exception."

tests = TestList
    [ TestLabel "Empty ELF" $ TestCase testEmptyElf
    ]

main = runTestTT tests
