{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
module Main
  ( main
  ) where

import           Control.Applicative
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy as L
import qualified Data.Map as Map
import           Data.Maybe
import           Data.String
import qualified Data.Vector as V
import           Data.Word ( Word32 )
import qualified System.IO as IO
import qualified Test.Tasty as T
import qualified Test.Tasty.HUnit as T
import qualified Test.Tasty.QuickCheck as T

import           Prelude

import qualified Data.ElfEdit as Elf

------------------------------------------------------------------------
-- Newtype for generating alphabetic strings.

newtype AsciiString = AsciiString { unwrapAsciiString :: B.ByteString }
                    deriving (Show)

instance T.Arbitrary AsciiString where
  arbitrary = AsciiString . fromString <$> genAsciiString

genAsciiString :: T.Gen String
genAsciiString = T.listOf genAsciiChar

genAsciiChar :: T.Gen Char
genAsciiChar = T.elements (['a'..'z'] ++ ['A'..'Z'])

------------------------------------------------------------------------
-- Test cases

withElf :: B.ByteString -> (forall w . Elf.Elf w -> T.Assertion) -> T.Assertion
withElf bs f =
  case Elf.decodeElf bs of
    Elf.Elf32Res err e32
      | null err  -> f e32
      | otherwise -> T.assertFailure ("Failed to parse elf file: " ++ show err)
    Elf.Elf64Res err e64
      | null err  -> f e64
      | otherwise -> T.assertFailure ("Failed to parse elf file: " ++ show err)
    Elf.ElfHeaderError _ e -> T.assertFailure $ "Failed to parse elf file: " ++ show e

withElfHeader :: B.ByteString -> (forall w . Elf.ElfHeaderInfo w -> T.Assertion) -> T.Assertion
withElfHeader bs f =
  case Elf.decodeElfHeaderInfo bs of
    Left (_,err) -> T.assertFailure ("Failed to parse elf file: " ++ show err)
    Right (Elf.SomeElf e) -> f e

testEmptyElf :: T.Assertion
testEmptyElf = IO.withBinaryFile "./tests/empty.elf" IO.ReadMode $ \h -> do
  fil <- B.hGetContents h
  case Elf.decodeElf fil of
    Elf.ElfHeaderError{} -> return ()
    _ -> T.assertFailure "Empty ELF did not cause an exception."

testIdentityTransform :: FilePath -> T.Assertion
testIdentityTransform fp = do
  bs <- B.readFile fp
  withElf bs $ \e -> do
    int0 <- Elf.elfInterpreter e
    withElf (L.toStrict (Elf.encodeElf e)) $ \e' -> do
      T.assertEqual "Segment Count" (length (Elf.elfSegments e)) (length (Elf.elfSegments e'))
      withElf bs $ \ehi -> do
        withElf (L.toStrict (Elf.encodeElf e)) $ \ehi' -> do
          let [st1] = Elf.elfSymtab ehi
              [st2] = Elf.elfSymtab ehi'
          let cnt1 = V.length (Elf.symtabEntries st1)
          let cnt2 = V.length (Elf.symtabEntries st2)
          T.assertEqual "Symbol table sizes" cnt1 cnt2
      int1 <- Elf.elfInterpreter e'
      T.assertEqual "Interpreter" int0 int1

stringTableConsistencyProp :: [AsciiString] -> Bool
stringTableConsistencyProp strings =
  all (checkStringTableEntry bytes) (Map.toList tab)
  where
    (bytes, tab) = Elf.encodeStringTable (map unwrapAsciiString strings)

checkStringTableEntry :: C8.ByteString -> (B.ByteString, Word32) -> Bool
checkStringTableEntry bytes (str, off) = str == bstr
  where
    bstr = C8.take (B.length str) $ C8.drop (fromIntegral off) bytes

testDynSymTable :: T.Assertion
testDynSymTable = do
  bs <- B.readFile "./tests/simple.elf"
  withElfHeader bs $ \e -> do
    let ph = Elf.headerPhdrs e
    dynPhdr <-
      case filter (\p -> Elf.phdrSegmentType p == Elf.PT_DYNAMIC) ph of
        [r] -> pure r
        _ -> T.assertFailure "Could not find DYNAMIC section"
    let hdr = Elf.header e
    let d  = Elf.headerData hdr
    let cl = Elf.headerClass hdr
    Elf.ELFCLASS64 <- pure cl
    let mach = Elf.headerMachine hdr
    Elf.EM_X86_64 <- pure mach
    let contents = Elf.headerFileContents e
    virtMap <- maybe (T.assertFailure "Overlapping loaded segments") pure $
                 Elf.virtAddrMap contents ph
    let dynContents = Elf.slice (Elf.phdrFileRange dynPhdr) contents
    dynSection <- either (T.assertFailure . show) pure $
        Elf.dynamicEntries d cl virtMap dynContents

    syms <- either (T.assertFailure . show) pure $ traverse (Elf.dynSymEntry dynSection) [0..2]
    let isVer Elf.VersionSpecific{} = True
        isVer Elf.VersionLocal  = False
        isVer Elf.VersionGlobal = False
    let symInfo :: (Elf.SymtabEntry B.ByteString u, Elf.VersionTableValue) -> (C8.ByteString, Bool)
        symInfo (s,v) = (Elf.steName s, isVer v)
    -- Statically define expected symbol information.
    let expectedSymInfo = [("",False), ("__libc_start_main",True), ("__gmon_start__", False)]
    T.assertEqual "Testing relocations" (symInfo <$> syms) expectedSymInfo

tests :: T.TestTree
tests = T.testGroup "ELF Tests"
    [ T.testCase "Empty ELF" testEmptyElf
    , T.testCase "Identity Transformation (simple static)" (testIdentityTransform "./tests/simple.static.elf")
    , T.testCase "Identity Transformation (simple)" (testIdentityTransform "./tests/simple.elf")
-- Remove this test case since the Elf file has a segment outside the file range.
    , T.testCase "Zero-sized BSS" (testIdentityTransform "./tests/zero-physical-bss.elf")
    , T.testProperty "stringTable consistency" stringTableConsistencyProp
    , T.testCase "dynSymTable" testDynSymTable
    ]

main :: IO ()
main = T.defaultMain tests
