{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
module Main
  ( main
  ) where

import           Control.Applicative
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy as L
import qualified Data.List as List
import qualified Data.Map as Map
import           Data.Maybe
import           Data.Ord ( comparing )
import           Data.Proxy
import           Data.String
import qualified Data.Vector as V
import           Data.Word ( Word32 )
import qualified System.Directory as Dir
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
  case Elf.parseElf bs of
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
  case Elf.parseElf fil of
    Elf.ElfHeaderError{} -> return ()
    _ -> T.assertFailure "Empty ELF did not cause an exception."

testIdentityTransform :: FilePath -> T.Assertion
testIdentityTransform fp = do
  bs <- B.readFile fp
  withElf bs $ \e -> do
    int0 <- Elf.elfInterpreter e
    withElf (L.toStrict (Elf.renderElf e)) $ \e' -> do
      T.assertEqual "Segment Count" (length (Elf.elfSegments e)) (length (Elf.elfSegments e'))
      withElf bs $ \ehi -> do
        withElf (L.toStrict (Elf.renderElf e)) $ \ehi' -> do
          st1 <- assertOneSymtab ehi
          st2 <- assertOneSymtab ehi'
          let cnt1 = V.length (Elf.symtabEntries st1)
          let cnt2 = V.length (Elf.symtabEntries st2)
          T.assertEqual "Symbol table sizes" cnt1 cnt2
      int1 <- Elf.elfInterpreter e'
      T.assertEqual "Interpreter" int0 int1

assertOneSymtab :: Elf.Elf w -> IO (Elf.Symtab w)
assertOneSymtab elf =
  case Elf.elfSymtab elf of
    [st] -> pure st
    sts  -> T.assertFailure $ "Expected one symbol table, found " ++ show (length sts)

stringTableConsistencyProp :: [AsciiString] -> Bool
stringTableConsistencyProp strings =
  all (checkStringTableEntry bytes) (Map.toList tab)
  where
    (bytes, tab) = Elf.encodeStringTable (map unwrapAsciiString strings)

checkStringTableEntry :: C8.ByteString -> (B.ByteString, Word32) -> Bool
checkStringTableEntry bytes (str, off) = str == bstr
  where
    bstr = C8.take (B.length str) $ C8.drop (fromIntegral off) bytes

-- | Test that the dynamic symbol table in an ELF binary match the expected
-- results. The @elf-edit@ library provides two different ways to compute the
-- dynamic function symbols, both of which are tested here:
--
-- * The 'Elf.decodeHeaderDynsym' function, which omits symbol version
--   information.
--
-- * The 'Elf.dynamicEntries' and 'Elf.dynSymEntry' functions, which return each
--   dynamic function symbol alongside their version information.
testDynSymTable :: FilePath
                -- ^ The path of the ELF file to load.
                -> [(B.ByteString, Bool)]
                -- ^ The name of each symbol that is expected to be in the
                -- dynamic symbol table, paired with 'True' if the symbol is
                -- versioned and 'False' otherwise.
                -> T.Assertion
testDynSymTable fp expectedSymInfo = do
  bs <- B.readFile fp
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

    -- Test decodeHeaderDynsym
    dynSymtab <- maybe (T.assertFailure "No dynamic symbol table found") pure $
                 Elf.decodeHeaderDynsym e
    syms1 <- either (T.assertFailure . show) (pure . V.toList . Elf.symtabEntries)
             dynSymtab
    T.assertEqual "Testing decodeHeaderDynsym"
                  (Elf.steName <$> syms1)
                  (fst <$> expectedSymInfo)

    -- Test dynamicEntries/dynSymEntry
    let contents = Elf.headerFileContents e
    virtMap <- maybe (T.assertFailure "Overlapping loaded segments") pure $
                 Elf.virtAddrMap contents ph
    let dynContents = Elf.slice (Elf.phdrFileRange dynPhdr) contents
    dynSection <- either (T.assertFailure . show) pure $
        Elf.dynamicEntries d cl dynContents

    versionDefs <- either (T.assertFailure . show) pure $ Elf.dynVersionDefMap dynSection virtMap
    versionReqs <- either (T.assertFailure . show) pure $ Elf.dynVersionReqMap dynSection virtMap
    syms2 <- either (T.assertFailure . show) pure $
              traverse (Elf.dynSymEntry dynSection virtMap versionDefs versionReqs)
                       [0 .. fromIntegral (length expectedSymInfo - 1)]
    let isVer Elf.VersionSpecific{} = True
        isVer Elf.VersionLocal  = False
        isVer Elf.VersionGlobal = False
    let symInfo :: (Elf.SymtabEntry B.ByteString u, Elf.VersionTableValue) -> (C8.ByteString, Bool)
        symInfo (s,v) = (Elf.steName s, isVer v)
    T.assertEqual "Testing dynSymEntry" (symInfo <$> syms2) expectedSymInfo

testDynNeeded :: FilePath
                -- ^ The path of the ELF file to load.
                -> [B.ByteString]
                -- ^ The name of each dynamic dependency that is expected to be
                -- in the @DT_NEEDED@ entries.
                -> T.Assertion
testDynNeeded fp expectedDtNeeded = do
  bs <- B.readFile fp
  withElfHeader bs $ \e -> do
    let ph = Elf.headerPhdrs e
    dynPhdr <-
      case filter (\p -> Elf.phdrSegmentType p == Elf.PT_DYNAMIC) ph of
        [r] -> pure r
        _ -> T.assertFailure "Could not find DYNAMIC section"
    let hdr = Elf.header e
    let d  = Elf.headerData hdr
    let cl = Elf.headerClass hdr
    Elf.elfClassInstances cl $ do
      let contents = Elf.headerFileContents e
      virtMap <- maybe (T.assertFailure "Overlapping loaded segments") pure $
                   Elf.virtAddrMap contents ph
      let dynContents = Elf.slice (Elf.phdrFileRange dynPhdr) contents
      dynSection <- either (T.assertFailure . show) pure $
          Elf.dynamicEntries d cl dynContents
      actualDtNeeded <- case Elf.dynNeeded dynSection virtMap of
        Left errMsg -> T.assertFailure errMsg
        Right deps  -> pure deps
      T.assertEqual "Testing DT_NEEDED entries" actualDtNeeded expectedDtNeeded

-- | Test that the list of RELA relocations in a dynamically linked ELF binary
-- match the expected results.
testRelocEntries ::
     forall tp proxy
   . (Eq tp, Ord (Elf.RelocationWord tp), Elf.IsRelocationType tp)
  => proxy tp
  -> FilePath
  -- ^ The path of the ELF file to load.
  -> [(Elf.RelocationWord tp, tp)]
  -- ^ The address and type of each relocation entry that is expected to be in
  -- the list of RELA relocations.
  -> T.Assertion
testRelocEntries _ fp expectedEntries = do
  bs <- B.readFile fp
  withElfHeader bs $ \e -> do
    let ph = Elf.headerPhdrs e
    dynPhdr <-
      case filter (\p -> Elf.phdrSegmentType p == Elf.PT_DYNAMIC) ph of
        [r] -> pure r
        _ -> T.assertFailure "Could not find DYNAMIC section"
    let hdr = Elf.header e
    let d   = Elf.headerData hdr
    let cl  = Elf.headerClass hdr
    Elf.elfClassInstances cl $ do
      let contents = Elf.headerFileContents e
      virtMap <- maybe (T.assertFailure "Overlapping loaded segments") pure $
                   Elf.virtAddrMap contents ph
      let dynContents = Elf.slice (Elf.phdrFileRange dynPhdr) contents
      dynSection <- either (T.assertFailure . show) pure $
          Elf.dynamicEntries d cl dynContents
      relaEntries <-
        case Elf.dynRelaBuffer dynSection virtMap of
          Left errMsg   -> T.assertFailure $ show errMsg
          Right Nothing -> pure []
          Right (Just relaBuffer) ->
            case Elf.decodeRelaEntries @tp d relaBuffer of
              Left errMsg       -> T.assertFailure errMsg
              Right relaEntries -> pure relaEntries
      relEntries <-
        case Elf.dynRelBuffer dynSection virtMap of
          Left errMsg   -> T.assertFailure $ show errMsg
          Right Nothing -> pure []
          Right (Just relBuffer) ->
            case Elf.decodeRelEntries @tp d relBuffer of
              Left errMsg      -> T.assertFailure errMsg
              Right relEntries -> pure relEntries
      let actualEntries =
               List.sortBy (comparing fst)
             $ map (\rela -> (Elf.relaAddr rela, Elf.relaType rela)) relaEntries
            ++ map (\rel  -> (Elf.relAddr  rel,  Elf.relType  rel))  relEntries
      T.assertEqual
        "Testing relocation entries"
        expectedEntries
        actualEntries

-- | Test whether an ELF executable is position-independent or not.
testPie ::
     FilePath
     -- ^ The path to the ELF executable.
  -> Bool
     -- ^ 'True' if the executable is expected to be position-independent.
     --   'False' otherwise.
  -> T.Assertion
testPie fp expectedPie = do
  perms <- Dir.getPermissions fp
  bs <- B.readFile fp
  withElfHeader bs $ \e -> do
    let actualPie = Elf.elfIsPie perms e
    T.assertEqual
      "Testing position independence"
      expectedPie
      actualPie

tests :: T.TestTree
tests = T.testGroup "ELF Tests"
    [ T.testCase "Empty ELF" testEmptyElf
    , T.testCase "Identity Transformation (simple static)" (testIdentityTransform "./tests/simple.static.elf")
    , T.testCase "Identity Transformation (simple)" (testIdentityTransform "./tests/simple.elf")
-- Remove this test case since the Elf file has a segment outside the file range.
    , T.testCase "Zero-sized BSS" (testIdentityTransform "./tests/zero-physical-bss.elf")
    , T.testProperty "stringTable consistency" stringTableConsistencyProp
    , T.testCase "dynNeeded" $
        testDynNeeded "./tests/fmax.elf" ["libm.so.6", "libc.so.6"]

    , T.testGroup "dynSymTable"
      [ T.testCase "simple binary" $
          testDynSymTable "./tests/simple.elf"
                          [ ("", False)
                          , ("__libc_start_main", True)
                          , ("__gmon_start__", False)
                          ]
      , T.testCase "version definitions" $
          testDynSymTable "./tests/libsymbol_versions.2.so"
                          [ ("", False)
                          , ("__cxa_finalize", False)
                          , ("_ITM_registerTMCloneTable", False)
                          , ("_ITM_deregisterTMCloneTable", False)
                          , ("__gmon_start__", False)
                          , ("foo", True) -- foo@MYSTUFF_1.1
                          , ("foo", True) -- foo@@MYSTUFF_1.2
                          , ("MYSTUFF_1.1", True)
                          , ("MYSTUFF_1.2", True)
                          ]
      ]

    , T.testGroup "Relocation entries"
      [ T.testCase "PPC32 relocations" $
          testRelocEntries
            (Proxy @Elf.PPC32_RelocationType)
            "./tests/ppc32-relocs.elf"
            [ (0x0001fecc, Elf.R_PPC_RELATIVE)
            , (0x0001fed0, Elf.R_PPC_RELATIVE)
            , (0x0001fed4, Elf.R_PPC_RELATIVE)
            , (0x0001fed8, Elf.R_PPC_RELATIVE)
            , (0x0001fedc, Elf.R_PPC_RELATIVE)
            , (0x0001fee0, Elf.R_PPC_RELATIVE)
            , (0x0001fee4, Elf.R_PPC_ADDR32)
            , (0x0001fee8, Elf.R_PPC_RELATIVE)
            , (0x0001feec, Elf.R_PPC_ADDR32)
            , (0x0001fef0, Elf.R_PPC_RELATIVE)
            , (0x0001fef4, Elf.R_PPC_ADDR32)
            , (0x0001fef8, Elf.R_PPC_RELATIVE)
            , (0x0001fefc, Elf.R_PPC_ADDR32)
            , (0x0001ff00, Elf.R_PPC_RELATIVE)
            , (0x0001ff04, Elf.R_PPC_ADDR32)
            , (0x0001ff08, Elf.R_PPC_RELATIVE)
            , (0x00020000, Elf.R_PPC_JMP_SLOT)
            , (0x00020004, Elf.R_PPC_JMP_SLOT)
            , (0x00020008, Elf.R_PPC_JMP_SLOT)
            , (0x0002000c, Elf.R_PPC_JMP_SLOT)
            , (0x00020010, Elf.R_PPC_RELATIVE)
            ]
      , T.testCase "PPC64 relocations" $
          testRelocEntries
            (Proxy @Elf.PPC64_RelocationType)
            "./tests/ppc64-relocs.elf"
            [ (0x000000000001fd10, Elf.R_PPC64_RELATIVE)
            , (0x000000000001fd18, Elf.R_PPC64_RELATIVE)
            , (0x000000000001ff08, Elf.R_PPC64_ADDR64)
            , (0x000000000001ff10, Elf.R_PPC64_ADDR64)
            , (0x000000000001ff18, Elf.R_PPC64_ADDR64)
            , (0x000000000001ff20, Elf.R_PPC64_ADDR64)
            , (0x000000000001ff28, Elf.R_PPC64_ADDR64)
            {-
            These relocations (which live in the binary's .rela.plt section)
            are not discovered by elf-edit. See
            https://github.com/GaloisInc/elf-edit/issues/40 for a diagnosis.
            -}
            -- , (0x0000000000020010, Elf.R_PPC64_JMP_SLOT)
            -- , (0x0000000000020018, Elf.R_PPC64_JMP_SLOT)
            -- , (0x0000000000020020, Elf.R_PPC64_JMP_SLOT)
            -- , (0x0000000000020028, Elf.R_PPC64_JMP_SLOT)
            , (0x0000000000020030, Elf.R_PPC64_RELATIVE)
            ]
      , T.testCase "RISC-V (32-bit) relocations" $
          testRelocEntries
            (Proxy @(Elf.RISCV_RelocationType 32))
            "./tests/riscv32-relocs.elf"
            [ (0x00001f18, Elf.R_RISCV_RELATIVE)
            , (0x00001f1c, Elf.R_RISCV_RELATIVE)
            , (0x00002000, Elf.R_RISCV_RELATIVE)
            , (0x0000200c, Elf.R_RISCV_JUMP_SLOT)
            , (0x00002014, Elf.R_RISCV_32)
            , (0x00002018, Elf.R_RISCV_32)
            , (0x0000201c, Elf.R_RISCV_32)
            , (0x00002020, Elf.R_RISCV_32)
            , (0x00002024, Elf.R_RISCV_32)
            , (0x00002028, Elf.R_RISCV_RELATIVE)
            , (0x0000202c, Elf.R_RISCV_32)
            , (0x00002030, Elf.R_RISCV_32)
            ]
      , T.testCase "RISC-V (64-bit) relocations" $
          testRelocEntries
            (Proxy @(Elf.RISCV_RelocationType 64))
            "./tests/riscv64-relocs.elf"
            [ (0x0000000000001e30, Elf.R_RISCV_RELATIVE)
            , (0x0000000000001e38, Elf.R_RISCV_RELATIVE)
            , (0x0000000000002000, Elf.R_RISCV_RELATIVE)
            , (0x0000000000002018, Elf.R_RISCV_JUMP_SLOT)
            , (0x0000000000002028, Elf.R_RISCV_64)
            , (0x0000000000002030, Elf.R_RISCV_64)
            , (0x0000000000002038, Elf.R_RISCV_64)
            , (0x0000000000002040, Elf.R_RISCV_64)
            , (0x0000000000002048, Elf.R_RISCV_64)
            , (0x0000000000002050, Elf.R_RISCV_RELATIVE)
            , (0x0000000000002058, Elf.R_RISCV_64)
            , (0x0000000000002060, Elf.R_RISCV_64)
            ]
      ]

    , T.testGroup "Position independence"
      [ T.testCase "Dynamically linked executable that is position-independent" $
          testPie "./tests/fmax.elf" True
      , T.testCase "Dynamically linked executable that is not position-independent" $
          testPie "./tests/simple.elf" False
      , T.testCase "Statically linked executable is not position-independent" $
          testPie "./tests/simple.static.elf" False
      ]
    ]

main :: IO ()
main = T.defaultMain tests
