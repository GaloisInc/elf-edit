{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
module Relocations
  ( tests
  ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Lazy as L
import qualified Data.List as List
import           Data.Maybe (mapMaybe)
import           Data.Proxy (Proxy(..))
import qualified Data.Vector as V
import qualified Test.Tasty as T
import qualified Test.Tasty.Golden as T
import qualified Test.Tasty.HUnit as T

import           Prelude

import qualified Data.ElfEdit as Elf

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

testRelocTargetBits :: T.Assertion
testRelocTargetBits = do
  T.assertEqual "PPC32 direct target" (Just 32)
    (Elf.relocTargetBits Elf.R_PPC_ADDR32)
  T.assertEqual "PPC32 instruction target" Nothing
    (Elf.relocTargetBits Elf.R_PPC_ADDR24)
  T.assertEqual "PPC64 instruction target" Nothing
    (Elf.relocTargetBits Elf.R_PPC64_REL24)
  T.assertEqual "RISC-V instruction target" Nothing
    (Elf.relocTargetBits
      (Elf.R_RISCV_BRANCH :: Elf.RISCV_RelocationType 32))
  T.assertEqual "RISC-V variable target" Nothing
    (Elf.relocTargetBits
      (Elf.R_RISCV_SET_ULEB128 :: Elf.RISCV_RelocationType 64))

-- | Parse fixtures that contain many kinds of relocations.
testRelocFixture :: forall tp proxy
                  . Elf.IsRelocationType tp
                 => proxy tp
                 -> String
                 -> FilePath
                 -> FilePath
                 -> Maybe FilePath
                 -> T.TestTree
testRelocFixture _ testName fp sourcePath goldenPath =
  case goldenPath of
    Nothing ->
      T.testCase testName $ do
        mismatches <- renderRelocationMismatches (Proxy @tp) fp sourcePath
        if L.null mismatches
          then pure ()
          else T.assertFailure (C8.unpack (L.toStrict mismatches))
    Just path ->
      T.goldenVsStringDiff
        testName
        (\ref new -> ["diff", "-u", ref, new])
        path
        (renderRelocationMismatches (Proxy @tp) fp sourcePath)

renderRelocationMismatches :: forall tp
                           . Elf.IsRelocationType tp
                          => Proxy tp
                          -> FilePath
                          -> FilePath
                          -> IO L.ByteString
renderRelocationMismatches _ fp sourcePath = do
  expected <- fixtureRelocationNames sourcePath
  actual <- decodeFixtureRelocations (Proxy @tp) fp
  T.assertEqual "fixture relocation count" (length expected) (length actual)
  pure . L.fromStrict . C8.pack . unlines $
    [ expectedName ++ " != " ++ actualName
    | (expectedName, actualName) <- zip expected actual
    , expectedName /= actualName
    ]

fixtureRelocationNames :: FilePath -> IO [String]
fixtureRelocationNames sourcePath =
  mapMaybe parseRelocation . lines <$> readFile sourcePath
  where
    -- An inline EXPECTED annotation gives the ABI mnemonic to compare when
    -- the assembler spelling or emitted relocation code differs from it.
    -- For example, LLVM accepts R_AARCH64_TLS_DTPMOD64, but emits code 1028,
    -- which the current ABI calls R_AARCH64_TLS_IMPDEF1.
    parseRelocation line =
      case words line of
        macro : relocation : rest
          | macro `elem` ["RELOC", "RELOC_NOSYM"]
            && "R_" `List.isPrefixOf` relocation ->
              Just (expectedName relocation rest)
        _ -> Nothing

    expectedName relocation rest =
      case rest of
        "#" : "EXPECTED:" : expected : _ -> expected
        "//" : "EXPECTED:" : expected : _ -> expected
        _ -> relocation

decodeFixtureRelocations :: forall tp
                         . Elf.IsRelocationType tp
                        => Proxy tp
                        -> FilePath
                        -> IO [String]
decodeFixtureRelocations _ fp = do
  bs <- B.readFile fp
  withElf bs (\_ -> pure ())
  case Elf.decodeElfHeaderInfo bs of
    Left (_, err) ->
      T.assertFailure ("Failed to parse elf file: " ++ show err)
    Right (Elf.SomeElf ehi) -> do
      let dta = Elf.headerData (Elf.header ehi)
          relocs =
            [ (Elf.elfSectionType section, Elf.elfSectionData section)
            | (_, section) <- V.toList (Elf.headerSections ehi)
            , Elf.elfSectionType section `elem` [Elf.SHT_REL, Elf.SHT_RELA]
            ]
      T.assertBool "fixture contains a relocation section" (not (null relocs))
      case traverse (decodeRelocationSection dta) relocs of
        Left err ->
          T.assertFailure ("Failed to decode relocations in " ++ fp ++ ": " ++ err)
        Right entries ->
          pure (show <$> concat entries)
  where
    decodeRelocationSection dta (sectionType, sectionData)
      | sectionType == Elf.SHT_REL =
          fmap (fmap Elf.relType) $
            Elf.decodeRelEntries @tp dta sectionData
      | sectionType == Elf.SHT_RELA =
          fmap (fmap Elf.relaType) $
            Elf.decodeRelaEntries @tp dta sectionData
      | otherwise =
          Right []

tests :: T.TestTree
tests = T.testGroup "Relocation fixtures"
  [ T.testCase "relocation target bits" testRelocTargetBits
  , T.testGroup "relocatable-object fixtures"
    [ testRelocFixture
        (Proxy @Elf.AArch64_RelocationType)
        "AArch64"
        "./tests/relocs/aarch64/relocs.o"
        "./tests/relocs/aarch64/relocs.s"
        (Just "./tests/relocs/aarch64/relocs.o.relocs")
    , testRelocFixture
        (Proxy @Elf.X86_64_RelocationType)
        "x86-64"
        "./tests/relocs/x86_64/relocs.o"
        "./tests/relocs/x86_64/relocs.s"
        (Just "./tests/relocs/x86_64/relocs.o.relocs")
    , testRelocFixture
        (Proxy @Elf.ARM32_RelocationType)
        "ARM32"
        "./tests/relocs/arm32/relocs.o"
        "./tests/relocs/arm32/relocs.s"
        (Just "./tests/relocs/arm32/relocs.o.relocs")
    , testRelocFixture
        (Proxy @Elf.PPC32_RelocationType)
        "PPC32"
        "./tests/relocs/ppc32/relocs.o"
        "./tests/relocs/ppc32/relocs.s"
        (Just "./tests/relocs/ppc32/relocs.o.relocs")
    , testRelocFixture
        (Proxy @Elf.PPC64_RelocationType)
        "PPC64"
        "./tests/relocs/ppc64/relocs.o"
        "./tests/relocs/ppc64/relocs.s"
        (Just "./tests/relocs/ppc64/relocs.o.relocs")
    , testRelocFixture
        (Proxy @(Elf.RISCV_RelocationType 32))
        "RISC-V (32-bit)"
        "./tests/relocs/riscv/relocs-rv32gc.o"
        "./tests/relocs/riscv/relocs.s"
        Nothing
    , testRelocFixture
        (Proxy @(Elf.RISCV_RelocationType 64))
        "RISC-V (64-bit)"
        "./tests/relocs/riscv/relocs-rv64gc.o"
        "./tests/relocs/riscv/relocs.s"
        Nothing
    ]
  ]
