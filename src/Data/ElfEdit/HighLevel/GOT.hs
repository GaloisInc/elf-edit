{-|
Provides special section to parse global offset table.
-}
module Data.ElfEdit.HighLevel.GOT
  ( ElfGOT(..)
  , elfGotSize
  , elfGotSectionFlags
  , elfGotSection
  , elfSectionAsGOT
  ) where

import Control.Monad
import Data.Bits
import Data.ByteString as B
import Data.Word

import Data.ElfEdit.Prim.Shdr
import Data.ElfEdit.HighLevel.Sections

------------------------------------------------------------------------
-- ElfGOT

-- | A global offset table section.
data ElfGOT w = ElfGOT
    { elfGotIndex     :: !Word16
    , elfGotName      :: !B.ByteString -- ^ Name of section.
    , elfGotAddr      :: !w
    , elfGotAddrAlign :: !w
    , elfGotEntSize   :: !w
    , elfGotData      :: !B.ByteString
    } deriving (Show)

elfGotSize :: Num w => ElfGOT w -> w
elfGotSize g = fromIntegral (B.length (elfGotData g))

elfGotSectionFlags :: (Bits w, Num w) => ElfSectionFlags w
elfGotSectionFlags = shf_write .|. shf_alloc

-- | Convert a GOT section to a standard section.
elfGotSection :: (Bits w, Num w) => ElfGOT w -> ElfSection w
elfGotSection g =
  ElfSection { elfSectionIndex = elfGotIndex g
             , elfSectionName  = elfGotName g
             , elfSectionType  = SHT_PROGBITS
             , elfSectionFlags = elfGotSectionFlags
             , elfSectionAddr  = elfGotAddr g
             , elfSectionSize  = elfGotSize g
             , elfSectionLink  = 0
             , elfSectionInfo  = 0
             , elfSectionAddrAlign = elfGotAddrAlign g
             , elfSectionEntSize   = elfGotEntSize g
             , elfSectionData      = elfGotData g
             }

-- | Attempt to convert a section to a GOT.
elfSectionAsGOT :: (Bits w, Num w)
                => ElfSection w
                -> Either String (ElfGOT w)
elfSectionAsGOT s = do
  -- TODO: Perform checks
  when (elfSectionType s /= SHT_PROGBITS) $ do
    Left "Unexpected .got section type (expected PROGBITS)"
  when (elfSectionFlags s /= elfGotSectionFlags) $ do
    Left "Unexpected .got section flags (expected write/alloc)"
  let d = elfSectionData s
  when (elfSectionSize s /= fromIntegral (B.length d)) $ do
    Left ".got section size does not match data length."
  when (elfSectionLink s /= 0) $ do
    Left "Unexpected .got section length"
  when (elfSectionInfo s /= 0) $ do
    Left "Unexpected .got section info"
  return ElfGOT { elfGotIndex = elfSectionIndex s
                , elfGotName  = elfSectionName s
                , elfGotAddr  = elfSectionAddr s
                , elfGotAddrAlign = elfSectionAddrAlign s
                , elfGotEntSize = elfSectionEntSize s
                , elfGotData = d
                }
