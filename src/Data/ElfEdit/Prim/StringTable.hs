{-|
Declares operations for string tables.
-}
module Data.ElfEdit.Prim.StringTable
  ( -- * String tables
    encodeStringTable
  , lookupString
  , LookupStringError(..)
  , strtabShdr
  ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Builder as Bld
import qualified Data.ByteString.Lazy as L
import qualified Data.Foldable as Foldable
import           Data.List (sort)
import           Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import           Data.Word

import           Data.ElfEdit.Prim.File
import           Data.ElfEdit.Prim.Shdr

------------------------------------------------------------------------
-- Creation

-- | A string table contains a  map from offsets, the number of elements,
-- and a builder with the current string.
type StringTable = (Map B.ByteString Word32, Word32, Bld.Builder)

insertTail :: B.ByteString
           -> Word32
           -> Map B.ByteString Word32
           -> Map B.ByteString Word32
insertTail bs base  m
  | B.null bs = m
  | otherwise =
    insertTail (B.tail bs) (base + 1) $!
      Map.insertWith (\_ -> id) bs base m

-- | Insert bytestring in list of strings.
insertString :: StringTable -> B.ByteString -> StringTable
insertString a@(m, base, b) bs
    | Map.member bs m = a
    | otherwise = seq m' $ seq base' $ seq b' $ (m', base',  b')
  where -- Insert all tails of the bytestring into the map so that
        -- we can find the index later if needed.
        l = B.length bs
        m' = insertTail bs base m
        b' = b `mappend` Bld.byteString bs `mappend` Bld.word8 0
        base' = base + fromIntegral l + 1

-- | Create a string table from the list of strings, and return a map
-- from strings in list to their offset for efficient lookup.
encodeStringTable :: [B.ByteString] -> (B.ByteString, Map B.ByteString Word32)
encodeStringTable strings = (res, stringMap)
  where -- Compress entries by removing a string if it is the prefiex of
        -- another string.
        --
        -- The inputs of compress have been sorted, so we know that if
        -- a string 'x' is a prefix of a string 'y', then 'y' appears after
        -- 'x', and any string 'z' betweeen 'x' and 'y' is also a prefix of 'x'.
        -- Thus to eliminate prefixes,
        compress :: [B.ByteString] -> [B.ByteString]
        compress (f:r@(s:_)) | f `B.isSuffixOf` s = compress r
        compress (f:r) = f:compress r
        compress [] = []

        -- The entries is obtained by taksing the list of names of bytestrings
        -- and eliminating all bytestrings that are suffixes of other strings.
        --
        -- To do this in near-linear time with respect to the number of strings
        -- (as opposed to quadratic), this is
        -- done by reversing each string, sorting it, then eliminating
        -- prefixes, before reversing the strings again.
        entries = compress $ fmap B.reverse $ sort $ fmap B.reverse strings

        -- Insert strings into map (first string must be empty string)
        empty_table = (Map.singleton B.empty 0
                      , 1
                      , Bld.word8 0
                      )

        -- We insert strings in order so that they will appear in sorted
        -- order in the bytestring.  This is likely not essential, but
        -- corresponds to ld's behavior.
        (m,_,b) = Foldable.foldl' insertString empty_table entries

        myFind bs =
          case Map.lookup bs m of
            Just v -> v
            Nothing -> error $ "internal: stringTable missing entry:\n"
              ++ unlines (show <$> strings)
              ++ show bs ++ "\n"
              ++ show entries ++ "\n"
              ++ show m
        stringMap = Map.fromList $ strings `zip` map myFind strings

        res = L.toStrict (Bld.toLazyByteString b)

------------------------------------------------------------------------
-- String table lookup

-- | An error that occurs when looking up a string in a table
data LookupStringError
   = IllegalStrtabIndex !Word32
   | MissingNullTerminator

instance Show LookupStringError where
  show (IllegalStrtabIndex i) = "Illegal strtab index " ++ show i ++ "."
  show MissingNullTerminator = "Missing null terminator in strtab."

-- | Returns null-terminated string at given index in bytestring, or returns
-- error if that fails.
lookupString :: Word32 -> B.ByteString -> Either LookupStringError B.ByteString
lookupString o b | toInteger o >= toInteger (B.length b) = Left $ IllegalStrtabIndex o
                 | B.length r == B.length s = Left MissingNullTerminator
                 | otherwise = Right r
  where s = B.drop (fromIntegral o) b
        r = B.takeWhile (/= 0) s

------------------------------------------------------------------------
-- Section header

-- | Create a section header for a string table.
strtabShdr :: Num w
           => nm
           -- ^ Name of section
           -> FileOffset w
           -- ^ Offset of section
           -> w
           -- ^ Size of section
           -> Shdr nm w
strtabShdr nm o sz =
  Shdr { shdrName = nm
            , shdrType = SHT_STRTAB
            , shdrFlags = shf_none
            , shdrAddr = 0
            , shdrOff  = o
            , shdrSize = sz
            , shdrLink = 0
            , shdrInfo = 0
            , shdrAddrAlign = 1
            , shdrEntSize = 0
            }
