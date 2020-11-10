module Data.ElfEdit.Utils
  ( -- * Sequencing
    enumCnt
    -- * Pretty printing
  , ppHex
  , showFlags
  , fixTableColumns
  , ColumnAlignmentFn
  , alignLeft
  , alignRight
    -- * Get utilities
  , strictRunGetOrFail
  ) where

import qualified Data.Binary.Get as Get
import           Data.Bits
import qualified Data.ByteString as B
import           Data.List (intercalate, transpose)
import qualified Data.Vector as V
import           Numeric (showHex)
import           Text.PrettyPrint.ANSI.Leijen hiding ((<>), (<$>))

-- | @enumCnt b c@ returns a list with @c@ enum values starting from @b@.
enumCnt :: (Enum e, Real r) => e -> r -> [e]
enumCnt e x = if x > 0 then e : enumCnt (succ e) (x-1) else []

ppHex :: (Bits a, Integral a, Show a) => a -> String
ppHex v | v >= 0 = "0x" ++ fixLength (bitSizeMaybe v) (showHex v "")
        | otherwise = error "ppHex given negative value"
  where fixLength (Just n) s | r == 0 && w > l = replicate (w - l) '0' ++ s
          where (w,r) = n `quotRem` 4
                l = length s
        fixLength _ s = s

-- | Shows a bitwise combination of flags
showFlags :: (Bits w, Integral w, Show w) => String -> V.Vector String -> Int -> w -> ShowS
showFlags noneStr names d w =
    case l of
      [] -> showString noneStr
      [e] -> showString e
      _ -> showParen (d > orPrec) $ showString $ intercalate " .|. " l
  where orPrec = 5
        nl = V.length names
        unknown = w .&. complement (1 `shiftL` nl - 1)
        unknown_val | unknown > 0  = ["0x" ++ showHex unknown ""]
                    | unknown == 0 = []
                    | otherwise = error "showFlags given negative value"
        l :: [String]
        l = fmap (names V.!) (filter (testBit w) (enumCnt 0 nl)) ++ unknown_val

-------------------------------------------------------------------------
-- ColumnAlignmentFn

type ColumnAlignmentFn = [String] -> [String]

alignLeft :: Int -> ColumnAlignmentFn
alignLeft minw l = ar <$> l
  where w = maximum $ minw : (length <$> l)
        ar s = s ++ replicate (w-n) ' '
          where n = length s

alignRight :: Int -> ColumnAlignmentFn
alignRight minw l = ar <$> l
  where w = maximum $ minw : (length <$> l)
        ar s = replicate (w-n) ' ' ++ s
          where n = length s

-- | Function for pretty printing a row of tables according to
-- rules for each column.
fixTableColumns :: [ColumnAlignmentFn]
                     -- ^ Functions for modifying each column
                -> [[String]]
                -> Doc
fixTableColumns colFns rows = vcat (hsep . fmap text <$> fixed_rows)
  where cols = transpose rows
        fixed_cols = zipWith ($) colFns cols
        fixed_rows = transpose fixed_cols

--------------------------------------------------------------------------------
-- Get utilities

strictRunGetOrFail :: Get.Get a
                   -> B.ByteString
                   -> Either (B.ByteString, Get.ByteOffset, String) (B.ByteString, Get.ByteOffset, a)
strictRunGetOrFail m bs =
  case Get.pushEndOfInput (Get.pushChunk (Get.runGetIncremental m) bs) of
    Get.Fail rest off msg -> Left (rest, off, msg)
    Get.Partial _cont -> error $ "internal error: Get partial failed."
    Get.Done rest off r -> Right (rest, off, r)
