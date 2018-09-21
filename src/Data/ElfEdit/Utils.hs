module Data.ElfEdit.Utils
  ( enumCnt
  , showFlags
  ) where

import           Data.Bits
import           Data.List (intercalate)
import qualified Data.Vector as V
import           Numeric (showHex)

-- | 'enumCnt b c' returns a list with c enum values starting from 'b'.
enumCnt :: (Enum e, Real r) => e -> r -> [e]
enumCnt e x = if x > 0 then e : enumCnt (succ e) (x-1) else []


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
