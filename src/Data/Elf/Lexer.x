{
module Data.Elf.Lexer 
  ( Pos(..)
  , ppPos
  , Token(..)
  , TokenStream(..)
  , lexEnum
  ) where

import qualified Data.ByteString as B
import Text.Read
}

%wrapper "posn"

$alpha = [A-Z a-z]
$digit = [0-9]
$idchar = [$alpha $digit \_]
@bool_ops = "&&" | "||"
@punct = "::" | ";" | "|" | "=" | "==" | "/=" |  "<=" | "<" | ">= " | ">" | @bool_ops


tokens :-
$white+      ;
"--"[^\n]*\n ;
[$alpha \_] $idchar* { \_ -> TSym }
$digit+              { \_ -> TNum . read }
@punct               { \_ -> TOp } 
\" (\\\"|[^\"])+ \"  { \_ -> TLit . read }



{

data Pos = Pos FilePath Int Int
  deriving (Eq,Show)

ppPos :: Pos -> String
ppPos (Pos p l c) = p ++ (':' : show l) ++ (':' : show c)

{-
alexMove :: Pos -> Char -> Pos
alexMove (Pos f l c) '\t' = Pos f l (((c+7) `div` 8)*8+1)
alexMove (Pos f l _) '\n' = Pos f (l+1) 1
alexMove (Pos f l c) _    = Pos f l (c+1)
-}

data Token
  = TSym String 
  | TNum Integer
  | TOp  String
  | TLit String -- ^ String literal
  deriving (Eq,Ord,Show)

data TokenStream
  = (:+) (Pos,Token) TokenStream
  | Error !Pos !String
  | End
  deriving (Show)

infixr 5 :+

addAlexPos :: Pos -> AlexPosn -> Pos
addAlexPos (Pos p l1 c1) (AlexPn _ l2 c2)
  | l2 == 0   = Pos p l1 (c1 + c2)
  | otherwise = Pos p (l1 + l2) c2

lexEnum :: Pos -> String -> TokenStream
lexEnum initPos i = go (alexStartPos, '\n',[],i)
  where go inp@(p,_,_,str) =
          case alexScan inp 0 of
                AlexEOF -> End
                AlexError _ -> Error (addAlexPos initPos p)  "lexical error"
                AlexSkip  inp' _  -> go inp'
                AlexToken inp' len act -> (addAlexPos initPos p, act p (take len str)) :+ go inp'
}