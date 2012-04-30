{
module Data.Elf.Lexer 
  ( Pos(..)
  , ppPos
  , Token(..)
  , TokenStream(..)
  , lexEnum
  ) where

import Text.Read
}

$alpha = [A-Z a-z]
$digit = [0-9]
$idchar = [$alpha $digit \_]
@bool_ops = "&&" | "||"
@punct = "::" | ";" | "|" | "=" | "==" | "/=" |  "<=" | "<" | ">= " | ">" | @bool_ops


tokens :-
$white+      ;
"--"[^\n]*\n ;
[$alpha \_] $idchar* { TSym }
$digit+              { TNum . read }
@punct               { TOp } 
\" (\\\"|[^\"])+ \"  { TLit . read }

{
type AlexInput = (Pos,          -- current position,
                  Char,         -- previous char
                  String)       -- current input string

alexInputPrevChar :: AlexInput -> Char
alexInputPrevChar (_, c, _) = c

alexGetChar :: AlexInput -> Maybe (Char,AlexInput)
alexGetChar (_,_,[]) = Nothing
alexGetChar (p,_,(c:s)) = p' `seq` Just (c, (p', c, s))
  where p' = alexMove p c

data Pos = Pos FilePath Int Int
  deriving (Eq,Show)

ppPos :: Pos -> String
ppPos (Pos p l c) = p ++ (':' : show l) ++ (':' : show c)

alexMove :: Pos -> Char -> Pos
alexMove (Pos f l c) '\t' = Pos f l (((c+7) `div` 8)*8+1)
alexMove (Pos f l _) '\n' = Pos f (l+1) 1
alexMove (Pos f l c) _    = Pos f l (c+1)

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

lexEnum :: Pos -> String -> TokenStream
lexEnum initPos i = go (initPos,'\n',i)
  where go inp@(pos,_,str) =
          case alexScan inp 0 of
            AlexEOF -> End
            AlexError (p,_,n) -> Error p n
            AlexSkip  inp' _     -> go inp'
            AlexToken inp' len act -> 
              (pos, act (take len str)) :+ go inp'
}