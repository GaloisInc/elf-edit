{
module Data.Elf.Parser  where

import Data.Elf.Lexer

}

%name parseEnum
%expect 0
%tokentype { (Pos,Token) }
%error { parseError }

%token 
'::'    { (_, TOp "::") }
'='     { (_, TOp "=") }
';'     { (_, TOp ";") }
'|'     { (_, TOp "|") }
var     { (_, TSym _) } 
str     { (_, TLit _) }
int     { (_, TNum _) }
'=='    { (_, TOp "==") }
'/='    { (_, TOp "/=") }
'<='    { (_, TOp "<=") }
'<'     { (_, TOp "<") }
'>='    { (_, TOp ">=") }
'>'     { (_, TOp ">") }
'&&'    { (_, TOp "&&") }
'||'    { (_, TOp "||") }
'true'  { (_, TOp "True") }
'false' { (_, TOp "False") }

%left '||'
%left '&&'
%nonassoc '<=' '<' '>=' '>'
%nonassoc '==' '/='
%%

EnumDec :: { EnumDec }
EnumDec : var '::' var EnumValList { EnumDec (sv $1) (sv $3) $4 }

EnumValList :: { [EnumVal] }
EnumValList : RevEnumValList { reverse $1 }

RevEnumValList :: { [EnumVal] }
RevEnumValList 
  : {- empty -} { [] }
  | RevEnumValList EnumVal { $2 : $1 }

EnumVal :: { EnumVal }
EnumVal 
  : var int          { EnumCns (sv $1) (iv $2) }
  | var var          { EnumPred (sv $1) (sv $2) Nothing }
  | var var '|' Expr { EnumPred (sv $1) (sv $2) (Just $4) }

Expr :: { PosExpr }
Expr
  : Expr '==' Expr  { PosF (pos $1) (Eq $1 $3) }
  | Expr '/=' Expr  { PosF (pos $1) (Ne $1 $3) }
  | Expr '<=' Expr  { PosF (pos $1) (Le $1 $3) }
  | Expr '<'  Expr  { PosF (pos $1) (Lt $1 $3) }
  | Expr '>=' Expr  { PosF (pos $1) (Ge $1 $3) }
  | Expr '>'  Expr  { PosF (pos $1) (Gt $1 $3) }
  | Expr '&&' Expr  { PosF (pos $1) (And $1 $3) }
  | Expr '||' Expr  { PosF (pos $1) (Or  $1 $3) }
  | 'true'          { PosF (fst $1) (ConstBool True) }
  | 'false'         { PosF (fst $1) (ConstBool False) }
  | int             { PosF (fst $1) (ConstInt (iv $1)) }
  | var             { PosF (fst $1) (Var (sv $1)) }

{
-- | Return string value associated with token.
sv :: (Pos,Token) -> String
sv (_,TLit v) = v
sv (_,TSym v) = v
sv _ = error "sv given bad token"

iv :: (Pos,Token) -> Integer
iv (_,TNum v) = v
iv _ = error "iv given bad token"

parseError :: [(Pos,Token)] -> a
parseError ((p,_):_) = error "Error parsing"

data ExprF e
  = Eq  e e
  | Ne  e e
  | Le  e e
  | Lt  e e
  | Ge  e e
  | Gt  e e
  | And e e
  | Or  e e
  | ConstBool Bool
  | ConstInt Integer  
  | Var String
  deriving (Show)

class ShowFoldable f where
  fshow :: Show x => f x -> String
  fshow x = fshows x ""
  fshows :: Show x => f x -> ShowS
  fshows x = (fshow x ++)

instance ShowFoldable ExprF where
  fshows e = shows e 

data PosF f = PosF { pos :: Pos, val :: f (PosF f)  }

instance ShowFoldable app => Show (PosF app) where
  showsPrec _ (PosF p v) s = "PosF " ++ shows p (' ' : fshows v s)

type PosExpr = PosF ExprF 

newtype Expr = Expr (ExprF Expr)

data EnumVal
  = EnumCns String Integer 
  | EnumPred String String (Maybe PosExpr)
  deriving (Show)

data EnumDec = EnumDec {
         enumType :: String
       , baseType :: String
       , enumVals :: [EnumVal]
       }
  deriving (Show)
}
