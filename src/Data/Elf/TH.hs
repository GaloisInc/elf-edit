module Data.Elf.TH (enum) where

import Data.Elf.Lexer
import Data.Elf.Parser
import Language.Haskell.TH
import Language.Haskell.TH.Quote

sconT :: String -> Type
sconT = ConT . mkName
        
sconE :: String -> Exp
sconE = ConE . mkName

enumDataDec :: EnumDec -> Dec
enumDataDec (EnumDec  nm bt args) = DataD [] (mkName nm) [] con cl
  where con = map enumValCtor args   
        enumValCtor (EnumCns cnm _) = NormalC (mkName cnm) []
        enumValCtor (EnumPred cnm _ _) = NormalC (mkName cnm) [(IsStrict, sconT bt)] 
        cl = [mkName "Eq", mkName "Ord", mkName "Show"]

parseExp :: PosExpr -> Exp
parseExp (PosF _ e) = 
  case e of
    Eq x y  -> app2 "==" (parseExp x) (parseExp y)
    Ne x y  -> app2 "/=" (parseExp x) (parseExp y)
    Le x y  -> app2 "<=" (parseExp x) (parseExp y)
    Lt x y  -> app2 "<"  (parseExp x) (parseExp y)
    Ge x y  -> app2 ">=" (parseExp x) (parseExp y)
    Gt x y  -> app2 ">"  (parseExp x) (parseExp y)
    And x y -> app2 "&&" (parseExp x) (parseExp y)
    Or x y  -> app2 "||" (parseExp x) (parseExp y)
    ConstBool True -> ConE (mkName "True")
    ConstBool False -> ConE (mkName "False")
    ConstInt v -> LitE (IntegerL v)
    Var nm -> VarE (mkName nm)
  where app2 op x y = (VarE (mkName op) `AppE` x) `AppE` y 

valMatchesAny :: EnumVal -> Bool
valMatchesAny (EnumPred _ _ Nothing) = True
valMatchesAny _ = False

enumValToClause :: (Exp -> Exp) -> EnumVal -> Q Clause
enumValToClause resFn (EnumCns nm v) = do
  return $ Clause [LitP (IntegerL v)] (NormalB (resFn (sconE nm))) []
enumValToClause resFn (EnumPred nm _var Nothing) = do
  vName <- newName "x"
  let body = NormalB (resFn (AppE (sconE nm) (VarE vName)))
  return $ Clause [VarP vName] body []
enumValToClause resFn (EnumPred nm var (Just c)) = do
  let vName = mkName var
  let res = resFn (AppE (sconE nm) (VarE vName))
  let body = GuardedB [(NormalG (parseExp c), res)]             
  return $ Clause [VarP (mkName var)] body []

enumValFromClause :: EnumVal -> Clause
enumValFromClause (EnumCns nm v) =
  Clause [ConP (mkName nm) []] (NormalB (LitE (IntegerL v))) []
enumValFromClause (EnumPred nm _ _) =
     Clause [ConP (mkName nm) [VarP xv]] (NormalB (VarE xv)) []
  where xv = mkName "x"

enumToDec :: EnumDec -> Q [Dec]
enumToDec (EnumDec nm tp args) 
    | any valMatchesAny args = do
      cll <- mapM (enumValToClause id) args
      return [ SigD toFn (sconT tp `arrT` sconT nm)
             , FunD toFn cll
             ]
    | otherwise = do
      cll <- mapM (enumValToClause (AppE (sconE "Just"))) args      
      return [ SigD toFn $
                 sconT tp `arrT` (AppT (sconT "Maybe") (sconT nm))
             , FunD toFn $ cll ++ [Clause [WildP] (NormalB (sconE "Nothing")) []]
             ]
  where arrT x y = AppT (ArrowT `AppT` x) y 
        toFn = mkName ("to" ++ nm)

enumFromDec :: EnumDec -> [Dec]
enumFromDec (EnumDec nm tp args) =
    [ SigD fromFn $ ArrowT `AppT` sconT nm `AppT` sconT tp
    , FunD fromFn $ map enumValFromClause args
    ]
  where fromFn = mkName $ "from" ++ nm

quoteEnumDec :: String -> Q [Dec]
quoteEnumDec msg = do
  loc <- location
  let (l,c) = loc_start loc
  let parseTokens s (h :+ r)    = parseTokens (h:s) r
      parseTokens _ (Error p _) = fail $ ppPos p ++ ": Error parsing enum."
      parseTokens s End = return (reverse s)
  tokens <- parseTokens [] $ lexEnum (Pos (loc_filename loc) l c) msg
  let d = parseEnum tokens
  toDec <- enumToDec d
  return $ enumDataDec d : toDec ++ enumFromDec d
    
-- | The enum quasiquoter provides a mechanism for declaring datatypes that
-- correspond with C enums in a typesafe way.
enum :: QuasiQuoter
enum = QuasiQuoter {
           quoteExp = unsupported
         , quotePat = unsupported
         , quoteType = unsupported
         , quoteDec = quoteEnumDec            
         }
  where unsupported _ = fail "enum quasiquote must appear as declaration."