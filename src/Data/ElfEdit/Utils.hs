module Data.ElfEdit.Utils

-- | Append names together with "|"
symbolNameMap :: Ord k => (a -> a -> a) -> [(k,a)] -> Map k a
symbolNameMap merge = foldl' ins Map.empty
  where ins m (k,v) = Map.insertWith merge k v m
