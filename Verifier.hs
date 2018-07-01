{-# language LambdaCase #-}
{-# language UndecidableInstances #-}
{-# language MonoLocalBinds #-}
{-# language GeneralizedNewtypeDeriving #-}
{-# language FlexibleInstances #-}

module Verifier where

import Control.Monad.Trans.State
import Data.Aeson
import Hash

newtype Auth a = Auth String
  deriving (ToJSON, FromJSON)

type M = StateT [Value] Maybe

class (ToJSON a, FromJSON a) => Evident a
instance (ToJSON a, FromJSON a) => Evident a

auth :: Evident a => a -> Auth a
auth = Auth . sha1 . toJSON

unauth :: Evident a => Auth a -> M a
unauth (Auth h) = StateT $ \case
  p:ps | sha1 p == h -> case fromJSON p of
    Error _ -> Nothing
    Success a -> Just (a, ps)
  _ -> Nothing

