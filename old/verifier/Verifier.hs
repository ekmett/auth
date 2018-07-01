{-# language LambdaCase #-}
{-# language UndecidableInstances #-}
{-# language MonoLocalBinds #-}
{-# language GeneralizedNewtypeDeriving #-}
{-# language FlexibleInstances #-}
{-# language TupleSections #-}

module Verifier where

import Control.Monad.Trans.State
import Hash
import Text.Read

newtype Auth a = Auth Hash

instance Show (Auth a) where
  showsPrec d (Auth h) = showsPrec d h

instance Read (Auth a) where
  readPrec = Auth <$> readPrec

type M = StateT [String] Maybe

class (Read a, Show a) => Evident a
instance (Read a, Show a) => Evident a

auth :: Evident a => a -> Auth a
auth = Auth . sha1 . show

unauth :: Evident a => Auth a -> M a
unauth (Auth h) = StateT $ \case
  p:ps | sha1 p == h -> (,ps) <$> readMaybe p
  _ -> Nothing

