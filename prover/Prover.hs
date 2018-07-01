{-# language TypeOperators, ConstraintKinds #-}
module Prover where

import Data.Constraint
import Control.Monad.Trans.Writer
import Hash

data Auth a = Auth a Hash

type M = Writer [String]

type Evident = Show

instance Show (Auth a) where
  showsPrec d (Auth _ h) = showsPrec d h

ejson :: (Show a, Read a) :- Evident a
ejson = Sub Dict

eauth :: Dict (Evident (Auth a))
eauth = Dict

auth :: Evident a => a -> Auth a
auth a = Auth a (sha1 (show a))

unauth :: Evident a => Auth a -> M a
unauth (Auth a _) = writer (a, [show a])
