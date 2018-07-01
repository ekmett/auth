{-# language TypeOperators, ConstraintKinds #-}
module Prover where

import Data.Constraint
import Data.Aeson
import Control.Monad.Trans.Writer
import Hash

data Auth a = Auth a String
  deriving Show

type M = Writer [Value]

type Evident = ToJSON

instance ToJSON (Auth a) where
  toJSON (Auth _ h) = toJSON h

ejson :: (ToJSON a, FromJSON a) :- Evident a
ejson = Sub Dict

eauth :: Dict (Evident (Auth a))
eauth = Dict

auth :: Evident a => a -> Auth a
auth a = Auth a (sha1 (toJSON a))

unauth :: Evident a => Auth a -> M a
unauth (Auth a _) = writer (a, [toJSON a])
