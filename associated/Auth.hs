{-# language AllowAmbiguousTypes #-}
{-# language ConstraintKinds #-}
{-# language DefaultSignatures #-}
{-# language DeriveFunctor #-}
{-# language FlexibleContexts #-}
{-# language KindSignatures #-}
{-# language LambdaCase #-}
{-# language RankNTypes #-}
{-# language ScopedTypeVariables #-}
{-# language TupleSections #-}
{-# language TypeApplications #-}
{-# language TypeFamilies #-}
{-# language TypeOperators #-}

module Auth where

import Control.Applicative
import Control.Monad (ap)
import Control.Monad.Trans.Class
import Crypto.Hash.SHA1
import Data.ByteString.Lazy.UTF8 as UTF8
import Data.ByteString.Base16 as Base16
import Text.Read hiding (lift)
import Control.Monad.Trans.State.Lazy as Lazy
import Control.Monad.Trans.State.Strict as Strict
import Control.Monad.Trans.Writer.Lazy as Lazy
import Control.Monad.Trans.Writer.Strict as Strict
import Control.Monad.Trans.Reader
import Control.Monad.Trans.RWS.Lazy as Lazy
import Control.Monad.Trans.RWS.Strict as Strict
import Prelude hiding (lookup)

type Hash = String

sha1 :: String -> Hash
sha1 = show . Base16.encode . hashlazy . UTF8.fromString

type Evident a = (Show a, Read a)

class Monad m => MonadAuth m where
  data Auth m :: * -> *
  auth  :: Evident a => a -> Auth m a
  unauth :: Evident a => Auth m a -> m a

  showsPrecAuth :: Int -> Auth m a -> ShowS
  readPrecAuth :: ReadPrec (Auth m a) -- lies!

instance MonadAuth m => Show (Auth m a) where
  showsPrec = showsPrecAuth

instance MonadAuth m => Read (Auth m a) where
  readPrec = readPrecAuth

instance MonadAuth m => MonadAuth (Lazy.StateT s m) where
  newtype Auth (Lazy.StateT s m) a = AuthLazyState { unauthLazyState :: Auth m a }
  auth = AuthLazyState . auth
  unauth = lift . unauth . unauthLazyState
  showsPrecAuth d = showsPrecAuth d . unauthLazyState
  readPrecAuth = AuthLazyState <$> readPrec

instance MonadAuth m => MonadAuth (Strict.StateT s m) where
  newtype Auth (Strict.StateT s m) a = AuthStrictState { unauthStrictState :: Auth m a }
  auth = AuthStrictState . auth
  unauth = lift . unauth . unauthStrictState
  showsPrecAuth d = showsPrecAuth d . unauthStrictState
  readPrecAuth = AuthStrictState <$> readPrec

instance (Monoid w, MonadAuth m) => MonadAuth (Lazy.WriterT w m) where
  newtype Auth (Lazy.WriterT w m) a = AuthLazyWriter { unauthLazyWriter :: Auth m a }
  auth = AuthLazyWriter . auth
  unauth = lift . unauth . unauthLazyWriter
  showsPrecAuth d = showsPrecAuth d . unauthLazyWriter
  readPrecAuth = AuthLazyWriter <$> readPrec

instance (Monoid w, MonadAuth m) => MonadAuth (Strict.WriterT w m ) where
  newtype Auth (Strict.WriterT w m) a = AuthStrictWriter { unauthStrictWriter :: Auth m a }
  auth = AuthStrictWriter . auth
  unauth = lift . unauth . unauthStrictWriter
  showsPrecAuth d = showsPrecAuth d . unauthStrictWriter
  readPrecAuth = AuthStrictWriter <$> readPrec

instance MonadAuth m => MonadAuth (ReaderT e m) where
  newtype Auth (ReaderT e m) a = AuthReader { unauthReader :: Auth m a }
  auth = AuthReader . auth
  unauth = lift . unauth . unauthReader
  showsPrecAuth d = showsPrecAuth d . unauthReader
  readPrecAuth = AuthReader <$> readPrec

instance (Monoid w, MonadAuth m) => MonadAuth (Lazy.RWST r w s m) where
  newtype Auth (Lazy.RWST r w s m) a = AuthLazyRWS { unauthLazyRWS :: Auth m a }
  auth = AuthLazyRWS . auth
  unauth = lift . unauth . unauthLazyRWS
  showsPrecAuth d = showsPrecAuth d . unauthLazyRWS
  readPrecAuth = AuthLazyRWS <$> readPrec

instance (Monoid w, MonadAuth m) => MonadAuth (Strict.RWST r w s m) where
  newtype Auth (Strict.RWST r w s m) a = AuthStrictRWS { unauthStrictRWS :: Auth m a }
  auth = AuthStrictRWS . auth
  unauth = lift . unauth . unauthStrictRWS
  showsPrecAuth d = showsPrecAuth d . unauthStrictRWS
  readPrecAuth = AuthStrictRWS <$> readPrec

type Certificate = [String]

newtype Prover a = Prover { runProver :: Certificate -> (a, Certificate ) } -- reversed cert
  deriving Functor

instance Applicative Prover where
  pure a = Prover $ \s -> (a, s)
  (<*>) = ap

instance Monad Prover where
  Prover m >>= f = Prover $ \s -> case m s of
    (a, s') -> runProver (f a) s'
  
instance MonadAuth Prover where
  data Auth Prover a = Proof a Hash
  auth a = Proof a (sha1 (show a))
  unauth (Proof a _) = Prover $ \s -> (a, show a:s)
  showsPrecAuth d (Proof _ h) = showsPrec d h
  readPrecAuth = empty

newtype Verifier a = Verifier { runVerifier :: Certificate -> Maybe (a, Certificate) }
  deriving Functor

instance Applicative Verifier where
  pure a = Verifier $ \s -> Just (a, s)
  (<*>) = ap

instance Monad Verifier where
  Verifier m >>= f = Verifier $ \s -> do
    (a, s') <- m s
    runVerifier (f a) s'
    
instance MonadAuth Verifier where
  newtype Auth Verifier a = Verification Hash
  auth = Verification . sha1 . show
  unauth (Verification h) = Verifier $ \case
    p:ps | sha1 p == h -> (,ps) <$> readMaybe p
    _ -> Nothing
  showsPrecAuth d (Verification h) = showsPrec d h
  readPrecAuth = Verification <$> readPrec

trust :: (forall m. MonadAuth m => m a) -> (a, Certificate)
trust m = reverse <$> runProver m []

verify :: (forall m. MonadAuth m => m a) -> Certificate -> Maybe a
verify m c = do
  (a, []) <- runVerifier m c
  pure a
  
trustButVerify :: (forall m. MonadAuth m => m a) -> (a, a)
trustButVerify m = (a, b)
  where 
    (a, c) = trust m
    Just b = verify m c

type Path = [Bool]

data T a b = Tip a | Bin b b
  deriving (Read, Show)

newtype Tree m a = Tree { runTree :: Auth m (T a (Tree m a)) }
  deriving (Read, Show)

tip :: (MonadAuth m, Evident a) => a -> Tree m a
tip a = Tree (auth (Tip a))

bin :: (MonadAuth m, Evident a) => Tree m a -> Tree m a -> Tree m a
bin l r = Tree (auth (Bin l r))

lookup :: (MonadAuth m, Evident a) => Path -> Tree m a -> m (Maybe a)
lookup p (Tree t) = unauth t >>= \tree -> case (p, tree) of
  ([], Tip a) -> return $ Just a
  (False:q, Bin l _) -> lookup q l
  (True:q, Bin _ r) -> lookup q r
  (_,_) -> return Nothing

update :: (MonadAuth m, Evident a) => Path -> a -> Tree m a -> m (Maybe (Tree m a))
update p v (Tree t) = 
