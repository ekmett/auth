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

import Control.Monad (ap)
import Control.Monad.Trans.Class
import Crypto.Hash.SHA1
import Data.ByteString.Lazy.UTF8 as UTF8
import Data.ByteString.Base16 as Base16
import Data.Constraint
import Text.Read hiding (lift)
import Control.Monad.Trans.State.Lazy as Lazy
import Control.Monad.Trans.State.Strict as Strict
import Control.Monad.Trans.Writer.Lazy as Lazy
import Control.Monad.Trans.Writer.Strict as Strict
import Control.Monad.Trans.Reader
import Control.Monad.Trans.RWS.Lazy as Lazy
import Control.Monad.Trans.RWS.Strict as Strict

type Hash = String

sha1 :: String -> Hash
sha1 = show . Base16.encode . hashlazy . UTF8.fromString

-- class ( forall a. Evident t (t a) , forall a. (Show a, Read a) => Evident t a) => Authentic t where
class Authentic t where
 type Evident t a :: Constraint
 type Evident t a = (Show a, Read a)
 ev :: (Show a, Read a) :- Evident t a
 eauth :: Dict (Evident t (t a))
 auth :: Evident t a => a -> t a

authv :: forall t a. (Authentic t, Read a, Show a) => a -> t a
authv a = case ev @t @a of
  Sub Dict -> auth a

authauth :: forall t a. Authentic t => t a -> t (t a)
authauth a = case eauth @t @a of
  Dict -> auth a

class (Monad m, Authentic (Auth m)) => MonadAuth m where
  type Auth m :: * -> *
  unauth :: Evident (Auth m) a => Auth m a -> m a
  default unauth :: (MonadTrans s, MonadAuth n, m ~ s n, Auth m ~ Auth n, Evident (Auth m) a) => Auth m a -> m a
  unauth = lift . unauth

unauthv :: forall m a. (MonadAuth m, Read a, Show a) => Auth m a -> m a
unauthv a = case ev @(Auth m) @a of
  Sub Dict -> unauth a

unauthauth :: forall m a. MonadAuth m => Auth m (Auth m a) -> m (Auth m a)
unauthauth a = case eauth @(Auth m) @a of
  Dict -> unauth a


instance MonadAuth m => MonadAuth (Lazy.StateT s m) where
  type Auth (Lazy.StateT s m) = Auth m

instance MonadAuth m => MonadAuth (Strict.StateT s m) where
  type Auth (Strict.StateT s m) = Auth m

instance (Monoid w, MonadAuth m) => MonadAuth (Lazy.WriterT w m) where
  type Auth (Lazy.WriterT w m) = Auth m

instance (Monoid w, MonadAuth m) => MonadAuth (Strict.WriterT w m ) where
  type Auth (Strict.WriterT w m) = Auth m

instance MonadAuth m => MonadAuth (ReaderT e m) where
  type Auth (ReaderT e m) = Auth m

instance (Monoid w, MonadAuth m) => MonadAuth (Lazy.RWST r w s m) where
  type Auth (Lazy.RWST r w s m) = Auth m

instance (Monoid w, MonadAuth m) => MonadAuth (Strict.RWST r w s m) where
  type Auth (Strict.RWST r w s m) = Auth m

-- Cont, Accum, ...

type Certificate = [String]

-- unauthv 
-- unauthauth 

data Proof a = Proof a Hash

instance Show (Proof a) where
  showsPrec d (Proof _ h) = showsPrec d h

instance Authentic Proof where
  type Evident Proof a = Show a
  auth a = Proof a (sha1 (show a))
  ev = Sub Dict
  eauth = Dict

newtype Prover a = Prover { runProver :: Certificate -> (a, Certificate ) } -- reversed cert
  deriving Functor

instance Applicative Prover where
  pure a = Prover $ \s -> (a, s)
  (<*>) = ap

instance Monad Prover where
  Prover m >>= f = Prover $ \s -> case m s of
    (a, s') -> runProver (f a) s'
  
instance MonadAuth Prover where
  type Auth Prover = Proof
  unauth (Proof a _) = Prover $ \s -> (a, show a:s)

newtype Verification a = Verification Hash

instance Show (Verification a) where
  showsPrec d (Verification h) = showsPrec d h

instance Read (Verification a) where
  readPrec = Verification <$> readPrec

instance Authentic Verification where
  type Evident Verification a = (Show a, Read a)
  ev = Sub Dict
  eauth = Dict
  auth = Verification . sha1 . show

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
  type Auth Verifier = Verification
  unauth (Verification h) = Verifier $ \case
    p:ps | sha1 p == h -> (,ps) <$> readMaybe p
    _ -> Nothing


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
