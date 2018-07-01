module Hash where

import Crypto.Hash.SHA1
import Data.ByteString.Lazy.UTF8 as UTF8

type Hash = String

sha1 :: String -> Hash
sha1 = show . hashlazy . UTF8.fromString
