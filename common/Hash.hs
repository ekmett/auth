module Hash where

import Crypto.Hash
import Data.Aeson

sha1 :: Value -> String
sha1 v = show (hashlazy (encode v) :: Digest SHA1)
