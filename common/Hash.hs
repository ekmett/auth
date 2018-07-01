module Hash where

import Crypto.Hash.SHA1
import Data.Aeson

sha1 :: Value -> String
sha1 v = show (hashlazy (encode v))
