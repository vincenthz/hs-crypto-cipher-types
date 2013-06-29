-- |
-- Module      : Crypto.Cipher.Types
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : Stable
-- Portability : Excellent
--
-- symmetric cipher basic types
--
{-# LANGUAGE DeriveDataTypeable #-}
module Crypto.Cipher.Types
    (
    -- * Cipher classes
      Cipher(..)
    , BlockCipher(..)
    , StreamCipher(..)
    -- * Key type and constructor
    , Key
    , key
    -- * Initial Vector type and constructor
    , IV
    , iv
    -- * Block type
    , Block(..)
    , block
    -- * Authentification Tag
    , AuthTag(..)
    ) where

import Data.SecureMem
--import Control.Exception (Exception, throw)
--import Data.Data
import Data.ByteString as B
import Data.Byteable

-- | Symmetric cipher class.
class Cipher cipher where
    -- | Initialize a cipher context from a key
    cipherInit    :: Key cipher -> cipher
    -- | return the size of the key required for this cipher.
    -- Some cipher accept any size for key
    cipherKeySize :: cipher -> Maybe Int

-- | Symmetric block cipher class
class Cipher cipher => BlockCipher cipher where
    -- | Return the size of block required for this block cipher
    blockSize    :: cipher -> Int
    -- | Encrypt one block using the block cipher
    blockEncrypt :: cipher -> Block cipher -> Block cipher
    -- | Decrypt one block using the block cipher
    blockDecrypt :: cipher -> Block cipher -> Block cipher

-- | Symmetric stream cipher class
class Cipher cipher => StreamCipher cipher where
    -- | Encrypt using the stream cipher
    streamEncrypt :: cipher -> ByteString -> (ByteString, cipher)
    -- | Decrypt using the stream cipher
    streamDecrypt :: cipher -> ByteString -> (ByteString, cipher)

-- | Block is a bytestring of a specific size through the parametrized c
newtype Block c = Block ByteString

instance Byteable (Block c) where
    toBytes (Block blk) = blk

-- | a Key parametrized by the cipher
newtype Key c = Key SecureMem deriving (Eq)

instance ToSecureMem (Key c) where
    toSecureMem (Key sm) = sm
instance Byteable (Key c) where
    toBytes (Key sm) = toBytes sm

-- | an IV parametrized by the cipher
newtype IV c = IV ByteString deriving (Eq)
instance Byteable (IV c) where
    toBytes (IV sm) = sm

-- | Authentification Tag for AE cipher mode
newtype AuthTag = AuthTag ByteString

instance Eq AuthTag where
    (AuthTag a) == (AuthTag b) = constEqBytes a b
instance Byteable AuthTag where
    toBytes (AuthTag bs) = bs

-- | Create a block for a specified block cipher
block :: (Byteable b, BlockCipher c) => b -> Maybe (Block c)
block b = toBlock undefined
  where toBlock :: BlockCipher c => c -> Maybe (Block c)
        toBlock cipher
          | byteableLength b == sz = Just (Block $ toBytes b)
          | otherwise              = Nothing
          where sz = blockSize cipher

-- | Create an IV for a specified block cipher
iv :: (Byteable b, BlockCipher c) => b -> Maybe (IV c)
iv b = toIV undefined
  where toIV :: BlockCipher c => c -> Maybe (IV c)
        toIV cipher
          | byteableLength b == sz = Just (IV $ toBytes b)
          | otherwise              = Nothing
          where sz = blockSize cipher

-- | Create a Key for a specified cipher
key :: (ToSecureMem b, Cipher c) => b -> Maybe (Key c)
key b = toKey undefined (toSecureMem b)
  where toKey :: Cipher c => c -> SecureMem -> Maybe (Key c)
        toKey cipher sm =
            case cipherKeySize cipher of
                Nothing                           -> Just $ Key sm
                Just sz | sz == byteableLength sm -> Just $ Key sm
                        | otherwise               -> Nothing
