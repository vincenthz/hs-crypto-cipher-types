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
    -- * Keys Types
      Key
    , Key64
    , Key128
    , Key192
    , Key256
    -- * Keys Constructors
    , key
    , key64
    , key128
    , key192
    , key256
    , InvalidKeySize(..)
    -- * Initial Vectors Types
    , IV(..)
    , IV64
    , IV128
    , IV256
    -- * Initial Vectors Constructors
    , iv64
    , iv128
    , iv256
    , InvalidIVSize(..)
    -- * Authentification Tag
    , AuthTag(..)
    ) where

import Data.SecureMem
import Control.Exception (Exception, throw)
import Data.Data
import Data.ByteString as B
import Data.Byteable

-- | arbitrary sized key
newtype Key = Key SecureMem
    deriving (Eq)

-- | 64 bits key
newtype Key64 = Key64 SecureMem
    deriving (Eq)

-- | 128 bits key
newtype Key128 = Key128 SecureMem
    deriving (Eq)

-- | 192 bits key
newtype Key192 = Key192 SecureMem
    deriving (Eq)

-- | 256 bits key
newtype Key256 = Key256 SecureMem
    deriving (Eq)

-- | Invalid Key size exception raised if key is not of proper size.
--
-- the first argument is the expected size and the second is the
-- received size.
data InvalidKeySize = InvalidKeySize Int Int
    deriving (Show,Eq,Typeable)

instance Exception InvalidKeySize

-- | Create an arbitrary size Key
key :: ByteString -> Key
key b = Key $ toSecureMem b

-- | Create a 64 bit Key
key64 :: ByteString -> Key64
key64 b
    | B.length b == 8 = Key64 $ toSecureMem b
    | otherwise       = throw $ InvalidKeySize 8 (B.length b)

-- | Create a 128 bit Key
key128 :: ByteString -> Key128
key128 b
    | B.length b == 16 = Key128 $ toSecureMem b
    | otherwise        = throw $ InvalidKeySize 16 (B.length b)

-- | Create a 192 bit Key
key192 :: ByteString -> Key192
key192 b
    | B.length b == 24 = Key192 $ toSecureMem b
    | otherwise        = throw $ InvalidKeySize 24 (B.length b)

-- | Create a 256 bit Key
key256 :: ByteString -> Key256
key256 b
    | B.length b == 32 = Key256 $ toSecureMem b
    | otherwise        = throw $ InvalidKeySize 32 (B.length b)

instance ToSecureMem Key where
    toSecureMem (Key sm) = sm
instance ToSecureMem Key64 where
    toSecureMem (Key64 sm) = sm
instance ToSecureMem Key128 where
    toSecureMem (Key128 sm) = sm
instance ToSecureMem Key192 where
    toSecureMem (Key192 sm) = sm
instance ToSecureMem Key256 where
    toSecureMem (Key256 sm) = sm
instance Byteable Key where
    toBytes (Key sm) = toBytes sm
instance Byteable Key64 where
    toBytes (Key64 sm) = toBytes sm
instance Byteable Key128 where
    toBytes (Key128 sm) = toBytes sm
instance Byteable Key192 where
    toBytes (Key192 sm) = toBytes sm
instance Byteable Key256 where
    toBytes (Key256 sm) = toBytes sm

-- | arbitrary size IV
newtype IV = IV ByteString
    deriving (Eq)

-- | 64 bits IV
newtype IV64 = IV64 ByteString
    deriving (Eq)

-- | 128 bits IV
newtype IV128 = IV128 ByteString
    deriving (Eq)

-- | 256 bits IV
newtype IV256 = IV256 ByteString
    deriving (Eq)

-- | Invalid IV size exception raised if IV is not of proper size.
--
-- the first argument is the expected size and the second is the
-- received size.
data InvalidIVSize = InvalidIVSize Int Int
    deriving (Show,Eq,Typeable)

instance Exception InvalidIVSize

-- | Create a 64 bits IV from a bytestring
iv64 :: ByteString -> IV64
iv64 b
    | B.length b == 8 = IV64 b
    | otherwise       = throw $ InvalidIVSize 8 (B.length b)

-- | Create a 128 bits IV from a bytestring
iv128 :: ByteString -> IV128
iv128 b
    | B.length b == 16 = IV128 b
    | otherwise        = throw $ InvalidIVSize 16 (B.length b)

-- | Create a 256 bits IV from a bytestring
iv256 :: ByteString -> IV256
iv256 b
    | B.length b == 32 = IV256 b
    | otherwise        = throw $ InvalidIVSize 32 (B.length b)

instance Byteable IV where
    toBytes (IV sm) = sm
instance Byteable IV64 where
    toBytes (IV64 sm) = sm
instance Byteable IV128 where
    toBytes (IV128 sm) = sm
instance Byteable IV256 where
    toBytes (IV256 sm) = sm

-- | Authentification Tag for AE cipher mode
newtype AuthTag = AuthTag ByteString

instance Eq AuthTag where
    (AuthTag a) == (AuthTag b) = constEqBytes a b
instance Byteable AuthTag where
    toBytes (AuthTag bs) = bs
