{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}

module Nats.Nkeys.Pairs where

import Crypto.Sign.Ed25519 (PublicKey (unPublicKey), SecretKey (unSecretKey), Signature, createKeypair, createKeypairFromSeed_, dsign, dverify)
import Data.ByteString (drop, index)
import Data.ByteString hiding (unpack)
import Data.Text (pack, unpack)
import Data.Text.Encoding (decodeUtf8, encodeUtf8)
import Nats.Nkeys.Codec (KeyPrefix (..), decode, encode, encodeSeed, extractSeedPrefix, fromByte)

-- | Represents an ed25519 key pair with NATS string encoding
data KeyPair = KeyPair {prefixByte :: KeyPrefix, pk :: PublicKey, sk :: SecretKey} deriving (Eq)

instance Show KeyPair where
  show p = unpack . decodeUtf8 $ publicKey p

-- | Returns the public key of the pair as a prefixed byte string
publicKey :: KeyPair -> ByteString
publicKey (KeyPair {prefixByte, pk, ..}) = encode prefixByte $ unPublicKey pk

-- | Returns the seed (private) key of the pair as a prefixed string starting with S
seed :: KeyPair -> ByteString
seed (KeyPair {prefixByte, sk, ..}) = encodeSeed prefixByte $ unSecretKey sk

-- | Creates a new keypair from an encoded seed with an appropriate prefix. Do not
-- call this function with unencoded ed25519 seeds
createFromSeed :: ByteString -> Maybe KeyPair
createFromSeed input =
  let decoded = decode input
      prefix = case extractSeedPrefix <$> decoded of
        Left _ -> Unknown
        Right p -> p
      rawkp = createKeypairFromSeed_ . Data.ByteString.drop 2 <$> decoded
   in case rawkp of
        Left x -> Nothing
        Right Nothing -> Nothing
        Right (Just (p, s)) ->
          Just KeyPair {prefixByte = prefix, pk = p, sk = s}

-- | This IO action creates a new key pair from a randomly generated 32-byte seed
create :: KeyPrefix -> IO KeyPair
create prefix = do
  (pk, sk) <- createKeypair
  return KeyPair {prefixByte = prefix, pk = pk, sk = sk}

-- | Signs the given input bytes using the key pair's seed key
sign :: KeyPair -> ByteString -> Maybe Signature
sign (KeyPair {prefixByte = Curve, ..}) = const Nothing
sign (KeyPair {sk, ..}) = Just . Crypto.Sign.Ed25519.dsign sk

-- | Verifies a signature against the key pair's public key and the input bytes
verify :: KeyPair -> ByteString -> Signature -> Bool
verify (KeyPair {prefixByte = Curve, ..}) = \ _ _ -> False
verify (KeyPair {pk, ..}) = Crypto.Sign.Ed25519.dverify pk