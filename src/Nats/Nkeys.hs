-- |
-- Module       : Nats.Nkeys
-- Copyright    : (c) 2023 Kevin Hoffman
-- License      : Apache-2.0
--
-- Maintainer   : Kevin Hoffman
--
-- Support for the NATS encoding of ed25519 key pairs. Internally these keys and seeds are standard
-- ed25519 bytes. This package provides an encoding/decoding layer on top that produces the long,
-- capital-letter keys that begin with well-known prefixes.
--
-- The main benefit to using the NATS encoding for ed25519 keys is that Nkeys are URL-safe, prefixed
-- with the purpose/role of the key, and are even double-clickable on most computers. Nkeys are also
-- an integral part of NATS's decentralized, JWT-based security.
--
-- =Usage
-- The following code shows some of the common ways of using this library
--
-- Creating a key pair from random bytes:
-- 
-- >>> bob <- create User
-- >>> bob
-- UBXEJQE5OZ2Y7YAWGLRQQDTFFUVUQMRZG6W4BU3FW2XDNYBXMH72OR45
--
-- Create a key pair from an existing seed:
--
-- >>> Just alice = createFromSeed $ seed bob
-- >>> alice
-- UBXEJQE5OZ2Y7YAWGLRQQDTFFUVUQMRZG6W4BU3FW2XDNYBXMH72OR45
-- 
-- Sign and verify messages using keys:
--
-- >>> let message = C.pack "hello there"
-- >>> let Just sig = sign bob message
-- >>> let verified = verify bob message sig
--

module Nats.Nkeys (
    module Nats.Nkeys.Pairs,
    module Nats.Nkeys.Codec,
    module Crypto.Sign.Ed25519    
) where

import Nats.Nkeys.Pairs (KeyPair, create, publicKey, seed, createFromSeed, sign, verify)
import Nats.Nkeys.Codec (KeyPrefix(..))
import Crypto.Sign.Ed25519 (Signature)
