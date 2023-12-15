{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE OverloadedStrings #-}

module Nats.Nkeys.Codec (KeyPrefix (..), Nats.Nkeys.Codec.encode, encodeSeed, fromByte, toByte, decode, extractSeedPrefix, extractCrc) where

import Data.Binary (encode, putWord8)
import Data.Bits
import Debug.Trace (trace)
import Text.Printf (printf)
import Data.ByteString as B
import Data.ByteString.Base32 (decodeBase32, decodeBase32Unpadded, encodeBase32Unpadded)
import Data.Data
import Data.Text (Text, pack, append)
import Data.Text.Encoding (encodeUtf8)
import Data.Word (Word16, Word8)
import Nats.Nkeys.Crc

-- | Represents the well-known prefixes available for NATS-encoded keys
data KeyPrefix = Seed -- ^ (__S__) Precedes all seed keys, followed by a type prefix
  | Private -- ^ (__P__) Used for private keys
  | Server -- ^ (__N__) Servers and their ilk (nodes, processes, etc)
  | Cluster -- ^ (__C__) Clusters
  | Operator -- ^ (__O__) Operators
  | Account -- ^ (__A__) Accounts
  | User -- ^ (__U__) Users
  | Curve  -- ^ (__X__) Curve keys used for encryption/decryption
  | Unknown -- ^ (__Z__) Catch-all for unknown prefixes
   deriving (Eq, Show, Data, Typeable)

toByte :: KeyPrefix -> Word8
toByte prefix = case prefix of
  Seed -> 18 `shiftL` 3
  Private -> 15 `shiftL` 3
  Server -> 13 `shiftL` 3
  Cluster -> 2 `shiftL` 3
  Operator -> 14 `shiftL` 3
  Account -> 0
  User -> 20 `shiftL` 3
  Curve -> 23 `shiftL` 3
  Unknown -> 25 `shiftL` 3

fromByte :: Word8 -> KeyPrefix
fromByte input = case input of
  144 -> Seed
  120 -> Private
  104 -> Server
  16 -> Cluster
  112 -> Operator
  0 -> Account
  160 -> User
  184 -> Curve
  200 -> Unknown
  _ -> Unknown

encode :: KeyPrefix -> ByteString -> ByteString
encode prefix input =
  let raw = B.cons (toByte prefix) input
   in encodeUtf8 . encodeBase32Unpadded $ appendCrc raw

encodeSeed :: KeyPrefix -> ByteString -> ByteString
encodeSeed publicPrefix input =
  let input' = B.take 32 input
      s = toByte Seed
      p = toByte publicPrefix
      raw = prefixBytes [s .|. p `shiftR` 5, fromIntegral $ (p .&. 31) `shiftL` 3] input'
   in encodeUtf8 . encodeBase32Unpadded $ appendCrc raw

decode :: ByteString -> Either Text ByteString
decode input =
  let decoded = decodeBase32Unpadded input
      trimmed = dropEnd 2 <$> decoded
      crc = crc16 <$> trimmed
      expectedCrc = extractCrc <$> decoded       
      crcValid = case (expectedCrc, crc) of
        (Left _, _) -> False
        (_, Left _) -> False
        (Right d, Right c) -> d == c  
  in
    if crcValid then
      trimmed
    else
      Left ("Invalid CRC " :: Text)

extractCrc :: ByteString -> Word16
extractCrc input =
  let input' = B.takeEnd 2 input
  in
  case B.unpack input' of
    [a,b] -> word16FromBytes (a, b)
    _ ->
      0

extractSeedPrefix :: ByteString -> KeyPrefix
extractSeedPrefix input =
  let r0 = B.head input
      r1 = B.index input 1
      b0 = r0 .&. 248
      b1 = ((r0 .&. 7) `shiftL` 5) .|. ((r1 .&. 248) `shiftR` 3)
      pb0 = fromByte b0
      pb1 = fromByte b1
  in
    if pb0 /= Seed
    then Unknown
    else pb1

prefixBytes :: [Word8] -> ByteString -> ByteString
prefixBytes bytes input =
  let prepend = B.pack bytes
  in
    B.append prepend input

appendBytes :: [Word8] -> ByteString -> ByteString
appendBytes bytes input =
  let suffix = B.pack bytes
  in
    B.append input suffix

appendCrc :: ByteString -> ByteString
appendCrc raw = 
  let crc = crc16 raw      
  in B.append raw $ B.pack $ encodeWord16 crc


encodeWord16 :: Word16 -> [Word8]
encodeWord16 x =
  let right_byte = x .&. 0xFF
      left_byte = ( x `shiftR` 8 ) .&. 0xFF
  in Prelude.map fromIntegral [right_byte, left_byte]

word16FromBytes :: (Word8, Word8) -> Word16 
word16FromBytes (a, b) =
  let a' = fromIntegral a
      b' = shift (fromIntegral b) 8
  in
    a' .|. b'