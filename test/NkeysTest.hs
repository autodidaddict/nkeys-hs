{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleInstances #-}

module Main where

import Test.HUnit
import qualified System.Exit as Exit
import qualified Data.ByteString.Char8 as C
import Data.Text.Encoding
import Crypto.Sign.Ed25519 hiding (sign, verify)
import Data.ByteString.Base32 (decodeBase32, decodeBase32Unpadded, encodeBase32Unpadded)

import Data.ByteString as BS
import Nats.Nkeys

codecRoundTrip :: Test
codecRoundTrip =
    TestCase (do bob <- create User
                 let bobSeed = seed bob
                 case createFromSeed bobSeed of
                    Just roundTripUser -> 
                        assertEqual "decoded encode should equal original key" bobSeed (seed roundTripUser)
                    Nothing ->
                        assertBool "failed round trip of generated pair" False)

verifyAndSignTest :: Test
verifyAndSignTest =
    TestCase (do bob <- create User                 
                 let message = "hello there" :: ByteString
                 let Just sig = sign bob message
                 let verified = verify bob message sig
                 assertEqual "signature should be verifiable" verified True)

officialGoRoundTrip :: Test
officialGoRoundTrip =
    TestCase (do let goPublic = "UAYTKBRMQCOPT7AGPZA3U5QYUNZIZYLL6TX4WY36GBEGZSVP4TIXUY3B"
                 let goSeed = "SUALB7CYOPEXH27JJHTWAR5JOLFRCVT2J2AJYBZ5GBP6I52HUW5JKLLJPU"
                 let Just roundTripUser = createFromSeed goSeed
                 assertEqual "decoded encode public key should match" goPublic (publicKey roundTripUser)
                 assertEqual "decoded encode should equal original key" goSeed (seed roundTripUser))

rejectBadCrc :: Test
rejectBadCrc = 
    -- note the last character of the go seed has been tampered with
    TestCase (do let goSeed = "SUALB7CYOPEXH27JJHTWAR5JOLFRCVT2J2AJYBZ5GBP6I52HUW5JKLLJPA"
                 let m = createFromSeed goSeed
                 assertEqual "should not be able to create seed with bad CRC" m Nothing)

-- commented out because I don't want the crc function exposed in the public API

-- crc :: Test 
-- crc = 
--     TestCase (do let goSeed = "SUALB7CYOPEXH27JJHTWAR5JOLFRCVT2J2AJYBZ5GBP6I52HUW5JKLLJPU" :: ByteString
--                      input = dropEnd 2 <$> decodeBase32Unpadded goSeed
--                      crc = case input of
--                         Right i -> crc16 i
--                         _ -> 42
                 
--                  assertEqual "CRC" crc 32105) -- 32105 obtained by executing crc16 function in the Go lib

tests :: Test
tests = TestList [TestLabel "Codec Round Trip" codecRoundTrip,
                  TestLabel "Round Trip with Go-Generated Seed" officialGoRoundTrip,
--                  TestLabel "Verify CRC matches Go CRC" crc,
                  TestLabel "Cannot create a pair with a bad CRC" rejectBadCrc,
                  TestLabel "Verification Round Trip" verifyAndSignTest]

main :: IO ()
main = do
    result <- runTestTT tests    
    if failures result > 0 then Exit.exitFailure else Exit.exitSuccess

