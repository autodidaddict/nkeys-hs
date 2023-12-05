module Main where

import Test.HUnit
import qualified System.Exit as Exit
import qualified Data.ByteString.Char8 as C
import Crypto.Sign.Ed25519 hiding (sign, verify)
import Data.ByteString as BS
import Nats.Nkeys

codecRoundTrip :: Test
codecRoundTrip =
    TestCase (do bob <- create User
                 let bobSeed = seed bob
                 let Just roundTripUser = createFromSeed bobSeed
                 assertEqual "decoded encode should equal original key" bobSeed (seed roundTripUser))

verifyAndSignTest :: Test
verifyAndSignTest =
    TestCase (do bob <- create User
                 let message = C.pack "hello there"
                 let Just sig = sign bob message
                 let verified = verify bob message sig
                 assertEqual "signature should be verifiable" verified True)

tests :: Test
tests = TestList [TestLabel "Codec Round Trip" codecRoundTrip,
                  TestLabel "Verification Round Trip" verifyAndSignTest]

main :: IO ()
main = do
    result <- runTestTT tests    
    if failures result > 0 then Exit.exitFailure else Exit.exitSuccess

