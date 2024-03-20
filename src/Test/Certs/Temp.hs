{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

{- |
Module      : Test.Certs.Temp
Copyright   : (c) 2023 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3

Provides functions and/or data types that allow configuration and generation of teemporary temporary certificates
-}
module Test.Certs.Temp (
  -- * @Config@
  Config (..),
  defaultConfig,

  -- * @CertPath@
  CertPaths (..),
  keyPath,
  certificatePath,
  generateAndStore,
  generateAndStore',
  withCertPathsInTmp',
  withCertPathsInTmp,
  withCertPaths,
) where

import qualified Data.ByteString as BS
import Data.Text (Text)
import qualified Data.Text as Text
import Data.Time (UTCTime, addUTCTime, getCurrentTime, nominalDay)
import Numeric.Natural (Natural)
import qualified OpenSSL.PEM as SSL
import qualified OpenSSL.RSA as SSL
import qualified OpenSSL.Random as SSL
import qualified OpenSSL.X509 as SSL
import System.FilePath ((</>))
import System.IO.Temp (getCanonicalTemporaryDirectory, withTempDirectory)


-- | Specifies the location to write the temporary certificates
data CertPaths = CertPaths
  { cpKey :: !FilePath
  , cpCert :: !FilePath
  , cpDir :: !FilePath
  }
  deriving (Eq, Show)


-- | The path of the generated key file
keyPath :: CertPaths -> FilePath
keyPath cp = cpDir cp </> cpKey cp


-- | The path of the generated certificate file
certificatePath :: CertPaths -> FilePath
certificatePath cp = cpDir cp </> cpCert cp


{- | A @CertPaths@ using default basenames for the certificate files, and
the system @TEMP@ directory
-}
sysTmpCertPaths :: IO CertPaths
sysTmpCertPaths = defaultBasenames <$> getCanonicalTemporaryDirectory


{- | A @CertPaths using the default basenames for the certificate files
@cpKey@ is @key.pem@
@cpCert@ is @certificate.pem@
-}
defaultBasenames :: FilePath -> CertPaths
defaultBasenames cpDir =
  CertPaths
    { cpDir
    , cpKey = "key.pem"
    , cpCert = "certificate.pem"
    }


-- | Configure some details of the generated certificates
data Config = Config
  { cCountry :: !Text
  , cProvince :: !Text
  , cCity :: !Text
  , cOrganization :: !Text
  , cCommonName :: !Text
  , cDurationDays :: !Natural
  }
  deriving (Eq, Show)


-- | A default value for @'Config'@
defaultConfig :: Config
defaultConfig =
  Config
    { cCountry = "Japan"
    , cProvince = "Fukuoka"
    , cCity = "Itoshima"
    , cOrganization = "haskell:test-certs"
    , cCommonName = "localhost"
    , cDurationDays = 365
    }


validityNow :: Natural -> IO (UTCTime, UTCTime)
validityNow ndays = do
  start <- getCurrentTime
  let end = (nominalDay * fromIntegral ndays) `addUTCTime` start
  pure (start, end)


testKeySize :: Int
testKeySize = 4096


testExponent :: Integer
testExponent = 257


genCerts :: Config -> IO (String, String)
genCerts nc = do
  -- set up values to use in the certificate fields
  let mkSerialNum = BS.foldl (\a w -> a * 256 + fromIntegral w) 0
  serialNumber <- mkSerialNum <$> SSL.randBytes 8
  (start, end) <- validityNow $ cDurationDays nc

  -- generate an RSA key pair
  kp <- SSL.generateRSAKey' testKeySize $ fromIntegral testExponent

  -- create and sign a certificate using the private key of the key pair
  cert <- SSL.newX509
  SSL.setVersion cert 2
  SSL.setSerialNumber cert serialNumber
  SSL.setIssuerName cert [("CN", "haskell:test-certs")]
  SSL.setSubjectName cert [("CN", "haskell:test-certs")]
  SSL.setNotBefore cert start
  SSL.setNotAfter cert end
  SSL.setPublicKey cert kp
  SSL.signX509 cert kp Nothing

  -- the PEM representation of the private key
  privString <- SSL.writePKCS8PrivateKey kp Nothing

  -- the PEM representation of the certificate
  certString <- SSL.writeX509 cert

  pure (certString, privString)


storeCerts :: CertPaths -> String -> String -> IO ()
storeCerts cp rsaKey signedCert = do
  writeFile (keyPath cp) rsaKey
  writeFile (certificatePath cp) signedCert


-- | Generate and store certificate files as specified as @'CertPaths'@
generateAndStore :: CertPaths -> Config -> IO ()
generateAndStore cp config = do
  (certificate, privKey) <- genCerts config
  storeCerts cp privKey certificate


-- | Like @generateAndStore@, but using default configuration
generateAndStore' :: IO ()
generateAndStore' = do
  sc <- sysTmpCertPaths
  generateAndStore sc defaultConfig


{- | Create certificates in a temporary directory below @parentDir@, specify the
locations using a @CertPaths@, use them, then delete them
-}
withCertPaths :: FilePath -> Config -> (CertPaths -> IO a) -> IO a
withCertPaths parentDir config useSc =
  withTempDirectory parentDir "temp-certs" $ \cpDir -> do
    let sc = defaultBasenames cpDir
    generateAndStore sc config
    useSc sc


-- | Like 'withCertPaths' with the system @TEMP@ dir as the @parentDir@
withCertPathsInTmp :: Config -> (CertPaths -> IO a) -> IO a
withCertPathsInTmp config action = do
  parentDir <- getCanonicalTemporaryDirectory
  withCertPaths parentDir config action


-- | Like 'withCertPathsInTmp' using a default @'Config'@
withCertPathsInTmp' :: (CertPaths -> IO a) -> IO a
withCertPathsInTmp' = withCertPathsInTmp defaultConfig
