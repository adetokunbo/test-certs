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
  -- * @NameConfig@
  NameConfig (..),
  defaultNameConfig,

  -- * @CertPath@
  CertPaths (..),
  keyPath,
  certificatePath,
  generateAndStoreSSL,
  generateAndStoreSSL',
  withCertPathsInTmpSSL',
  withCertPathsInTmpSSL,
  withCertPathsSSL,
) where

import qualified Data.ByteString as BS
import Data.Text (Text)
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
systemTmpStoreConfig :: IO CertPaths
systemTmpStoreConfig = defaultBasenames <$> getCanonicalTemporaryDirectory


{- | A @CertPaths using the default basenames for the certificate files
@cpKey@ is @key.pem@
@cpCert@ is @certificate.pem@
-}
defaultBasenames :: FilePath -> CertPaths
defaultBasenames cpDir = CertPaths {cpDir, cpKey = "key.pem", cpCert = "certificate.pem"}


-- | Configure details of the information in the generated certificates
data NameConfig = NameConfig
  { ncCountry :: !Text
  , ncProvince :: !Text
  , ncCity :: !Text
  , ncOrganization :: !Text
  , ncTitle :: !Text
  , ncDurationDays :: !Natural
  }
  deriving (Eq, Show)


-- | A default value for @'NameConfig'@
defaultNameConfig :: NameConfig
defaultNameConfig =
  NameConfig
    { ncCountry = "Japan"
    , ncProvince = "Fukuoka"
    , ncCity = "Itoshima"
    , ncOrganization = "haskell:test-certs"
    , ncTitle = "localhost"
    , ncDurationDays = 365
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


genCertsSSL :: NameConfig -> IO (String, String)
genCertsSSL nc = do
  -- set up values to use in the certificate fields
  let mkSerialNum = BS.foldl (\a w -> a * 256 + fromIntegral w) 0
  serialNumber <- mkSerialNum <$> SSL.randBytes 8
  (start, end) <- validityNow $ ncDurationDays nc

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


storeCertsSSL :: CertPaths -> String -> String -> IO ()
storeCertsSSL cp rsaKey signedCert = do
  writeFile (keyPath cp) rsaKey
  writeFile (certificatePath cp) signedCert


-- | Generate and store certificate files as specified as @'CertPaths'@
generateAndStoreSSL :: CertPaths -> NameConfig -> IO ()
generateAndStoreSSL cp nc = do
  (certificate, privKey) <- genCertsSSL nc
  storeCertsSSL cp privKey certificate


-- | Like @generateAndStore@, but using default configuration
generateAndStoreSSL' :: IO ()
generateAndStoreSSL' = do
  sc <- systemTmpStoreConfig
  generateAndStoreSSL sc defaultNameConfig


{- | Create certificates in a temporary directory below @parentDir@, specify the
locations using a @CertPaths@, use them, then delete them
-}
withCertPathsSSL :: FilePath -> NameConfig -> (CertPaths -> IO a) -> IO a
withCertPathsSSL parentDir nc useSc =
  withTempDirectory parentDir "temp-certs" $ \cpDir -> do
    let sc = defaultBasenames cpDir
    generateAndStoreSSL sc nc
    useSc sc


-- | Like 'withCertPaths' with the system @TEMP@ dir as the @parentDir@
withCertPathsInTmpSSL :: NameConfig -> (CertPaths -> IO a) -> IO a
withCertPathsInTmpSSL nc action = do
  parentDir <- getCanonicalTemporaryDirectory
  withCertPathsSSL parentDir nc action


-- | Like 'withCertPathsInTmp' using a default @'NameConfig'@
withCertPathsInTmpSSL' :: (CertPaths -> IO a) -> IO a
withCertPathsInTmpSSL' = withCertPathsInTmpSSL defaultNameConfig
