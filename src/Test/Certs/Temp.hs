{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TupleSections #-}

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
  generateAndStore,
  generateAndStore',
  withCertPathsInTmp',
  withCertPathsInTmp,
  withCertPaths,
  keyPath,
  certificatePath,
) where

import Control.Exception (ErrorCall (..), throwIO)
import Crypto.Hash (SHA256 (..))
import Crypto.PubKey.RSA (PrivateKey (..), PublicKey (..), generate)
import Crypto.PubKey.RSA.PKCS15 (signSafer)
import Crypto.Random (DRG (..), getSystemDRG)
import Data.ASN1.BinaryEncoding (DER (DER))
import Data.ASN1.Encoding (encodeASN1')
import Data.ASN1.OID (OIDable (..))
import Data.ASN1.Prim (ASN1 (..), ASN1ConstructionType (..))
import Data.ASN1.Types (asn1CharacterString)
import Data.ASN1.Types.String (ASN1StringEncoding (..))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Data.Hourglass (DateTime (..), Duration (..), TimeOfDay (..), timeAdd)
import Data.Maybe (fromMaybe)
import Data.PEM (PEM (PEM), pemWriteBS)
import Data.Text (Text)
import qualified Data.Text as Text
import Data.X509 (
  Certificate (..),
  DistinguishedName (DistinguishedName),
  DnElement (DnCommonName, DnCountry, DnOrganization),
  Extensions (Extensions),
  HashALG (HashSHA256),
  PubKey (PubKeyRSA),
  PubKeyALG (PubKeyALG_RSA),
  SignatureALG (SignatureALG),
  SignedExact (encodeSignedObject),
  objectToSignedExactF,
 )
import Numeric.Natural (Natural)
import qualified OpenSSL.RSA as SSL
import qualified OpenSSL.Random as SSL
import System.FilePath ((</>))
import System.IO.Temp (getCanonicalTemporaryDirectory, withTempDirectory)
import Time.System (dateCurrent)


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


fromConfig :: NameConfig -> DistinguishedName
fromConfig nc =
  let unpack = asn1CharacterString UTF8 . Text.unpack
   in DistinguishedName
        [ (getObjectID DnCountry, unpack $ ncCountry nc)
        , ([2, 4, 5, 8], unpack $ ncProvince nc)
        , ([2, 4, 5, 7], unpack $ ncCity nc)
        , (getObjectID DnOrganization, unpack $ ncOrganization nc)
        , (getObjectID DnCommonName, unpack $ ncTitle nc)
        ]


validityNow' :: Natural -> IO (DateTime, DateTime)
validityNow' ndays = do
  let
    -- https://github.com/vincenthz/hs-certificate/issues/119
    cropToSecs dt = dt {dtTime = dt.dtTime {todNSec = 0}}
  start <- cropToSecs <$> dateCurrent
  let end = start `timeAdd` mempty {durationHours = fromIntegral ndays * 24}
  pure (start, end)


-- | Like @generateAndStore@, but using default configuration
generateAndStore' :: IO ()
generateAndStore' = do
  sc <- systemTmpStoreConfig
  generateAndStore sc defaultNameConfig


-- | Generate and store certificate files as specified as @'CertPaths'@
generateAndStore :: CertPaths -> NameConfig -> IO ()
generateAndStore cp nc = do
  (certificate, privKey) <- newCertificate nc
  putStrLn "got certificate and private key"
  let alg = certSignatureAlg certificate
      signF = fmap (,alg) <$> signWithKeyAndAlg privKey
      rsaKey = encodeASN1' DER $ rsaToASN1 privKey
  signedCert <- encodeSignedObject <$> objectToSignedExactF signF certificate
  putStrLn "signed certificate"
  storeCerts cp rsaKey signedCert


{- | Create certificates in a temporary directory below @parentDir@, specify the
locations using a @CertPaths@, use them, then delete them
-}
withCertPaths :: FilePath -> NameConfig -> (CertPaths -> IO a) -> IO a
withCertPaths parentDir nc useSc =
  withTempDirectory parentDir "temp-certs" $ \cpDir -> do
    let sc = defaultBasenames cpDir
    putStrLn "generating"
    generateAndStore sc nc
    putStrLn $ "generated, will use " ++ show sc
    useSc sc


-- | Like 'withCertPaths' with the system @TEMP@ dir as the @parentDir@
withCertPathsInTmp :: NameConfig -> (CertPaths -> IO a) -> IO a
withCertPathsInTmp nc action = do
  parentDir <- getCanonicalTemporaryDirectory
  withCertPaths parentDir nc action


-- | Like 'withCertPathsInTmp' using a default @'NameConfig'@
withCertPathsInTmp' :: (CertPaths -> IO a) -> IO a
withCertPathsInTmp' = withCertPathsInTmp defaultNameConfig


testKeySize :: Int
testKeySize = 4096


testExponent :: Integer
testExponent = 257


genRandomFields :: (Num c) => IO (PublicKey, PrivateKey, c)
genRandomFields = do
  g <- getSystemDRG
  let (bs, _) = randomBytesGenerate 8 g -- generate 8 random bytes for the serial number
      serialNum = BS.foldl' (\a w -> a * 256 + fromIntegral w) 0 bs
  (pub, privKey) <- generate testKeySize testExponent
  pure (pub, privKey, serialNum)


genRandomFields' :: (Num c) => IO (PublicKey, PrivateKey, c)
genRandomFields' = do
  bs <- SSL.randBytes 8
  kp <- SSL.generateRSAKey' testKeySize $ fromIntegral testExponent
  let serialNum = BS.foldl (\a w -> a * 256 + fromIntegral w) 0 bs
      pub =
        PublicKey
          { public_size = SSL.rsaSize kp
          , public_n = SSL.rsaN kp
          , public_e = SSL.rsaE kp
          }
      privKey =
        PrivateKey
          { private_pub = pub
          , private_d = SSL.rsaD kp
          , private_p = SSL.rsaP kp
          , private_q = SSL.rsaQ kp
          , private_dP = fromMaybe 0 $ SSL.rsaDMP1 kp
          , private_dQ = fromMaybe 0 $ SSL.rsaDMQ1 kp
          , private_qinv = fromMaybe 0 $ SSL.rsaIQMP kp
          }
  pure (pub, privKey, serialNum)


newCertificate :: NameConfig -> IO (Certificate, PrivateKey)
newCertificate nc = do
  certValidity <- validityNow' $ ncDurationDays nc
  putStrLn "got validity"
  (pubKey, privKey, certSerial) <- genRandomFields'
  putStrLn "got random fields"
  let dName = fromConfig nc
      certificate =
        Certificate
          { certSubjectDN = dName
          , certIssuerDN = dName
          , certValidity
          , certPubKey = PubKeyRSA pubKey
          , certSerial
          , certVersion = 0 -- 0 => v1
          , certSignatureAlg = SignatureALG HashSHA256 PubKeyALG_RSA
          , certExtensions = Extensions Nothing
          }
  pure (certificate, privKey)


signWithKeyAndAlg ::
  PrivateKey ->
  C8.ByteString ->
  IO C8.ByteString
signWithKeyAndAlg privKey x =
  signSafer (Just SHA256) privKey x >>= either (throwIO . ErrorCall . show) pure


storeCerts :: CertPaths -> C8.ByteString -> C8.ByteString -> IO ()
storeCerts cp rsaKey signedCert = do
  writePemFile (keyPath cp) "RSA PRIVATE KEY" rsaKey
  writePemFile (certificatePath cp) "CERTIFICATE" signedCert


writePemFile :: FilePath -> String -> C8.ByteString -> IO ()
writePemFile path title rawBytes =
  BS.writeFile path $ pemWriteBS $ PEM title [] rawBytes


rsaToASN1 :: PrivateKey -> [ASN1]
rsaToASN1 privKey =
  let pub = private_pub privKey
   in [ Start Sequence
      , IntVal 0
      , IntVal $ public_n pub
      , IntVal $ public_e pub
      , IntVal $ private_d privKey
      , IntVal $ private_p privKey
      , IntVal $ private_q privKey
      , IntVal $ private_dP privKey
      , IntVal $ private_dQ privKey
      , IntVal $ private_qinv privKey
      , End Sequence
      ]
