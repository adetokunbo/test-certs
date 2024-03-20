{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : Certs.TempSpec
Copyright   : (c) 2023 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3
-}
module Certs.TempSpec (spec) where

import Data.Either (isRight)
import Network.TLS (credentialLoadX509)
import Test.Certs.Temp
import Test.Hspec


spec :: Spec
spec = describe "Temp" $ do
  context "using credentialLoadX509 to load" $ do
    context "the generated certificates" $ do
      it "should succeed" $ do
        withCertPathsInTmp' canLoad509 >>= (`shouldBe` True)


canLoad509 :: CertPaths -> IO Bool
canLoad509 cp = do
  let cert = certificatePath cp
      key = keyPath cp
  isRight <$> credentialLoadX509 cert key
