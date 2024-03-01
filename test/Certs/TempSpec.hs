{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : Certs.TempSpec
Copyright   : (c) 2023 Tim Emiola
Maintainer  : Tim Emiola <adetokunbo@emio.la>
SPDX-License-Identifier: BSD3
-}
module Certs.TempSpec (spec) where

import Test.Hspec
import Test.Certs.Temp

spec :: Spec
spec = describe "Temp" $ do
  context "endsThen" $
    it "should be a simple test" $ do
      getIt `endsThen` (== (Just "a string"))


getIt :: IO (Maybe String)
getIt = pure $ Just "a string"
