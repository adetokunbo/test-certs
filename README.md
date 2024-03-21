# test-certs

[![GitHub CI](https://github.com/adetokunbo/test-certs/actions/workflows/nix-ci.yml/badge.svg)](https://github.com/adetokunbo/test-certs/actions)
[![Stackage Nightly](http://stackage.org/package/test-certs/badge/nightly)](http://stackage.org/nightly/package/test-certs)
[![Hackage][hackage-badge]][hackage]
[![Hackage Dependencies][hackage-deps-badge]][hackage-deps]
[![BSD3](https://img.shields.io/badge/license-BSD3-green.svg?dummy)](https://github.com/adetokunbo/test-certs/blob/master/LICENSE)

test-certs provides functions that generate temporary SSL certificates for tests.

Its functions generate the certificates as files in a temporary directory

Note: this package depends on [HsOpenSSL][]. It expects the openssl system
libraries to be available on your system; this is usually the case on most
modern linux distributions.

[hackage-deps-badge]: <https://img.shields.io/hackage-deps/v/test-certs.svg>
[hackage-deps]:       <http://packdeps.haskellers.com/feed?needle=test-certs>
[hackage-badge]:      <https://img.shields.io/hackage/v/test-certs.svg>
[hackage]:            <https://hackage.haskell.org/package/test-certs>
[HSOpenSSL]:          <https://hackage.haskell.org/package/HsOpenSSL>
