# OAuth 2.1 server package
[![Build Status](https://github.com/emicklei/oauth2server/actions/workflows/test.yml/badge.svg)](https://github.com/emicklei/oauth2server/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/emicklei/oauth2server/branch/main/graph/badge.svg)](https://codecov.io/gh/emicklei/oauth2server)

This is a simple OAuth 2.1 server package in Go.

## Features

- Zero dependencies
- OAuth 2.1 compliant
- Authorization Code Grant with PKCE (S256)
- Refresh Tokens with rotation
- Dynamic Client Registration
- Pluggable behavior via Config

## Example

See the `example` folder for composing a server using this package.
