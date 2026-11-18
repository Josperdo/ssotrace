// Package oidc parses OAuth 2.0 and OpenID Connect artifacts found in a
// capture. It decodes JWTs (Parse) using only the standard library.
// Decoding is not verification: a parsed token's claims are what the token
// says about itself.
package oidc
