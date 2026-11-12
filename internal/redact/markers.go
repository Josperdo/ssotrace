package redact

import (
	"strings"

	"github.com/Josperdo/ssotrace/internal/saml"
)

// Markers the redactor writes in place of secrets. The scanner treats a
// value in one of these forms as safe and anything else as a possible
// leak, so the two must agree exactly; that is why they live together.
const (
	// Redacted replaces a value that was removed outright.
	Redacted = "[redacted]"

	// maskPrefix starts a salted-hash stand-in for an identifier, such as
	// "redacted-3f9a2c1d5e6b". The same input gives the same stand-in within
	// one run, so a person can still see "these two messages are about the
	// same user" without learning who the user is.
	maskPrefix = "redacted-"

	// maskDomain is the domain of a masked email address. .invalid is
	// reserved (RFC 2606) and can never be a real domain.
	maskDomain = "redacted.invalid"

	// sigVerified and sigUnverified replace an XML SignatureValue, recording
	// what ssotrace found before removing it. The rest of the Signature
	// (algorithms, certificate) stays, so expiry and algorithm checks still
	// work on the redacted file.
	sigVerified   = saml.RedactedSigVerified
	sigUnverified = saml.RedactedSigUnverified

	// jwtSigMarker replaces a JWT's signature segment.
	jwtSigMarker = "ssotrace-redacted"
)

// isRedacted reports whether v is empty or one of the redactor's markers.
func isRedacted(v string) bool {
	v = strings.TrimSpace(v)
	switch {
	case v == "", v == Redacted, v == sigVerified, v == sigUnverified:
		return true
	case strings.HasPrefix(v, Redacted), strings.HasPrefix(v, maskPrefix):
		return true
	case strings.HasSuffix(v, "@"+maskDomain):
		return true
	case strings.HasSuffix(v, "."+jwtSigMarker):
		// A JWT the redactor rewrote: its claims are filtered and its
		// signature is gone.
		return true
	}
	return false
}
