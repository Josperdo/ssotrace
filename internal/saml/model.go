package saml

// Times are kept as the raw xs:dateTime strings from the message. A
// malformed timestamp is itself a finding, so the model records what was
// sent and leaves interpreting it to the rules (see ParseTime).

// AuthnRequest is an SP's request to authenticate a user.
type AuthnRequest struct {
	ID              string        `json:"id"`
	Version         string        `json:"version"`
	IssueInstant    string        `json:"issue_instant"`
	Destination     string        `json:"destination,omitempty"`
	ACSURL          string        `json:"acs_url,omitempty"`
	ProtocolBinding string        `json:"protocol_binding,omitempty"`
	Issuer          string        `json:"issuer"`
	NameIDPolicy    *NameIDPolicy `json:"name_id_policy,omitempty"`
	ForceAuthn      string        `json:"force_authn,omitempty"`
	IsPassive       string        `json:"is_passive,omitempty"`
	Signature       Signature     `json:"signature"`
}

// NameIDPolicy is what the SP asked for as the user identifier.
type NameIDPolicy struct {
	Format      string `json:"format,omitempty"`
	AllowCreate string `json:"allow_create,omitempty"`
}

// Response is an IdP's answer to an AuthnRequest, or an unsolicited
// (IdP-initiated) login.
type Response struct {
	ID           string `json:"id"`
	InResponseTo string `json:"in_response_to,omitempty"`
	Version      string `json:"version"`
	IssueInstant string `json:"issue_instant"`
	Destination  string `json:"destination,omitempty"`
	Issuer       string `json:"issuer,omitempty"`
	Status       Status `json:"status"`

	Signature  Signature   `json:"signature"`
	Assertions []Assertion `json:"assertions"`
	// EncryptedAssertions counts assertions ssotrace cannot read without
	// the SP's private key.
	EncryptedAssertions int `json:"encrypted_assertions,omitempty"`
}

// Status is the outcome the IdP reports. SubCode carries the specific
// reason (for example AuthnFailed or NoPassive) when Code is not Success.
type Status struct {
	Code    string `json:"code"`
	SubCode string `json:"sub_code,omitempty"`
	Message string `json:"message,omitempty"`
}

// Assertion is the IdP's signed statement about the user.
type Assertion struct {
	ID           string `json:"id"`
	Version      string `json:"version"`
	IssueInstant string `json:"issue_instant"`
	Issuer       string `json:"issuer"`

	// Verified is true when the content below is covered by a signature
	// that validated: the assertion's own, or the enclosing Response's.
	// When false, every field below may have been altered in transit.
	Verified  bool      `json:"verified"`
	Signature Signature `json:"signature"`

	Subject    Subject          `json:"subject"`
	Conditions *Conditions      `json:"conditions,omitempty"`
	AuthnStmts []AuthnStatement `json:"authn_statements,omitempty"`
	Attributes []Attribute      `json:"attributes,omitempty"`
}

// Subject identifies the user and says how the SP may confirm the
// assertion is meant for this browser session.
type Subject struct {
	NameID        NameID                `json:"name_id"`
	Confirmations []SubjectConfirmation `json:"confirmations,omitempty"`
}

// NameID is the user identifier the IdP chose.
type NameID struct {
	Value  string `json:"value"`
	Format string `json:"format,omitempty"`
}

// SubjectConfirmation is one way to confirm the subject. Browser SSO uses
// the "bearer" method: whoever presents the assertion to Recipient before
// NotOnOrAfter is accepted.
type SubjectConfirmation struct {
	Method       string `json:"method"`
	Recipient    string `json:"recipient,omitempty"`
	NotBefore    string `json:"not_before,omitempty"`
	NotOnOrAfter string `json:"not_on_or_after,omitempty"`
	InResponseTo string `json:"in_response_to,omitempty"`
}

// Conditions limit when and by whom the assertion may be used.
type Conditions struct {
	NotBefore    string   `json:"not_before,omitempty"`
	NotOnOrAfter string   `json:"not_on_or_after,omitempty"`
	Audiences    []string `json:"audiences,omitempty"`
}

// AuthnStatement records how and when the user authenticated.
type AuthnStatement struct {
	AuthnInstant        string `json:"authn_instant,omitempty"`
	SessionNotOnOrAfter string `json:"session_not_on_or_after,omitempty"`
	// SessionIndex identifies the IdP session, which makes it usable for
	// logout requests; only a preview is kept.
	SessionIndexPreview string `json:"session_index_preview,omitempty"`
	ClassRef            string `json:"class_ref,omitempty"`
}

// Attribute is one user attribute released by the IdP.
type Attribute struct {
	Name         string   `json:"name"`
	FriendlyName string   `json:"friendly_name,omitempty"`
	Values       []string `json:"values"`
}

// Signature describes an enveloped XML signature and whether it verified.
type Signature struct {
	Present bool `json:"present"`
	// Verified means the signature matches the certificate embedded in it.
	// That proves the content was not altered after signing (integrity),
	// not that the signer is the IdP you expect (trust): an attacker can
	// sign with their own key and embed their own certificate.
	Verified  bool   `json:"verified"`
	TrustedBy string `json:"trusted_by,omitempty"` // "embedded-certificate" until a pinned cert is supplied
	Error     string `json:"error,omitempty"`
	// Redacted means ssotrace redact replaced the SignatureValue with a
	// marker, so the signature cannot be checked again. RedactedVerified
	// is what the marker says the check found before removal. It is a
	// claim recorded in the file, not something this run proved.
	Redacted         bool `json:"redacted,omitempty"`
	RedactedVerified bool `json:"redacted_verified,omitempty"`

	Algorithm       string       `json:"algorithm,omitempty"`
	DigestAlgorithm string       `json:"digest_algorithm,omitempty"`
	Certificate     *Certificate `json:"certificate,omitempty"`
}

// Certificate summarizes the X.509 certificate embedded in a signature.
// Certificates are public, so these fields are safe to display.
type Certificate struct {
	Subject      string `json:"subject"`
	Issuer       string `json:"issuer"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
	SHA256       string `json:"sha256"` // fingerprint, as admin consoles show it
	SelfSigned   bool   `json:"self_signed"`
	PublicKeyAlg string `json:"public_key_algorithm"`
	// ValidityAtCapture compares the certificate's dates with the HAR
	// timestamp of the message: one of the Validity* constants.
	ValidityAtCapture string `json:"validity_at_capture"`
}

// Certificate validity at the time a message was captured.
const (
	ValidityValid       = "valid"
	ValidityExpired     = "expired"
	ValidityNotYetValid = "not-yet-valid"
	ValidityUnknown     = "unknown" // the HAR entry had no usable timestamp
)
