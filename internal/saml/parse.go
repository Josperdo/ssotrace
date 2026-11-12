package saml

import (
	"fmt"
	"time"

	"github.com/Josperdo/ssotrace/internal/secret"
	"github.com/beevik/etree"
)

// Kind is the type of a SAML protocol message, taken from its root element.
type Kind string

// Message kinds. ssotrace models AuthnRequest and Response; the logout
// messages are recognized so flows can show them, but not modeled yet.
const (
	KindAuthnRequest   Kind = "AuthnRequest"
	KindResponse       Kind = "Response"
	KindLogoutRequest  Kind = "LogoutRequest"
	KindLogoutResponse Kind = "LogoutResponse"
	KindUnknown        Kind = "Unknown"
)

// Message is one parsed SAML message. Exactly one of AuthnRequest and
// Response is set when Kind names a modeled message.
type Message struct {
	Kind         Kind          `json:"kind"`
	AuthnRequest *AuthnRequest `json:"authn_request,omitempty"`
	Response     *Response     `json:"response,omitempty"`
}

// Parse parses a decoded SAML message. at is the reference time used to
// judge certificate validity during signature checks; pass the HAR
// timestamp of the entry that carried the message.
func Parse(raw []byte, at time.Time) (*Message, error) {
	root, err := parseXML(raw)
	if err != nil {
		return nil, err
	}
	if root.NamespaceURI() != nsProtocol {
		return &Message{Kind: KindUnknown}, fmt.Errorf("root element is not in the SAML 2.0 protocol namespace")
	}
	switch Kind(root.Tag) {
	case KindAuthnRequest:
		return &Message{Kind: KindAuthnRequest, AuthnRequest: parseAuthnRequest(root, at)}, nil
	case KindResponse:
		return &Message{Kind: KindResponse, Response: parseResponse(root, at)}, nil
	case KindLogoutRequest, KindLogoutResponse:
		return &Message{Kind: Kind(root.Tag)}, nil
	default:
		return &Message{Kind: KindUnknown}, nil
	}
}

func parseAuthnRequest(root *etree.Element, at time.Time) *AuthnRequest {
	// A POST-binding AuthnRequest may carry an enveloped signature. If it
	// verifies, read from the validated element only.
	sig, validated := verify(root, at)
	src := root
	if validated != nil {
		src = validated
	}
	req := &AuthnRequest{
		ID:              attr(src, "ID"),
		Version:         attr(src, "Version"),
		IssueInstant:    attr(src, "IssueInstant"),
		Destination:     attr(src, "Destination"),
		ACSURL:          attr(src, "AssertionConsumerServiceURL"),
		ProtocolBinding: attr(src, "ProtocolBinding"),
		Issuer:          text(child(src, nsAssertion, "Issuer")),
		ForceAuthn:      attr(src, "ForceAuthn"),
		IsPassive:       attr(src, "IsPassive"),
		Signature:       sig,
	}
	if p := child(src, nsProtocol, "NameIDPolicy"); p != nil {
		req.NameIDPolicy = &NameIDPolicy{
			Format:      attr(p, "Format"),
			AllowCreate: attr(p, "AllowCreate"),
		}
	}
	return req
}

func parseResponse(root *etree.Element, at time.Time) *Response {
	sig, validated := verify(root, at)
	src := root
	if validated != nil {
		src = validated
	}

	resp := &Response{
		ID:           attr(src, "ID"),
		InResponseTo: attr(src, "InResponseTo"),
		Version:      attr(src, "Version"),
		IssueInstant: attr(src, "IssueInstant"),
		Destination:  attr(src, "Destination"),
		Issuer:       text(child(src, nsAssertion, "Issuer")),
		Status:       parseStatus(child(src, nsProtocol, "Status")),
		Signature:    sig,
		Assertions:   []Assertion{},
	}
	resp.EncryptedAssertions = len(children(src, nsAssertion, "EncryptedAssertion"))

	for _, a := range children(src, nsAssertion, "Assertion") {
		asig, av := verify(a, at)
		asrc := a
		if av != nil {
			asrc = av
		}
		as := parseAssertion(asrc)
		as.Signature = asig
		// Content inside a verified Response is protected by the
		// Response's signature even if the assertion has none of its own.
		as.Verified = asig.Verified || sig.Verified
		resp.Assertions = append(resp.Assertions, as)
	}
	return resp
}

func parseStatus(el *etree.Element) Status {
	code := child(el, nsProtocol, "StatusCode")
	return Status{
		Code:    attr(code, "Value"),
		SubCode: attr(child(code, nsProtocol, "StatusCode"), "Value"),
		Message: text(child(el, nsProtocol, "StatusMessage")),
	}
}

func parseAssertion(el *etree.Element) Assertion {
	a := Assertion{
		ID:           attr(el, "ID"),
		Version:      attr(el, "Version"),
		IssueInstant: attr(el, "IssueInstant"),
		Issuer:       text(child(el, nsAssertion, "Issuer")),
	}

	if subj := child(el, nsAssertion, "Subject"); subj != nil {
		nid := child(subj, nsAssertion, "NameID")
		a.Subject.NameID = NameID{Value: text(nid), Format: attr(nid, "Format")}
		for _, sc := range children(subj, nsAssertion, "SubjectConfirmation") {
			data := child(sc, nsAssertion, "SubjectConfirmationData")
			a.Subject.Confirmations = append(a.Subject.Confirmations, SubjectConfirmation{
				Method:       attr(sc, "Method"),
				Recipient:    attr(data, "Recipient"),
				NotBefore:    attr(data, "NotBefore"),
				NotOnOrAfter: attr(data, "NotOnOrAfter"),
				InResponseTo: attr(data, "InResponseTo"),
			})
		}
	}

	if c := child(el, nsAssertion, "Conditions"); c != nil {
		cond := &Conditions{
			NotBefore:    attr(c, "NotBefore"),
			NotOnOrAfter: attr(c, "NotOnOrAfter"),
		}
		for _, ar := range children(c, nsAssertion, "AudienceRestriction") {
			for _, aud := range children(ar, nsAssertion, "Audience") {
				cond.Audiences = append(cond.Audiences, text(aud))
			}
		}
		a.Conditions = cond
	}

	for _, st := range children(el, nsAssertion, "AuthnStatement") {
		stmt := AuthnStatement{
			AuthnInstant:        attr(st, "AuthnInstant"),
			SessionNotOnOrAfter: attr(st, "SessionNotOnOrAfter"),
			ClassRef:            text(child(child(st, nsAssertion, "AuthnContext"), nsAssertion, "AuthnContextClassRef")),
		}
		if idx := attr(st, "SessionIndex"); idx != "" {
			stmt.SessionIndexPreview = secret.Preview(idx)
		}
		a.AuthnStmts = append(a.AuthnStmts, stmt)
	}

	for _, as := range children(el, nsAssertion, "AttributeStatement") {
		for _, at := range children(as, nsAssertion, "Attribute") {
			attrib := Attribute{
				Name:         attr(at, "Name"),
				FriendlyName: attr(at, "FriendlyName"),
				Values:       []string{},
			}
			for _, v := range children(at, nsAssertion, "AttributeValue") {
				attrib.Values = append(attrib.Values, text(v))
			}
			a.Attributes = append(a.Attributes, attrib)
		}
	}
	return a
}

// ParseTime parses an xs:dateTime as SAML uses it: UTC, usually with a "Z"
// suffix, sometimes with fractional seconds or a numeric offset.
func ParseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("not an xs:dateTime")
	}
	return t, nil
}
