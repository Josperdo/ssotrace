package saml

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/beevik/etree"
)

// MaxDepth caps XML element nesting. A real SAML Response nests about ten
// levels deep; a hostile one can nest thousands to exhaust the stack or
// memory of whatever walks the tree.
const MaxDepth = 64

// SAML and XML Signature namespaces. Elements are matched on namespace URI,
// never on prefix: "saml:", "saml2:", and "" can all mean the same thing,
// and a prefix proves nothing about which namespace it is bound to.
const (
	nsProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	nsAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
	nsDSig      = "http://www.w3.org/2000/09/xmldsig#"
)

// parseXML checks raw against the hostile-input limits, then parses it.
//
// The check runs first, with the standard library's streaming decoder, so
// that an oversized or malicious document is rejected before etree builds a
// tree from it.
func parseXML(raw []byte) (*etree.Element, error) {
	if err := checkXML(raw); err != nil {
		return nil, err
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return nil, errors.New("xml: malformed document")
	}
	root := doc.Root()
	if root == nil {
		return nil, errors.New("xml: no root element")
	}
	return root, nil
}

// checkXML walks every token once, enforcing MaxDepth and rejecting DOCTYPE.
//
// SAML never needs a DOCTYPE. Refusing it removes the whole family of entity
// attacks (billion laughs, external entities) instead of relying on every
// parser downstream to handle them safely.
func checkXML(raw []byte) error {
	d := xml.NewDecoder(bytes.NewReader(raw))
	depth := 0
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		// An unclosed element at end of input is a SyntaxError, not io.EOF.
		// Its Msg is the decoder's own fixed text, never document content.
		var se *xml.SyntaxError
		if errors.As(err, &se) && se.Msg == "unexpected EOF" {
			return errors.New("xml: document is truncated")
		}
		if err != nil {
			// The decoder's message can quote document text, so only the
			// position is reported.
			return fmt.Errorf("xml: malformed document near byte %d", d.InputOffset())
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			if depth > MaxDepth {
				return fmt.Errorf("xml: nesting deeper than %d levels", MaxDepth)
			}
		case xml.EndElement:
			depth--
		case xml.Directive:
			if bytes.HasPrefix(bytes.TrimSpace(t), []byte("DOCTYPE")) {
				return errors.New("xml: DOCTYPE is not allowed in SAML messages")
			}
		}
	}
}

// is reports whether el is the element local in namespace ns.
func is(el *etree.Element, ns, local string) bool {
	return el != nil && el.Tag == local && el.NamespaceURI() == ns
}

// child returns el's first child element named local in namespace ns.
func child(el *etree.Element, ns, local string) *etree.Element {
	if el == nil {
		return nil
	}
	for _, c := range el.ChildElements() {
		if is(c, ns, local) {
			return c
		}
	}
	return nil
}

// children returns all of el's child elements named local in namespace ns.
func children(el *etree.Element, ns, local string) []*etree.Element {
	if el == nil {
		return nil
	}
	var out []*etree.Element
	for _, c := range el.ChildElements() {
		if is(c, ns, local) {
			out = append(out, c)
		}
	}
	return out
}

// attr returns an unqualified attribute's value. SAML attributes such as ID
// and Destination carry no namespace prefix.
func attr(el *etree.Element, name string) string {
	if el == nil {
		return ""
	}
	for _, a := range el.Attr {
		if a.Space == "" && a.Key == name {
			return a.Value
		}
	}
	return ""
}

// text returns all of el's character data, joined, with surrounding space
// trimmed.
//
// etree's Text() returns only the first run of text. For
// "alice@example.com<!---->.evil.example" that is "alice@example.com", while
// the signature covers the whole string with the comment removed. That gap
// is how the 2018 SAML comment-injection attacks impersonated users, so this
// helper reads every text node, the same way canonicalization does.
func text(el *etree.Element) string {
	if el == nil {
		return ""
	}
	var b strings.Builder
	for _, tok := range el.Child {
		if cd, ok := tok.(*etree.CharData); ok {
			b.WriteString(cd.Data)
		}
	}
	return strings.TrimSpace(b.String())
}
