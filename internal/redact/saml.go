package redact

import (
	"bytes"
	"compress/flate"
	"encoding/base64"

	"github.com/beevik/etree"

	"github.com/Josperdo/ssotrace/internal/saml"
)

// samlParam redacts a SAMLRequest or SAMLResponse value and re-encodes it
// in the same binding. If anything about the message cannot be read or
// rewritten, the whole value is replaced: a message that cannot be edited
// cannot be shown to be safe.
func (r *redactor) samlParam(v string, redirect bool) string {
	decode := saml.DecodePOST
	if redirect {
		decode = saml.DecodeRedirect
	}
	raw, err := decode(v)
	if err != nil {
		return Redacted
	}
	out, err := r.samlXML(raw)
	if err != nil {
		return Redacted
	}
	if !redirect {
		return base64.StdEncoding.EncodeToString(out)
	}
	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		return Redacted
	}
	if _, err := fw.Write(out); err != nil {
		return Redacted
	}
	if err := fw.Close(); err != nil {
		return Redacted
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// samlXML rewrites a SAML message so it keeps everything diagnosis checks
// (issuers, audiences, destinations, times, algorithms, the signing
// certificate) and loses everything that identifies the user or could be
// replayed.
//
//   - SignatureValue: replaced with a marker saying whether it verified
//     before removal. Without it the message cannot be replayed.
//   - DigestValue: removed. It is a hash of the original signed content,
//     so it would let someone confirm a guessed NameID by hashing
//     candidates, undoing the masking below.
//   - NameID, AttributeValue, SessionIndex: masked with the salted hash.
//   - StatusMessage, client addresses: removed.
//   - Comments: removed. They can hold anything, and removing them also
//     undoes any comment-split NameID trick.
func (r *redactor) samlXML(raw []byte) ([]byte, error) {
	// Verify first, on the original bytes, to record each signature's
	// result before its value is removed.
	verified := map[string]bool{}
	if msg, err := saml.Parse(raw, r.at); err == nil {
		switch {
		case msg.Response != nil:
			verified[msg.Response.ID] = wasVerified(msg.Response.Signature)
			for _, a := range msg.Response.Assertions {
				verified[a.ID] = wasVerified(a.Signature)
			}
		case msg.AuthnRequest != nil:
			verified[msg.AuthnRequest.ID] = wasVerified(msg.AuthnRequest.Signature)
		}
	}

	root, err := saml.ParseXML(raw)
	if err != nil {
		return nil, err
	}
	r.samlElement(root, nil, verified)

	doc := etree.NewDocument()
	doc.SetRoot(root)
	return doc.WriteToBytes()
}

// samlElement redacts el and its descendants. signed is the element whose
// Signature is being walked, so a SignatureValue knows whose it is.
func (r *redactor) samlElement(el, signed *etree.Element, verified map[string]bool) {
	// Comments first, so no text hides between them.
	kept := el.Child[:0]
	for _, tok := range el.Child {
		if _, isComment := tok.(*etree.Comment); !isComment {
			kept = append(kept, tok)
		}
	}
	el.Child = kept

	switch el.Tag {
	case "SignatureValue":
		marker := sigUnverified
		if signed != nil && verified[signed.SelectAttrValue("ID", "")] {
			marker = sigVerified
		}
		setText(el, marker)
		return
	case "DigestValue", "StatusMessage":
		setText(el, Redacted)
		return
	case "NameID", "AttributeValue":
		setText(el, r.mask(allText(el)))
		return
	case "AuthnStatement":
		if a := el.SelectAttr("SessionIndex"); a != nil {
			a.Value = r.mask(a.Value)
		}
	case "SubjectConfirmationData", "SubjectLocality":
		for _, name := range []string{"Address", "DNSName"} {
			if a := el.SelectAttr(name); a != nil {
				a.Value = Redacted
			}
		}
	}

	for _, c := range el.ChildElements() {
		s := signed
		if c.Tag == "Signature" {
			// An enveloped signature belongs to its parent element.
			s = el
		}
		r.samlElement(c, s, verified)
	}
}

// setText replaces all of el's content with one text node.
func setText(el *etree.Element, s string) {
	el.Child = nil
	el.SetText(s)
}

// wasVerified is a signature's result: checked now, or, for a file that was
// already redacted, as its marker recorded. Without the second case,
// redacting a redacted file would downgrade every "verified" marker.
func wasVerified(s saml.Signature) bool {
	return s.Verified || (s.Redacted && s.RedactedVerified)
}
