package diagnose

import (
	"fmt"
	"time"

	"github.com/Josperdo/ssotrace/internal/saml"
)

// validityWindow is SAML006: the assertion was delivered outside the time
// window it is valid for. This is the classic clock-skew failure.
//
// The reference time is when the browser sent the Response (from the HAR),
// because that is as close as a capture gets to when the SP received it.
type validityWindow struct{}

func (validityWindow) ID() string { return "SAML006" }

// bound is one time limit on an assertion, with where it came from.
type bound struct {
	label string // e.g. "Conditions NotOnOrAfter"
	raw   string
	t     time.Time
}

func (validityWindow) Check(ctx Context) []Finding {
	var out []Finding
	checked := 0
	for _, v := range samlResponses(ctx) {
		at, ok := sentAt(ctx, v.Msg)
		if !ok {
			continue
		}
		for _, a := range v.Resp.Assertions {
			notBefore, notAfter, bad := assertionBounds(a)
			if bad != nil {
				out = append(out, Finding{
					RuleID:   "SAML006",
					Severity: Warn,
					Title:    "Assertion has an unreadable timestamp",
					Detail:   "A validity time in the assertion is not a valid xs:dateTime, so SPs may reject the assertion or ignore the limit.",
					Fix:      "This is an IdP bug. Check the IdP's version and report the malformed timestamp to its vendor.",
					Evidence: []Evidence{
						{Label: "Response", Value: where(v.Msg)},
						{Label: bad.label, Value: truncate(bad.raw, 64)},
					},
				})
				continue
			}
			if notBefore == nil && notAfter == nil {
				continue
			}
			checked++

			var limit *bound
			var outside time.Duration
			early := false
			switch {
			case notBefore != nil && at.Before(notBefore.t):
				limit, outside, early = notBefore, notBefore.t.Sub(at), true
			case notAfter != nil && !at.Before(notAfter.t):
				limit, outside = notAfter, at.Sub(notAfter.t)
			default:
				continue
			}
			out = append(out, windowFinding(ctx, v, a, at, limit, outside, early))
		}
	}
	if len(out) == 0 && checked > 0 {
		return []Finding{passFinding("SAML006", "Assertions delivered within their validity window",
			fmt.Sprintf("Checked %s against the time the browser sent them.", plural(checked, "assertion")))}
	}
	return out
}

// assertionBounds finds the tightest limits: Conditions NotBefore, and the
// earliest of Conditions NotOnOrAfter and each bearer confirmation's
// NotOnOrAfter. It returns the first unparseable value as bad.
func assertionBounds(a saml.Assertion) (notBefore, notAfter, bad *bound) {
	parse := func(label, raw string) (*bound, bool) {
		if raw == "" {
			return nil, true
		}
		t, err := saml.ParseTime(raw)
		if err != nil {
			return &bound{label: label, raw: raw}, false
		}
		return &bound{label: label, raw: raw, t: t}, true
	}

	if c := a.Conditions; c != nil {
		b, ok := parse("Conditions NotBefore", c.NotBefore)
		if !ok {
			return nil, nil, b
		}
		notBefore = b
		b, ok = parse("Conditions NotOnOrAfter", c.NotOnOrAfter)
		if !ok {
			return nil, nil, b
		}
		notAfter = b
	}
	for _, sc := range a.Subject.Confirmations {
		if sc.Method != bearerMethod {
			continue
		}
		b, ok := parse("SubjectConfirmationData NotOnOrAfter", sc.NotOnOrAfter)
		if !ok {
			return nil, nil, b
		}
		if b != nil && (notAfter == nil || b.t.Before(notAfter.t)) {
			notAfter = b
		}
	}
	return notBefore, notAfter, nil
}

func windowFinding(ctx Context, v responseView, a saml.Assertion, at time.Time, limit *bound, outside time.Duration, early bool) Finding {
	// Within the tolerance most SPs allow, the login probably works, but it
	// is living on borrowed time: a slightly stricter SP or a little more
	// drift and it fails.
	sev, title := Fail, "Assertion was delivered after it expired"
	if early {
		title = "Assertion was delivered before it became valid"
	}
	if outside <= ctx.ClockSkew {
		sev = Warn
		title += " (within clock-skew tolerance)"
	}

	ev := []Evidence{
		{Label: "Response", Value: where(v.Msg)},
		{Label: "Browser sent it at", Value: at.UTC().Format(time.RFC3339)},
		{Label: limit.label, Value: limit.raw},
		{Label: "Outside the window by", Value: humanDuration(outside)},
		{Label: "Clock-skew tolerance", Value: humanDuration(ctx.ClockSkew)},
	}

	detail := "Timestamps are compared with the browser's clock, taken from the HAR. "
	if issued, err := saml.ParseTime(a.IssueInstant); err == nil {
		ev = append(ev, Evidence{Label: "Assertion issued at", Value: a.IssueInstant})
		// An assertion cannot really be issued after it was delivered, so
		// an IssueInstant in the browser's future measures clock skew
		// directly. The other way round is ambiguous: a delay or a slow
		// clock look the same.
		if gap := issued.Sub(at); gap > 0 {
			ev = append(ev, Evidence{Label: "Estimated clock difference", Value: "IdP is at least " + humanDuration(gap) + " ahead of the browser"})
			detail += fmt.Sprintf("The IdP stamped this assertion %s after the browser had already sent it, so the IdP's clock (or the user's) is wrong by at least that much. ", humanDuration(gap))
		} else if !early {
			detail += fmt.Sprintf("The assertion was issued %s before the browser delivered it: either the user waited that long (for example on a consent or MFA page), or the IdP's clock is behind. ", humanDuration(-gap))
		}
	}

	var fix string
	if early {
		detail += "SPs reject an assertion that is not yet valid."
		fix = "Synchronize the IdP's clock with NTP. If the IdP's time is correct, check the clock on the SP's server and on the user's machine " +
			"(a wrong time on the user's machine shifts every timestamp in the HAR)."
	} else {
		detail += "SPs reject an assertion that has expired."
		fix = "Check that the IdP and SP servers both synchronize their clocks with NTP. If the clocks are right and the user simply took a long time, " +
			"have them retry; if this happens often, lengthen the assertion lifetime in the IdP (Keycloak calls it \"Assertion Lifespan\")."
	}
	if sev == Warn {
		fix = "The SP probably accepts this today because it allows some clock skew, but a stricter SP or more drift will break it. " + fix
	}
	return Finding{RuleID: "SAML006", Severity: sev, Title: title, Detail: detail, Fix: fix, Evidence: ev}
}
