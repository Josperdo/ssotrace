package diagnose

import (
	"fmt"
	"slices"
	"time"
)

// tokenTimes is OIDC006: a token was delivered outside the window its exp
// and nbf claims allow, or its timestamps contradict each other. Like
// SAML006, the reference time is when the browser received the token,
// taken from the HAR, and anything within the clock-skew tolerance is a
// warning rather than a failure.
type tokenTimes struct{}

func (tokenTimes) ID() string { return "OIDC006" }

func (tokenTimes) Check(ctx Context) []Finding {
	var out []Finding
	checked := 0
	for _, v := range tokens(ctx, true) {
		at, ok := entryTime(ctx, v.Sent.Entry)
		if !ok {
			continue
		}
		c := v.Token.Claims
		base := []Evidence{
			{Label: v.label(), Value: sentWhere(v.Sent)},
			{Label: "Browser received it at", Value: stamp(at)},
		}
		if c.Expires == nil {
			if v.Kind == "ID token" {
				out = append(out, Finding{
					RuleID: "OIDC006", OIDCFlow: v.flowRef(), Severity: Fail,
					Title:    "ID token has no expiry",
					Detail:   "OIDC requires every ID token to carry an exp claim, and clients reject one without it.",
					Fix:      "This is an IdP bug or a custom token mapper removing exp. Check the IdP's token settings and mappers for this client.",
					Evidence: base,
				})
			}
			continue // access tokens may legitimately carry no exp
		}
		checked++

		if c.IssuedAt != nil && !c.Expires.After(*c.IssuedAt) {
			out = append(out, Finding{
				RuleID: "OIDC006", OIDCFlow: v.flowRef(), Severity: Warn,
				Title:  "Token expires before it was issued",
				Detail: "The token's exp is not after its iat, so its lifetime is zero or negative. A client can only accept it by stretching its clock-skew tolerance.",
				Fix:    "Increase the token lifespan in the IdP (Keycloak: \"Access Token Lifespan\"). A few minutes is typical; a few seconds is usually a mistake.",
				Evidence: append(base,
					Evidence{Label: "iat", Value: stamp(*c.IssuedAt)},
					Evidence{Label: "exp", Value: stamp(*c.Expires)}),
			})
		}

		var limitLabel string
		var limit time.Time
		var outside time.Duration
		early := false
		switch {
		case c.NotBefore != nil && at.Before(*c.NotBefore):
			limitLabel, limit, outside, early = "nbf", *c.NotBefore, c.NotBefore.Sub(at), true
		case !at.Before(*c.Expires):
			limitLabel, limit, outside = "exp", *c.Expires, at.Sub(*c.Expires)
		}

		// An iat in the browser's future measures clock skew directly: a
		// token cannot be issued after it was received.
		var ahead time.Duration
		if c.IssuedAt != nil && c.IssuedAt.After(at) {
			ahead = c.IssuedAt.Sub(at)
		}

		if limitLabel == "" {
			if ahead > ctx.ClockSkew {
				out = append(out, Finding{
					RuleID: "OIDC006", OIDCFlow: v.flowRef(), Severity: Warn,
					Title: "Token was issued in the future",
					Detail: fmt.Sprintf("The token's iat is %s after the browser received it, beyond the clock-skew tolerance. "+
						"Many libraries reject a token issued in the future.", humanDuration(ahead)),
					Fix: "Synchronize the IdP's clock with NTP, and check the clock on the user's machine: a wrong time there shifts every timestamp in the HAR.",
					Evidence: append(base,
						Evidence{Label: "iat", Value: stamp(*c.IssuedAt)},
						Evidence{Label: "Clock-skew tolerance", Value: humanDuration(ctx.ClockSkew)}),
				})
			}
			continue
		}

		sev, title := Fail, cap1(v.Kind)+" had expired when it arrived"
		detail := "Timestamps are compared with the browser's clock, taken from the HAR. Clients reject an expired token."
		fix := "Check that the IdP's servers synchronize their clocks with NTP, and the clock on the user's machine. " +
			"If the clocks are right, the token lifetime is too short for how long the exchange takes; lengthen it in the IdP."
		if early {
			title = cap1(v.Kind) + " was not yet valid when it arrived"
			detail = "Timestamps are compared with the browser's clock, taken from the HAR. Clients reject a token before its nbf time."
			fix = "Synchronize the IdP's clock with NTP. If the IdP's time is correct, check the clock on the application's server and on the user's machine."
		}
		if outside <= ctx.ClockSkew {
			sev = Warn
			title += " (within clock-skew tolerance)"
			fix = "The client probably accepts this today because it allows some clock skew, but a stricter client or more drift will break it. " + fix
		}
		ev := append(slices.Clone(base),
			Evidence{Label: limitLabel, Value: stamp(limit)},
			Evidence{Label: "Outside the window by", Value: humanDuration(outside)},
			Evidence{Label: "Clock-skew tolerance", Value: humanDuration(ctx.ClockSkew)})
		if ahead > 0 {
			ev = append(ev, Evidence{Label: "Estimated clock difference", Value: "IdP is at least " + humanDuration(ahead) + " ahead of the browser"})
		}
		out = append(out, Finding{RuleID: "OIDC006", OIDCFlow: v.flowRef(), Severity: sev, Title: title, Detail: detail, Fix: fix, Evidence: ev})
	}
	if len(out) == 0 && checked > 0 {
		return []Finding{passFinding("OIDC006", "Tokens were within their validity window",
			fmt.Sprintf("Checked %s against the time the browser received them.", plural(checked, "token")))}
	}
	return out
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// cap1 capitalizes the first letter: "ID token", "Access token".
func cap1(s string) string {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return s
	}
	return string(s[0]-'a'+'A') + s[1:]
}
