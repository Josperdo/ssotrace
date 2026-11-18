package diagnose

import "fmt"

// stateMismatch is OIDC002: the callback's state differs from the state
// the application sent. Applications must reject such a callback, because
// state is their defense against an attacker's callback being injected
// into the user's browser (CSRF, RFC 6749 §10.12).
type stateMismatch struct{}

func (stateMismatch) ID() string { return "OIDC002" }

func (stateMismatch) Check(ctx Context) []Finding {
	flows := oidcFlows(ctx)
	var out []Finding
	checked := 0
	for i := range flows {
		f := &flows[i]
		switch {
		case f.Callback == nil, f.Repeats != nil:
			// A repeated callback carries the state already checked
			// against its original request.
			continue
		case f.Authorization == nil:
			if f.Callback.Params.State == "" {
				continue
			}
			out = append(out, Finding{
				RuleID: "OIDC002", OIDCFlow: flowRef(i), Severity: Info,
				Title:  "State could not be checked",
				Detail: "The capture has this callback but not the authorization request it answers, so ssotrace cannot compare state values.",
				Fix:    "Capture again with \"Preserve log\" on, starting before the user clicks sign in.",
				Evidence: []Evidence{
					{Label: "Callback", Value: sentWhere(f.Callback.Sent)},
				},
			})
		case f.StateMismatch:
			req, cb := f.Authorization.Params.State, f.Callback.Params.State
			detail := "The state value the IdP returned does not match the one the application sent with this request. The application will reject the callback."
			if cb == "" {
				detail = "The application sent a state value, but the callback came back without one. The application will reject the callback."
			}
			out = append(out, Finding{
				RuleID: "OIDC002", OIDCFlow: flowRef(i), Severity: Fail,
				Title:  "State does not match",
				Detail: detail,
				Fix: "Usually the callback belongs to a different sign-in attempt: the user started two sign-ins (two tabs, a double click, or the back button), " +
					"or a load balancer sent the callback to a server that does not hold the session. Make sessions sticky or shared, start one sign-in at a time, " +
					"and retry from the application's own sign-in page.",
				Evidence: []Evidence{
					{Label: "Authorization request", Value: sentWhere(f.Authorization.Sent)},
					{Label: "Callback", Value: sentWhere(f.Callback.Sent)},
					{Label: "state sent", Value: previewOrNone(req)},
					{Label: "state returned", Value: previewOrNone(cb)},
				},
			})
		case f.Authorization.Params.State != "":
			checked++
		}
	}
	if len(out) == 0 && checked > 0 {
		return []Finding{passFinding("OIDC002", "State matches",
			fmt.Sprintf("Checked %s against the request it answers.", plural(checked, "callback")))}
	}
	return out
}
