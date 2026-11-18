package diagnose

import (
	"fmt"
	"strconv"

	"github.com/Josperdo/ssotrace/internal/flow"
)

// callbackError is OIDC001: the authorization server answered with an
// error instead of a code or token, or rejected the authorization request
// outright and never sent the browser back.
type callbackError struct{}

func (callbackError) ID() string { return "OIDC001" }

func (callbackError) Check(ctx Context) []Finding {
	flows := oidcFlows(ctx)
	var out []Finding
	checked := 0
	for i := range flows {
		f := &flows[i]
		switch {
		case f.Callback != nil && f.Callback.Params.Error != "":
			out = append(out, errorCallbackFinding(i, f))
		case f.Callback != nil:
			checked++
		case f.Authorization != nil && f.Authorization.HTTPStatus >= 400:
			out = append(out, rejectedRequestFinding(i, f))
		}
	}
	if len(out) == 0 && checked > 0 {
		return []Finding{passFinding("OIDC001", "Authorization server returned no errors",
			fmt.Sprintf("Checked %s.", plural(checked, "callback")))}
	}
	return out
}

func errorCallbackFinding(i int, f *flow.OIDCFlow) Finding {
	cb := f.Callback
	code := cb.Params.Error
	ev := []Evidence{
		{Label: "Callback", Value: sentWhere(cb.Sent)},
		{Label: "error", Value: truncate(code, 64)},
	}
	if d := cb.Params.ErrorDescription; d != "" {
		ev = append(ev, Evidence{Label: "error_description", Value: truncate(d, 300)})
	}
	if u := cb.Params.ErrorURI; u != "" {
		ev = append(ev, Evidence{Label: "error_uri", Value: truncate(u, 200)})
	}
	if id, _ := clientID(f); id != "" {
		ev = append(ev, Evidence{Label: "client_id", Value: id})
	}

	if silentErrors[code] {
		prompt := ""
		if f.Authorization != nil {
			prompt = f.Authorization.Params.Prompt
		}
		if hasWord(prompt, "none") {
			return Finding{
				RuleID: "OIDC001", OIDCFlow: flowRef(i), Severity: Info,
				Title: "Silent sign-in needs the user (" + code + ")",
				Detail: "The application asked the IdP to sign the user in without showing anything (prompt=none), and the IdP answered that the user has to interact first. " +
					"This is expected when the IdP session has ended; the application should then start a normal, interactive sign-in.",
				Fix:      "If the user gets stuck instead of seeing a sign-in page, the application does not handle this error; make it fall back to an interactive sign-in.",
				Evidence: ev,
			}
		}
	}

	f2 := Finding{
		RuleID: "OIDC001", OIDCFlow: flowRef(i), Severity: Fail,
		Title: "Authorization server returned an error (" + truncate(code, 40) + ")",
		Detail: "The IdP sent the browser back to the application with an error instead of an authorization code or token, " +
			"so the user is not signed in.",
		Fix:      "Read error_description in the evidence, then check the IdP's sign-in log for this user at this time.",
		Evidence: ev,
	}
	if a, ok := authorizationErrors[code]; ok {
		f2.Detail += " " + a.meaning
		f2.Fix = a.fix
	} else if silentErrors[code] {
		f2.Detail += " The IdP needs the user to sign in, consent, or choose an account first."
		f2.Fix = "Start an interactive sign-in without prompt=none, and make sure the user can complete the IdP's prompts."
	}
	return f2
}

func rejectedRequestFinding(i int, f *flow.OIDCFlow) Finding {
	a := f.Authorization
	return Finding{
		RuleID: "OIDC001", OIDCFlow: flowRef(i), Severity: Fail,
		Title: "Authorization server rejected the request",
		Detail: "The IdP answered the authorization request with an HTTP error and never sent the browser back to the application. " +
			"IdPs do this, rather than return an error to the callback, when they cannot trust the request's client_id or redirect_uri.",
		Fix: "Open the error page from the evidence entry in the browser's developer tools; it usually names the problem. " +
			"Check that the client_id exists in the IdP and that the redirect_uri is registered for it exactly.",
		Evidence: []Evidence{
			{Label: "Authorization request", Value: sentWhere(a.Sent)},
			{Label: "IdP HTTP status", Value: strconv.Itoa(a.HTTPStatus)},
			{Label: "client_id", Value: a.Params.ClientID},
			{Label: "redirect_uri", Value: a.Params.RedirectURI},
		},
	}
}
