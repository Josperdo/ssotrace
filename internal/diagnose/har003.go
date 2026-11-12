package diagnose

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Josperdo/ssotrace/internal/flow"
)

// redirectLoop is HAR003: the browser bounced between the application and
// the IdP repeatedly. The IdP keeps logging the user in and the SP keeps
// sending them back, usually because the SP never keeps the session it
// just created.
type redirectLoop struct{}

func (redirectLoop) ID() string { return "HAR003" }

const (
	// loopRepeats is how many times the same hop must recur to count as a
	// loop. Two can be an honest retry; three automatic round trips is not.
	loopRepeats = 3
	// loopWindow is how close together those repeats must be. A loop runs
	// at machine speed; a person retrying by hand is much slower, so their
	// attempts spread beyond this window and are not reported.
	loopWindow = 30 * time.Second
)

func (redirectLoop) Check(ctx Context) []Finding {
	if ctx.HAR == nil {
		return nil
	}

	// A hop is a request that is part of the sign-in dance: answered with
	// a redirect, or carrying an SSO message. Plain page loads and polling
	// are ignored, so a dashboard that refreshes every few seconds is not a
	// "loop".
	times := map[string][]time.Time{}
	hops := 0
	for i := range ctx.HAR.Log.Entries {
		e := &ctx.HAR.Log.Entries[i]
		redirect := e.Response.Status >= 300 && e.Response.Status < 400
		if !redirect && flow.Detect(e) == flow.None {
			continue
		}
		t, err := e.Started()
		if err != nil {
			continue
		}
		hops++
		// The key drops the query string: each round of a loop carries a
		// fresh state or SAMLRequest value, but the URL is the same.
		key := describeRequest(&e.Request)
		times[key] = append(times[key], t)
	}
	if hops == 0 {
		return nil
	}

	type looping struct {
		key   string
		count int
		span  time.Duration
	}
	var loops []looping
	for key, ts := range times {
		if n, span := densest(ts, loopWindow); n >= loopRepeats {
			loops = append(loops, looping{key, n, span})
		}
	}
	if len(loops) == 0 {
		return []Finding{passFinding("HAR003", "No redirect loop",
			fmt.Sprintf("No sign-in request repeated %d or more times within %s.", loopRepeats, humanDuration(loopWindow)))}
	}
	// Most repeated first; ties broken by URL so output is stable.
	sort.Slice(loops, func(i, j int) bool {
		if loops[i].count != loops[j].count {
			return loops[i].count > loops[j].count
		}
		return loops[i].key < loops[j].key
	})

	top := loops[0]
	f := Finding{
		RuleID:   "HAR003",
		Severity: Fail,
		Title:    "Redirect loop between the application and the IdP",
		Detail: fmt.Sprintf("The same sign-in request was made %d times in %s. The IdP keeps completing the login and the application keeps sending the user back to log in again, "+
			"so the user never gets in. The application is not keeping the session it creates after the login.", top.count, humanDuration(top.span)),
		Fix: "Check the application's session cookie on the response to the login callback: it must be set, and the browser must send it back. " +
			"Common causes: the cookie lacks SameSite=None; Secure and is dropped on the cross-site POST from the IdP; the cookie is marked Secure but the site is served over http; " +
			"the cookie's domain or path does not match; or the application rejects the login (see the other findings) and silently starts a new one.",
		Evidence: []Evidence{
			{Label: "Repeated request", Value: top.key},
			{Label: "Times", Value: fmt.Sprintf("%d in %s", top.count, humanDuration(top.span))},
		},
	}
	var others []string
	for _, l := range loops[1:] {
		others = append(others, l.key)
		if len(others) == maxExamplesShown {
			break
		}
	}
	if len(others) > 0 {
		f.Evidence = append(f.Evidence, Evidence{Label: "Also repeating", Value: strings.Join(others, "; ")})
	}
	return []Finding{f}
}

// densest returns the largest number of times in ts that fall within one
// window, and the span they cover. ts is in capture order, which HAR
// exporters keep chronological, but it is sorted to be safe.
func densest(ts []time.Time, window time.Duration) (int, time.Duration) {
	sorted := append([]time.Time(nil), ts...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Before(sorted[j]) })
	best, span := 0, time.Duration(0)
	start := 0
	for end := range sorted {
		for sorted[end].Sub(sorted[start]) > window {
			start++
		}
		if n := end - start + 1; n > best {
			best, span = n, sorted[end].Sub(sorted[start])
		}
	}
	return best, span
}
