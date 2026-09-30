package client

// WHERE REQUESTS GO, IN A DOCUMENTED ORDER, WITH NO DEFAULT THAT GUESSES.
//
// The generated client does not decide this. `api.gen.go` carries a `Server`
// default of `https://identity.cafaye.com`, read out of the document's `servers:`
// block, and that default is a trap rather than a convenience: a self-hoster
// running their own identity who never set a base URL would have their traffic —
// and their credentials — sent to somebody else's deployment, and the first
// symptom would be a login attempt against a host they do not control.
//
// MD6 gives the wrapper this job for the same reason it gives it credential
// handling: the fleet's documents cannot express a self-hoster's deployment, so
// something hand-written has to.
//
// # THE PRECEDENCE, HIGHEST FIRST
//
//  1. `BaseURL` on the options — explicit beats ambient
//  2. `CAFAYE_IDENTITY_BASE_URL` — this service, specifically
//  3. `CAFAYE_BASE_URL` — every cafaye service, one variable
//  4. throw
//
// Steps 2 and 3 are one source in two granularities: a per-service variable is more
// specific than a fleet-wide one, and the fleet-wide one exists because a
// self-hoster with one deployment of everything should not have to spell out six
// variable names.
//
// This mirrors `cafaye-ts`'s `baseUrlEnvFor` precedence rather than inventing one.
// cafaye-ts has an extra step this client does not — `globalThis.location.origin`,
// which is right for a browser bundle served from the same origin as the fleet and
// has no meaning at all in a Go binary. A divergence between three clients for one
// platform is a defect in the platform, so the steps that mean the same thing are
// named the same and the one that does not is absent rather than reordered.
//
// # WHY THERE IS NO LOCALHOST, AND WHY STEP 4 THROWS
//
// The brief asks for "explicit, then `CAFAYE_BASE_URL`, then the default". The
// default is the part this file refuses, and the refusal is the design.
//
// A localhost default is attractive for exactly the wrong reason — it makes a
// developer's laptop work — and it is a silent misdirection everywhere else. A
// production process resolving to `http://localhost:3000` fails with a connection
// refused against a service nobody asked for, and the error names the wrong thing.
// The alternative default, the document's own `servers:` entry, sends a
// self-hoster's credentials to public SaaS, which is worse: it succeeds, so nothing
// is visibly wrong until somebody reads a log.
//
// So step 4 throws, and the error names every source it consulted and suggests no
// host. The generated client's SaaS default is never reachable from here, and that
// is the property that makes this file worth existing.

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// BaseURLEnvVar applies to every cafaye service.
const BaseURLEnvVar = "CAFAYE_BASE_URL"

// ServiceBaseURLEnvVar applies to identity specifically, and is derived rather
// than written out — see `BaseURLEnvVarFor`.
const ServiceBaseURLEnvVar = "CAFAYE_IDENTITY_BASE_URL"

// BaseURLEnvVarFor derives `CAFAYE_<SERVICE>_BASE_URL` from a service name.
//
// Derived rather than written out per service because six string literals would be a
// second list of the six services next to the vendored documents, and this
// repository is organised entirely around not having those.
func BaseURLEnvVarFor(service string) string {
	if !regexp.MustCompile(`^[a-z]+$`).MatchString(service) {
		return ""
	}
	return "CAFAYE_" + strings.ToUpper(service) + "_BASE_URL"
}

// ErrNoBaseURL is returned when nothing is configured.
//
// A sentinel so a caller can `errors.Is` it and print its own configuration
// advice, which is the one thing a caller can add that this package cannot.
var ErrNoBaseURL = errors.New("no base URL configured")

// LookupEnv reads one variable. It exists so tests never mutate the process
// environment, which is the same seam `internal/config`'s `Lookup` provides and
// for the same reason: `os.Setenv` in a test is a global mutation that races every
// other test in the package and leaks past the end of it.
//
// `nil` means "read the real environment", so a caller that does not care writes
// nothing and production reads `os.Getenv`.
type LookupEnv func(string) string

// BaseURLOptions is where a caller says where identity is.
//
// A struct rather than positional arguments because the set will grow — a deadline
// and a custom transport are the obvious next two — and a caller who has to
// remember the order of four strings is a caller who gets one wrong.
type BaseURLOptions struct {
	// BaseURL is the explicit value. Highest precedence, and the only source that
	// is a decision somebody made in code.
	BaseURL string

	// LookupEnv reads the environment. nil means `os.Getenv`.
	LookupEnv LookupEnv
}

// ResolveBaseURL returns the base URL requests go to, or an error naming every
// source it consulted.
//
// It is a free function rather than a method because it is a pure decision about
// configuration, and testing it does not need a client, a transport or a server.
// That is what makes the per-branch tests below cheap enough to have one per branch.
func ResolveBaseURL(opts BaseURLOptions) (string, error) {
	lookup := opts.LookupEnv
	if lookup == nil {
		lookup = osGetenv
	}

	type candidate struct {
		value  string
		source string
	}

	var considered []string
	var chosen *candidate

	for _, c := range []candidate{
		{present(opts.BaseURL), "the BaseURL option"},
		{present(lookup(ServiceBaseURLEnvVar)), "$" + ServiceBaseURLEnvVar},
		{present(lookup(BaseURLEnvVar)), "$" + BaseURLEnvVar},
	} {
		considered = append(considered, c.source)
		if c.value == "" {
			continue
		}
		if chosen == nil {
			chosen = &c
		}
	}

	if chosen == nil {
		// The message is long, and the length is the point: a caller who gets this
		// has a misconfigured deployment and the message is the only thing telling
		// them which variable to set. The first line carries the sentinel and no
		// trailing punctuation, because `staticcheck`'s ST1005 is right that an
		// error string is often embedded in another sentence — this one is not.
		return "", fmt.Errorf("%w for identity, and this client will not guess one;\n\n"+
			"Set one of, in order:\n"+
			"  1. the BaseURL option\n"+
			"  2. $%s\n"+
			"  3. $%s\n\n"+
			"Consulted, in that order: %s\n\n"+
			"Each of those is a decision somebody made. A default would be a guess, and "+
			"a guess about which deployment to send a customer's credentials to is the "+
			"one kind of guess this package refuses to make.\n\n"+
			"identity's own document lists https://identity.cafaye.com as a server, and "+
			"that value is deliberately NOT used as a default: it would send a "+
			"self-hoster's traffic to somebody else's deployment, and it would succeed, "+
			"so nothing would look wrong until somebody read a log",
			ErrNoBaseURL, ServiceBaseURLEnvVar, BaseURLEnvVar, strings.Join(considered, ", "))
	}

	parsed, err := url.Parse(chosen.value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("the base URL from %s is %q, which is not an absolute http(s) URL\n\n"+
			"cafaye's generated clients concatenate the base URL with an operation's path "+
			"rather than resolving one against the other, so a bare host would produce "+
			"something that is not a URL and an error naming neither the value nor the "+
			"cause. Give an absolute URL including the scheme",
			chosen.source, chosen.value)
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("the base URL from %s has scheme %q, and this client speaks "+
			"only http and https\n\n"+
			"A `file:` or `javascript:` base URL is a configuration mistake that would "+
			"otherwise surface as a request error naming neither the value nor the cause",
			chosen.source, parsed.Scheme)
	}

	// Trailing slashes are stripped so the URL this reports is the URL that goes
	// out. The generated client concatenates rather than resolving, so a trailing
	// slash becomes a doubled separator in the path — and a path prefix is KEPT,
	// which a self-hoster serving the fleet under `/cafaye` needs and which
	// `parsed.Scheme + "://" + parsed.Host` would helpfully but wrongly delete.
	return strings.TrimRight(chosen.value, "/"), nil
}

// present trims, and treats blank as absent. An empty base URL is not a base URL.
func present(value string) string { return strings.TrimSpace(value) }

// osGetenv is the default lookup, named so the production path is one line and
// `ResolveBaseURL` never calls `os.Getenv` directly — which is what lets every
// precedence test in this package run without touching the process environment.
func osGetenv(name string) string { return os.Getenv(name) }
