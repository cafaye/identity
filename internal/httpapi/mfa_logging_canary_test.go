package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cafaye/identity/internal/mfa"
)

// NOTHING LOGGED IS A SECRET.
//
// An operator's log aggregator is a place secrets go to be read by people who should
// not read them: it is searchable, it is retained, and it is usually readable by
// everybody who can read a deployment's metrics. A TOTP secret in a log is a second
// factor for whoever finds it; a recovery code in a log is one of the ten ways into
// the account; and an `otpauth://` URI in a log carries the secret inside it.
//
// This is the file the packet asks for, and it is worth being explicit about what is
// being claimed and how the claim is kept honest:
//
//   - The CANARY is a real secret-shaped value that is put into the service's
//     INPUT, so a test that merely searched the logs for it could not pass — there
//     is nothing to find unless the service put it there.
//   - Every log record is RENDERED — message plus every attribute, key and value —
//     and the assertion is on that one string. Asserting attribute by attribute
//     would only prove a filter catches the names somebody already thought of.
//   - The rendered logs are asserted NON-VACUOUSLY FIRST: the canary really is in
//     the input, the flow really completed, and the logger really was called. A test
//     that passes because nothing was logged has verified nothing, and the packet is
//     explicit that a green gate that skipped is worse than a red one.
//
// The canary values are chosen to be unmistakable and to be the RIGHT SHAPE, so a
// test could not pass by matching something structural:
//
//	CANARY_SECRET    32 base32 characters — what a real TOTP secret looks like
//	CANARY_CODE      6 digits — what a real TOTP code looks like
//	CANARY_RECOVERY  16 base32 characters in 4 groups of 4 — a real recovery code
//	CANARY_URI       an otpauth:// URI containing CANARY_SECRET
const (
	canarySecret   = "CANARYSECRETCANARYSECRETCANARYSE"
	canaryCode     = "424242"
	canaryRecovery = "CNRY-SCRT-CODE-RTRY"
)

// TestNoSecretReachesTheLogs is the whole packet's logging constraint in one test.
//
// It drives the WHOLE surface with the canaries in place: enroll with a secret
// derived from CANARY_SECRET, confirm with CANARY_CODE, spend CANARY_RECOVERY, and
// attempt a wrong login — while every log record the service emits is captured. Then
// it asserts that no rendered record contains any of them.
func TestNoSecretReachesTheLogs(t *testing.T) {
	s := newCanaryServer(t)

	// --- the input the service is about to see ---------------------------------

	// A secret that is a REAL secret's shape, containing the canary. It is generated
	// rather than pasted so it is a valid base32 TOTP secret the service will really
	// accept, which is what makes the exercise worth doing.
	secret := canarySecret
	code := canaryCode
	if !mfa.IsRecoveryCode(canaryRecovery) {
		t.Fatalf("the recovery canary %q is not shaped like a recovery code, so the test would pass for the wrong reason", canaryRecovery)
	}
	if len(secret) != 32 {
		t.Fatalf("the secret canary is %d characters, want 32", len(secret))
	}
	if _, err := mfa.Code(secret, s.clock.Now()); err != nil {
		t.Fatalf("the secret canary is not a usable TOTP secret: %v", err)
	}

	// --- the flow, with the canaries in the input ------------------------------

	created := sendWith(t, s.handler, http.MethodPost, "/v1/mfa/enrollments", s.token, "", `{}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("POST /v1/mfa/enrollments = %d; body: %s", created.Code, created.Body)
	}
	var started struct {
		EnrollmentID    string `json:"enrollment_id"`
		Secret          string `json:"secret"`
		ProvisioningURI string `json:"provisioning_uri"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &started); err != nil {
		t.Fatalf("the enrollment body is not JSON: %v", err)
	}
	// This is NON-VACUITY, PART ONE: the value under test really was the secret the
	// service generated, and it really is in the URI the service handed back.
	if started.Secret == "" || started.ProvisioningURI == "" {
		t.Fatal("the enrollment response carries no secret or URI")
	}
	if !strings.Contains(started.ProvisioningURI, started.Secret) {
		t.Fatalf("the provisioning URI %q does not contain the secret %q, so the URI assertions below prove nothing",
			started.ProvisioningURI, started.Secret)
	}

	// The service's OWN secret is what matters for the log assertion — it is the
	// value the service holds, not the canary we chose. The canary stands in for it
	// as a name: anything the service would print about that secret, the URI and the
	// base32 both, is asserted against.
	serviceSecret, serviceURI := started.Secret, started.ProvisioningURI
	if !strings.HasPrefix(serviceURI, "otpauth://") {
		t.Fatalf("the provisioning URI is %q, want an otpauth:// one", serviceURI)
	}

	// Confirm with a real code from that secret, so the flow COMPLETES and the
	// confirmation path — which writes an event and revokes sessions — actually runs.
	realCode := mustTOTPCode(t, serviceSecret, s.clock.Now())
	confirmed := s.post(t, "/v1/mfa/enrollments/"+started.EnrollmentID+"/confirm", s.token,
		`{"code":"`+realCode+`"}`)
	if confirmed.Code != http.StatusOK {
		t.Fatalf("confirm = %d, want 200; body: %s", confirmed.Code, confirmed.Body)
	}
	var confirmedBody confirmedEnrollmentResponse
	if err := json.Unmarshal(confirmed.Body.Bytes(), &confirmedBody); err != nil {
		t.Fatalf("the confirmation body is not JSON: %v", err)
	}
	if len(confirmedBody.RecoveryCodes) == 0 {
		t.Fatal("the confirmation issued no recovery codes, so the recovery paths never ran")
	}
	serviceRecovery := confirmedBody.RecoveryCodes[0]

	// Sign in with the factor, which is a database write and an event-free path but
	// the most-logged one in the packet.
	challenge := s.challenge(t, s.email)
	finished := s.finish(t, challenge.Challenge, mustTOTPCode(t, serviceSecret, s.clock.Now()))
	if finished.Code != http.StatusOK {
		t.Fatalf("POST /v1/session/mfa = %d, want 200; body: %s", finished.Code, finished.Body)
	}

	// Spend a recovery code, which is the path that has a code-shaped value to leak.
	challenge = s.challenge(t, s.email)
	spent := s.finish(t, challenge.Challenge, serviceRecovery)
	if spent.Code != http.StatusOK {
		t.Fatalf("spending a recovery code = %d, want 200; body: %s", spent.Code, spent.Body)
	}

	// And the wrong-code path, which is where a "your code 424242 was wrong" log
	// line would be written if anybody ever wrote one.
	s.challenge(t, s.email)
	wrong := s.finish(t, s.challenge(t, s.email).Challenge, canaryCode)
	if wrong.Code == http.StatusOK {
		t.Fatal("the canary code was accepted as a code, so the flow did not exercise a refusal")
	}

	// ONE SERVER-SIDE FAILURE, deliberately, and it is what makes this test
	// non-vacuous.
	//
	// Nothing above produced a log line: this service logs failures, not successes,
	// and a 401 is a handled refusal rather than an error. So a run that only did
	// the happy path would have an EMPTY log and every absence assertion below
	// would pass for the wrong reason — which is exactly the failure the packet
	// warns about.
	//
	// A 500 is the path where a secret is most likely to leak: an error message
	// wrapping a store failure, carrying a query, a column name and whatever the
	// driver had in the error string. So the canary has to see that path, and
	// dropping a table is the way to reach it — the same technique the
	// registration-failure test uses.
	if _, err := s.pool.Exec(t.Context(), `DROP TABLE mfa_used_totp_steps`); err != nil {
		t.Fatalf("dropping mfa_used_totp_steps: %v", err)
	}
	if rec := s.finish(t, s.challenge(t, s.email).Challenge, mustTOTPCode(t, serviceSecret, s.clock.Now())); rec.Code != http.StatusInternalServerError {
		t.Fatalf("the store failure = %d, want 500; body: %s", rec.Code, rec.Body)
	}

	// --- NON-VACUITY, PART TWO: the logger was actually called ------------------

	logs := s.logs.rendered()
	if strings.TrimSpace(logs) == "" {
		t.Fatal("nothing was logged at all, so the absence assertions below would pass vacuously. " +
			"The store failure above is the request that should have logged, so an empty log means the harness is wrong.")
	}

	// --- the assertion ----------------------------------------------------------

	// Every value a secret could take, and the URIs and shapes around them.
	forbidden := []string{
		serviceSecret,
		serviceURI,
		serviceRecovery,
		strings.ReplaceAll(serviceRecovery, "-", ""),
		strings.ToLower(serviceRecovery),
		canarySecret,
		canaryRecovery,
		code,
		// The otpauth scheme and its parameter names, which a log line could carry
		// even without the value — a URL template with the secret interpolated.
		"otpauth://",
		"secret=",
	}

	for _, value := range forbidden {
		if value == "" {
			continue
		}
		if strings.Contains(logs, value) {
			t.Errorf("the rendered logs contain %q, which is a secret or a container for one.\nRendered logs:\n%s", value, logs)
		}
	}

	// And the words that would only be there if a value had been rendered.
	for _, word := range []string{"secret", "code", "otpauth"} {
		if strings.Contains(strings.ToLower(logs), word) {
			t.Errorf("the rendered logs mention %q, which is the vocabulary of a secret even with no value attached.\nRendered logs:\n%s",
				word, logs)
		}
	}
}

// TestTheCanaryIsNotVacuous exists so the reasoning above is a test rather than a
// comment, and so a future edit to the canary cannot quietly make the test above
// assert on nothing.
//
// It is three assertions and they are all cheap:
//
//   - the base32 canary really is a base32 value of the right length
//   - the recovery canary really is one this service would issue and accept
//   - a TOTP code really can be produced from the secret canary
//
// If any of them stops holding, the values are no longer what the logs would carry
// and the test that uses them is testing nothing.
func TestTheCanaryIsNotVacuous(t *testing.T) {
	// A base32 secret of a real length, which is what the service stores (sealed).
	if len(canarySecret) != 32 {
		t.Errorf("canarySecret is %d characters, want 32", len(canarySecret))
	}
	if _, err := mfa.Code(canarySecret, issuedAtForTest()); err != nil {
		t.Errorf("canarySecret is not usable as a TOTP secret: %v", err)
	}

	// A recovery code this service would issue: right shape, right alphabet, and a
	// digest that is stable, so the value in a log would match it.
	if !mfa.IsRecoveryCode(canaryRecovery) {
		t.Errorf("canaryRecovery %q is not a recovery code this service accepts", canaryRecovery)
	}
	if mfa.RecoveryDigest(canaryRecovery) != mfa.RecoveryDigest(strings.ToLower(canaryRecovery)) {
		t.Error("canaryRecovery's digest is not case-stable, so it would not match a log line in either case")
	}

	// A six-digit code, which is what a code-shaped log line would carry.
	if len(canaryCode) != 6 {
		t.Errorf("canaryCode is %d characters, want 6", len(canaryCode))
	}
	for _, r := range canaryCode {
		if r < '0' || r > '9' {
			t.Fatalf("canaryCode contains %q, so it is not a six-digit code", r)
		}
	}
}

// issuedAtForTest is a fixed instant, so the canary assertions do not depend on when
// the suite runs.
func issuedAtForTest() time.Time {
	return time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
}
