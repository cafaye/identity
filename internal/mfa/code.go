package mfa

import (
	"strconv"
	"strings"
)

// The small normalisations the code path shares, in one file so there is one
// definition of "what a presented code looks like" rather than one per use case.

// isTOTPCode reports whether a presented value has the shape of a TOTP code.
//
// Digits only, and exactly the configured width. A code with a space in it, a
// code typed with a dash, a code in a word processor that turned "1" into "l" —
// all of them are refused, and all of them are refused the same way as a wrong
// code, because a value this service cannot interpret is not a value it can be
// lenient about.
func isTOTPCode(value string) bool {
	if len(value) != Digits {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

// trimCode removes the whitespace a browser form adds and nothing else.
//
// A code pasted out of a password manager arrives with a trailing newline, and a
// user on a phone keyboard has a space bar within reach. Trimming whitespace is
// the only leniency here and it is the leniency every implementation of every
// login form has; nothing else about the value is repaired.
func trimCode(code string) string {
	return strings.TrimSpace(code)
}

// itoa is strconv.Itoa under a name that says which number it is for.
func itoa(n int) string { return strconv.Itoa(n) }
