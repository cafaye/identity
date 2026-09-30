package httpapi

import (
	"log/slog"
	"net/http"
)

// recoverPanics turns a panic in a handler into a 500 with a trace id.
//
// A panic in an identity handler is a bug, and the two acceptable outcomes are a
// logged 500 and a process that stays up. Letting it reach net/http is neither:
// the connection is closed with no response, so a client cannot tell a server bug
// from a network fault, and the log line is a bare panic with no request
// attached — no path, no trace id, nothing to correlate a report against.
//
// The stack is logged, not returned. It names internal package paths and, in the
// general case, whatever values were on the stack.
func recoverPanics(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tracked := &trackedWriter{ResponseWriter: w}

		defer func() {
			recovered := recover()
			if recovered == nil {
				return
			}
			// http.ErrAbortHandler is the documented way to abandon a response, and
			// it is not a bug. Re-panicking with it lets net/http close the
			// connection quietly instead of inventing a 500 for a deliberate abort.
			if recovered == http.ErrAbortHandler {
				panic(recovered)
			}

			logPanic(logger, r, tracked, recovered)

			// Nothing can be written once the status line is out: a second
			// WriteHeader is ignored and appending a body to a response that is
			// already committed produces a document no client can parse. Logging
			// and closing the connection is the honest outcome.
			if tracked.wroteHeader {
				return
			}
			unexpected(tracked, r, logger, panicError{recovered})
		}()

		next.ServeHTTP(tracked, r)
	})
}

// trackedWriter records whether the response has been committed, which is the one
// thing a recovery handler needs to know and cannot get from a bare
// ResponseWriter.
type trackedWriter struct {
	http.ResponseWriter
	wroteHeader bool
}

func (w *trackedWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(status)
}

func (w *trackedWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.wroteHeader = true
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer, so anything
// that needs Flush or Hijack still works through the wrapper.
func (w *trackedWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// panicError carries a recovered value as an error so it can go through the same
// reporting path as every other failure.
type panicError struct{ value any }

func (e panicError) Error() string {
	if err, ok := e.value.(error); ok {
		return "panic: " + err.Error()
	}
	return "panic"
}

func logPanic(logger *slog.Logger, r *http.Request, w *trackedWriter, recovered any) {
	if logger == nil {
		return
	}
	// The stack goes here and only here. It is the one artifact that reliably
	// identifies the bug, and the one artifact that must never reach a caller.
	logger.Error("panic in a handler",
		"error", panicError{recovered},
		"method", r.Method,
		"path", r.URL.Path,
		"trace_id", traceIDFrom(r.Context()),
		"response_committed", w.wroteHeader,
	)
}
