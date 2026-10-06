package logr

import (
	"github.com/effective-security/xlog"
	"github.com/go-logr/logr"
)

const (
	nameKey       = "src"
	nameSeparator = "."
	msgKey        = "msg"
	errKey        = "err"
)

// prov is a logr.LogSink over an xlog.KeyValueLogger. It is immutable:
// WithValues and WithName return new sinks.
type prov struct {
	logger xlog.KeyValueLogger
	name   string
}

// New returns logr.Logger
func New(logger xlog.KeyValueLogger) logr.Logger {
	return logr.New(&prov{logger: logger})
}

// Init receives optional information about the logr library for LogSink
// implementations that need it.
func (p *prov) Init(info logr.RuntimeInfo) {}

// Enabled tests whether this Logger is enabled. Every verbosity is
// accepted here; the line is mapped to an xlog level (see xlogLevel) and
// xlog's global level decides whether it is written.
func (p *prov) Enabled(level int) bool {
	return true
}

// xlogLevel maps a logr verbosity to an xlog level: 0 is INFO, 1 is
// TRACE, 2 and above are DEBUG.
func xlogLevel(level int) xlog.LogLevel {
	switch {
	case level <= 0:
		return xlog.INFO
	case level == 1:
		return xlog.TRACE
	default:
		return xlog.DEBUG
	}
}

// entries returns the key/value list for a line: the sink name when set,
// the caller's pairs, then extra. It never appends to the caller's slice.
func (p *prov) entries(keysAndValues []any, extra ...any) []any {
	kv := make([]any, 0, len(keysAndValues)+len(extra)+2)
	if p.name != "" {
		kv = append(kv, nameKey, p.name)
	}
	kv = append(kv, keysAndValues...)
	return append(kv, extra...)
}

// Info logs a non-error message with the given key/value pairs as context.
//
// The msg argument should be used to add some constant description to
// the log line.  The key/value pairs can then be used to add additional
// variable information.  The key/value pairs should alternate string
// keys and arbitrary values.
func (p *prov) Info(level int, msg string, keysAndValues ...any) {
	p.logger.KV(xlogLevel(level), p.entries(keysAndValues, msgKey, msg)...)
}

// Error logs an error, with the given message and key/value pairs as context.
// It functions similarly to calling Info with the "error" named value, but may
// have unique behavior, and should be preferred for logging errors (see the
// package documentations for more information).
//
// The msg field should be used to add context to any underlying error,
// while the err field should be used to attach the actual error that
// triggered this log line, if present.
func (p *prov) Error(err error, msg string, keysAndValues ...any) {
	if err == nil {
		p.logger.KV(xlog.ERROR, p.entries(keysAndValues, msgKey, msg)...)
		return
	}
	p.logger.KV(xlog.ERROR, p.entries(keysAndValues, msgKey, msg, errKey, err.Error())...)
}

// WithValues returns a new sink with the key-value pairs added to its
// context; the receiver is unchanged.
// See Info for documentation on how key/value pairs work.
func (p *prov) WithValues(keysAndValues ...any) logr.LogSink {
	return &prov{
		logger: p.logger.WithValues(keysAndValues...),
		name:   p.name,
	}
}

// WithName returns a new sink whose name has the element appended
// (dot-separated); the receiver is unchanged. The name is logged under the
// src key. It's strongly recommended that name segments contain only
// letters, digits, and hyphens (see the package documentation for more
// information).
func (p *prov) WithName(name string) logr.LogSink {
	if p.name != "" {
		name = p.name + nameSeparator + name
	}
	return &prov{
		logger: p.logger,
		name:   name,
	}
}
