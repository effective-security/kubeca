package logr_test

import (
	"bufio"
	"bytes"
	"errors"
	"testing"

	"github.com/effective-security/kubeca/internal/logr"
	"github.com/effective-security/xlog"
	"github.com/stretchr/testify/assert"
)

func TestLogr(t *testing.T) {
	logger := xlog.NewPackageLogger("github.com/effective-security/kubeca", "logr")

	var b bytes.Buffer
	writer := bufio.NewWriter(&b)

	xlog.SetGlobalLogLevel(xlog.INFO)
	xlog.SetFormatter(xlog.NewPrettyFormatter(writer))

	logr := logr.New(logger)
	assert.True(t, logr.Enabled())
	logr = logr.V(0)
	logr = logr.WithName("x")
	logr.WithValues("k1", "val1")
	logr.Info("test message", "k1", "v1")
	logr.Error(errors.New("some error"), "error message", "k1", "v1")

	result := b.String()
	assert.Contains(t, result, "I | pkg=logr, func=Info, src=\"x\", k1=\"val1\", k1=\"v1\", msg=\"test message\"\n")
	assert.Contains(t, result, "E | pkg=logr, func=Error, src=\"x\", k1=\"val1\", k1=\"v1\", msg=\"error message\", err=\"some error\"\n")
}
