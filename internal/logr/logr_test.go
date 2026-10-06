package logr_test

import (
	"bufio"
	"bytes"
	"errors"
	"testing"

	"github.com/effective-security/kubeca/internal/logr"
	"github.com/effective-security/xlog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogr(t *testing.T) {
	logger := xlog.NewPackageLogger("github.com/effective-security/kubeca", "logr")

	var b bytes.Buffer
	writer := bufio.NewWriter(&b)

	xlog.SetGlobalLogLevel(xlog.INFO)
	xlog.SetFormatter(xlog.NewPrettyFormatter(writer))

	base := logr.New(logger)
	assert.True(t, base.Enabled())
	assert.True(t, base.V(2).Enabled())

	named := base.V(0).WithName("x").WithValues("k1", "val1")
	named.Info("test message", "k1", "v1")
	named.Error(errors.New("some error"), "error message", "k1", "v1")
	named.Error(nil, "error without err")
	named.WithName("y").Info("nested name")
	// mapped to TRACE and DEBUG, below the INFO global level
	named.V(1).Info("trace message")
	named.V(2).Info("debug message")
	// the base logger must not carry the values or the name of the derived
	// one (KUBECA-009)
	base.Info("base message")

	require.NoError(t, writer.Flush())
	result := b.String()
	assert.Contains(t, result, "I | pkg=logr, func=Info, k1=val1, src=x, k1=v1, msg=\"test message\"\n")
	assert.Contains(t, result, "E | pkg=logr, func=Error, k1=val1, src=x, k1=v1, msg=\"error message\", err=\"some error\"\n")
	assert.Contains(t, result, "E | pkg=logr, func=Error, k1=val1, src=x, msg=\"error without err\"\n")
	assert.Contains(t, result, "I | pkg=logr, func=Info, k1=val1, src=x.y, msg=\"nested name\"\n")
	assert.Contains(t, result, "I | pkg=logr, func=Info, msg=\"base message\"\n")
	assert.NotContains(t, result, "trace message")
	assert.NotContains(t, result, "debug message")
}
