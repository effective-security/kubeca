package version

import (
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildVersion(t *testing.T) {
	vcs := func(revision string, modified bool) *debug.BuildInfo {
		info := &debug.BuildInfo{Main: debug.Module{Path: "github.com/effective-security/kubeca", Version: "(devel)"}}
		if revision != "" {
			info.Settings = append(info.Settings, debug.BuildSetting{Key: "vcs.revision", Value: revision})
		}
		if modified {
			info.Settings = append(info.Settings, debug.BuildSetting{Key: "vcs.modified", Value: "true"})
		} else if revision != "" {
			info.Settings = append(info.Settings, debug.BuildSetting{Key: "vcs.modified", Value: "false"})
		}
		return info
	}
	tcases := []struct {
		name  string
		build string
		info  *debug.BuildInfo
		ok    bool
		exp   string
	}{
		{"linker", "v0.7.123-host", vcs("0123456789abcdef", true), true, "v0.7.123-host"},
		{"no build info", "", nil, false, "devel"},
		{"module version", "", &debug.BuildInfo{Main: debug.Module{Version: "v0.7.5"}}, true, "v0.7.5"},
		{"pseudo version", "", &debug.BuildInfo{Main: debug.Module{Version: "v0.7.1-0.20260927101010-0123456789ab+dirty"}}, true, "v0.7.1-0.20260927101010-0123456789ab+dirty"},
		{"vcs", "", vcs("0123456789abcdef0123", false), true, "devel-0123456789ab"},
		{"vcs dirty", "", vcs("0123456789abcdef0123", true), true, "devel-0123456789ab-dirty"},
		{"short revision", "", vcs("abc", false), true, "devel-abc"},
		{"no vcs", "", vcs("", false), true, "devel"},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.exp, buildVersion(tc.build, tc.info, tc.ok))
		})
	}
}

func TestCurrent(t *testing.T) {
	v := Current()
	assert.NotEmpty(t, v.Build)
	assert.NotEqual(t, "(devel)", v.Build)
	assert.NotEmpty(t, v.Runtime)
	assert.Equal(t, v.Build, v.String())
}
