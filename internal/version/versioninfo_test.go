package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInfo_ParseBuild(t *testing.T) {
	tcases := []struct {
		build  string
		major  uint
		minor  uint
		commit uint
		flt    float32
	}{
		{"v1.2.114", 1, 2, 114, 1.2*1000000 + 114},
		{"1.2.114", 1, 2, 114, 1.2*1000000 + 114},
		{"v1.2.114-dirty", 1, 2, 114, 1.2*1000000 + 114},
		{"v0.7.231-host", 0, 7, 231, 0.7*1000000 + 231},
		// a plain go build: no panic, zero values
		{"devel", 0, 0, 0, 0},
		{"devel-0123456789ab-dirty", 0, 0, 0, 0},
		{"", 0, 0, 0, 0},
	}
	for _, tc := range tcases {
		t.Run(tc.build, func(t *testing.T) {
			v := Info{Build: tc.build}
			v.PopulateFromBuild()
			assert.Equal(t, tc.major, v.Major, "Major")
			assert.Equal(t, tc.minor, v.Minor, "Minor")
			assert.Equal(t, tc.commit, v.Commit, "Commit")
			assert.Equal(t, tc.flt, v.Float(), "Float")
			assert.Equal(t, tc.build, v.String())
			assert.NotEmpty(t, v.Runtime)
		})
	}
}

func TestInfo_GreaterOrEqual(t *testing.T) {
	v01 := Info{0, 1, 3, "", "go1.5", float32(0.1*1000000 + 3)}
	v02 := Info{0, 2, 3, "", "go1.5", float32(0.2*1000000 + 3)}
	v10 := Info{1, 0, 3, "", "go1.5", float32(1.0*1000000 + 3)}
	v12 := Info{1, 2, 3, "", "go1.5", float32(1.2*1000000 + 3)}
	v20 := Info{2, 0, 3, "", "go1.5", float32(2.0*1000000 + 3)}
	f := func(v, other Info, expected bool) {
		act := v.GreaterOrEqual(other)
		assert.Equal(t, expected, act, "%v GreaterOrEqual (%v) return wrong result", v, other)
	}
	f(v01, v01, true)
	f(v02, v01, true)
	f(v10, v01, true)
	f(v20, v12, true)
	f(v02, v10, false)
	f(v01, v02, false)
}
