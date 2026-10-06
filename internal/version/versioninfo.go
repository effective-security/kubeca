package version

import (
	"fmt"
	"runtime"
	"strings"
)

// Info describes a version of an executable
type Info struct {
	Major   uint   `json:"major"`
	Minor   uint   `json:"minor"`
	Commit  uint   `json:"commi"`
	Build   string `json:"build"`
	Runtime string `json:"runtime"`
	flt     float32
}

// PopulateFromBuild parses the major, minor and commit values from Build,
// which is expected in the format [v]major.minor.commit[-dirty]; make build
// links it in from GIT_VERSION (see current.go). Values that do not match
// stay zero; it never panics, since a plain go build reports a module
// version or "devel".
func (v *Info) PopulateFromBuild() {
	build := strings.TrimPrefix(v.Build, "v")
	_, _ = fmt.Sscanf(build, "%d.%d.%d", &v.Major, &v.Minor, &v.Commit)
	_, _ = fmt.Sscanf(build, "%f-", &v.flt)
	v.flt = v.flt*1000000 + float32(v.Commit)
	v.Runtime = runtime.Version()
}

func (v Info) String() string {
	return v.Build
}

// GreaterOrEqual returns true if the version 'v' is the same or new that the supplied parameter 'other'
// This only examines the Major & Minor field (as the SHA in Build provides no ordering indication)
func (v Info) GreaterOrEqual(than Info) bool {
	if v.Major > than.Major {
		return true
	}
	if v.Major < than.Major {
		return false
	}
	return v.Minor >= than.Minor
}

// Float returns the version as one float32 for ordering: Major.Minor
// scaled by 1e6 plus Commit, so v1.2.114 gives 1200114 (the encoding of
// xpki's internal/version). It is lossy (v1.2.x and v1.20.x collide) and
// zero until PopulateFromBuild has parsed Build; nothing in this module
// calls it.
func (v Info) Float() float32 {
	return v.flt
}
