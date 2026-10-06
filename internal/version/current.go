package version

import (
	"runtime"
	"runtime/debug"
)

// build is the build version, "[v]major.minor.commit[-dirty]", set by the
// linker:
//
//	go build -ldflags "-X github.com/effective-security/kubeca/internal/version.build=v0.7.123"
//
// make build passes GIT_VERSION (.VERSION, the commit count and a dirty
// suffix). Without it, the version comes from the module build information
// (see buildVersion).
var build string

var currentVersion = Info{
	Runtime: runtime.Version(),
}

func init() {
	info, ok := debug.ReadBuildInfo()
	currentVersion.Build = buildVersion(build, info, ok)
	currentVersion.PopulateFromBuild()
}

// Current returns the current version [set by the build]
func Current() Info {
	return currentVersion
}

// develVersion is the version of a binary built without a build version,
// module version or VCS information.
const develVersion = "devel"

// vcsRevisionLength is the number of revision characters kept in a devel
// version.
const vcsRevisionLength = 12

// buildVersion returns the version of the running binary: build when the
// linker set it; otherwise the main module version recorded by the go
// command, which is the requested version of a `go install ...@version` and
// the tag or pseudo-version of a `go build` in a checkout (with "+dirty" when
// modified); otherwise "devel-<revision>[-dirty]" from the VCS settings, or
// "devel" when there are none.
func buildVersion(build string, info *debug.BuildInfo, ok bool) string {
	if build != "" {
		return build
	}
	if !ok || info == nil {
		return develVersion
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	var revision, dirty string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "-dirty"
			}
		}
	}
	if revision == "" {
		return develVersion
	}
	if len(revision) > vcsRevisionLength {
		revision = revision[:vcsRevisionLength]
	}
	return develVersion + "-" + revision + dirty
}
