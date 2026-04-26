// Package version exposes build-stamped identifiers for the running binary.
//
// Commit and CommitDate are populated at link time by Bazel x_defs (see
// BUILD.bazel) using values produced by scripts/workspace_status.sh. Builds
// that skip stamping (e.g. plain `go build`, or `bazel build --nostamp`) leave
// the defaults in place.
package version

var (
	Commit     = "unknown"
	CommitDate = "unknown"
)
