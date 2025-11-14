// server_tunnel_suite_test.go
// Ginkgo suite bootstrap for server_tunnel_ginkgo_test.go.
// This file provides the standard Go test entrypoint so the Ginkgo Describe blocks
// in server_tunnel_test.go are executed by `go test` / Bazel test rules.
//
// It registers Gomega's fail handler and calls RunSpecs from Ginkgo v2.
package server_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestServerTunnel(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Server + Tunnel Suite")
}
