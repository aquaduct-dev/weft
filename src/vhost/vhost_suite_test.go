package vhost_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestVhost(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Vhost Suite")
}
