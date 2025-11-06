package server

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"testing"

	. "github.com/onsi/gomega"
)

func TestTunnelTCPProxy(t *testing.T) {

	RegisterFailHandler(func(message string, callerSkip ...int) {

		t.Helper()

		t.Fatal(message)

	})

	// Create a mock TCP server

	mockServer, err := net.Listen("tcp", "127.0.0.1:0")

	Expect(err).ToNot(HaveOccurred())

	defer mockServer.Close()

	go func() {

		for {

			conn, err := mockServer.Accept()

			if err != nil {

				return

			}

			go func(c net.Conn) {

				defer c.Close()

				io.Copy(c, c)

			}(conn)

		}

	}()

	// Create a tunnel proxy

	localURL, err := url.Parse(fmt.Sprintf("tcp://%s", mockServer.Addr().String()))

	Expect(err).ToNot(HaveOccurred())

	remoteURL, err := url.Parse("tcp://127.0.0.1:0")

	Expect(err).ToNot(HaveOccurred())

	ln, err := net.Listen("tcp", remoteURL.Host)

	Expect(err).ToNot(HaveOccurred())

	defer ln.Close()

	go func() {

		for {

			conn, err := ln.Accept()

			if err != nil {

				return

			}

			go ProxyTCP(conn, localURL.Host)

		}

	}()

	// Connect to the tunnel proxy

	conn, err := net.Dial("tcp", ln.Addr().String())

	Expect(err).ToNot(HaveOccurred())

	defer conn.Close()

	// Send data to the tunnel proxy

	message := "hello"

	_, err = conn.Write([]byte(message))

	Expect(err).ToNot(HaveOccurred())

	// Assert that the mock TCP server received the data

	buf := make([]byte, len(message))

	_, err = conn.Read(buf)

	Expect(err).ToNot(HaveOccurred())

	Expect(string(buf)).To(Equal(message))

}
