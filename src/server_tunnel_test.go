/*
server_tunnel_ginkgo_test.go

Ginkgo-style integration test (separate file) that starts a dummy HTTP backend,
runs the server in-process, and uses a simple TCP forwarder to validate tunneling.
*/
package server_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"aquaduct.dev/weft/src/auth"
	"aquaduct.dev/weft/src/proxy"
	"aquaduct.dev/weft/src/server"
	"aquaduct.dev/weft/src/tunnel"
	"aquaduct.dev/weft/types"
	"aquaduct.dev/weft/wireguard"
)

func openPort() (net.Listener, int) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	Expect(err).NotTo(HaveOccurred())
	addr := ln.Addr().String()
	var port int
	fmt.Sscanf(strings.Split(addr, ":")[1], "%d", &port)
	return ln, port
}

func randomBody() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func TestGinkgoSuite(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ServerTunnel Ginkgo Suite")
}

func encodeRequest(req types.ConnectRequest, token string) *http.Request {
	data, err := json.Marshal(req)
	Expect(err).ToNot(HaveOccurred())
	encReq := httptest.NewRequest("POST", "http://127.0.0.1/connect", bytes.NewReader(data))
	encReq.Header.Set("Content-Type", "application/json")
	encReq.Header.Set("Authorization", "Bearer "+token)
	return encReq
}

func decodeResponse(data *bytes.Buffer) types.ConnectResponse {
	fmt.Printf("%s", data.Bytes())
	resp := types.ConnectResponse{}
	err := json.Unmarshal(data.Bytes(), &resp)
	Expect(err).ToNot(HaveOccurred())
	return resp
}

var _ = Describe("ServerTunnel integration (Ginkgo) - separate file", func() {
	var (
		cancel       context.CancelFunc
		backendLn    net.Listener
		backendPort  int
		backendSrv   *http.Server
		tunnelSrv    *server.Server
		controlPort  int
		remotePort   int
		token        string
		privateKey   wgtypes.Key
		expectedBody string
	)

	BeforeEach(func() {
		_, cancel = context.WithCancel(context.Background())
		backendLn, backendPort = openPort()
		backendSrv = &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				expectedBody = randomBody()
				GinkgoWriter.Printf("backend received request %s %s\n", r.Method, r.URL.Path)
				w.Header().Set("X-Test-Body", expectedBody)
				_, _ = w.Write([]byte("backend:" + expectedBody))
			}),
		}
		go func() { _ = backendSrv.Serve(backendLn) }()
		var remoteLn net.Listener
		remoteLn, remotePort = openPort()
		remoteLn.Close() // we only needed the free port number

		var tunnelLn net.Listener
		tunnelLn, controlPort = openPort()
		tunnelLn.Close() // we only needed the free port number
		tunnelSrv = server.NewServer(controlPort, "")
		go tunnelSrv.ListenAndServe()

		// Generate a new private key.
		var err error
		privateKey, err = wireguard.GeneratePrivateKey()
		Expect(err).ToNot(HaveOccurred())

		token, err = auth.Login(fmt.Sprintf("127.0.0.1:%d", controlPort), tunnelSrv.ConnectionSecret, "test-tunnel")
		Expect(err).ToNot(HaveOccurred())
	})

	AfterEach(func() {
		cancel()
		if backendSrv != nil {
			_ = backendSrv.Close()
		}
		if tunnelSrv != nil {
			_ = tunnelSrv.Close()
		}
	})
	It("proxies http > http", func() {

		w := httptest.NewRecorder()
		r := encodeRequest(types.ConnectRequest{
			ClientPublicKey: privateKey.PublicKey().String(),
			RemotePort:      remotePort,
			Protocol:        "http",
			Hostname:        "127.0.0.1",
			Upstream:        fmt.Sprintf("http://127.0.0.1:%d", backendPort),
			TunnelName:      "test-tunnel",
		}, token)

		tunnelSrv.ConnectHandler(w, r)
		connectResp := decodeResponse(w.Body)

		// TODO: Remove extra args
		device, err := tunnel.Tunnel("127.0.0.1", &url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", backendPort)}, &connectResp, privateKey, proxy.NewProxyManager(), "test-tunnel")
		Expect(err).ToNot(HaveOccurred())
		defer device.Device.Close()

		var resp *http.Response
		Eventually(func() error {
			var err error
			resp, err = http.Get(fmt.Sprintf("http://127.0.0.1:%d", remotePort))
			return err
		}).Should(Succeed())

		defer resp.Body.Close()
		//Expect(resp.StatusCode).To(Equal(http.StatusOK))
		body, err := io.ReadAll(resp.Body)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(body)).To(Equal("backend:" + expectedBody))
		Expect(resp.Header.Get("X-Test-Body")).To(Equal(expectedBody))
	})
})
