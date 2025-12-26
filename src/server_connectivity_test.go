/*
server_connectivity_ginkgo_test.go
*/
package server_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/aquaduct-dev/weft/src/auth"
	"github.com/aquaduct-dev/weft/src/proxy"
	"github.com/aquaduct-dev/weft/src/server"
	"github.com/aquaduct-dev/weft/src/tunnel"
	"github.com/aquaduct-dev/weft/types"
	"github.com/aquaduct-dev/weft/wireguard"
)

var _ = Describe("Server Connectivity Checks", func() {
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
	)

	BeforeEach(func() {
		_, cancel = context.WithCancel(context.Background())
		By("creating a test backend http server on a free port")
		backendLn, backendPort = openPort()
		backendSrv = &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
			}),
		}
		go func() { _ = backendSrv.Serve(backendLn) }()
		var remoteLn net.Listener
		remoteLn, remotePort = openPort()
		remoteLn.Close() // we only needed the free port number

		By("finding a free port for the tunnel server")
		var tunnelLn net.Listener
		tunnelLn, controlPort = openPort()
		tunnelLn.Close() // we only needed the free port number
		
		tunnelSrv = server.NewServer(controlPort, "127.0.0.1", "", "", "")
		
		go tunnelSrv.ListenAndServeTLS("", "")

		// Generate a new private key.
		By("generating a WireGuard keypair for the client")
		var err error
		privateKey, err = wireguard.GeneratePrivateKey()
		Expect(err).ToNot(HaveOccurred())

		By("logging in to the test server")
		Eventually(func() error {
			var e error
			token, _, e = auth.GetToken(fmt.Sprintf("127.0.0.1:%d", controlPort), tunnelSrv.ConnectionSecret, "conn-test-tunnel")
			return e
		}).Should(Succeed())
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

	It("removes tunnel when backend is unreachable", func() {
		By("connecting the tunnel")
		w := httptest.NewRecorder()
		r := encodeRequest(types.ConnectRequest{
			ClientPublicKey: privateKey.PublicKey().String(),
			RemotePort:      remotePort,
			Protocol:        "http",
			Hostname:        "conn-test.com",
			TunnelName:      "conn-test-tunnel",
		}, token)

		tunnelSrv.ConnectHandler(w, r)
		connectResp := decodeResponse(w.Body)

		device, err := tunnel.Tunnel("127.0.0.1", &url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", backendPort)}, "conn-test.com", &connectResp, privateKey, proxy.NewProxyManager(), "conn-test-tunnel", nil, nil)
		Expect(err).ToNot(HaveOccurred())
		defer device.Device.Close()

		By("verifying tunnel is listed")
		Eventually(func() bool {
			req := httptest.NewRequest("GET", "http://127.0.0.1/list", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			tunnelSrv.ListHandler(w, req)
			return strings.Contains(w.Body.String(), "conn-test-tunnel")
		}, 5*time.Second, 500*time.Millisecond).Should(BeTrue())

		By("stopping the backend")
		backendSrv.Close()
		backendLn.Close()

		By("waiting for tunnel removal due to connectivity failure")
		// The server checks every 10s. It needs 3 consecutive failures.
		// So roughly 30s. We set timeout to 45s.
		Eventually(func() bool {
			req := httptest.NewRequest("GET", "http://127.0.0.1/list", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			tunnelSrv.ListHandler(w, req)
			// Detailed debug output could help if it fails
			// fmt.Printf("List body: %s\n", w.Body.String())
			return !strings.Contains(w.Body.String(), "conn-test-tunnel")
		}, 60*time.Second, 2*time.Second).Should(BeTrue(), "Tunnel should be removed after backend becomes unreachable")
	})
})
