/*
server_eviction_repro_test.go

Reproduces the lab0 tunnel crash-loop kill chain at the weft layer.

In production the bastion's WireGuard data path to a client breaks (the server
never learns the client's endpoint, so dials to 10.1.0.x time out). The F-9
WGAwareRoundTripper cleanup then *removes the peer* after a few failed dials.
The damage that turns a transient data-path hiccup into a permanent crash loop
is entirely weft-controlled and is what this test pins down:

 1. once the server has removed (evicted) a peer, its /healthcheck returns 404
    ("Proxy not found"); and
 2. the client's HealthMonitor classifies that 404 as a *permanent* failure and
    fires OnFatal — i.e. the tunnel process exits instead of re-registering,
    which under Kubernetes becomes CrashLoopBackOff.

The underlying WG packet-loss trigger is environmental and not reproducible in a
loopback test (see server_tunnel_test.go: the happy-path data flow passes). This
test deliberately injects the eviction via Server.RemoveTunnel — exactly the
call F-9 cleanup makes — and then exercises the real client HealthMonitor.
*/
package server_test

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/aquaduct-dev/weft/src/auth"
	"github.com/aquaduct-dev/weft/src/client"
	"github.com/aquaduct-dev/weft/src/server"
	"github.com/aquaduct-dev/weft/types"
	"github.com/aquaduct-dev/weft/wireguard"
)

var _ = Describe("Tunnel crash-loop kill chain (eviction -> 404 -> fatal)", func() {
	const tunnelName = "repro-evicted-tunnel"

	var (
		tunnelSrv   *server.Server
		controlPort int
		remotePort  int
		token       string
		authed      *http.Client
		healthURL   string
		privateKey  wgtypes.Key
	)

	BeforeEach(func() {
		By("starting a tunnel server on a free port")
		var ln net.Listener
		ln, controlPort = openPort()
		ln.Close()

		var remoteLn net.Listener
		remoteLn, remotePort = openPort()
		remoteLn.Close()

		tunnelSrv = server.NewServer(controlPort, "127.0.0.1", "", "", "")
		go tunnelSrv.ListenAndServeTLS("", "")

		var err error
		privateKey, err = wireguard.GeneratePrivateKey()
		Expect(err).ToNot(HaveOccurred())

		addr := fmt.Sprintf("127.0.0.1:%d", controlPort)
		healthURL = fmt.Sprintf("https://%s/healthcheck", addr)

		By("logging in (token for /connect, authed client for the HealthMonitor)")
		Eventually(func() error {
			var e error
			token, _, e = auth.GetToken(addr, tunnelSrv.ConnectionSecret, tunnelName)
			return e
		}).Should(Succeed())
		Eventually(func() error {
			var e error
			authed, e = auth.Login(addr, tunnelSrv.ConnectionSecret, tunnelName)
			return e
		}).Should(Succeed())
	})

	AfterEach(func() {
		if tunnelSrv != nil {
			_ = tunnelSrv.Close()
		}
	})

	// postHealthcheck performs the same POST /healthcheck the client makes and
	// returns the HTTP status code.
	postHealthcheck := func() int {
		resp, err := authed.Post(healthURL, "application/json", nil)
		if err != nil {
			return -1
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	It("evicting a peer 404s its healthcheck and makes the client HealthMonitor fatal", func() {
		By("registering the tunnel via /connect")
		w := httptest.NewRecorder()
		r := encodeRequest(types.ConnectRequest{
			ClientPublicKey: privateKey.PublicKey().String(),
			RemotePort:      remotePort,
			Protocol:        "http",
			Hostname:        "repro.com",
			TunnelName:      tunnelName,
		}, token)
		tunnelSrv.Handler.ServeHTTP(w, r)
		Expect(w.Code).To(Equal(http.StatusOK), "expected /connect to register the peer")

		By("sanity: a healthcheck for a live peer returns 200")
		Eventually(postHealthcheck, 5*time.Second, 200*time.Millisecond).Should(Equal(http.StatusOK))

		By("injecting the eviction F-9 cleanup performs on repeated WG dial failure")
		tunnelSrv.RemoveTunnel(tunnelName)

		By("server-side half: the evicted peer's healthcheck now 404s")
		Eventually(postHealthcheck, 5*time.Second, 200*time.Millisecond).Should(Equal(http.StatusNotFound))

		By("client-side half: the real HealthMonitor treats that 404 as fatal")
		fatal := make(chan string, 1)
		mon := client.NewHealthMonitor(client.HealthMonitorConfig{
			Client:       authed,
			HealthURL:    healthURL,
			TunnelName:   tunnelName,
			MaxRetries:   3,
			BaseInterval: 50 * time.Millisecond,
			OnFatal: func(reason string) {
				select {
				case fatal <- reason:
				default:
				}
			},
		})
		go mon.Start()
		defer mon.Stop()

		var reason string
		Eventually(fatal, 5*time.Second).Should(Receive(&reason),
			"a single 404 should make the tunnel exit (this is the crash-loop trigger)")
		Expect(reason).To(ContainSubstring("404"))
	})
})
