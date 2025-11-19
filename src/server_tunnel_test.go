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
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"aquaduct.dev/weft/src/auth"
	aqcrypto "aquaduct.dev/weft/src/crypto"
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

func encodeRequest(req types.ConnectRequest, token string) *http.Request {
	data, err := json.Marshal(req)
	Expect(err).ToNot(HaveOccurred())
	encReq := httptest.NewRequest("POST", "http://127.0.0.1/connect", bytes.NewReader(data))
	encReq.Header.Set("Content-Type", "application/json")
	encReq.Header.Set("Authorization", "Bearer "+token)
	return encReq
}

func decodeResponse(data *bytes.Buffer) types.ConnectResponse {
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
		By("creating a test backend http server on a free port")
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

		By("finding a free port for the tunnel server")
		var tunnelLn net.Listener
		tunnelLn, controlPort = openPort()
		tunnelLn.Close() // we only needed the free port number
		tunnelSrv = server.NewServer(controlPort, "127.0.0.1", "", "")
		go tunnelSrv.ListenAndServeTLS("", "")

		// Generate a new private key.
		By("generating a WireGuard keypair for the client")
		var err error
		privateKey, err = wireguard.GeneratePrivateKey()
		Expect(err).ToNot(HaveOccurred())

		By("logging in to the test server")
		// Server may not be immediately ready to accept connections after ListenAndServe is started.
		// Use Gomega's Eventually to retry auth.Login until it succeeds to avoid a race where
		// the test attempts to contact /login before the server is listening.
		Eventually(func() error {
			var e error
			token, e = auth.GetToken(fmt.Sprintf("127.0.0.1:%d", controlPort), tunnelSrv.ConnectionSecret, "test-tunnel")
			return e
		}).Should(Succeed(), "auth.Login should eventually succeed once server is accepting connections")
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
	It("tunnels http>http", func() {

		w := httptest.NewRecorder()
		r := encodeRequest(types.ConnectRequest{
			ClientPublicKey: privateKey.PublicKey().String(),
			RemotePort:      remotePort,
			Protocol:        "http",
			Hostname:        "test.com",
			TunnelName:      "test-tunnel",
		}, token)

		tunnelSrv.ConnectHandler(w, r)
		connectResp := decodeResponse(w.Body)

		// TODO: Remove extra args
		device, err := tunnel.Tunnel("127.0.0.1", &url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", backendPort)}, &connectResp, privateKey, proxy.NewProxyManager(), "test-tunnel", nil, nil)
		Expect(err).ToNot(HaveOccurred())
		defer device.Device.Close()

		var resp *http.Response
		By("reading HTTP data from the server")
		Eventually(func() error {
			var err error
			// Use https scheme when connecting to the remote forwarded port so the client performs TLS.
			req, err := http.NewRequest("GET", fmt.Sprintf("http://test.com:%d", remotePort), nil)
			if err != nil {
				return err
			}
			//req.Header.Set("Host", "test.com")
			transport := http.DefaultTransport.(*http.Transport).Clone()
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				if addr == fmt.Sprintf("test.com:%d", remotePort) {
					addr = fmt.Sprintf("127.0.0.1:%d", remotePort)
				}
				return net.Dial(network, addr)
			}
			client := http.Client{
				Transport: transport,
			}
			resp, err = (&client).Do(req)
			if err != nil {
				return err
			}
			if resp.StatusCode != 200 {
				return errors.New("invalid response code")
			}
			return nil
		}).Should(Succeed())

		defer resp.Body.Close()
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
		body, err := io.ReadAll(resp.Body)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(body)).To(Equal("backend:" + expectedBody))
		Expect(resp.Header.Get("X-Test-Body")).To(Equal(expectedBody))
	})
	It("tunnels http>https", func() {
		// Prepare connect request for http->https tunnel. Upstream uses https.
		By("requesting a new tunnel from the server")
		w := httptest.NewRecorder()
		certPem, keyPem, err := aqcrypto.GenerateCert("test.com", []string{})
		Expect(err).ToNot(HaveOccurred())
		r := encodeRequest(types.ConnectRequest{
			ClientPublicKey: privateKey.PublicKey().String(),
			RemotePort:      remotePort,
			Protocol:        "https",
			Hostname:        "test.com",
			TunnelName:      "test-tunnel",
			CertificatePEM:  string(certPem),
			PrivateKeyPEM:   string(keyPem),
		}, token)

		tunnelSrv.ConnectHandler(w, r)
		connectResp := decodeResponse(w.Body)

		// Create tunnel device; pass upstream URL so the tunnel knows it's https.
		By("connecting to the tunnel from the server")
		device, err := tunnel.Tunnel("127.0.0.1", &url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", backendPort)}, &connectResp, privateKey, proxy.NewProxyManager(), "test-tunnel", certPem, keyPem)
		Expect(err).ToNot(HaveOccurred())
		defer device.Device.Close()

		// HTTPS client to talk to the remote port (https) — the tunnel should forward to upstream https.
		By("reading HTTPS data from the server")
		var resp *http.Response
		Eventually(func() error {
			var err error
			// Use https scheme when connecting to the remote forwarded port so the client performs TLS.
			req, err := http.NewRequest("GET", fmt.Sprintf("https://test.com:%d", remotePort), nil)
			if err != nil {
				return err
			}
			//req.Header.Set("Host", "test.com")
			transport := http.DefaultTransport.(*http.Transport).Clone()
			transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				if addr == fmt.Sprintf("test.com:%d", remotePort) {
					addr = fmt.Sprintf("127.0.0.1:%d", remotePort)
				}
				return net.Dial(network, addr)
			}
			client := http.Client{
				Transport: transport,
			}
			resp, err = (&client).Do(req)
			if err != nil {
				return err
			}
			if resp.StatusCode != 200 {
				return errors.New("invalid response code")
			}
			return nil
		}).Should(Succeed())

		defer resp.Body.Close()
		Expect(resp.StatusCode).To(Equal(http.StatusOK))
		body, err := io.ReadAll(resp.Body)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(body)).To(Equal("backend:" + expectedBody))
		Expect(resp.Header.Get("X-Test-Body")).To(Equal(expectedBody))
	})

	It("tunnels tcp>tcp", func() {
		// Start a simple TCP backend that echoes a random body.
		var (
			echoLn   net.Listener
			echoPort int
		)
		echoLn, echoPort = openPort()
		defer echoLn.Close()

		// Accept a single connection and respond with a header and body.
		go func() {
			conn, err := echoLn.Accept()
			if err != nil {
				GinkgoWriter.Printf("echo backend accept error: %v\n", err)
				return
			}
			defer conn.Close()
			body := randomBody()
			GinkgoWriter.Printf("echo backend got connection, writing body %s\n", body)
			_, _ = conn.Write([]byte("ECHO:" + body))
		}()

		// Prepare connect request for tcp tunnel.
		w := httptest.NewRecorder()
		r := encodeRequest(types.ConnectRequest{
			ClientPublicKey: privateKey.PublicKey().String(),
			RemotePort:      remotePort,
			Protocol:        "tcp",
			Hostname:        "127.0.0.1",
			TunnelName:      "test-tunnel",
		}, token)

		tunnelSrv.ConnectHandler(w, r)
		connectResp := decodeResponse(w.Body)

		device, err := tunnel.Tunnel("127.0.0.1", &url.URL{Scheme: "tcp", Host: fmt.Sprintf("127.0.0.1:%d", echoPort)}, &connectResp, privateKey, proxy.NewProxyManager(), "test-tunnel", nil, nil)
		Expect(err).ToNot(HaveOccurred())
		defer device.Device.Close()

		// Try to connect to the remote port and read the echoed body.
		var conn net.Conn
		Eventually(func() error {
			var err error
			conn, err = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", remotePort))
			return err
		}).Should(Succeed())
		defer conn.Close()

		buf := make([]byte, 1024)
		n, err := io.ReadFull(conn, buf[:6]) // read the "ECHO:" prefix first
		if err != nil && err != io.ErrUnexpectedEOF {
			Fail(fmt.Sprintf("failed to read from tcp connection: %v", err))
		}
		// read the rest (up to remaining bytes)
		rest := make([]byte, 1024)
		m, _ := conn.Read(rest)
		data := string(buf[:n]) + string(rest[:m])
		Expect(strings.HasPrefix(data, "ECHO:")).To(BeTrue())
	})

	It("reports usage on tunnel shutdown", func() {
		usageChan := make(chan string, 1)
		usageServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			usageChan <- string(body)
			w.WriteHeader(200)
		}))
		defer usageServer.Close()

		// Close the existing server from BeforeEach
		tunnelSrv.Close()

		// Start new server with usage reporting
		tunnelSrv = server.NewServer(controlPort, "127.0.0.1", "", usageServer.URL)
		go tunnelSrv.ListenAndServeTLS("", "")

		// Login again
		Eventually(func() error {
			var e error
			token, e = auth.GetToken(fmt.Sprintf("127.0.0.1:%d", controlPort), tunnelSrv.ConnectionSecret, "test-tunnel-usage")
			return e
		}).Should(Succeed())

		// Connect tunnel
		w := httptest.NewRecorder()
		r := encodeRequest(types.ConnectRequest{
			ClientPublicKey: privateKey.PublicKey().String(),
			RemotePort:      remotePort,
			Protocol:        "tcp",
			Hostname:        "127.0.0.1",
			TunnelName:      "test-tunnel-usage",
		}, token)
		tunnelSrv.ConnectHandler(w, r)
		connectResp := decodeResponse(w.Body)

		device, err := tunnel.Tunnel("127.0.0.1", &url.URL{Scheme: "tcp", Host: fmt.Sprintf("127.0.0.1:%d", backendPort)}, &connectResp, privateKey, proxy.NewProxyManager(), "test-tunnel-usage", nil, nil)
		Expect(err).ToNot(HaveOccurred())
		defer device.Device.Close()

		// Send some traffic
		var conn net.Conn
		Eventually(func() error {
			var err error
			conn, err = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", remotePort))
			return err
		}).Should(Succeed())
		_, err = conn.Write([]byte("hello"))
		Expect(err).ToNot(HaveOccurred())
		conn.Close()

		// Trigger shutdown via /shutdown endpoint
		req := httptest.NewRequest("POST", "http://127.0.0.1/shutdown", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		wShutdown := httptest.NewRecorder()
		tunnelSrv.ShutdownHandler(wShutdown, req)

		Expect(wShutdown.Result().StatusCode).To(Equal(200))

		// Verify usage report
		Eventually(usageChan).Should(Receive(ContainSubstring("test-tunnel-usage")))
	})

})
