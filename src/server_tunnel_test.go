package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"aquaduct.dev/weft/types"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestServerTunnel(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Server Tunnel Suite")
}

// login performs the challenge-response flow to get a JWT token for a given tunnel name.
func login(serverURL *url.URL, tunnelName string) string {
	// 1. Get challenge
	getChallengeURL := serverURL.String() + "/login"
	resp, err := http.Get(getChallengeURL)
	Expect(err).ToNot(HaveOccurred())
	Expect(resp.StatusCode).To(Equal(http.StatusOK))
	encryptedChallenge, err := io.ReadAll(resp.Body)
	Expect(err).ToNot(HaveOccurred())
	resp.Body.Close()

	// 2. Decrypt challenge
	decrypted, err := Decrypt("test-secret", encryptedChallenge)
	Expect(err).ToNot(HaveOccurred())

	// 3. Encrypt response and POST
	challengeResponse, err := Encrypt("test-secret", string(decrypted[len("server-"):]))
	Expect(err).ToNot(HaveOccurred())

	loginReq := map[string]interface{}{
		"challenge":  base64.StdEncoding.EncodeToString(challengeResponse),
		"proxy_name": tunnelName,
	}
	jsonBody, err := json.Marshal(loginReq)
	Expect(err).ToNot(HaveOccurred())

	postChallengeURL := serverURL.String() + "/login"
	resp, err = http.Post(postChallengeURL, "application/json", bytes.NewBuffer(jsonBody))
	Expect(err).ToNot(HaveOccurred())
	Expect(resp.StatusCode).To(Equal(http.StatusOK))

	jwt, err := io.ReadAll(resp.Body)
	Expect(err).ToNot(HaveOccurred())
	resp.Body.Close()

	return string(jwt)
}

var _ = Describe("Server Tunnel Functionality", func() {
	var s *Server
	var serverURL *url.URL
	BeforeEach(func() {
		s = NewServer(0)
		ln, err := net.Listen("tcp", ":0")
		Expect(err).ToNot(HaveOccurred())
		go s.Server.Serve(ln)
		serverURL, err = url.Parse(fmt.Sprintf("http://%s", ln.Addr().String()))
		Expect(err).ToNot(HaveOccurred())
	})
	AfterEach(func() {
		s.Shutdown(context.Background())
	})
	It("proxies TCP", func() {
		// Create an echo server
		upstream, err := net.Listen("tcp", "127.0.0.1:0")
		Expect(err).ToNot(HaveOccurred())
		defer upstream.Close()
		go func() {
			for {
				conn, err := upstream.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					defer c.Close()
					io.Copy(c, c)
				}(conn)
			}
		}()

		// Generate a WireGuard key for the tunnel
		privateKey, err := wgtypes.GeneratePrivateKey()
		Expect(err).ToNot(HaveOccurred())

		tunnelName := "tcp-test-1"
		jwt := login(serverURL, tunnelName)

		req := &types.ConnectRequest{
			ClientPublicKey: privateKey.PublicKey().String(),
			RemotePort:      upstream.Addr().(*net.TCPAddr).Port,
			Protocol:        "tcp",
			TunnelName:      tunnelName,
		}
		// Create a request to the /connect endpoint
		jsonBody, err := json.Marshal(req)
		Expect(err).ToNot(HaveOccurred())
		httpReq, err := http.NewRequest("POST", serverURL.String()+"/connect", bytes.NewBuffer(jsonBody))
		Expect(err).ToNot(HaveOccurred())
		httpReq.Header.Set("Authorization", "Bearer "+jwt)
		httpResp, err := http.DefaultClient.Do(httpReq)
		Expect(err).ToNot(HaveOccurred())
		Expect(httpResp.StatusCode).To(Equal(http.StatusOK))
		// Decode the response
		var resp types.ConnectResponse
		err = json.NewDecoder(httpResp.Body).Decode(&resp)
		Expect(err).ToNot(HaveOccurred())
		// Create a tunnel
		localUrl, err := url.Parse("tcp://localhost:1234")
		Expect(err).ToNot(HaveOccurred())
		p := NewProxyManager()
		tunnel, err := Tunnel("127.0.0.1", localUrl, &resp, privateKey, p, tunnelName)
		Expect(err).ToNot(HaveOccurred())
		Expect(tunnel).ToNot(BeNil())
		// Connect to the tunnel
		conn, err := tunnel.NetStack.Dial("tcp", upstream.Addr().String())
		Expect(err).ToNot(HaveOccurred())
		defer conn.Close()

		// Send data and check the response
		message := "hello"
		_, err = conn.Write([]byte(message))
		Expect(err).ToNot(HaveOccurred())
		buf := make([]byte, len(message))
		_, err = conn.Read(buf)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(buf)).To(Equal(message))
	})
	It("proxies UDP", func() {
		// Generate a WireGuard key for the tunnel
		privateKey, err := wgtypes.GeneratePrivateKey()
		Expect(err).ToNot(HaveOccurred())

		// Create a UDP echo server
		udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
		Expect(err).ToNot(HaveOccurred())
		udpConn, err := net.ListenUDP("udp", udpAddr)
		Expect(err).ToNot(HaveOccurred())
		defer udpConn.Close()
		go func() {
			buf := make([]byte, 1024)
			for {
				n, addr, err := udpConn.ReadFrom(buf)
				if err != nil {
					return
				}
				udpConn.WriteTo(buf[:n], addr)
			}
		}()

		tunnelName := "udp-test-1"
		jwt := login(serverURL, tunnelName)

		// Create a request to the /connect endpoint
		udpReq := &types.ConnectRequest{
			ClientPublicKey: privateKey.PublicKey().String(),
			RemotePort:      udpConn.LocalAddr().(*net.UDPAddr).Port,
			Protocol:        "udp",
			TunnelName:      tunnelName,
		}
		jsonBody, err := json.Marshal(udpReq)
		Expect(err).ToNot(HaveOccurred())
		httpReq, err := http.NewRequest("POST", serverURL.String()+"/connect", bytes.NewBuffer(jsonBody))
		Expect(err).ToNot(HaveOccurred())
		httpReq.Header.Set("Authorization", "Bearer "+jwt)

		// Make the request
		httpResp, err := http.DefaultClient.Do(httpReq)
		Expect(err).ToNot(HaveOccurred())
		// Decode the response
		var resp types.ConnectResponse
		err = json.NewDecoder(httpResp.Body).Decode(&resp)
		Expect(err).ToNot(HaveOccurred())
		GinkgoT().Logf("Client received ConnectResponse: %+v", resp)

		// Create a tunnel
		localUrl, err := url.Parse("udp://localhost:1234")
		Expect(err).ToNot(HaveOccurred())
		p := NewProxyManager()
		tunnel, err := Tunnel("127.0.0.1", localUrl, &resp, privateKey, p, tunnelName)
		Expect(err).ToNot(HaveOccurred())
		Expect(tunnel).ToNot(BeNil())
		// Test UDP proxy functionality
		clientConn, err := tunnel.NetStack.Dial("udp", udpConn.LocalAddr().String())
		Expect(err).ToNot(HaveOccurred())
		defer clientConn.Close()
		message := "Hello UDP Proxy"
		_, err = clientConn.Write([]byte(message))
		Expect(err).ToNot(HaveOccurred())
		response := make([]byte, 1024)
		n, err := clientConn.Read(response)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(response[:n])).To(Equal(message))
	})
	It("proxies HTTP", func() {
		// Generate a WireGuard key for the tunnel
		privateKey, err := wgtypes.GeneratePrivateKey()
		Expect(err).ToNot(HaveOccurred())

		// Create an HTTP server
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "upstream-body")
		}))
		defer up.Close()

		tunnelName := "http-test-1"
		jwt := login(serverURL, tunnelName)

		// Create a request to the /connect endpoint
		createReq := &types.ConnectRequest{
			ClientPublicKey: privateKey.PublicKey().String(),
			Protocol:        "http",
			Hostname:        "test.local",
			Upstream:        up.URL,
			TunnelName:      tunnelName,
		}
		jsonBody, err := json.Marshal(createReq)
		Expect(err).ToNot(HaveOccurred())
		httpReq, err := http.NewRequest("POST", serverURL.String()+"/connect", bytes.NewBuffer(jsonBody))
		Expect(err).ToNot(HaveOccurred())
		httpReq.Header.Set("Authorization", "Bearer "+jwt)
		// Make the request
		httpResp, err := http.DefaultClient.Do(httpReq)
		Expect(err).ToNot(HaveOccurred())
		Expect(httpResp.StatusCode).To(Equal(http.StatusOK))

		// Decode the response
		var resp types.ConnectResponse
		err = json.NewDecoder(httpResp.Body).Decode(&resp)
		// Create a tunnel
		p := NewProxyManager()
		localUrl, err := url.Parse(createReq.Upstream)
		Expect(err).ToNot(HaveOccurred())
		tunnel, err := Tunnel("127.0.0.1", localUrl, &resp, privateKey, p, tunnelName)
		Expect(err).ToNot(HaveOccurred())
		Expect(tunnel).ToNot(BeNil())
		// Make a request through the tunnel
		client := &http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
					return tunnel.NetStack.Dial("tcp", addr)
				},
			},
		}
		// Attempt to request the server through the tunnel
		preq, err := http.NewRequest("GET", "http://127.0.0.1:80", nil)
		Expect(err).ToNot(HaveOccurred())
		preq.Host = "test.local"
		httpResp2, err := client.Do(preq)
		Expect(err).ToNot(HaveOccurred())
		defer httpResp2.Body.Close()
		body, err := io.ReadAll(httpResp2.Body)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(body)).To(Equal("upstream-body"))
	})
	// This test registers TLS termination in the VHostProxy and mounts a TLS listener
	// that proxies to an upstream httptest server (device is nil in tests).
	It("proxies HTTPS", func() {
		// Generate a WireGuard key for the tunnel
		privateKey, err := wgtypes.GeneratePrivateKey()
		Expect(err).ToNot(HaveOccurred())

		// Create a local test HTTP server
		up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "hello-secure")
		}))
		defer up.Close()

		// Generate TLS certificate
		certPEM, keyPEM, err := GenerateCert("secure.test")
		Expect(err).ToNot(HaveOccurred())

		tunnelName := "https-test-1"
		jwt := login(serverURL, tunnelName)

		// Create a connect request
		connectReq := &types.ConnectRequest{
			ClientPublicKey: privateKey.PublicKey().String(),
			Protocol:        "https",
			Hostname:        "secure.test",
			Upstream:        up.URL,
			CertificatePEM:  string(certPEM),
			PrivateKeyPEM:   string(keyPEM),
			TunnelName:      tunnelName,
		}
		// Create a request to the /connect endpoint
		jsonBody, err := json.Marshal(connectReq)
		Expect(err).ToNot(HaveOccurred())
		httpReq, err := http.NewRequest("POST", serverURL.String()+"/connect", bytes.NewBuffer(jsonBody))
		Expect(err).ToNot(HaveOccurred())
		httpReq.Header.Set("Authorization", "Bearer "+jwt)
		// Make the request
		httpResp, err := http.DefaultClient.Do(httpReq)
		Expect(err).ToNot(HaveOccurred())
		Expect(httpResp.StatusCode).To(Equal(http.StatusOK))
		// Decode the response
		var resp types.ConnectResponse
		err = json.NewDecoder(httpResp.Body).Decode(&resp)
		Expect(err).ToNot(HaveOccurred())

		// Create a tunnel
		p := NewProxyManager()
		localUrl, err := url.Parse(connectReq.Upstream)
		Expect(err).ToNot(HaveOccurred())
		tunnel, err := Tunnel("127.0.0.1", localUrl, &resp, privateKey, p, tunnelName)
		Expect(err).ToNot(HaveOccurred())
		Expect(tunnel).ToNot(BeNil())
		// Make an HTTPS request through the tunnel
		client := &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return tunnel.NetStack.Dial(network, addr)
				},
				// Since the server is using a self-signed cert for the vhost, we need to skip verification.
				// The ServerName must match the cert's CN.
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					ServerName:         "secure.test",
				},
			},
		}
		httpResp2, err := client.Get("https://127.0.0.1:443")
		Expect(err).ToNot(HaveOccurred())
		defer httpResp2.Body.Close()
		body, err := io.ReadAll(httpResp2.Body)
		Expect(err).ToNot(HaveOccurred())
		Expect(string(body)).To(Equal("hello-secure"))
	})
})
