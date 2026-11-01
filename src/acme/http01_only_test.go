// Tests for HTTP01OnlyTransport: tls-alpn-01 disappears from ACME
// authorizations, and every other response passes through untouched.
package acme

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

const authzWithBoth = `{
  "status": "pending",
  "identifier": {"type": "dns", "value": "rr.example.com"},
  "challenges": [
    {"type": "http-01", "url": "https://ca.test/chal/1", "token": "tokHTTP", "status": "pending"},
    {"type": "dns-01", "url": "https://ca.test/chal/2", "token": "tokDNS", "status": "pending"},
    {"type": "tls-alpn-01", "url": "https://ca.test/chal/3", "token": "tokALPN", "status": "pending"}
  ]
}`

func fetchThrough(t *testing.T, contentType, body string, status int) (*http.Response, []byte) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Replay-Nonce", "nonce-123")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	client := &http.Client{Transport: HTTP01OnlyTransport(nil)}
	resp, err := client.Post(srv.URL, "application/jose+json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, b
}

func TestHTTP01OnlyTransport_RemovesTLSALPN01(t *testing.T) {
	resp, body := fetchThrough(t, "application/json", authzWithBoth, http.StatusOK)

	var authz struct {
		Status     string `json:"status"`
		Identifier struct {
			Value string `json:"value"`
		} `json:"identifier"`
		Challenges []struct {
			Type  string `json:"type"`
			Token string `json:"token"`
		} `json:"challenges"`
	}
	if err := json.Unmarshal(body, &authz); err != nil {
		t.Fatalf("filtered body is not JSON: %v\n%s", err, body)
	}
	var types []string
	for _, c := range authz.Challenges {
		types = append(types, c.Type)
	}
	if len(types) != 2 || types[0] != "http-01" || types[1] != "dns-01" {
		t.Errorf("challenge types = %v, want [http-01 dns-01]", types)
	}
	if authz.Challenges[0].Token != "tokHTTP" {
		t.Errorf("http-01 token = %q, want tokHTTP", authz.Challenges[0].Token)
	}
	if authz.Status != "pending" || authz.Identifier.Value != "rr.example.com" {
		t.Errorf("other fields changed: %+v", authz)
	}
	if resp.ContentLength != int64(len(body)) {
		t.Errorf("ContentLength = %d, body is %d bytes", resp.ContentLength, len(body))
	}
	if resp.Header.Get("Replay-Nonce") != "nonce-123" {
		t.Errorf("Replay-Nonce header lost; the ACME client needs it")
	}
}

func TestHTTP01OnlyTransport_PassesOtherResponsesThrough(t *testing.T) {
	cases := []struct {
		name, contentType, body string
		status                  int
	}{
		{"order without challenges", "application/json", `{"status":"pending","authorizations":["https://ca.test/authz/1"]}`, http.StatusOK},
		{"authz with only http-01", "application/json", `{"challenges":[{"type":"http-01","token":"t"}]}`, http.StatusOK},
		{"certificate chain", "application/pem-certificate-chain", "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n", http.StatusOK},
		{"error problem document", "application/problem+json", `{"type":"urn:ietf:params:acme:error:rateLimited","challenges":[{"type":"tls-alpn-01"}]}`, http.StatusTooManyRequests},
		{"not JSON despite the header", "application/json", "not json", http.StatusOK},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, body := fetchThrough(t, c.contentType, c.body, c.status)
			if string(body) != c.body {
				t.Errorf("body changed:\n got %s\nwant %s", body, c.body)
			}
		})
	}
}

func TestNewHTTP01OnlyClient_LeavesKeyForAutocert(t *testing.T) {
	c := NewHTTP01OnlyClient()
	if c.Key != nil {
		t.Error("Key must stay nil so autocert loads the cached account key")
	}
	if c.DirectoryURL == "" || c.HTTPClient == nil {
		t.Errorf("client not configured: %+v", c)
	}
}
