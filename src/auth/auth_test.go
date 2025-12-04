package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// MockRoundTripper implements http.RoundTripper
type MockRoundTripper struct {
	lastRequest *http.Request
}

func (m *MockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	m.lastRequest = req
	return &http.Response{StatusCode: http.StatusOK}, nil
}

func generateToken(expiry time.Time) string {
	claims := jwt.MapClaims{
		"exp": expiry.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Signing key doesn't matter for ParseUnverified
	s, _ := token.SignedString([]byte("secret"))
	return s
}

func TestWithJwt_Renewal(t *testing.T) {
	mockRT := &MockRoundTripper{}

	// 1. Create a token that expires in 30 seconds (needs renewal, since threshold is 1 min)
	oldToken := generateToken(time.Now().Add(30 * time.Second))

	// 2. Create a token that expires in 1 hour (valid)
	newToken := generateToken(time.Now().Add(1 * time.Hour))

	renewalCount := 0
	renewalFunc := func() (string, error) {
		renewalCount++
		return newToken, nil
	}

	// 3. Initialize transport
	// WithJWT returns a struct value. We take the address to use pointer receivers.
	transportVal := WithJWT(mockRT, oldToken, renewalFunc)
	transport := &transportVal

	req, _ := http.NewRequest("GET", "http://example.com", nil)

	// 4. First Request - Should trigger renewal
	_, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}

	if renewalCount != 1 {
		t.Errorf("Expected renewal count 1, got %d", renewalCount)
	}

	authHeader := mockRT.lastRequest.Header.Get("Authorization")
	expectedHeader := "Bearer " + newToken
	if authHeader != expectedHeader {
		t.Errorf("Expected header %s, got %s", expectedHeader, authHeader)
	}

	// Verify internal state (accessible since we are in package auth)
	if transport.jwt != newToken {
		t.Errorf("Transport JWT not updated internally")
	}

	// 5. Second Request - Should NOT trigger renewal
	_, err = transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}

	if renewalCount != 1 {
		t.Errorf("Expected renewal count to remain 1, got %d", renewalCount)
	}

	authHeader = mockRT.lastRequest.Header.Get("Authorization")
	if authHeader != expectedHeader {
		t.Errorf("Expected header %s, got %s", expectedHeader, authHeader)
	}
}
