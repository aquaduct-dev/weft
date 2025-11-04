package types

// ConnectRequest is the request body for the /connect endpoint.
type ConnectRequest struct {
	ClientPublicKey string `json:"client_public_key"`
	RemotePort      int    `json:"remote_port"`
	Protocol        string `json:"protocol"`
	Hostname        string `json:"hostname"`
	// Optional PEM-encoded certificate and private key. When provided,
	// the server will terminate TLS for the given Hostname using this cert.
	// Certificate should be a PEM-encoded certificate (may contain chain).
	CertificatePEM string `json:"certificate_pem,omitempty"`
	// PrivateKeyPEM should be the PEM-encoded private key matching CertificatePEM.
	PrivateKeyPEM string `json:"private_key_pem,omitempty"`
	// TunnelName is an optional logical identifier for the tunnel. If empty, the client will
	// default it to a sha256(src|dst) so tunnels can be referenced by name on the server.
	TunnelName string `json:"tunnel_name,omitempty"`
	// Upstream is the target URL for vhost proxying.
	Upstream string `json:"upstream,omitempty"`
}

// ConnectResponse is the response body for the /connect endpoint.
type ConnectResponse struct {
	ServerPublicKey string `json:"server_public_key"`
	ClientAddress   string `json:"client_address"`
	ServerPort      int    `json:"server_port"`
}
