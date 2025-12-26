package types

// ConnectRequest is the request body for the /connect endpoint.
type ConnectRequest struct {
	ClientPublicKey string `json:"client_public_key"`
	RemotePort      int    `json:"remote_port"`
	Protocol        string `json:"protocol"`
	Hostname        string `json:"hostname"`
	// Path prefix to match on the remote side. If set, this prefix will be stripped
	// from the incoming request path before being proxied.
	RemotePath string `json:"remote_path,omitempty"`
	// Query string to match on the remote side.
	RemoteQuery string `json:"remote_query,omitempty"`
	// Fragment to match on the remote side (used for headers/methods).
	RemoteFragment string `json:"remote_fragment,omitempty"`
	// Modifiers to apply to the request (from localURL fragment).
	RemoteModifiers string `json:"remote_modifiers,omitempty"`
	// Optional PEM-encoded certificate and private key. When provided,
	// the server will terminate TLS for the given Hostname using this cert.
	// Certificate should be a PEM-encoded certificate (may contain chain).
	CertificatePEM string `json:"certificate_pem,omitempty"`
	// PrivateKeyPEM should be the PEM-encoded private key matching CertificatePEM.
	PrivateKeyPEM string `json:"private_key_pem,omitempty"`
	// TunnelName is an optional logical identifier for the tunnel. If empty, the client will
	// default it to a sha256(src|dst) so tunnels can be referenced by name on the server.
	TunnelName string `json:"tunnel_name,omitempty"`

	// ProxiedUpstream is the source URL of the tunnel.
	ProxiedUpstream string `json:"proxied_upstream,omitempty"`
}

// ConnectResponse is the response body for the /connect endpoint.
type ConnectResponse struct {
	ServerPublicKey string `json:"server_public_key"`
	ClientAddress   string `json:"client_address"`
	// ServerWGPort is the UDP listen port of the server's WireGuard device (for client endpoint).
	ServerWGPort int `json:"server_wg_port"`
	// TunnelProxyPort is the port on the server that the tunnel proxy was assigned to
	// (for protocols where the server selects a proxy port). For TCP/UDP this matches the
	// port the server will proxy to the client's WireGuard IP.
	TunnelProxyPort int `json:"tunnel_proxy_port"`
}

// HealthcheckRequest is the request body for health checks.
type HealthcheckRequest struct {
	// Optional: A message to include in the health check request.
	Message string `json:"message,omitempty"`
}

// HealthcheckResponse is the response body for health checks.
type HealthcheckResponse struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// TunnelUsage represents the usage statistics for a specific tunnel for reporting.
type TunnelUsage struct {
	TunnelName  string `json:"tunnel_name"`
	InstanceId  string `json:"instance_id"`
	BytesTx     uint64 `json:"bytes_tx"`
	BytesRx     uint64 `json:"bytes_rx"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
}

// UsageReport is a collection of usage statistics for multiple tunnels.
type UsageReport struct {
	Tunnels []TunnelUsage `json:"tunnels"`
}
