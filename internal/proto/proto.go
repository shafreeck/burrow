// Package proto defines the WebSocket tunnel protocol between
// burrow-server (public side) and burrow-agent (VM side).
//
// Two frame types:
//   - Text frames: JSON control messages (see Type constants)
//   - Binary frames: stream data, format: [idLen(1)][id][payload]
package proto

// Message types for JSON control frames.
const (
	// Fetch asks the agent to do a single HTTP request via upstream proxy.
	// Response: FetchResult.
	TypeFetch       = "fetch"
	TypeFetchResult = "fetch_result"

	// Connect asks the agent to open a TCP stream to host:port via
	// upstream HTTP CONNECT proxy. Response: ConnectResult.
	// Then both sides exchange binary data frames with the stream ID.
	TypeConnect       = "connect"
	TypeConnectResult = "connect_result"

	// Close terminates a stream. Sent by either side.
	TypeClose = "close"

	// Data carries stream payload as base64 in a text frame.
	// Used instead of binary frames for Cloudflare Tunnel compatibility
	// (Quick Tunnel drops or breaks binary WebSocket frames).
	TypeData = "data"

	// Ping/Pong for keepalive (in addition to WS protocol ping).
	TypePing = "ping"
	TypePong = "pong"

	// Hello is sent by agent right after WS handshake.
	TypeHello    = "hello"
	TypeHelloAck = "hello_ack"
)

// Fetch is a single HTTP request through the tunnel.
type Fetch struct {
	Type    string            `json:"type"` // "fetch"
	ID      string            `json:"id"`
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    []byte            `json:"body,omitempty"`
}

// FetchResult is the agent's response to Fetch.
type FetchResult struct {
	Type    string            `json:"type"` // "fetch_result"
	ID      string            `json:"id"`
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    []byte            `json:"body,omitempty"`
	Error   string            `json:"error,omitempty"`
}

// Connect asks the agent to open a TCP stream.
type Connect struct {
	Type string `json:"type"` // "connect"
	ID   string `json:"id"`   // stream id
	Host string `json:"host"`
	Port int    `json:"port"`
}

// ConnectResult answers a Connect.
type ConnectResult struct {
	Type  string `json:"type"` // "connect_result"
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// Close terminates a stream.
type Close struct {
	Type string `json:"type"` // "close"
	ID   string `json:"id"`
}

// Data carries stream payload. Payload is base64-encoded to travel
// as a WebSocket text frame (Cloudflare Tunnel compatible).
type Data struct {
	Type    string `json:"type"` // "data"
	ID      string `json:"id"`
	Payload string `json:"payload"` // base64
}

// Hello is sent by the agent on connect.
type Hello struct {
	Type    string `json:"type"` // "hello"
	Token   string `json:"token,omitempty"`
	Version string `json:"version"`
}

// HelloAck answers Hello.
type HelloAck struct {
	Type string `json:"type"` // "hello_ack"
	OK   bool   `json:"ok"`
}

// EncodeDataFrame builds a binary data frame: [idLen(1)][id][payload].
func EncodeDataFrame(id string, payload []byte) []byte {
	if len(id) > 255 {
		id = id[:255]
	}
	out := make([]byte, 1+len(id)+len(payload))
	out[0] = byte(len(id))
	copy(out[1:], id)
	copy(out[1+len(id):], payload)
	return out
}

// DecodeDataFrame parses a binary data frame.
func DecodeDataFrame(frame []byte) (id string, payload []byte, ok bool) {
	if len(frame) < 1 {
		return "", nil, false
	}
	idLen := int(frame[0])
	if len(frame) < 1+idLen {
		return "", nil, false
	}
	return string(frame[1 : 1+idLen]), frame[1+idLen:], true
}
