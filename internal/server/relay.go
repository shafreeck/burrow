package server

import (
	"io"
	"net"
	"sync"
)

// relayDirect relays bytes bidirectionally between client and target.
// Used for Cloudflare edge bypass (and other direct-dial cases) where
// the agent tunnel is not involved.
func (s *Server) relayDirect(client, target net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	// client -> target
	go func() {
		defer wg.Done()
		io.Copy(target, client)
		// Half-close to signal EOF
		if tc, ok := target.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	// target -> client
	go func() {
		defer wg.Done()
		io.Copy(client, target)
		if tc, ok := client.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
	client.Close()
	target.Close()
}
