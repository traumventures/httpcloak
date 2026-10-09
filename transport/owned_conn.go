package transport

import (
	"context"
	"fmt"
	"net"

	utls "github.com/sardanioss/utls"
)

// Owned-connection API.
//
// These entry points run requests on connections whose lifecycle the caller
// owns, bypassing the transport's pool, its silent reconnects and its retries.
// The preset's TLS ClientHello, HTTP/2 framing and header shaping still apply,
// through the same builders the pooled paths use; only connection management
// changes.
//
// The use case is a forwarding proxy that binds one upstream connection to one
// client tunnel. Its upstream hop usually goes through a residential proxy
// whose sticky session is chosen per CONNECT, so a pool that quietly re-dials a
// dead connection moves the flow to a different exit IP mid-session, and a
// retry on a fresh connection replays a request on someone else's behalf.
// Owning the connection makes both impossible by construction: when it fails,
// the caller sees the failure and decides.

// HandshakeOwnedTLS performs the TLS handshake on a caller-dialled connection
// with the same ClientHello this transport presents on its own connections,
// including WithCustomFingerprint JA3 overrides. See
// HTTP2Transport.HandshakeOnConn.
func (t *Transport) HandshakeOwnedTLS(ctx context.Context, rawConn net.Conn, serverName string, echConfigList []byte) (*utls.UConn, error) {
	h2 := t.snapshot().h2
	if h2 == nil {
		return nil, fmt.Errorf("transport: HTTP/2 subsystem not initialised")
	}
	return h2.HandshakeOnConn(ctx, rawConn, serverName, echConfigList)
}
