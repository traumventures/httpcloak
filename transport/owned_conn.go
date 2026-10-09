package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	http "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/protocol"
	"github.com/sardanioss/net/http2"
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
//
// A typical sequence: dial the upstream yourself, HandshakeOwnedTLS, then
// dispatch on the negotiated ALPN — NewH2ClientConn + DoOnH2Conn for "h2",
// DoOnTLSConn for "http/1.1".

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

// ---------------------------------------------------------------------------
// HTTP/2
// ---------------------------------------------------------------------------

// H2ClientConn is an HTTP/2 client over a caller-owned TLS connection. There is
// no pool behind it and no reconnection: when it fails, it stays failed. Obtain
// one with HTTP2Transport.NewClientConnOnConn or Transport.NewH2ClientConn, and
// Close it when done.
type H2ClientConn struct {
	tlsConn *utls.UConn
	h2Conn  *http2.ClientConn
}

// TLSConn returns the underlying TLS connection, for inspection only. Reading
// from or writing to it while the HTTP/2 session is live corrupts the session.
func (c *H2ClientConn) TLSConn() *utls.UConn { return c.tlsConn }

// ClientConn returns the underlying *http2.ClientConn, e.g. to query
// CanTakeNewRequest or State.
func (c *H2ClientConn) ClientConn() *http2.ClientConn { return c.h2Conn }

// Close tears down the HTTP/2 session and the TLS connection under it.
func (c *H2ClientConn) Close() error {
	if c.h2Conn != nil {
		_ = c.h2Conn.Close()
	}
	if c.tlsConn != nil {
		return c.tlsConn.Close()
	}
	return nil
}

// NewClientConnOnConn starts an HTTP/2 session on a TLS connection that has
// completed its handshake with ALPN "h2". The connection preface (SETTINGS
// values and order, WINDOW_UPDATE, priority mode, HPACK policy) comes from the
// same builder as this transport's pooled connections, so an owned connection
// is indistinguishable from a pooled one on the wire.
//
// The returned H2ClientConn takes ownership of tlsConn: close it through
// H2ClientConn.Close. On error tlsConn is left open.
func (t *HTTP2Transport) NewClientConnOnConn(ctx context.Context, tlsConn *utls.UConn) (*H2ClientConn, error) {
	if tlsConn == nil {
		return nil, fmt.Errorf("H2ClientConn: nil TLS connection")
	}
	if proto := tlsConn.ConnectionState().NegotiatedProtocol; proto != "h2" {
		return nil, fmt.Errorf("H2ClientConn: ALPN is %q, want %q", proto, "h2")
	}
	h2Conn, err := t.clientTransport().NewClientConn(tlsConn)
	if err != nil {
		return nil, fmt.Errorf("HTTP/2 setup failed: %w", err)
	}
	return &H2ClientConn{tlsConn: tlsConn, h2Conn: h2Conn}, nil
}

// NewH2ClientConn starts an HTTP/2 session on a caller-owned TLS connection.
// See HTTP2Transport.NewClientConnOnConn.
func (t *Transport) NewH2ClientConn(ctx context.Context, tlsConn *utls.UConn) (*H2ClientConn, error) {
	h2 := t.snapshot().h2
	if h2 == nil {
		return nil, fmt.Errorf("transport: HTTP/2 subsystem not initialised")
	}
	return h2.NewClientConnOnConn(ctx, tlsConn)
}

// DoOnH2Conn runs one request on a caller-owned H2ClientConn and returns the
// buffered response, like Do. Headers are shaped exactly as on the pooled
// path. A failed request is reported, never retried, and the connection is
// left to the caller.
func (t *Transport) DoOnH2Conn(ctx context.Context, req *Request, h2c *H2ClientConn) (*Response, error) {
	if h2c == nil || h2c.h2Conn == nil {
		return nil, fmt.Errorf("transport: DoOnH2Conn called with nil H2ClientConn")
	}
	return t.doOnConn(ctx, req, "h2", h2c.h2Conn.RoundTrip)
}

// ---------------------------------------------------------------------------
// HTTP/1.1
// ---------------------------------------------------------------------------

// Bounds on draining an unread HTTP/1.1 body on Close so the connection can
// carry the next request. Past either bound the connection is closed instead:
// draining an event stream that never ends would block Close forever.
const (
	ownedDrainLimit   = 256 << 10
	ownedDrainTimeout = 2 * time.Second
)

// ErrOwnedConnNotReusable is returned by the Close of an owned HTTP/1.1
// response body (RoundTripOnConn, DoStreamOnTLSConn) when the connection had
// to be closed rather than left at a message boundary: the body could not be
// drained within bounds, or the exchange was interrupted. A nil error from
// Close means the connection can carry the next request.
var ErrOwnedConnNotReusable = errors.New("http1: response body closed before EOF and could not be drained; connection closed")

// RoundTripOnConn performs one HTTP/1.1 exchange on a TLS connection whose
// lifecycle the caller owns. The connection is neither pooled nor closed after
// the response, and a failure is never retried on a new connection.
//
// HTTP/1.1 is not multiplexed: the caller must not start another exchange on
// tlsConn until the returned body is closed. Close leaves the connection at
// the next message boundary when it can: after EOF trivially, otherwise by
// draining a bounded remainder (256 KiB / 2 s). When it cannot, when the
// exchange was interrupted (error, cancelled context), or when the exchange
// ended the connection (Connection: close on either side, a body delimited
// by the peer closing), the connection is closed and Close reports
// ErrOwnedConnNotReusable.
//
// The socket deadline follows the request context: once headers arrive the
// body is bounded by the context's deadline if it has one, and by nothing
// otherwise, so a long-lived stream is not cut by the transport's
// response-header timeout. Cancelling the context interrupts the exchange at
// any point.
func (t *HTTP1Transport) RoundTripOnConn(req *http.Request, tlsConn *utls.UConn, host, port string) (*http.Response, error) {
	t.closedMu.RLock()
	closed := t.closed
	t.closedMu.RUnlock()
	if closed {
		return nil, &TransportError{
			Op:       "roundtrip_on_conn",
			Host:     host,
			Protocol: "h1",
			Cause:    ErrClosed,
			Category: ErrClosed,
		}
	}
	if tlsConn == nil {
		return nil, fmt.Errorf("http1: RoundTripOnConn called with nil TLS connection")
	}

	conn := newHandoffConn(tlsConn, host, port)
	ctx := req.Context()
	stopWatch := watchContext(ctx, conn)
	resp, err := t.doRequest(conn, req)
	if err != nil || ctx.Err() != nil {
		stopWatch()
		// A partly written request or partly read response leaves the
		// connection at an unknown offset; the next exchange on it would
		// misframe. Close it so that fails loudly instead.
		conn.poison()
		if ctxErr := contextError(ctx); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, WrapError("request", host, port, "h1", err)
	}

	// doRequest armed the socket with the response-header timeout. From here
	// the body is bounded by the caller's context only.
	deadline, _ := ctx.Deadline()
	conn.conn.SetDeadline(deadline)

	resp.Body = &ownedBodyWrapper{
		body:      resp.Body,
		conn:      conn,
		stopWatch: stopWatch,
		ctx:       ctx,
		// The exchange ends the connection when either side said so
		// (Connection: close, an HTTP/1.0 peer without keep-alive) or when
		// the body is delimited by the peer closing it: http.ReadResponse
		// sets resp.Close for both. Reusing it would write the next request
		// into a socket the peer is closing, or after a body whose end was
		// the close itself.
		lastExchange: resp.Close || req.Close || headerHasToken(req.Header, "Connection", "close"),
	}
	return resp, nil
}

// ownedBodyWrapper is the body of a RoundTripOnConn response. Close leaves the
// connection open at a message boundary, or closes it when that is impossible.
type ownedBodyWrapper struct {
	body      io.ReadCloser
	conn      *http1Conn
	stopWatch func()
	ctx       context.Context
	eof       atomic.Bool
	once      sync.Once
	closeErr  error

	// lastExchange marks a response after which the connection must not
	// carry another request.
	lastExchange bool
}

func (w *ownedBodyWrapper) Read(p []byte) (int, error) {
	n, err := w.body.Read(p)
	if err == io.EOF {
		w.eof.Store(true)
	} else if err != nil {
		err = translateBodyError(w.ctx, err)
	}
	return n, err
}

func (w *ownedBodyWrapper) Close() error {
	w.once.Do(func() {
		reusable := !w.lastExchange
		if reusable && !w.eof.Load() {
			// Bound the drain in time as well as size. The deadline also
			// unblocks a Read still in flight on another goroutine, which
			// holds the body's lock the drain needs.
			w.conn.conn.SetReadDeadline(time.Now().Add(ownedDrainTimeout))
			n, err := io.CopyN(io.Discard, w.body, ownedDrainLimit+1)
			reusable = err == io.EOF && n <= ownedDrainLimit
		}
		if err := w.body.Close(); err != nil {
			reusable = false
		}
		w.stopWatch()
		if !reusable || w.conn.poisoned.Load() {
			w.conn.poison()
			w.closeErr = ErrOwnedConnNotReusable
			return
		}
		w.conn.conn.SetDeadline(time.Time{})
	})
	return w.closeErr
}

// headerHasToken reports whether the comma-separated header contains token,
// case-insensitively.
func headerHasToken(h http.Header, name, token string) bool {
	for _, v := range h.Values(name) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

// DoOnTLSConn runs one HTTP/1.1 request on a caller-owned TLS connection that
// completed its handshake with ALPN "http/1.1" (or none), and returns the
// buffered response, like Do. Headers are shaped exactly as on the pooled
// path. A failed request is reported, never retried.
//
// The caller must serialize requests on tlsConn; HTTP/1.1 is not multiplexed.
func (t *Transport) DoOnTLSConn(ctx context.Context, req *Request, tlsConn *utls.UConn) (*Response, error) {
	rt, err := t.h1OwnedRoundTripper(req, tlsConn)
	if err != nil {
		return nil, err
	}
	return t.doOnConn(ctx, req, "h1", rt)
}

func (t *Transport) h1OwnedRoundTripper(req *Request, tlsConn *utls.UConn) (func(*http.Request) (*http.Response, error), error) {
	h1 := t.snapshot().h1
	if h1 == nil {
		return nil, fmt.Errorf("transport: HTTP/1.1 subsystem not initialised")
	}
	if tlsConn == nil {
		return nil, fmt.Errorf("transport: nil TLS connection")
	}
	host, port, err := ownedHostPort(req.URL)
	if err != nil {
		return nil, NewRequestError("parse_url", "", "", "h1", err)
	}
	return func(httpReq *http.Request) (*http.Response, error) {
		return h1.RoundTripOnConn(httpReq, tlsConn, host, port)
	}, nil
}

// ---------------------------------------------------------------------------
// Shared request and response handling
// ---------------------------------------------------------------------------

// newOwnedRequest builds the *http.Request for an owned-connection exchange.
// Every step is the one the pooled paths (doHTTP1, doHTTP2, DoStream) take, in
// the same order: preset header block, per-request or session header order,
// client-hint policy, exact-headers mode, then the caller's headers. Any
// difference here would make an owned connection a different client than a
// pooled one.
func (t *Transport) newOwnedRequest(ctx context.Context, snap transportSnapshot, req *Request, proto string) (*http.Request, error) {
	method := req.Method
	if method == "" {
		method = "GET"
	}

	var bodyReader io.Reader
	if req.BodyReader != nil {
		bodyReader = req.BodyReader
	} else if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	} else if method == "POST" || method == "PUT" || method == "PATCH" {
		bodyReader = bytes.NewReader([]byte{})
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, req.URL, bodyReader)
	if err != nil {
		return nil, err
	}
	applyContentLength(httpReq, req)

	effectiveTLSOnly := t.tlsOnly
	if req.TLSOnly != nil {
		effectiveTLSOnly = *req.TLSOnly
	}
	applyPresetHeaders(httpReq, snap.preset, t.effectiveHeaderOrder(req), t.getCustomPseudoOrder(), effectiveTLSOnly, proto, req.Headers, req.DisableClientHints, req.ExactHeaders)
	mergeCallerHeaders(httpReq, req)
	return httpReq, nil
}

// doOnConn is the buffered owned-connection exchange: build the request, run
// it through roundTrip, read and decompress the body.
func (t *Transport) doOnConn(ctx context.Context, req *Request, proto string, roundTrip func(*http.Request) (*http.Response, error)) (*Response, error) {
	snap := t.snapshot()
	startTime := time.Now()
	timing := &protocol.Timing{}

	host, port, err := ownedHostPort(req.URL)
	if err != nil {
		return nil, NewRequestError("parse_url", "", "", proto, err)
	}

	timeout := t.timeout
	if req.Timeout > 0 {
		timeout = req.Timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	httpReq, err := t.newOwnedRequest(ctx, snap, req, proto)
	if err != nil {
		return nil, NewRequestError("create_request", host, port, proto, err)
	}

	reqStart := time.Now()
	resp, err := roundTrip(httpReq)
	if err != nil {
		return nil, WrapError("roundtrip", host, port, proto, err)
	}
	defer resp.Body.Close()
	timing.FirstByte = float64(time.Since(reqStart).Milliseconds())

	body, err := readBodyOptimized(resp.Body, resp.ContentLength)
	if err != nil {
		return nil, NewRequestError("read_body", host, port, proto, err)
	}
	if ce := resp.Header.Get("Content-Encoding"); ce != "" {
		decompressed, err := decompress(body, ce)
		if err != nil {
			return nil, NewRequestError("decompress", host, port, proto, err)
		}
		body = decompressed
	}
	timing.Total = float64(time.Since(startTime).Milliseconds())

	return &Response{
		StatusCode:    resp.StatusCode,
		Headers:       buildHeadersMap(resp.Header),
		HeaderOrder:   responseHeaderOrder(resp.Header),
		HeaderCasing:  takeHeaderCasing(resp.Header),
		Trailer:       buildTrailerMap(resp.Trailer),
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		FinalURL:      req.URL,
		Timing:        timing,
		Protocol:      proto,
		bodyBytes:     body,
		bodyRead:      true,
	}, nil
}

// ownedHostPort extracts host and port for error reporting and the HTTP/1.1
// connection record. Owned connections are TLS, so the default port is 443
// unless the URL says http.
func ownedHostPort(rawURL string) (host, port string, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", err
	}
	host, port = u.Hostname(), u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	return host, port, nil
}
