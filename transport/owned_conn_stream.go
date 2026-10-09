package transport

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	http "github.com/sardanioss/http"
	"github.com/sardanioss/httpcloak/protocol"
	utls "github.com/sardanioss/utls"
)

// Streaming variants of DoOnH2Conn / DoOnTLSConn.
//
// The buffered variants read the whole body before returning, which a
// forwarding proxy cannot use: server-sent events, long-poll and chunked
// progress responses only arrive once the origin ends the stream (for an event
// stream, never), and every large download is held in memory in full. These
// return as soon as the response headers are in and hand back a live body.
//
// Two contract differences from the buffered path:
//
//   - The timeout (Request.Timeout, else the transport's) bounds the wait for
//     response headers only, as in DoStream. Once headers arrive the stream sets
//     its own pace; a caller that wants a total cap puts it on ctx.
//   - The caller owns the body and must Close it. Closing cancels the exchange.
//     On HTTP/1.1 the connection carries nothing else until then.
//
// Response.ContentLength tells the caller how to frame what it reads: the
// origin's length when the body passes through as-is, -1 when it is chunked
// or decoded on the fly (gzip, br, deflate, zstd).

// DoStreamOnH2Conn is DoOnH2Conn with a live response body.
func (t *Transport) DoStreamOnH2Conn(ctx context.Context, req *Request, h2c *H2ClientConn) (*Response, error) {
	if h2c == nil || h2c.h2Conn == nil {
		return nil, fmt.Errorf("transport: DoStreamOnH2Conn called with nil H2ClientConn")
	}
	return t.doStreamOnConn(ctx, req, "h2", h2c.h2Conn.RoundTrip)
}

// DoStreamOnTLSConn is DoOnTLSConn with a live response body. The caller must
// not start another exchange on tlsConn until the body is closed: HTTP/1.1 has
// no multiplexing, so a second request written while this body is still on the
// wire corrupts the framing of both. See HTTP1Transport.RoundTripOnConn for
// what Close does to the connection.
func (t *Transport) DoStreamOnTLSConn(ctx context.Context, req *Request, tlsConn *utls.UConn) (*Response, error) {
	rt, err := t.h1OwnedRoundTripper(req, tlsConn)
	if err != nil {
		return nil, err
	}
	return t.doStreamOnConn(ctx, req, "h1", rt)
}

// doStreamOnConn is the streaming twin of doOnConn. Request construction is
// shared (newOwnedRequest); only the response handling differs.
func (t *Transport) doStreamOnConn(ctx context.Context, req *Request, proto string, roundTrip func(*http.Request) (*http.Response, error)) (*Response, error) {
	snap := t.snapshot()
	startTime := time.Now()
	timing := &protocol.Timing{}

	host, port, err := ownedHostPort(req.URL)
	if err != nil {
		return nil, NewRequestError("parse_url", "", "", proto, err)
	}

	// Cancellation belongs to the body, not to this call: the body is still
	// being read after we return. The timeout covers the header wait only, the
	// same way DoStream bounds establishment and then lets the stream run.
	ctx, cancel := context.WithCancel(ctx)
	finishHeaderWait := boundStreamEstablishment(t.streamEffectiveTimeout(req), cancel)

	httpReq, err := t.newOwnedRequest(ctx, snap, req, proto)
	if err != nil {
		finishHeaderWait()
		cancel()
		return nil, NewRequestError("create_request", host, port, proto, err)
	}

	reqStart := time.Now()
	resp, err := roundTrip(httpReq)
	finishHeaderWait()
	if err != nil {
		cancel()
		return nil, WrapError("roundtrip", host, port, proto, err)
	}
	timing.FirstByte = float64(time.Since(reqStart).Milliseconds())
	timing.Total = float64(time.Since(startTime).Milliseconds())

	encoding := resp.Header.Get("Content-Encoding")
	contentLength := resp.ContentLength
	if decodesStream(encoding) {
		contentLength = -1 // the decoded length is not known until EOF
	}

	return &Response{
		StatusCode:    resp.StatusCode,
		Headers:       buildHeadersMap(resp.Header),
		HeaderOrder:   responseHeaderOrder(resp.Header),
		HeaderCasing:  takeHeaderCasing(resp.Header),
		Body:          &ownedStreamBody{raw: resp.Body, encoding: encoding, cancel: cancel},
		ContentLength: contentLength,
		FinalURL:      req.URL,
		Timing:        timing,
		Protocol:      proto,
	}, nil
}

// decodesStream reports whether setupStreamDecompressor decodes this
// Content-Encoding. Anything else is passed through as received.
func decodesStream(encoding string) bool {
	switch strings.ToLower(encoding) {
	case "gzip", "br", "deflate", "zstd":
		return true
	}
	return false
}

// ownedStreamBody is the live body of a streamed owned-connection response.
//
// The decoder is set up on the first Read rather than up front, because
// gzip.NewReader reads the gzip header from the wire: built eagerly, it would
// hold the response back until the origin sends its first body bytes, which
// for an event stream can be a long time after the headers a proxy wants to
// relay right away.
//
// Close tears down the decoder, the wire body and the request context exactly
// once. Callers routinely close twice (explicitly and deferred), and on an
// owned connection a repeated teardown must not touch an exchange that has
// since started on the same connection.
type ownedStreamBody struct {
	raw      io.ReadCloser
	encoding string
	cancel   context.CancelFunc

	initOnce sync.Once
	reader   io.ReadCloser
	decoder  io.Closer

	closeOnce sync.Once
	closeErr  error
}

func (b *ownedStreamBody) Read(p []byte) (int, error) {
	b.initOnce.Do(func() {
		b.reader, b.decoder = setupStreamDecompressor(b.raw, b.encoding)
	})
	return b.reader.Read(p)
}

func (b *ownedStreamBody) Close() error {
	b.closeOnce.Do(func() {
		// The wire body first: it unblocks a Read (or a decoder set-up) in
		// flight on another goroutine and, on HTTP/1.1, returns the connection
		// to a message boundary before the context goes away.
		b.closeErr = b.raw.Close()
		// Waits for an in-flight set-up, or rules out a later one.
		b.initOnce.Do(func() { b.reader = b.raw })
		if b.decoder != nil {
			b.decoder.Close() //nolint:errcheck
		}
		b.cancel()
	})
	return b.closeErr
}
