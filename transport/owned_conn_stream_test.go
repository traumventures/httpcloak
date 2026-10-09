package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	stdhttp "net/http"
	"strings"
	"testing"
	"time"
)

// streamingH1Handler serves:
//
//	/held     chunked: "first", then waits for release, then "-rest"
//	/slow     chunked: ten chunks 150ms apart
//	/endless  chunked: a chunk every 50ms until the connection dies
//	/big      Content-Length 100000 of 'x'
//	/gzheld   gzip-encoded, headers first, body only after release
//	default   Content-Length "path=<path>"
func streamingH1Handler(t *testing.T, release <-chan struct{}) func(io.Writer, *stdhttp.Request) bool {
	gz := gzipBytes(t, []byte("gzipped stream"))
	return func(w io.Writer, req *stdhttp.Request) bool {
		switch req.URL.Path {
		case "/held":
			io.WriteString(w, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nfirst\r\n")
			<-release
			io.WriteString(w, "5\r\n-rest\r\n0\r\n\r\n")
		case "/slow":
			io.WriteString(w, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
			for i := 0; i < 10; i++ {
				time.Sleep(150 * time.Millisecond)
				fmt.Fprintf(w, "1\r\n%d\r\n", i)
			}
			io.WriteString(w, "0\r\n\r\n")
		case "/endless":
			io.WriteString(w, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
			for {
				if _, err := io.WriteString(w, "6\r\ndata:\n\r\n"); err != nil {
					return false
				}
				time.Sleep(50 * time.Millisecond)
			}
		case "/big":
			io.WriteString(w, "HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n")
			w.Write([]byte(strings.Repeat("x", 100000)))
		case "/gzheld":
			fmt.Fprintf(w, "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n", len(gz))
			<-release
			w.Write(gz)
		default:
			body := "path=" + req.URL.Path
			fmt.Fprintf(w, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
		}
		return true
	}
}

func readN(t *testing.T, r io.Reader, n int) string {
	t.Helper()
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	return string(buf)
}

// The response comes back as soon as the headers do, the body arrives as the
// origin sends it, and after Close the same connection carries the next
// request.
func TestOwnedH1StreamDeliversIncrementallyAndReuses(t *testing.T) {
	release := make(chan struct{})
	srv := startH1WireServer(t, streamingH1Handler(t, release))
	tr := newTestTransport(t, "chrome-latest")
	tlsConn := dialOwned(t, tr, srv.addr)

	resp, err := tr.DoStreamOnTLSConn(context.Background(), &Request{URL: localURL(srv.addr, "/held")}, tlsConn)
	if err != nil {
		t.Fatal(err)
	}
	if resp.ContentLength != -1 {
		t.Fatalf("chunked response ContentLength %d, want -1", resp.ContentLength)
	}
	if got := readN(t, resp.Body, 5); got != "first" {
		t.Fatalf("first chunk %q", got)
	}
	close(release)
	rest, err := io.ReadAll(resp.Body)
	if err != nil || string(rest) != "-rest" {
		t.Fatalf("rest %q, %v", rest, err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("Close after EOF: %v", err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	resp, err = tr.DoStreamOnTLSConn(context.Background(), &Request{URL: localURL(srv.addr, "/next")}, tlsConn)
	if err != nil {
		t.Fatalf("reuse after Close: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "path=/next" || resp.ContentLength != int64(len("path=/next")) {
		t.Fatalf("second response %q, ContentLength %d", body, resp.ContentLength)
	}
	if n := srv.connCount(); n != 1 {
		t.Fatalf("server saw %d connections, want 1", n)
	}
}

// The timeout bounds the header wait only. A stream that outlives both the
// request timeout and the transport's response-header timeout is not cut.
func TestOwnedH1StreamOutlivesTimeouts(t *testing.T) {
	srv := startH1WireServer(t, streamingH1Handler(t, nil))
	tr := newTestTransport(t, "chrome-latest")
	tr.SetTimeout(400 * time.Millisecond)
	tr.snapshot().h1.responseTimeout = 400 * time.Millisecond
	tlsConn := dialOwned(t, tr, srv.addr)

	resp, err := tr.DoStreamOnTLSConn(context.Background(), &Request{URL: localURL(srv.addr, "/slow")}, tlsConn)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("stream cut after %q: %v", body, err)
	}
	if string(body) != "0123456789" {
		t.Fatalf("body %q", body)
	}
}

// A header wait longer than the timeout fails, and the connection, whose
// framing is now unknown, is closed.
func TestOwnedH1StreamHeaderTimeout(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	srv := startH1WireServer(t, func(w io.Writer, req *stdhttp.Request) bool {
		<-release
		return false
	})
	tr := newTestTransport(t, "chrome-latest")
	tlsConn := dialOwned(t, tr, srv.addr)
	start := time.Now()
	_, err := tr.DoStreamOnTLSConn(context.Background(), &Request{URL: localURL(srv.addr, "/"), Timeout: 300 * time.Millisecond}, tlsConn)
	if err == nil {
		t.Fatal("no error for a response that never came")
	}
	// A timeout, not a cancellation: the caller must be able to tell a slow
	// origin from its own context ending.
	if !errors.Is(err, ErrResponseHeaderTimeout) || errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want ErrResponseHeaderTimeout and not context.Canceled", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("timeout took %v", d)
	}
	if _, err := tlsConn.Write([]byte("x")); err == nil {
		t.Fatal("connection still open after an interrupted exchange")
	}
}

// The same on HTTP/2.
func TestOwnedH2StreamHeaderTimeout(t *testing.T) {
	hold := make(chan struct{})
	defer close(hold)
	srv := startH2Server(t, h2Config{OnRequest: func(uint32, int) { <-hold }})
	tr := newTestTransport(t, "chrome-latest")
	h2c, err := tr.NewH2ClientConn(context.Background(), dialOwned(t, tr, srv.addr))
	if err != nil {
		t.Fatal(err)
	}
	defer h2c.Close()
	_, err = tr.DoStreamOnH2Conn(context.Background(), &Request{URL: localURL(srv.addr, "/"), Timeout: 300 * time.Millisecond}, h2c)
	if !errors.Is(err, ErrResponseHeaderTimeout) || errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want ErrResponseHeaderTimeout and not context.Canceled", err)
	}
	// The caller's own cancellation is still a cancellation.
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	_, err = tr.DoStreamOnH2Conn(ctx, &Request{URL: localURL(srv.addr, "/"), Timeout: 5 * time.Second}, h2c)
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrResponseHeaderTimeout) {
		t.Fatalf("caller cancel: err = %v, want context.Canceled", err)
	}
}

// Closing a body with a small unread remainder drains it, so the connection
// stays usable.
func TestOwnedH1StreamEarlyCloseDrains(t *testing.T) {
	srv := startH1WireServer(t, streamingH1Handler(t, nil))
	tr := newTestTransport(t, "chrome-latest")
	tlsConn := dialOwned(t, tr, srv.addr)

	resp, err := tr.DoStreamOnTLSConn(context.Background(), &Request{URL: localURL(srv.addr, "/big")}, tlsConn)
	if err != nil {
		t.Fatal(err)
	}
	if resp.ContentLength != 100000 {
		t.Fatalf("ContentLength %d, want 100000", resp.ContentLength)
	}
	readN(t, resp.Body, 10)
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("Close with a drainable remainder: %v", err)
	}
	resp, err = tr.DoOnTLSConn(context.Background(), &Request{URL: localURL(srv.addr, "/after")}, tlsConn)
	if err != nil {
		t.Fatalf("connection unusable after drain: %v", err)
	}
	if body, _ := resp.Text(); body != "path=/after" {
		t.Fatalf("misframed next response: %q", body)
	}
	if n := srv.connCount(); n != 1 {
		t.Fatalf("server saw %d connections, want 1", n)
	}
}

// Closing an endless stream must not block forever trying to drain it: the
// connection is closed instead and Close says so.
func TestOwnedH1StreamEarlyCloseOnEndlessStream(t *testing.T) {
	srv := startH1WireServer(t, streamingH1Handler(t, nil))
	tr := newTestTransport(t, "chrome-latest")
	tlsConn := dialOwned(t, tr, srv.addr)

	resp, err := tr.DoStreamOnTLSConn(context.Background(), &Request{URL: localURL(srv.addr, "/endless")}, tlsConn)
	if err != nil {
		t.Fatal(err)
	}
	readN(t, resp.Body, 6)

	// A reader still blocked in Read on another goroutine, as in a proxy
	// relaying the stream when its client hangs up.
	readDone := make(chan struct{})
	go func() {
		io.Copy(io.Discard, resp.Body)
		close(readDone)
	}()
	time.Sleep(100 * time.Millisecond)

	start := time.Now()
	err = resp.Body.Close()
	if d := time.Since(start); d > ownedDrainTimeout+2*time.Second {
		t.Fatalf("Close blocked for %v", d)
	}
	if !errors.Is(err, ErrOwnedConnNotReusable) {
		t.Fatalf("Close on an undrainable body returned %v, want ErrOwnedConnNotReusable", err)
	}
	select {
	case <-readDone:
	case <-time.After(3 * time.Second):
		t.Fatal("concurrent Read not released by Close")
	}
	if _, err := tlsConn.Write([]byte("x")); err == nil {
		t.Fatal("connection still open although it could not be drained")
	}
}

// A gzip stream's headers come back before its body: the decoder must not
// read the gzip header off the wire before the caller asks for body bytes.
func TestOwnedH1StreamGzipHeadersBeforeBody(t *testing.T) {
	release := make(chan struct{})
	srv := startH1WireServer(t, streamingH1Handler(t, release))
	tr := newTestTransport(t, "chrome-latest")
	tlsConn := dialOwned(t, tr, srv.addr)

	done := make(chan *Response, 1)
	go func() {
		resp, err := tr.DoStreamOnTLSConn(context.Background(), &Request{URL: localURL(srv.addr, "/gzheld")}, tlsConn)
		if err != nil {
			t.Error(err)
		}
		done <- resp
	}()
	var resp *Response
	select {
	case resp = <-done:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("headers held back until the gzip body arrived")
	}
	close(release)
	if resp == nil {
		return
	}
	defer resp.Body.Close()
	if resp.ContentLength != -1 {
		t.Fatalf("decoded stream ContentLength %d, want -1", resp.ContentLength)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil || string(body) != "gzipped stream" {
		t.Fatalf("body %q, %v", body, err)
	}
}

// HTTP/2: the stream returns at headers, delivers incrementally, and the
// connection carries further requests after Close, including after a body
// closed before its end.
func TestOwnedH2StreamDeliversIncrementallyAndReuses(t *testing.T) {
	hold := make(chan struct{})
	body := []byte(strings.Repeat("y", 4000))
	srv := startH2Server(t, h2Config{Body: body, SendContentLength: true, Chunk: 1000, ChunkDelay: 20 * time.Millisecond, HoldEndStream: hold})
	tr := newTestTransport(t, "chrome-latest")
	tr.SetTimeout(500 * time.Millisecond)
	h2c, err := tr.NewH2ClientConn(context.Background(), dialOwned(t, tr, srv.addr))
	if err != nil {
		t.Fatal(err)
	}
	defer h2c.Close()

	resp, err := tr.DoStreamOnH2Conn(context.Background(), &Request{URL: localURL(srv.addr, "/a")}, h2c)
	if err != nil {
		t.Fatal(err)
	}
	if resp.ContentLength != int64(len(body)) {
		t.Fatalf("ContentLength %d, want %d", resp.ContentLength, len(body))
	}
	if got := readN(t, resp.Body, len(body)); got != string(body) {
		t.Fatal("body mismatch")
	}
	// The stream is still open (END_STREAM held) well past the timeout.
	time.Sleep(700 * time.Millisecond)
	close(hold)
	if rest, err := io.ReadAll(resp.Body); err != nil || len(rest) != 0 {
		t.Fatalf("after END_STREAM: %q, %v", rest, err)
	}
	resp.Body.Close()

	// Early close: read a little, close, the connection stays good.
	resp, err = tr.DoStreamOnH2Conn(context.Background(), &Request{URL: localURL(srv.addr, "/b")}, h2c)
	if err != nil {
		t.Fatal(err)
	}
	readN(t, resp.Body, 10)
	resp.Body.Close()

	resp, err = tr.DoOnH2Conn(context.Background(), &Request{URL: localURL(srv.addr, "/c")}, h2c)
	if err != nil {
		t.Fatalf("connection unusable after an early close: %v", err)
	}
	if b, _ := resp.Bytes(); len(b) != len(body) {
		t.Fatalf("third response %d bytes", len(b))
	}
	if n := srv.connCount(); n != 1 {
		t.Fatalf("server saw %d connections, want 1", n)
	}
}
