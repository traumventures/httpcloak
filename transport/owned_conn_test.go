package transport

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	stdhttp "net/http"
	"strings"
	"sync"
	"testing"
	"time"

	utls "github.com/sardanioss/utls"
)

// ------------------------------------------------------------------ helpers

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// h1Exchange is one request as the server saw it.
type h1Exchange struct {
	conn   int
	header string // raw request line + header block, as sent
	body   []byte
}

// h1WireServer is an HTTP/1.1-only TLS server that records each request's
// raw header block and answers through handle, which writes a complete raw
// response. handle returning false closes the connection afterwards.
type h1WireServer struct {
	addr   string
	handle func(w io.Writer, req *stdhttp.Request) bool

	mu        sync.Mutex
	exchanges []h1Exchange
	conns     int
}

func startH1WireServer(t *testing.T, handle func(w io.Writer, req *stdhttp.Request) bool) *h1WireServer {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(t)},
		NextProtos:   []string{"http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &h1WireServer{addr: ln.Addr().String(), handle: handle}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns++
			id := s.conns
			s.mu.Unlock()
			go s.serve(c, id)
		}
	}()
	return s
}

func (s *h1WireServer) serve(c net.Conn, id int) {
	defer c.Close()
	var rec bytes.Buffer
	br := bufio.NewReader(io.TeeReader(c, &rec))
	for {
		c.SetReadDeadline(time.Now().Add(30 * time.Second))
		rec.Reset()
		req, err := stdhttp.ReadRequest(br)
		if err != nil {
			return
		}
		header := rec.String()
		if i := strings.Index(header, "\r\n\r\n"); i >= 0 {
			header = header[:i+4]
		}
		body, _ := io.ReadAll(req.Body)
		s.mu.Lock()
		s.exchanges = append(s.exchanges, h1Exchange{conn: id, header: header, body: body})
		s.mu.Unlock()
		if !s.handle(c, req) {
			return
		}
	}
}

func (s *h1WireServer) recorded() []h1Exchange {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]h1Exchange(nil), s.exchanges...)
}

func (s *h1WireServer) connCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns
}

func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(b)
	zw.Close()
	return buf.Bytes()
}

// standardH1Handler serves the paths the tests use.
func standardH1Handler(t *testing.T) func(w io.Writer, req *stdhttp.Request) bool {
	gz := gzipBytes(t, []byte("decompressed body"))
	return func(w io.Writer, req *stdhttp.Request) bool {
		switch req.URL.Path {
		case "/gzip":
			fmt.Fprintf(w, "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n", len(gz))
			w.Write(gz)
		case "/chunked":
			io.WriteString(w, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
		case "/close":
			io.WriteString(w, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbye!")
			return false
		case "/echo":
			b, _ := io.ReadAll(req.Body)
			_ = b
			io.WriteString(w, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		default:
			body := "path=" + req.URL.Path
			fmt.Fprintf(w, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
		}
		return true
	}
}

func newTestTransport(t *testing.T, preset string) *Transport {
	t.Helper()
	tr := NewTransport(preset)
	tr.SetInsecureSkipVerify(true)
	tr.SetTimeout(10 * time.Second)
	t.Cleanup(tr.Close)
	return tr
}

// dialOwned dials addr and handshakes through tr, the way a forwarding proxy
// builds its upstream connection.
func dialOwned(t *testing.T, tr *Transport, addr string) *utls.UConn {
	t.Helper()
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tlsConn, err := tr.HandshakeOwnedTLS(ctx, raw, "localhost", nil)
	if err != nil {
		raw.Close()
		t.Fatalf("HandshakeOwnedTLS: %v", err)
	}
	t.Cleanup(func() { tlsConn.Close() })
	return tlsConn
}

func localURL(addr, path string) string {
	_, port, _ := net.SplitHostPort(addr)
	return "https://localhost:" + port + path
}

// ------------------------------------------------------------------ HTTP/2

// An owned HTTP/2 connection must be indistinguishable from a pooled one on
// the wire: same preface (SETTINGS, WINDOW_UPDATE) and byte-identical HPACK
// header blocks for the same requests.
func TestOwnedH2MatchesPooledWire(t *testing.T) {
	for _, preset := range []string{"chrome-latest", "firefox-latest", "safari-18"} {
		t.Run(preset, func(t *testing.T) {
			srv := startH2Server(t, h2Config{Body: []byte("hello"), SendContentLength: true, ReadToEndStream: true})
			reqs := func() []*Request {
				return []*Request{
					{Method: "GET", URL: localURL(srv.addr, "/a"), Headers: map[string][]string{"X-Test": {"1"}}},
					{Method: "POST", URL: localURL(srv.addr, "/b"), Body: []byte("payload"), Headers: map[string][]string{"Content-Type": {"application/json"}}},
				}
			}

			pooled := newTestTransport(t, preset)
			pooled.SetProtocol(ProtocolHTTP2)
			for _, r := range reqs() {
				resp, err := pooled.Do(context.Background(), r)
				if err != nil {
					t.Fatalf("pooled: %v", err)
				}
				if resp.Protocol != "h2" {
					t.Fatalf("pooled protocol %q", resp.Protocol)
				}
			}
			pooled.Close()

			owned := newTestTransport(t, preset)
			h2c, err := owned.NewH2ClientConn(context.Background(), dialOwned(t, owned, srv.addr))
			if err != nil {
				t.Fatal(err)
			}
			defer h2c.Close()
			for _, r := range reqs() {
				resp, err := owned.DoOnH2Conn(context.Background(), r, h2c)
				if err != nil {
					t.Fatalf("owned: %v", err)
				}
				if body, _ := resp.Text(); body != "hello" || resp.Protocol != "h2" {
					t.Fatalf("owned response %q over %q", body, resp.Protocol)
				}
			}

			if srv.connCount() != 2 {
				t.Fatalf("server saw %d connections, want one pooled and one owned", srv.connCount())
			}
			byConn := map[int][]h2Frame{}
			for _, f := range srv.recorded() {
				// Timing-dependent on both paths, not part of the shape: PINGs,
				// the SETTINGS ack, and the RST_STREAM(CANCEL) a client sends when
				// it closes a fully read Content-Length body before END_STREAM.
				if f.Type == frPing || f.Type == frRSTStream || (f.Type == frSettings && f.Flags&flAck != 0) {
					continue
				}
				byConn[f.Conn] = append(byConn[f.Conn], f)
			}
			p, o := byConn[1], byConn[2]
			if len(p) != len(o) {
				t.Fatalf("frame count differs: pooled %d, owned %d\n%s", len(p), len(o), srv.dump())
			}
			for i := range p {
				if p[i].Type != o[i].Type || p[i].Flags != o[i].Flags || p[i].StreamID != o[i].StreamID || !bytes.Equal(p[i].Payload, o[i].Payload) {
					t.Fatalf("frame %d differs:\n pooled %s flags=%#x stream=%d %x\n owned  %s flags=%#x stream=%d %x",
						i, p[i].name(), p[i].Flags, p[i].StreamID, p[i].Payload, o[i].name(), o[i].Flags, o[i].StreamID, o[i].Payload)
				}
			}
		})
	}
}

func TestNewH2ClientConnRequiresH2ALPN(t *testing.T) {
	srv := startH1WireServer(t, standardH1Handler(t))
	tr := newTestTransport(t, "chrome-latest")
	tlsConn := dialOwned(t, tr, srv.addr)
	if _, err := tr.NewH2ClientConn(context.Background(), tlsConn); err == nil || !strings.Contains(err.Error(), "ALPN") {
		t.Fatalf("expected an ALPN error on an http/1.1 connection, got %v", err)
	}
}

// A dead owned HTTP/2 connection reports the failure; it is never replaced by
// a fresh one behind the caller's back.
func TestOwnedH2DoesNotRedial(t *testing.T) {
	srv := startH2Server(t, h2Config{})
	tr := newTestTransport(t, "chrome-latest")
	h2c, err := tr.NewH2ClientConn(context.Background(), dialOwned(t, tr, srv.addr))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.DoOnH2Conn(context.Background(), &Request{URL: localURL(srv.addr, "/")}, h2c); err != nil {
		t.Fatal(err)
	}
	h2c.TLSConn().Close()
	if _, err := tr.DoOnH2Conn(context.Background(), &Request{URL: localURL(srv.addr, "/")}, h2c); err == nil {
		t.Fatal("request on a closed owned connection succeeded")
	}
	if n := srv.connCount(); n != 1 {
		t.Fatalf("server saw %d connections, want 1: the transport re-dialled", n)
	}
}

// ------------------------------------------------------------------ HTTP/1.1

// An owned HTTP/1.1 exchange writes the same request bytes as the pooled
// HTTP/1.1 path: request line, header order, casing and framing.
func TestOwnedH1MatchesPooledWire(t *testing.T) {
	for _, preset := range []string{"chrome-latest", "firefox-latest", "safari-18"} {
		t.Run(preset, func(t *testing.T) {
			srv := startH1WireServer(t, standardH1Handler(t))
			reqs := func() []*Request {
				return []*Request{
					{Method: "GET", URL: localURL(srv.addr, "/a?q=1"), Headers: map[string][]string{"X-Test": {"1"}, "Cookie": {"a=b; c=d"}}},
					{Method: "POST", URL: localURL(srv.addr, "/echo"), Body: []byte(`{"k":1}`), Headers: map[string][]string{"Content-Type": {"application/json"}}},
					{Method: "GET", URL: localURL(srv.addr, "/c"), HeaderOrder: []string{"x-b", "x-a"}, Headers: map[string][]string{"X-A": {"a"}, "X-B": {"b"}}},
				}
			}

			pooled := newTestTransport(t, preset)
			pooled.SetProtocol(ProtocolHTTP1)
			for _, r := range reqs() {
				if _, err := pooled.Do(context.Background(), r); err != nil {
					t.Fatalf("pooled: %v", err)
				}
			}

			owned := newTestTransport(t, preset)
			tlsConn := dialOwned(t, owned, srv.addr)
			for _, r := range reqs() {
				if _, err := owned.DoOnTLSConn(context.Background(), r, tlsConn); err != nil {
					t.Fatalf("owned: %v", err)
				}
			}

			ex := srv.recorded()
			if len(ex) != 6 {
				t.Fatalf("server saw %d requests, want 6", len(ex))
			}
			for i := 0; i < 3; i++ {
				p, o := ex[i], ex[i+3]
				if p.header != o.header {
					t.Fatalf("request %d differs:\n--- pooled\n%s--- owned\n%s", i, p.header, o.header)
				}
				if !bytes.Equal(p.body, o.body) {
					t.Fatalf("request %d body differs: %q vs %q", i, p.body, o.body)
				}
			}
		})
	}
}

// One owned connection carries many sequential exchanges, whatever the
// response framing (Content-Length, chunked, gzip).
func TestOwnedH1ConnReuse(t *testing.T) {
	srv := startH1WireServer(t, standardH1Handler(t))
	tr := newTestTransport(t, "chrome-latest")
	tlsConn := dialOwned(t, tr, srv.addr)
	want := map[string]string{
		"/one":     "path=/one",
		"/gzip":    "decompressed body",
		"/chunked": "hello world",
		"/two":     "path=/two",
	}
	for _, path := range []string{"/one", "/gzip", "/chunked", "/two"} {
		resp, err := tr.DoOnTLSConn(context.Background(), &Request{URL: localURL(srv.addr, path)}, tlsConn)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if body, _ := resp.Text(); body != want[path] {
			t.Fatalf("%s: body %q, want %q", path, body, want[path])
		}
		if resp.Protocol != "h1" {
			t.Fatalf("%s: protocol %q", path, resp.Protocol)
		}
	}
	if n := srv.connCount(); n != 1 {
		t.Fatalf("server saw %d connections, want 1", n)
	}
}

// When the origin closes an owned HTTP/1.1 connection, the next request fails
// instead of silently going out on a new connection.
func TestOwnedH1DoesNotRedial(t *testing.T) {
	srv := startH1WireServer(t, standardH1Handler(t))
	tr := newTestTransport(t, "chrome-latest")
	tlsConn := dialOwned(t, tr, srv.addr)
	resp, err := tr.DoOnTLSConn(context.Background(), &Request{URL: localURL(srv.addr, "/close")}, tlsConn)
	if err != nil {
		t.Fatal(err)
	}
	if body, _ := resp.Text(); body != "bye!" {
		t.Fatalf("body %q", body)
	}
	if _, err := tr.DoOnTLSConn(context.Background(), &Request{URL: localURL(srv.addr, "/again")}, tlsConn); err == nil {
		t.Fatal("request on a connection the origin closed succeeded")
	}
	if n := srv.connCount(); n != 1 {
		t.Fatalf("server saw %d connections, want 1: the transport re-dialled", n)
	}
}
