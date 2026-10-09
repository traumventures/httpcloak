package httpcloak

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sardanioss/httpcloak/transport"
)

func TestNewTransportRejectsUnknownPreset(t *testing.T) {
	tr, err := NewTransport("chrome-1430")
	if err == nil {
		tr.Close()
		t.Fatal("NewTransport accepted an unknown preset; it must not silently fall back to another browser")
	}
	if !strings.Contains(err.Error(), "chrome-1430") {
		t.Fatalf("error should name the preset, got %v", err)
	}
}

func TestNewTransportReturnsOptionErrors(t *testing.T) {
	if tr, err := NewTransport("chrome-latest", WithCustomFingerprint(CustomFingerprint{Akamai: "not-an-akamai-string"})); err == nil {
		tr.Close()
		t.Fatal("invalid Akamai fingerprint was accepted")
	}
	if tr, err := NewTransport("chrome-latest", WithCustomFingerprint(CustomFingerprint{
		JA3:                 "771,4865-4866,0-23,29,0",
		SignatureAlgorithms: []string{"not-a-sigalg"},
	})); err == nil {
		tr.Close()
		t.Fatal("invalid signature algorithm was accepted")
	}
}

// The transport must be configured exactly like the one NewSession builds for
// the same options; both go through session.BuildTransport.
func TestNewTransportMatchesSessionTransport(t *testing.T) {
	opts := []SessionOption{
		WithSessionTimeout(7 * time.Second),
		WithECHFrom("cloudflare-ech.com"),
		WithCustomFingerprint(CustomFingerprint{JA3: "771,4865-4866-4867,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0"}),
		WithoutRedirects(), // session-only, must be ignored
		WithRetry(3),       // session-only, must be ignored
	}
	tr, err := NewTransport("chrome-latest", opts...)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	s := NewSession("chrome-latest", opts...)
	defer s.Close()
	st := s.GetTransport()

	if tr.Timeout() != 7*time.Second || tr.Timeout() != st.Timeout() {
		t.Fatalf("timeout: transport %v, session %v, want 7s", tr.Timeout(), st.Timeout())
	}
	got, want := tr.GetConfig(), st.GetConfig()
	if got == nil || want == nil {
		t.Fatalf("missing transport config: transport %v, session %v", got, want)
	}
	if got.CustomJA3 != want.CustomJA3 || got.TLSOnly != want.TLSOnly || got.ECHConfigDomain != want.ECHConfigDomain {
		t.Fatalf("config drift: transport %+v, session %+v", got, want)
	}
	if !got.TLSOnly {
		t.Fatal("a custom JA3 implies TLS-only mode")
	}
}

// A bare transport must not act as an HTTP client: it returns a redirect
// as-is and does not replay cookies the origin set.
func TestNewTransportHasNoClientState(t *testing.T) {
	var sawCookie atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "" {
			sawCookie.Store(true)
		}
		if r.URL.Path == "/start" {
			http.SetCookie(w, &http.Cookie{Name: "flow", Value: "a"})
			http.Redirect(w, r, "/next", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tr, err := NewTransport("chrome-latest", WithInsecureSkipVerify(), WithForceHTTP1())
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	ctx := context.Background()
	resp, err := tr.Do(ctx, &transport.Request{Method: "GET", URL: srv.URL + "/start"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status %d: the transport followed a redirect", resp.StatusCode)
	}
	if _, err := tr.Do(ctx, &transport.Request{Method: "GET", URL: srv.URL + "/next"}); err != nil {
		t.Fatal(err)
	}
	if sawCookie.Load() {
		t.Fatal("the transport replayed a cookie from an earlier response")
	}
}

// WithSessionProxy and WithInsecureSkipVerify reach the transport.
func TestNewTransportAppliesProxyAndTLSOptions(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	var connects atomic.Int32
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyLn.Close()
	go func() {
		for {
			c, err := proxyLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil || req.Method != http.MethodConnect {
					return
				}
				connects.Add(1)
				up, err := net.Dial("tcp", req.Host)
				if err != nil {
					return
				}
				defer up.Close()
				c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
				go func() { _, _ = copyConn(up, c) }()
				_, _ = copyConn(c, up)
			}(c)
		}
	}()

	tr, err := NewTransport("chrome-latest", WithSessionProxy("http://"+proxyLn.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	_, err = tr.Do(context.Background(), &transport.Request{Method: "GET", URL: srv.URL})
	tr.Close()
	if err == nil {
		t.Fatal("self-signed certificate accepted without WithInsecureSkipVerify")
	}

	// Both protocols' CONNECT paths: the proxy answers 200 with no body and
	// keeps the tunnel open, so a client that tried to read a CONNECT body
	// would hang here until the timeout.
	for _, force := range []SessionOption{WithForceHTTP1(), WithForceHTTP2()} {
		before := connects.Load()
		tr, err = NewTransport("chrome-latest", WithSessionProxy("http://"+proxyLn.Addr().String()), WithInsecureSkipVerify(), WithSessionTimeout(5*time.Second), force)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		resp, err := tr.Do(context.Background(), &transport.Request{Method: "GET", URL: srv.URL})
		tr.Close()
		if err != nil {
			t.Fatal(err)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Fatalf("request through CONNECT took %v", d)
		}
		if body, _ := resp.Text(); body != "ok" {
			t.Fatalf("body %q", body)
		}
		if connects.Load() == before {
			t.Fatal("request did not go through the configured proxy")
		}
	}
}

func copyConn(dst, src net.Conn) (int64, error) {
	buf := make([]byte, 32*1024)
	var n int64
	for {
		r, err := src.Read(buf)
		if r > 0 {
			w, werr := dst.Write(buf[:r])
			n += int64(w)
			if werr != nil {
				return n, werr
			}
		}
		if err != nil {
			return n, err
		}
	}
}
