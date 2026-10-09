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

// framingH1Handler serves raw HTTP/1.1 responses whose framing the client has
// to get exactly right to keep the connection usable:
//
//	/hints      103 Early Hints, then 200 "hinted"
//	/continue   100 Continue twice, then 200 "continued"
//	/flood      six 103s, then 200
//	/close      200 "bye" with Connection: close (the server then hangs up)
//	/eof        200 "until-eof", delimited by the server closing
//	/echo       200 with the length of the body it read
//	other       200 "path=<path>"
func framingH1Handler(w io.Writer, req *stdhttp.Request) bool {
	body, _ := io.ReadAll(req.Body)
	switch req.URL.Path {
	case "/hints":
		io.WriteString(w, "HTTP/1.1 103 Early Hints\r\nLink: </x.css>; rel=preload\r\n\r\n")
		io.WriteString(w, "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nhinted")
	case "/continue":
		io.WriteString(w, "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 100 Continue\r\n\r\n")
		io.WriteString(w, "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\ncontinued")
	case "/flood":
		for i := 0; i < 6; i++ {
			io.WriteString(w, "HTTP/1.1 103 Early Hints\r\n\r\n")
		}
		io.WriteString(w, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	case "/close":
		io.WriteString(w, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 3\r\n\r\nbye")
		return false
	case "/eof":
		io.WriteString(w, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nuntil-eof")
		return false
	case "/echo":
		b := fmt.Sprintf("read=%d", len(body))
		fmt.Fprintf(w, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(b), b)
	default:
		b := "path=" + req.URL.Path
		fmt.Fprintf(w, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(b), b)
	}
	return true
}

// A 1xx is not the response: the final one follows on the same connection.
// Treating the 103 as final left the 200 unread, and the next request on the
// connection was answered with it.
func TestH1SkipsInterimResponses(t *testing.T) {
	t.Run("owned", func(t *testing.T) {
		srv := startH1WireServer(t, framingH1Handler)
		tr := newTestTransport(t, "chrome-latest")
		tlsConn := dialOwned(t, tr, srv.addr)
		for path, want := range map[string]string{"/hints": "hinted", "/continue": "continued"} {
			resp, err := tr.DoOnTLSConn(context.Background(), &Request{URL: localURL(srv.addr, path)}, tlsConn)
			if err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			if body, _ := resp.Text(); resp.StatusCode != 200 || body != want {
				t.Fatalf("%s: %d %q, want 200 %q", path, resp.StatusCode, body, want)
			}
			resp, err = tr.DoOnTLSConn(context.Background(), &Request{URL: localURL(srv.addr, "/next")}, tlsConn)
			if err != nil {
				t.Fatalf("request after %s: %v", path, err)
			}
			if body, _ := resp.Text(); body != "path=/next" {
				t.Fatalf("request after %s got %q: the previous response leaked into it", path, body)
			}
		}
	})
	t.Run("streamed", func(t *testing.T) {
		srv := startH1WireServer(t, framingH1Handler)
		tr := newTestTransport(t, "chrome-latest")
		tlsConn := dialOwned(t, tr, srv.addr)
		resp, err := tr.DoStreamOnTLSConn(context.Background(), &Request{URL: localURL(srv.addr, "/hints")}, tlsConn)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || string(body) != "hinted" {
			t.Fatalf("got %d %q", resp.StatusCode, body)
		}
	})
	t.Run("pooled", func(t *testing.T) {
		srv := startH1WireServer(t, framingH1Handler)
		tr := newTestTransport(t, "chrome-latest")
		tr.SetProtocol(ProtocolHTTP1)
		for _, path := range []string{"/hints", "/next"} {
			resp, err := tr.Do(context.Background(), &Request{URL: localURL(srv.addr, path)})
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]string{"/hints": "hinted", "/next": "path=/next"}[path]
			if body, _ := resp.Text(); body != want {
				t.Fatalf("%s: %q, want %q", path, body, want)
			}
		}
	})
	t.Run("bounded", func(t *testing.T) {
		srv := startH1WireServer(t, framingH1Handler)
		tr := newTestTransport(t, "chrome-latest")
		tlsConn := dialOwned(t, tr, srv.addr)
		if _, err := tr.DoOnTLSConn(context.Background(), &Request{URL: localURL(srv.addr, "/flood")}, tlsConn); err == nil {
			t.Fatal("six interim responses accepted; the cap is five")
		}
	})
}

// A body that does not match its declared Content-Length must fail the
// request rather than go out misframed.
func TestRequestContentLengthEnforcedH1(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		length int64
	}{
		{"short", "abc", 10},
		{"long", "abcdefgh", 3},
	}
	for _, tc := range cases {
		for _, path := range []string{"owned", "pooled"} {
			t.Run(tc.name+"/"+path, func(t *testing.T) {
				srv := startH1WireServer(t, framingH1Handler)
				tr := newTestTransport(t, "chrome-latest")
				req := &Request{Method: "POST", URL: localURL(srv.addr, "/echo"), BodyReader: opaque(tc.body), ContentLength: tc.length, Timeout: 3 * time.Second}
				var err error
				if path == "owned" {
					tlsConn := dialOwned(t, tr, srv.addr)
					_, err = tr.DoOnTLSConn(context.Background(), req, tlsConn)
				} else {
					tr.SetProtocol(ProtocolHTTP1)
					_, err = tr.Do(context.Background(), req)
				}
				if !errors.Is(err, ErrContentLengthMismatch) {
					t.Fatalf("err = %v, want ErrContentLengthMismatch", err)
				}
			})
		}
	}
	t.Run("exact", func(t *testing.T) {
		srv := startH1WireServer(t, framingH1Handler)
		tr := newTestTransport(t, "chrome-latest")
		tlsConn := dialOwned(t, tr, srv.addr)
		resp, err := tr.DoOnTLSConn(context.Background(), &Request{Method: "POST", URL: localURL(srv.addr, "/echo"), BodyReader: opaque("abcde"), ContentLength: 5}, tlsConn)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := resp.Text(); err != nil {
			t.Fatal(err)
		}
		ex := srv.recorded()
		if got := string(ex[len(ex)-1].body); got != "abcde" {
			t.Fatalf("origin read body %q", got)
		}
	})
}

// HTTP/2 frames the body itself; a mismatch must still fail the stream.
func TestRequestContentLengthEnforcedH2(t *testing.T) {
	srv := startH2Server(t, h2Config{ReadToEndStream: true})
	tr := newTestTransport(t, "chrome-latest")
	h2c, err := tr.NewH2ClientConn(context.Background(), dialOwned(t, tr, srv.addr))
	if err != nil {
		t.Fatal(err)
	}
	defer h2c.Close()
	for _, tc := range []struct {
		body   string
		length int64
	}{{"abc", 10}, {"abcdefgh", 3}} {
		_, err := tr.DoOnH2Conn(context.Background(), &Request{Method: "POST", URL: localURL(srv.addr, "/"), BodyReader: opaque(tc.body), ContentLength: tc.length, Timeout: 3 * time.Second}, h2c)
		if err == nil {
			t.Fatalf("body of %d bytes with content-length %d was accepted", len(tc.body), tc.length)
		}
	}
}

// A response that ends the connection (Connection: close, or a body delimited
// by the server closing) must not leave the connection looking reusable.
func TestOwnedH1LastExchangeIsNotReusable(t *testing.T) {
	for _, tc := range []struct {
		name    string
		path    string
		headers map[string][]string
		want    string
	}{
		{"server Connection: close", "/close", nil, "bye"},
		{"close-delimited body", "/eof", nil, "until-eof"},
		{"client Connection: close", "/plain", map[string][]string{"Connection": {"close"}}, "path=/plain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := startH1WireServer(t, framingH1Handler)
			tr := newTestTransport(t, "chrome-latest")
			tlsConn := dialOwned(t, tr, srv.addr)
			resp, err := tr.DoStreamOnTLSConn(context.Background(), &Request{URL: localURL(srv.addr, tc.path), Headers: tc.headers}, tlsConn)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil || string(body) != tc.want {
				t.Fatalf("body %q, %v", body, err)
			}
			if err := resp.Body.Close(); !errors.Is(err, ErrOwnedConnNotReusable) {
				t.Fatalf("Close = %v, want ErrOwnedConnNotReusable", err)
			}
			if _, err := tlsConn.Write([]byte("x")); err == nil {
				t.Fatal("connection left open after its last exchange")
			}
		})
	}
}

func TestOwnedBufferedResponseContentLength(t *testing.T) {
	srv := startH1WireServer(t, framingH1Handler)
	tr := newTestTransport(t, "chrome-latest")
	resp, err := tr.DoOnTLSConn(context.Background(), &Request{URL: localURL(srv.addr, "/some")}, dialOwned(t, tr, srv.addr))
	if err != nil {
		t.Fatal(err)
	}
	if resp.ContentLength != int64(len("path=/some")) {
		t.Fatalf("ContentLength %d", resp.ContentLength)
	}
	h2 := startH2Server(t, h2Config{Body: []byte(strings.Repeat("z", 123))})
	h2c, err := tr.NewH2ClientConn(context.Background(), dialOwned(t, tr, h2.addr))
	if err != nil {
		t.Fatal(err)
	}
	defer h2c.Close()
	resp, err = tr.DoOnH2Conn(context.Background(), &Request{URL: localURL(h2.addr, "/")}, h2c)
	if err != nil {
		t.Fatal(err)
	}
	if resp.ContentLength != 123 {
		t.Fatalf("h2 ContentLength %d", resp.ContentLength)
	}
}
