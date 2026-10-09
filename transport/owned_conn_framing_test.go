package transport

import (
	"context"
	"fmt"
	"io"
	stdhttp "net/http"
	"testing"
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
