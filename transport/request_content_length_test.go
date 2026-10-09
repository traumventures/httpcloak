package transport

import (
	"context"
	"io"
	"strings"
	"testing"
)

// opaqueReader hides the concrete reader type, as a proxy's streamed request
// body does, so http.NewRequest cannot infer a length from it.
type opaqueReader struct{ r io.Reader }

func (o *opaqueReader) Read(p []byte) (int, error) { return o.r.Read(p) }

func opaque(s string) io.Reader { return &opaqueReader{strings.NewReader(s)} }

func headerHas(head, line string) bool {
	for _, l := range strings.Split(head, "\r\n") {
		if strings.EqualFold(l, line) {
			return true
		}
	}
	return false
}

func headerNamed(head, name string) bool {
	for _, l := range strings.Split(head, "\r\n") {
		if i := strings.IndexByte(l, ':'); i > 0 && strings.EqualFold(l[:i], name) {
			return true
		}
	}
	return false
}

// Request.ContentLength frames a streamed body without buffering it: a stated
// length goes out as Content-Length, -1 as chunked, and 0 keeps the type-based
// inference. Checked on the owned and the pooled HTTP/1.1 paths.
func TestRequestContentLengthFramesH1(t *testing.T) {
	const payload = "streamed-body"
	cases := []struct {
		name      string
		length    int64
		wantCL    bool
		wantChunk bool
	}{
		{"stated", int64(len(payload)), true, false},
		{"unknown", -1, false, true},
		{"inferred", 0, false, true}, // opaque reader: nothing to infer from
	}
	srv := startH1WireServer(t, standardH1Handler(t))
	owned := newTestTransport(t, "chrome-latest")
	tlsConn := dialOwned(t, owned, srv.addr)
	pooled := newTestTransport(t, "chrome-latest")
	pooled.SetProtocol(ProtocolHTTP1)

	for _, tc := range cases {
		for _, path := range []string{"owned", "pooled"} {
			req := &Request{Method: "POST", URL: localURL(srv.addr, "/echo"), BodyReader: opaque(payload), ContentLength: tc.length}
			var err error
			if path == "owned" {
				var resp *Response
				resp, err = owned.DoStreamOnTLSConn(context.Background(), req, tlsConn)
				if err == nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			} else {
				_, err = pooled.Do(context.Background(), req)
			}
			if err != nil {
				t.Fatalf("%s/%s: %v", tc.name, path, err)
			}
			ex := srv.recorded()
			last := ex[len(ex)-1]
			if string(last.body) != payload {
				t.Fatalf("%s/%s: server read body %q", tc.name, path, last.body)
			}
			gotCL := headerHas(last.header, "Content-Length: 13")
			gotChunk := headerHas(last.header, "Transfer-Encoding: chunked")
			if gotCL != tc.wantCL || gotChunk != tc.wantChunk {
				t.Fatalf("%s/%s: content-length=%v chunked=%v, want %v/%v\n%s", tc.name, path, gotCL, gotChunk, tc.wantCL, tc.wantChunk, last.header)
			}
		}
	}
}

// On HTTP/2 a stated length becomes the content-length field; an unknown one
// sends none.
func TestRequestContentLengthFramesH2(t *testing.T) {
	srv := startH2Server(t, h2Config{ReadToEndStream: true})
	tr := newTestTransport(t, "chrome-latest")
	h2c, err := tr.NewH2ClientConn(context.Background(), dialOwned(t, tr, srv.addr))
	if err != nil {
		t.Fatal(err)
	}
	defer h2c.Close()
	for _, length := range []int64{5, -1} {
		resp, err := tr.DoStreamOnH2Conn(context.Background(), &Request{Method: "POST", URL: localURL(srv.addr, "/"), BodyReader: opaque("hello"), ContentLength: length}, h2c)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	dec := srv.decoded()
	if len(dec) != 2 {
		t.Fatalf("%d header blocks", len(dec))
	}
	if dec[0]["content-length"] != "5" {
		t.Fatalf("stated length: content-length %q", dec[0]["content-length"])
	}
	if v, ok := dec[1]["content-length"]; ok {
		t.Fatalf("unknown length sent content-length %q", v)
	}
}
