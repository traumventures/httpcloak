package transport

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// helloCapture accepts TCP connections, records the first TLS record (the
// ClientHello) of each, and hangs up. The handshake fails, which is fine: only
// what the client sent matters.
type helloCapture struct {
	ln     net.Listener
	hellos chan []byte
}

func newHelloCapture(t *testing.T) *helloCapture {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := &helloCapture{ln: ln, hellos: make(chan []byte, 16)}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				hdr := make([]byte, 5)
				if _, err := io.ReadFull(conn, hdr); err != nil {
					return
				}
				body := make([]byte, binary.BigEndian.Uint16(hdr[3:5]))
				if _, err := io.ReadFull(conn, body); err != nil {
					return
				}
				c.hellos <- body
			}(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return c
}

func (c *helloCapture) port() string {
	_, p, _ := net.SplitHostPort(c.ln.Addr().String())
	return p
}

func (c *helloCapture) next(t *testing.T) []byte {
	t.Helper()
	select {
	case h := <-c.hellos:
		return h
	case <-time.After(10 * time.Second):
		t.Fatal("no ClientHello captured")
		return nil
	}
}

func isGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

// helloShape reduces a ClientHello handshake message to what identifies the
// client: cipher suites, extension order and the contents of every extension
// that does not legitimately vary per connection. GREASE values, the random,
// the session id, key share and PSK material, and the GREASE ECH payload are
// per-connection noise and are masked.
type helloShape struct {
	Version    uint16
	Ciphers    []string
	Extensions []string
}

func parseHelloShape(t *testing.T, msg []byte) helloShape {
	t.Helper()
	if len(msg) < 4 || msg[0] != 1 {
		t.Fatalf("not a ClientHello: % x", msg[:min(len(msg), 8)])
	}
	b := msg[4:]
	var s helloShape
	s.Version = binary.BigEndian.Uint16(b)
	b = b[2+32:]        // version, random
	b = b[1+int(b[0]):] // session id
	n := int(binary.BigEndian.Uint16(b))
	for i := 0; i < n; i += 2 {
		v := binary.BigEndian.Uint16(b[2+i:])
		if isGREASE(v) {
			s.Ciphers = append(s.Ciphers, "GREASE")
		} else {
			s.Ciphers = append(s.Ciphers, fmt.Sprintf("%04x", v))
		}
	}
	b = b[2+n:]
	b = b[1+int(b[0]):] // compression methods
	b = b[2:]           // extensions length
	for len(b) >= 4 {
		id := binary.BigEndian.Uint16(b)
		l := int(binary.BigEndian.Uint16(b[2:]))
		data := b[4 : 4+l]
		b = b[4+l:]
		switch {
		case isGREASE(id):
			s.Extensions = append(s.Extensions, "GREASE")
		case id == 51: // key_share: keep the group list only
			var groups []string
			ks := data[2:]
			for len(ks) >= 4 {
				g := binary.BigEndian.Uint16(ks)
				kl := int(binary.BigEndian.Uint16(ks[2:]))
				if isGREASE(g) {
					groups = append(groups, "GREASE")
				} else {
					groups = append(groups, fmt.Sprintf("%04x", g))
				}
				ks = ks[4+kl:]
			}
			s.Extensions = append(s.Extensions, "51:"+strings.Join(groups, ","))
		case id == 41, id == 65037, id == 21: // psk, ECH (GREASE payload), padding
			s.Extensions = append(s.Extensions, fmt.Sprintf("%d", id))
		case id == 10, id == 13:
			s.Extensions = append(s.Extensions, fmt.Sprintf("%d:%x", id, maskGREASE(data, 2)))
		case id == 43:
			s.Extensions = append(s.Extensions, fmt.Sprintf("%d:%x", id, maskGREASE(data, 1)))
		case id == 51764: // trust anchors, entry order shuffled per handshake
			s.Extensions = append(s.Extensions, fmt.Sprintf("%d:%s", id, sortedEntries(data)))
		default:
			s.Extensions = append(s.Extensions, fmt.Sprintf("%d:%x", id, data))
		}
	}
	return s
}

// maskGREASE zeroes GREASE uint16 values in a list that starts at offset
// (supported_groups and signature_algorithms after a 2-byte length,
// supported_versions after a 1-byte one).
func maskGREASE(data []byte, offset int) []byte {
	out := append([]byte(nil), data...)
	for i := offset; i+1 < len(out); i += 2 {
		if isGREASE(binary.BigEndian.Uint16(out[i:])) {
			out[i], out[i+1] = 0, 0
		}
	}
	return out
}

// sortedEntries normalises a list of 1-byte-length-prefixed entries after a
// 2-byte list length by sorting them. The trust-anchors extension carries its
// entries in a per-handshake random order.
func sortedEntries(data []byte) string {
	var entries []string
	for b := data[2:]; len(b) > 0; {
		l := int(b[0])
		entries = append(entries, fmt.Sprintf("%x", b[1:1+l]))
		b = b[1+l:]
	}
	sort.Strings(entries)
	return strings.Join(entries, ",")
}

func setMinus(a, b []string) []string {
	have := map[string]int{}
	for _, x := range b {
		have[x]++
	}
	var out []string
	for _, x := range a {
		if have[x] > 0 {
			have[x]--
			continue
		}
		out = append(out, x)
	}
	return out
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

// HandshakeOwnedTLS must put the same ClientHello on the wire as the pooled
// HTTP/2 path of the same transport. If it does not, every connection a
// forwarding proxy dials itself is a different client than the preset claims.
func TestHandshakeOwnedTLSMatchesPooledClientHello(t *testing.T) {
	cases := []struct {
		preset string
		config *TransportConfig
	}{
		{preset: "chrome-latest"},
		{preset: "chrome-143"},
		{preset: "chrome-149-windows"},
		{preset: "firefox-latest"},
		{preset: "safari-18"},
		{preset: "chrome-latest", config: &TransportConfig{
			CustomJA3: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
			TLSOnly:   true,
		}},
	}
	for _, tc := range cases {
		name := tc.preset
		if tc.config != nil {
			name += "/custom-ja3"
		}
		t.Run(name, func(t *testing.T) {
			capture := newHelloCapture(t)
			tr := NewTransportWithConfig(tc.preset, nil, tc.config)
			defer tr.Close()
			tr.SetProtocol(ProtocolHTTP2)
			tr.SetTimeout(5 * time.Second)

			pooled := func() helloShape {
				_, _ = tr.Do(context.Background(), &Request{Method: "GET", URL: "https://localhost:" + capture.port() + "/"})
				return parseHelloShape(t, capture.next(t))
			}
			owned := func() helloShape {
				raw, err := net.Dial("tcp", capture.ln.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer raw.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_, _ = tr.HandshakeOwnedTLS(ctx, raw, "localhost", nil)
				return parseHelloShape(t, capture.next(t))
			}

			p1, p2 := pooled(), pooled()
			o := owned()

			if !reflect.DeepEqual(o.Ciphers, p1.Ciphers) || o.Version != p1.Version {
				t.Fatalf("cipher suites differ:\n pooled %v\n owned  %v", p1.Ciphers, o.Ciphers)
			}
			// Extension order is part of the fingerprint when the pooled path
			// itself is stable across connections (per-transport shuffle seed);
			// presets that permute per handshake are compared as sets.
			if reflect.DeepEqual(p1.Extensions, p2.Extensions) {
				if !reflect.DeepEqual(o.Extensions, p1.Extensions) {
					t.Fatalf("extensions differ:\n pooled %v\n owned  %v", p1.Extensions, o.Extensions)
				}
			} else if !reflect.DeepEqual(sortedCopy(o.Extensions), sortedCopy(p1.Extensions)) {
				t.Fatalf("extension sets differ: only pooled %v, only owned %v", setMinus(p1.Extensions, o.Extensions), setMinus(o.Extensions, p1.Extensions))
			}
		})
	}
}

// The handshake honours the caller's context: a server that never answers
// must not hold the caller past its deadline.
func TestHandshakeOwnedTLSHonoursContext(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			time.Sleep(5 * time.Second)
		}
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	tr := NewTransport("chrome-latest")
	defer tr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := tr.HandshakeOwnedTLS(ctx, raw, "localhost", nil); err == nil {
		t.Fatal("handshake against a silent server succeeded")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("handshake ignored the context deadline, took %v", d)
	}
}
