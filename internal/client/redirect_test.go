package client

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// An https server that redirects to plain http mustn't get the token or a
// build across it, with or without a pin.
func TestNoRedirectToHTTP(t *testing.T) {
	var reached atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Add(1) }))
	defer plain.Close()
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+r.URL.Path, http.StatusFound)
	}))
	defer secure.Close()

	c := New(secure.URL, "kd_fake", "")
	c.HTTP.Transport = secure.Client().Transport // trusts the test certificate
	if err := c.Download("/cli/SHA256SUMS", &bytes.Buffer{}, 1024); !errors.Is(err, ErrRedirectToHTTP) {
		t.Fatalf("download: %v", err)
	}
	if _, err := c.Whoami(); !errors.Is(err, ErrRedirectToHTTP) {
		t.Fatalf("authenticated call: %v", err)
	}
	if n := reached.Load(); n != 0 {
		t.Fatalf("the http server was reached %d times", n)
	}
}

// Redirects that stay on https, or that move up to it, still work.
func TestRedirectsWithinHTTPS(t *testing.T) {
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cli/old" {
			http.Redirect(w, r, "/cli/new", http.StatusFound)
			return
		}
		w.Write([]byte("ok"))
	}))
	defer secure.Close()
	c := New(secure.URL, "", "")
	c.HTTP.Transport = secure.Client().Transport
	var b bytes.Buffer
	if err := c.Download("/cli/old", &b, 1024); err != nil || b.String() != "ok" {
		t.Fatalf("%v %q", err, b.String())
	}
}

func TestRedirectLoopStops(t *testing.T) {
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/again", http.StatusFound)
	}))
	defer secure.Close()
	c := New(secure.URL, "", "")
	c.HTTP.Transport = secure.Client().Transport
	if err := c.Download("/cli/x", &bytes.Buffer{}, 1024); err == nil {
		t.Fatal("followed a redirect loop")
	}
}
