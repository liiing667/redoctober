// server_test.go: tests for the pre-read request validation in
// server.go. These tests ensure that illegitimate requests (wrong
// method, missing client certificate, closed connection, oversized
// body, unknown route) are rejected before the request body is read,
// while normal JSON requests and the static index page keep working.
//
// Copyright (c) 2013 CloudFlare, Inc.

package server

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cloudflare/redoctober/config"
	"github.com/cloudflare/redoctober/core"
)

const (
	testCertPath = "../testdata/server.crt"
	testKeyPath  = "../testdata/server.pem"
)

func initTestCore(t *testing.T) {
	t.Helper()
	if err := core.Init("memory", config.New()); err != nil {
		t.Fatalf("failed to initialize core: %v", err)
	}
}

// spyReadCloser records whether anything was ever read from it.
type spyReadCloser struct {
	read *bool
}

func (s spyReadCloser) Read(p []byte) (int, error) {
	*s.read = true
	return 0, io.EOF
}

func (s spyReadCloser) Close() error { return nil }

func responseStatus(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var s core.ResponseData
	if err := json.Unmarshal(rec.Body.Bytes(), &s); err != nil {
		t.Fatalf("response is not a valid ResponseData: %v", err)
	}
	return s.Status
}

// TestNormalJSONRequest ensures a well-formed POST request is still
// processed with the existing error semantics.
func TestNormalJSONRequest(t *testing.T) {
	initTestCore(t)

	body := `{"Name":"Alice","Password":"Lewis"}`
	req := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(body))
	rec := httptest.NewRecorder()
	processRequest("/create", false, rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	if status := responseStatus(t, rec); status != "ok" {
		t.Fatalf("expected status \"ok\", got %q", status)
	}

	// The existing JSON error semantics are preserved: creating the
	// vault twice is a domain error reported in the Status field.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(body))
	processRequest("/create", false, rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	if status := responseStatus(t, rec); status != "Vault is already created" {
		t.Fatalf("expected \"Vault is already created\", got %q", status)
	}
}

// TestUnknownRoute ensures unknown routes are rejected with the
// existing error semantics.
func TestUnknownRoute(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/bogus", nil)
	rec := httptest.NewRecorder()
	processRequest("/bogus", false, rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Unknown request") {
		t.Fatalf("expected \"Unknown request\" body, got %q", rec.Body.String())
	}
}

// TestMethodRejectedBeforeRead ensures non-POST requests are rejected
// before the request body is read.
func TestMethodRejectedBeforeRead(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		read := false
		req := httptest.NewRequest(method, "/create", nil)
		req.Body = spyReadCloser{read: &read}
		rec := httptest.NewRecorder()
		processRequest("/create", false, rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s: expected status 405, got %d", method, rec.Code)
		}
		if read {
			t.Fatalf("%s: request body was read before rejection", method)
		}
	}
}

// TestClientCertificateRequired ensures requests without a verified
// client certificate are rejected before the body is read when the
// server requires client certificate authentication.
func TestClientCertificateRequired(t *testing.T) {
	initTestCore(t)

	body := `{"Name":"Alice","Password":"Lewis"}`

	// No TLS state at all.
	read := false
	req := httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(body))
	req.Body = spyReadCloser{read: &read}
	rec := httptest.NewRecorder()
	processRequest("/create", true, rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}
	if read {
		t.Fatal("request body was read before rejection")
	}

	// TLS state without any peer certificate.
	req = httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(body))
	req.TLS = &tls.ConnectionState{}
	rec = httptest.NewRecorder()
	processRequest("/create", true, rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", rec.Code)
	}

	// A verified peer certificate passes the identity check.
	req = httptest.NewRequest(http.MethodPost, "/create", strings.NewReader(body))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}
	rec = httptest.NewRecorder()
	processRequest("/create", true, rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	if status := responseStatus(t, rec); status != "ok" {
		t.Fatalf("expected status \"ok\", got %q", status)
	}
}

// TestClosedConnectionRejected ensures requests whose client
// connection is already closed are rejected before the body is read.
func TestClosedConnectionRejected(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	read := false
	req := httptest.NewRequest(http.MethodPost, "/create", nil).WithContext(ctx)
	req.Body = spyReadCloser{read: &read}
	rec := httptest.NewRecorder()
	processRequest("/create", false, rec, req)

	if rec.Code != http.StatusRequestTimeout {
		t.Fatalf("expected status 408, got %d", rec.Code)
	}
	if read {
		t.Fatal("request body was read before rejection")
	}
}

// TestOversizedContentLengthRejected ensures requests declaring a body
// larger than the shared limit are rejected before the body is read.
func TestOversizedContentLengthRejected(t *testing.T) {
	read := false
	req := httptest.NewRequest(http.MethodPost, "/create", nil)
	req.Body = spyReadCloser{read: &read}
	req.ContentLength = core.MaxRequestSize + 1
	rec := httptest.NewRecorder()
	processRequest("/create", false, rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected status 413, got %d", rec.Code)
	}
	if read {
		t.Fatal("request body was read before rejection")
	}
}

// TestOversizedBodyCapped ensures a request that under-reports its
// size is still bounded by the read path.
func TestOversizedBodyCapped(t *testing.T) {
	body := strings.NewReader(strings.Repeat(" ", core.MaxRequestSize+1))
	req := httptest.NewRequest(http.MethodPost, "/create", body)
	req.ContentLength = -1 // as with a chunked transfer encoding
	rec := httptest.NewRecorder()
	processRequest("/create", false, rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "too large") {
		t.Fatalf("expected a \"too large\" error, got %q", rec.Body.String())
	}
}

// startTestServer starts a real TLS server on an ephemeral port.
func startTestServer(t *testing.T) (*http.Server, net.Listener) {
	t.Helper()
	srv, lstnr, err := NewServer("", "localhost:0", "",
		[]string{testCertPath}, []string{testKeyPath}, false)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	go func() {
		srv.Serve(lstnr)
	}()
	t.Cleanup(func() { srv.Close() })
	return srv, lstnr
}

// TestEarlyRejectAndRecoverOnOneConnection is the acceptance test: on
// a single TLS connection, an illegitimate request is rejected early
// and the same connection then serves a legitimate JSON request and
// the static index page.
func TestEarlyRejectAndRecoverOnOneConnection(t *testing.T) {
	initTestCore(t)
	_, lstnr := startTestServer(t)
	addr := lstnr.Addr().String()

	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)

	readResponse := func() *http.Response {
		t.Helper()
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatalf("failed to read response: %v", err)
		}
		return resp
	}

	// 1. An illegitimate request (wrong method) is rejected early.
	fmt.Fprintf(conn, "PUT /create HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}", addr)
	resp := readResponse()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", resp.StatusCode)
	}
	if _, err := io.Copy(ioutil.Discard, resp.Body); err != nil {
		t.Fatalf("failed to drain response body: %v", err)
	}
	resp.Body.Close()

	// 2. The same connection recovers: a valid JSON request succeeds.
	createBody := `{"Name":"Alice","Password":"Lewis"}`
	fmt.Fprintf(conn, "POST /create HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		addr, len(createBody), createBody)
	resp = readResponse()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	respBody, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	var s core.ResponseData
	if err := json.Unmarshal(respBody, &s); err != nil {
		t.Fatalf("response is not a valid ResponseData: %v", err)
	}
	if s.Status != "ok" {
		t.Fatalf("expected status \"ok\", got %q", s.Status)
	}

	// 3. The same connection still serves the static index page.
	fmt.Fprintf(conn, "GET /index HTTP/1.1\r\nHost: %s\r\n\r\n", addr)
	resp = readResponse()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("expected a text/html content type, got %q", ct)
	}
	if _, err := io.Copy(ioutil.Discard, resp.Body); err != nil {
		t.Fatalf("failed to drain response body: %v", err)
	}
	resp.Body.Close()
}

// TestStaticIndex ensures the built-in static index page is served.
func TestStaticIndex(t *testing.T) {
	handler := &indexHandler{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.handle(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("expected a text/html content type, got %q", ct)
	}
}
