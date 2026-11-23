// client_test.go: tests for the client-side enforcement of the shared
// request size boundary.
//
// Copyright (c) 2013 CloudFlare, Inc.

package client

import (
	"testing"

	"github.com/cloudflare/redoctober/core"
)

// TestDoActionRejectsOversizedRequest ensures the client refuses to
// send a request that the server would reject, so CLI users observe
// the same rejection boundary as direct core callers.
func TestDoActionRejectsOversizedRequest(t *testing.T) {
	server, err := NewRemoteServer("localhost:0", "")
	if err != nil {
		t.Fatalf("failed to create remote server: %v", err)
	}

	_, err = server.doAction("create", make([]byte, core.MaxRequestSize+1))
	if err != core.ErrRequestTooLarge {
		t.Fatalf("expected ErrRequestTooLarge, got %v", err)
	}

	// A request at exactly the limit passes the client-side check.
	if err := core.ValidateRequestSize(int64(core.MaxRequestSize)); err != nil {
		t.Fatalf("request of exactly MaxRequestSize bytes should be accepted: %v", err)
	}
}
