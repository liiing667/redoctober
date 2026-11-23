// concurrency_test.go exercises the keycache consumption transaction
// through the public JSON request entry points (Delegate, Encrypt and
// Decrypt), the same path served over HTTP by the Red October server.
//
// Copyright (c) 2013 CloudFlare, Inc.

package core

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/cloudflare/redoctober/config"
)

// setupConcurrentVault creates an in-memory vault with a single admin
// and returns an encrypted blob that can only be unwrapped with the
// admin's delegated key.
func setupConcurrentVault(t *testing.T) (encrypted []byte) {
	t.Helper()

	cfg := config.New()
	if err := Init("memory", cfg); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	createReq, err := json.Marshal(CreateRequest{Name: "Alice", Password: "Hello"})
	if err != nil {
		t.Fatalf("%v", err)
	}
	resp, err := Create(createReq)
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}
	var status ResponseData
	if err = json.Unmarshal(resp, &status); err != nil || status.Status != "ok" {
		t.Fatalf("create returned %v: %s", err, resp)
	}

	// "Hello Jelly" base64-encoded, mirroring the other core tests.
	encryptReq, err := json.Marshal(EncryptRequest{
		Name:     "Alice",
		Password: "Hello",
		Minimum:  1,
		Owners:   []string{"Alice"},
		Data:     []byte("SGVsbG8gSmVsbG8="),
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
	resp, err = Encrypt(encryptReq)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	if err = json.Unmarshal(resp, &status); err != nil || status.Status != "ok" {
		t.Fatalf("encrypt returned %v: %s", err, resp)
	}

	return status.Response
}

// delegateUses issues a delegation request through the public Delegate
// entry point with the requested number of uses.
func delegateUses(t *testing.T, uses int) {
	t.Helper()

	req, err := json.Marshal(DelegateRequest{
		Name:     "Alice",
		Password: "Hello",
		Time:     "1h",
		Uses:     uses,
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
	resp, err := Delegate(req)
	if err != nil {
		t.Fatalf("delegate failed: %v", err)
	}
	var status ResponseData
	if err = json.Unmarshal(resp, &status); err != nil || status.Status != "ok" {
		t.Fatalf("delegate returned %v: %s", err, resp)
	}
}

// decryptOnce drives one full public Decrypt request.
func decryptOnce(t *testing.T, encrypted []byte) error {
	t.Helper()

	req, err := json.Marshal(DecryptRequest{
		Name:     "Alice",
		Password: "Hello",
		Data:     encrypted,
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
	resp, err := Decrypt(req)
	if err != nil {
		return err
	}
	var status ResponseData
	if err = json.Unmarshal(resp, &status); err != nil {
		return err
	}
	if status.Status != "ok" {
		// Rejected requests must still leave the cache consistent.
		return errDecryptRejected
	}
	return nil
}

var errDecryptRejected = errors.New("decrypt returned a non-ok status")

// TestConcurrentDecryptHonoursUses fires many concurrent public
// Decrypt requests against a delegation with a small use budget. The
// number of successful requests must equal the delegated uses exactly,
// proving the read/check/decrement is one consumption transaction even
// under contention.
func TestConcurrentDecryptHonoursUses(t *testing.T) {
	const uses = 10
	encrypted := setupConcurrentVault(t)
	delegateUses(t, uses)

	const clients = 80
	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	success, failure := 0, 0

	wg.Add(clients)
	for i := 0; i < clients; i++ {
		go func() {
			defer wg.Done()
			<-start
			err := decryptOnce(t, encrypted)
			mu.Lock()
			if err == nil {
				success++
			} else {
				failure++
			}
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()

	if success != uses {
		t.Fatalf("successful decryptions = %d, want exactly %d (failures=%d)", success, uses, failure)
	}
	if success+failure != clients {
		t.Fatalf("accounting mismatch: %d ok + %d failed != %d", success, failure, clients)
	}

	// Every use is spent: the live cache must be empty, and a further
	// request must be rejected rather than overspending.
	if live := len(crypt.LiveSummary()); live != 0 {
		t.Fatalf("exhausted delegation left %d live entries: %v", live, crypt.LiveSummary())
	}
	if err := decryptOnce(t, encrypted); err == nil {
		t.Fatal("decryption succeeded after the delegation was exhausted")
	}
}

// TestSequentialDecryptConsumesEveryUse sanity-checks the old Uses
// semantics on the public path: sequential requests consume one use
// each and the delegation disappears exactly on the last one.
func TestSequentialDecryptConsumesEveryUse(t *testing.T) {
	const uses = 3
	encrypted := setupConcurrentVault(t)
	delegateUses(t, uses)

	for i := 0; i < uses; i++ {
		if err := decryptOnce(t, encrypted); err != nil {
			t.Fatalf("decryption %d failed: %v", i+1, err)
		}
		want := uses - i - 1
		if got := len(crypt.LiveSummary()); (want == 0) != (got == 0) {
			t.Fatalf("after %d uses live entries=%d, want emptiness=%v", i+1, got, want == 0)
		}
	}

	if err := decryptOnce(t, encrypted); err == nil {
		t.Fatal("decryption succeeded after the delegation was exhausted")
	}
}

// TestConcurrentRedelegateThenDecrypt ensures a re-delegation starts a
// fresh slot generation that concurrent decryptions converge on:
// failures against the old generation never corrupt the new use
// counter, and the new budget is still honoured exactly.
func TestConcurrentRedelegateThenDecrypt(t *testing.T) {
	encrypted := setupConcurrentVault(t)
	delegateUses(t, 1)

	// Consume the first generation, then accept a new delegation for
	// the same slot through the public Delegate request.
	if err := decryptOnce(t, encrypted); err != nil {
		t.Fatalf("initial decryption failed: %v", err)
	}
	delegateUses(t, 5)

	const clients = 40
	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	success, failure := 0, 0

	wg.Add(clients)
	for i := 0; i < clients; i++ {
		go func() {
			defer wg.Done()
			<-start
			err := decryptOnce(t, encrypted)
			mu.Lock()
			if err == nil {
				success++
			} else {
				failure++
			}
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()

	if success != 5 {
		t.Fatalf("successful decryptions = %d, want 5 from the new generation (failures=%d)", success, failure)
	}
	if len(crypt.LiveSummary()) != 0 {
		t.Fatalf("new generation not fully consumed: %v", crypt.LiveSummary())
	}
}
