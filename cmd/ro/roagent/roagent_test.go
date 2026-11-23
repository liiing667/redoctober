// roagent_test.go: tests for the ROAgent signing chain.

package roagent

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	roclient "github.com/cloudflare/redoctober/client"
	"golang.org/x/crypto/ssh"
)

// testAgent returns an ROAgent pointed at an unreachable Red October
// server. All staleness checks happen before any network access, and
// the unreachable server exercises the failure-eviction path.
func testAgent(t *testing.T) *ROAgent {
	server, err := roclient.NewRemoteServer("127.0.0.1:1", "")
	if err != nil {
		t.Fatalf("error creating test client: %v", err)
	}
	return NewROAgent(server, "user", "pass")
}

func testPubKey(t *testing.T) ssh.PublicKey {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("error generating test key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("error generating test key: %v", err)
	}
	return signer.PublicKey()
}

func addTestSigner(t *testing.T, agent *ROAgent) ssh.PublicKey {
	pub := testPubKey(t)
	err := agent.Add(AddedKey{PrivateKey: &ROSigner{pub: pub, encKey: []byte("enc-key")}})
	if err != nil {
		t.Fatalf("error adding test signer: %v", err)
	}
	return pub
}

// TestRemoveDeletesRequestedKey ensures that removing a key that is
// not at the head of the keyring removes that key and no other.
func TestRemoveDeletesRequestedKey(t *testing.T) {
	agent := testAgent(t)
	pub1 := addTestSigner(t, agent)
	pub2 := addTestSigner(t, agent)

	if err := agent.Remove(pub2); err != nil {
		t.Fatalf("error removing second key: %v", err)
	}

	keys, err := agent.List()
	if err != nil {
		t.Fatalf("error listing keys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key after removal, got %d", len(keys))
	}
	if keys[0].Type() != pub1.Type() || string(keys[0].Marshal()) != string(pub1.Marshal()) {
		t.Fatalf("wrong key removed: expected %v to remain", pub1.Marshal())
	}

	if err := agent.Remove(pub2); err == nil {
		t.Fatalf("expected error removing already-removed key")
	}
}

// TestStaleSignerAfterRemove ensures a signer handle minted before a
// removal can no longer sign afterwards.
func TestStaleSignerAfterRemove(t *testing.T) {
	agent := testAgent(t)
	pub := addTestSigner(t, agent)

	signers, err := agent.Signers()
	if err != nil {
		t.Fatalf("error getting signers: %v", err)
	}
	if len(signers) != 1 {
		t.Fatalf("expected 1 signer, got %d", len(signers))
	}

	if err := agent.Remove(pub); err != nil {
		t.Fatalf("error removing key: %v", err)
	}

	if _, err := signers[0].Sign(rand.Reader, []byte("data")); err != errStaleSigner {
		t.Fatalf("expected stale signer error after removal, got %v", err)
	}
}

// TestLockInvalidatesSigners ensures a locked agent cannot serve old
// signing requests, and that RemoveAll also invalidates old handles.
func TestLockInvalidatesSigners(t *testing.T) {
	agent := testAgent(t)
	addTestSigner(t, agent)

	signers, err := agent.Signers()
	if err != nil {
		t.Fatalf("error getting signers: %v", err)
	}

	if err := agent.Lock([]byte("pass")); err != nil {
		t.Fatalf("error locking agent: %v", err)
	}

	if _, err := signers[0].Sign(rand.Reader, []byte("data")); err != errLocked {
		t.Fatalf("expected locked error, got %v", err)
	}

	if keys, _ := agent.List(); len(keys) != 0 {
		t.Fatalf("locked agent must list no keys, got %d", len(keys))
	}

	if err := agent.Unlock([]byte("pass")); err != nil {
		t.Fatalf("error unlocking agent: %v", err)
	}

	// After RemoveAll, handles minted beforehand are stale.
	signers, err = agent.Signers()
	if err != nil {
		t.Fatalf("error getting signers: %v", err)
	}
	if err := agent.RemoveAll(); err != nil {
		t.Fatalf("error removing all keys: %v", err)
	}
	if _, err := signers[0].Sign(rand.Reader, []byte("data")); err != errStaleSigner {
		t.Fatalf("expected stale signer error after RemoveAll, got %v", err)
	}
}

// TestFailedSignEvicts ensures a failed signing attempt does not leave
// a usable signer behind for retries.
func TestFailedSignEvicts(t *testing.T) {
	agent := testAgent(t)
	pub := addTestSigner(t, agent)

	// The test server is unreachable, so the sign must fail.
	if _, err := agent.Sign(pub, []byte("data")); err == nil {
		t.Fatalf("expected signing against unreachable server to fail")
	}

	keys, err := agent.List()
	if err != nil {
		t.Fatalf("error listing keys: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("expected failed signer to be evicted, %d keys remain", len(keys))
	}

	if _, err := agent.Sign(pub, []byte("data")); err == nil {
		t.Fatalf("expected retry with evicted signer to fail")
	}
}
