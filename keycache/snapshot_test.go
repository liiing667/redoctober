// snapshot_test.go: tests for cache snapshot/rollback used by re-encryption.
//
// Copyright (c) 2013 CloudFlare, Inc.

package keycache

import (
	"testing"

	"github.com/cloudflare/redoctober/passvault"
	"github.com/cloudflare/redoctober/symcrypt"
)

func TestSnapshotRollback(t *testing.T) {
	records, err := passvault.InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}

	pr, err := records.AddNewRecord("user", "weakpassword", true, passvault.DefaultRecordType)
	if err != nil {
		t.Fatalf("%v", err)
	}

	cache := NewCache()
	if err = cache.AddKeyFromRecord(pr, "user", "weakpassword", nil, nil, 2, "", "1h"); err != nil {
		t.Fatalf("%v", err)
	}

	snapshot := cache.Snapshot()
	if len(snapshot) != 1 {
		t.Fatalf("snapshot should contain one delegation, got %d", len(snapshot))
	}

	// Consume a delegated key use, which decrements the counter.
	dummy := make([]byte, 16)
	key, err := symcrypt.MakeRandom(16)
	if err != nil {
		t.Fatalf("%v", err)
	}
	encKey, err := symcrypt.EncryptCBC(dummy, dummy, key)
	if err != nil {
		t.Fatalf("%v", err)
	}
	pubEncryptedKey, err := pr.EncryptKey(key)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if _, err = cache.DecryptKey(encKey, "user", "anybody", []string{}, pubEncryptedKey); err != nil {
		t.Fatalf("%v", err)
	}

	// The snapshot must not be affected by the later mutation.
	if got := snapshot[DelegateIndex{Name: "user"}].Usage.Uses; got != 2 {
		t.Fatalf("snapshot mutated after DecryptKey: uses=%d", got)
	}

	// Roll back the consumed use.
	cache.Rollback(snapshot)
	if got := cache.UserKeys[DelegateIndex{Name: "user"}].Usage.Uses; got != 2 {
		t.Fatalf("rollback did not restore uses: got %d", got)
	}

	// Rolling back to an empty snapshot purges the cache.
	cache.Rollback(map[DelegateIndex]ActiveUser{})
	if len(cache.UserKeys) != 0 {
		t.Fatalf("expected empty cache after rolling back to empty snapshot")
	}
}
