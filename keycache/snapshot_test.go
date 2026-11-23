package keycache

import (
	"testing"
	"time"

	"github.com/cloudflare/redoctober/passvault"
)

func snapshotFixture(t *testing.T) map[string]ActiveUser {
	t.Helper()

	records, err := passvault.InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}

	users := []string{"alice", "bob", "carol"}
	out := make(map[string]ActiveUser)
	for _, user := range users {
		pr, err := records.AddNewRecord(user, "weakpassword", true, passvault.DefaultRecordType)
		if err != nil {
			t.Fatalf("%v", err)
		}

		cache := NewCache()
		if err = cache.AddKeyFromRecord(pr, user, "weakpassword",
			[]string{"ci"}, []string{"red"}, 1, "", "1h"); err != nil {
			t.Fatalf("%v", err)
		}

		for di, active := range cache.UserKeys {
			out[di.Name] = active
		}
	}

	return out
}

func TestRestoreFromSnapshotDropsExpired(t *testing.T) {
	users := snapshotFixture(t)

	expired := users["alice"]
	expired.Expiry = time.Now().Add(-time.Minute)
	users["alice"] = expired

	snapshot := Snapshot{
		ID:    "snapshot-1",
		Users: users,
	}

	cache, err := RestoreFromSnapshot(snapshot, nil)
	if err != nil {
		t.Fatalf("RestoreFromSnapshot failed: %v", err)
	}

	if _, ok := cache.UserKeys[DelegateIndex{Name: "alice"}]; ok {
		t.Fatal("expired delegation should not have been restored")
	}
	if _, ok := cache.UserKeys[DelegateIndex{Name: "bob"}]; !ok {
		t.Fatal("valid delegation should have been restored")
	}
	if _, ok := cache.UserKeys[DelegateIndex{Name: "carol"}]; !ok {
		t.Fatal("valid delegation should have been restored")
	}
	if len(cache.UserKeys) != 2 {
		t.Fatalf("expected 2 restored delegations, have %d", len(cache.UserKeys))
	}
}

func TestRestoreFromSnapshotDropsRevoked(t *testing.T) {
	users := snapshotFixture(t)

	// Alice's persisted delegation is generation 0; the vault now
	// reports generation 2 because her record was revoked twice.
	valid := func(index DelegateIndex, user ActiveUser) bool {
		generations := map[string]uint64{
			"alice": 2,
			"bob":   0,
			"carol": 0,
		}
		return !user.Usage.Revoked(generations[index.Name])
	}

	cache, err := RestoreFromSnapshot(Snapshot{ID: "snapshot-1", Users: users}, valid)
	if err != nil {
		t.Fatalf("RestoreFromSnapshot failed: %v", err)
	}

	if _, ok := cache.UserKeys[DelegateIndex{Name: "alice"}]; ok {
		t.Fatal("revoked delegation should not have been restored")
	}
	if len(cache.UserKeys) != 2 {
		t.Fatalf("expected 2 restored delegations, have %d", len(cache.UserKeys))
	}
}

func TestRestoreFromSnapshotAtomicOnBadKey(t *testing.T) {
	users := snapshotFixture(t)

	bad := users["bob"]
	bad.Key = []byte("not a private key")
	users["bob"] = bad

	if _, err := RestoreFromSnapshot(Snapshot{ID: "snapshot-1", Users: users}, nil); err == nil {
		t.Fatal("restore should fail when a retained entry's key cannot parse")
	}
}

func TestUsageExpiryAndRevocation(t *testing.T) {
	valid := Usage{Expiry: time.Now().Add(time.Hour), Generation: 1}
	if valid.Expired() {
		t.Fatal("delegation in the future should not be expired")
	}
	if valid.Revoked(1) {
		t.Fatal("matching generation should not be revoked")
	}
	if !valid.Revoked(2) {
		t.Fatal("newer generation should revoke the delegation")
	}

	expired := Usage{Expiry: time.Now().Add(-time.Hour), Generation: 1}
	if !expired.Expired() {
		t.Fatal("delegation in the past should be expired")
	}

	zero := Usage{Generation: 0}
	if zero.Expired() {
		t.Fatal("zero expiry should never expire")
	}
}
