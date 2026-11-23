package cryptor

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/cloudflare/redoctober/config"
	"github.com/cloudflare/redoctober/keycache"
	"github.com/cloudflare/redoctober/passvault"
	"github.com/cloudflare/redoctober/persist"
)

func newRestoreCryptor(t *testing.T, location string, records *passvault.Records) *Cryptor {
	t.Helper()

	cfg := &config.Delegations{
		Persist:   true,
		Mechanism: persist.FileMechanism,
		Location:  location,
		Policy:    "(Alice & Bob) | (Bob & Carl)",
		Users:     []string{"Alice", "Bob", "Carl"},
	}

	store, err := persist.New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	cache := keycache.NewCache()
	return &Cryptor{records: records, cache: &cache, persist: store}
}

// newActiveCryptor creates a cryptor whose store is actively
// persisting (the state of a running server before a restart).
func newActiveCryptor(t *testing.T, location string, records *passvault.Records) *Cryptor {
	c := newRestoreCryptor(t, location, records)
	c.persist.Persist()
	return c
}

func restoreUsers(t *testing.T) (map[string]passvault.PasswordRecord, *passvault.Records) {
	t.Helper()

	records, err := passvault.InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}

	recs := make(map[string]passvault.PasswordRecord)
	for _, name := range []string{"Alice", "Bob", "Carl"} {
		pr, err := records.AddNewRecord(name, "weakpassword", true, passvault.DefaultRecordType)
		if err != nil {
			t.Fatalf("%v", err)
		}
		recs[name] = pr
	}
	return recs, &records
}

// completeRestore drives a restore to completion using all three
// delegators.
func completeRestore(t *testing.T, c *Cryptor) {
	t.Helper()

	if err := c.Restore("Alice", "weakpassword", 2, "", "1h"); err != ErrRestoreDelegations {
		t.Fatalf("expected ErrRestoreDelegations, have %v", err)
	}
	if err := c.Restore("Carl", "weakpassword", 2, "", "1h"); err != ErrRestoreDelegations {
		t.Fatalf("expected ErrRestoreDelegations, have %v", err)
	}
	if err := c.Restore("Bob", "weakpassword", 2, "", "1h"); err != nil {
		t.Fatalf("restore should succeed, have %v", err)
	}
	if c.Status().State != persist.Active {
		t.Fatalf("store should be active after restore, have %s", c.Status().State)
	}
}

func TestRestoreDropsExpiredDelegations(t *testing.T) {
	temp, err := tempName()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(temp)

	recs, records := restoreUsers(t)
	c := newActiveCryptor(t, temp, records)

	if err = c.Delegate(recs["Alice"], "Alice", "weakpassword",
		[]string{"Bob"}, []string{}, 5, "", "1h"); err != nil {
		t.Fatal(err)
	}
	if err = c.Delegate(recs["Carl"], "Carl", "weakpassword",
		[]string{"Bob"}, []string{}, 5, "", "10ms"); err != nil {
		t.Fatal(err)
	}

	// Restart against the same on-disk snapshot.
	restarted := newRestoreCryptor(t, temp, records)

	// Let Carl's persisted delegation expire before the restore.
	time.Sleep(30 * time.Millisecond)

	completeRestore(t, restarted)

	if _, ok := restarted.cache.UserKeys[keycache.DelegateIndex{Name: "Alice"}]; !ok {
		t.Fatal("unexpired Alice delegation should have been restored")
	}
	if _, ok := restarted.cache.UserKeys[keycache.DelegateIndex{Name: "Carl"}]; ok {
		t.Fatal("expired Carl delegation should not have been restored")
	}
	if len(restarted.cache.UserKeys) != 1 {
		t.Fatalf("expected a single restored delegation, have %d", len(restarted.cache.UserKeys))
	}
}

func TestRestoreDropsRevokedDelegations(t *testing.T) {
	temp, err := tempName()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(temp)

	recs, records := restoreUsers(t)
	c := newActiveCryptor(t, temp, records)

	if err = c.Delegate(recs["Alice"], "Alice", "weakpassword",
		[]string{"Bob"}, []string{}, 5, "", "1h"); err != nil {
		t.Fatal(err)
	}
	if err = c.Delegate(recs["Carl"], "Carl", "weakpassword",
		[]string{"Bob"}, []string{}, 5, "", "1h"); err != nil {
		t.Fatal(err)
	}

	// Revoke Alice after her delegation was persisted.
	if err = records.RevokeRecord("Alice"); err != nil {
		t.Fatal(err)
	}

	restarted := newRestoreCryptor(t, temp, records)
	completeRestore(t, restarted)

	if _, ok := restarted.cache.UserKeys[keycache.DelegateIndex{Name: "Alice"}]; ok {
		t.Fatal("revoked Alice delegation should not have been restored")
	}
	if _, ok := restarted.cache.UserKeys[keycache.DelegateIndex{Name: "Carl"}]; !ok {
		t.Fatal("valid Carl delegation should have been restored")
	}
}

func TestRestoreRetriesLeaveOldSnapshotIntact(t *testing.T) {
	temp, err := tempName()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(temp)

	recs, records := restoreUsers(t)
	c := newActiveCryptor(t, temp, records)

	if err = c.Delegate(recs["Alice"], "Alice", "weakpassword",
		[]string{"Bob"}, []string{}, 5, "", "1h"); err != nil {
		t.Fatal(err)
	}

	restarted := newRestoreCryptor(t, temp, records)
	originalID := restarted.persist.SnapshotID()
	if originalID == "" {
		t.Fatal("loaded store should carry a snapshot identity")
	}

	// Several incomplete restore attempts must not mutate any shared
	// state: the store stays inactive and keeps the exact snapshot.
	for i := 0; i < 3; i++ {
		if err = restarted.Restore("Alice", "weakpassword", 2, "", "1h"); err != ErrRestoreDelegations {
			t.Fatalf("attempt %d: expected ErrRestoreDelegations, have %v", i, err)
		}
		if restarted.Status().State != persist.Inactive {
			t.Fatalf("attempt %d: store should remain inactive", i)
		}
		if restarted.persist.SnapshotID() != originalID {
			t.Fatalf("attempt %d: failed retry changed the snapshot identity", i)
		}
		if len(restarted.cache.UserKeys) != 0 {
			t.Fatalf("attempt %d: failed retry leaked delegations into the live cache", i)
		}
	}

	// Completing the restore activates one complete, approved
	// snapshot rather than a partial merge.
	completeRestore(t, restarted)
	if _, ok := restarted.cache.UserKeys[keycache.DelegateIndex{Name: "Alice"}]; !ok {
		t.Fatal("Alice delegation should have been restored on success")
	}
}

func TestRestoreRejectsForeignSnapshotIdentity(t *testing.T) {
	temp, err := tempName()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(temp)

	recs, records := restoreUsers(t)
	c := newActiveCryptor(t, temp, records)

	if err = c.Delegate(recs["Alice"], "Alice", "weakpassword",
		[]string{"Bob"}, []string{}, 5, "", "1h"); err != nil {
		t.Fatal(err)
	}

	restarted := newRestoreCryptor(t, temp, records)

	// Tamper with the on-disk snapshot after start-up: the store's
	// loaded identity no longer matches the blob that Restore would
	// decrypt, so the restore must be rejected.
	tampered := append(append([]byte{}, restarted.persist.Blob()...), 0)
	if err = ioutil.WriteFile(temp, tampered, 0644); err != nil {
		t.Fatal(err)
	}

	if err = restarted.Restore("Alice", "weakpassword", 2, "", "1h"); err == nil {
		t.Fatal("restore of a foreign snapshot should fail")
	}
	if restarted.Status().State != persist.Inactive {
		t.Fatal("rejected restore must leave the store inactive")
	}
	if len(restarted.cache.UserKeys) != 0 {
		t.Fatal("rejected restore must not touch the live cache")
	}
}

func TestResetPersistedClearsSnapshot(t *testing.T) {
	temp, err := tempName()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(temp)

	recs, records := restoreUsers(t)
	c := newActiveCryptor(t, temp, records)

	if err = c.Delegate(recs["Alice"], "Alice", "weakpassword",
		[]string{"Bob"}, []string{}, 5, "", "1h"); err != nil {
		t.Fatal(err)
	}

	st, err := c.ResetPersisted()
	if err != nil {
		t.Fatalf("ResetPersisted failed: %v", err)
	}
	if st.State != persist.Active {
		t.Fatalf("after reset the store should be %s, have %s", persist.Active, st.State)
	}
	if c.persist.SnapshotID() != "" || c.persist.Blob() != nil {
		t.Fatal("after reset no snapshot identity or blob should remain")
	}
	if _, err = os.Stat(temp); !os.IsNotExist(err) {
		t.Fatal("reset should remove the persisted file")
	}
}

// TestRestoreLegacySnapshotFormat makes sure snapshots written by
// older servers that persisted a bare key cache summary (no envelope
// version) can still be restored.
func TestRestoreLegacySnapshotFormat(t *testing.T) {
	temp, err := tempName()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(temp)

	recs, records := restoreUsers(t)
	c := newActiveCryptor(t, temp, records)

	if err = c.Delegate(recs["Alice"], "Alice", "weakpassword",
		[]string{"Bob"}, []string{}, 5, "", "1h"); err != nil {
		t.Fatal(err)
	}

	// Rewrite the persisted payload in the legacy, un-enveloped
	// format (re-encrypted with the same restore policy).
	legacy, err := json.Marshal(c.cache.GetSummary())
	if err != nil {
		t.Fatal(err)
	}
	access := AccessStructure{
		Names:     c.persist.Users(),
		Predicate: c.persist.Policy(),
	}
	legacyBlob, err := c.Encrypt(legacy, persist.Labels, persist.Usages, access)
	if err != nil {
		t.Fatal(err)
	}
	if err = ioutil.WriteFile(temp, legacyBlob, 0644); err != nil {
		t.Fatal(err)
	}

	restarted := newRestoreCryptor(t, temp, records)
	completeRestore(t, restarted)

	if _, ok := restarted.cache.UserKeys[keycache.DelegateIndex{Name: "Alice"}]; !ok {
		t.Fatal("legacy snapshot delegation should have been restored")
	}
}
