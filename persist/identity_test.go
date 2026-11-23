package persist

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/cloudflare/redoctober/config"
)

func TestSnapshotIDFor(t *testing.T) {
	if SnapshotIDFor(nil) != "" {
		t.Fatal("empty blob should have the empty snapshot identity")
	}

	a := []byte("snapshot a")
	b := []byte("snapshot b")

	if SnapshotIDFor(a) != SnapshotIDFor(append([]byte{}, a...)) {
		t.Fatal("identical bytes must share one snapshot identity")
	}
	if SnapshotIDFor(a) == SnapshotIDFor(b) {
		t.Fatal("different snapshots must have different identities")
	}
}

func TestFileSnapshotIdentityStableAcrossLoad(t *testing.T) {
	sf, err := tempName()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(sf)

	cfg := &config.Delegations{
		Persist:   true,
		Mechanism: FileMechanism,
		Policy:    "alice & bob",
		Users:     []string{"alice", "bob"},
		Location:  sf,
	}

	first, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	first.Persist()

	blob := []byte("persisted snapshot")
	if err = first.Store(blob); err != nil {
		t.Fatal(err)
	}
	wantID := SnapshotIDFor(blob)
	if first.SnapshotID() != wantID {
		t.Fatalf("expected identity %s, have %s", wantID, first.SnapshotID())
	}

	// Simulate a restart: reloading the untouched file must expose
	// the same identity, so start-up loading and an explicit restore
	// share one snapshot identity.
	second, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if second.Status().State != Inactive {
		t.Fatalf("reloaded store should start %s, have %s", Inactive, second.Status().State)
	}
	if second.SnapshotID() != wantID {
		t.Fatalf("reloaded store identity %s != %s", second.SnapshotID(), wantID)
	}
	if string(second.Blob()) != string(blob) {
		t.Fatal("reloaded store should hold the original snapshot bytes")
	}

	// Purge must clear both the blob and its identity; the store
	// returns to a fresh, persisting state.
	if err = second.Purge(); err != nil {
		t.Fatal(err)
	}
	if second.SnapshotID() != "" {
		t.Fatalf("purged store should have no identity, have %s", second.SnapshotID())
	}
	if second.Blob() != nil {
		t.Fatal("purged store should have no blob")
	}
	if second.Status().State != Active {
		t.Fatalf("purged store should be %s, have %s", Active, second.Status().State)
	}
	if _, err = ioutil.ReadFile(sf); !os.IsNotExist(err) {
		t.Fatal("purged snapshot file should be removed")
	}
}

func TestFileStoreKeepsIdentityUntilWriteSucceeds(t *testing.T) {
	sf, err := tempName()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(sf)

	cfg := &config.Delegations{
		Persist:   true,
		Mechanism: FileMechanism,
		Policy:    "alice & bob",
		Users:     []string{"alice", "bob"},
		Location:  sf,
	}

	f, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.Persist()

	original := []byte("original snapshot")
	if err = f.Store(original); err != nil {
		t.Fatal(err)
	}
	originalID := f.SnapshotID()

	// A store that is not active must swallow the write and must not
	// move the identity (a failed retry can't partially advance it).
	file := f.(*File)
	file.state = Inactive
	if err = f.Store([]byte("new snapshot")); err != nil {
		t.Fatal(err)
	}
	if f.SnapshotID() != originalID {
		t.Fatal("inactive store must not change the snapshot identity")
	}
	if string(f.Blob()) != string(original) {
		t.Fatal("inactive store must keep the complete old snapshot")
	}
}
