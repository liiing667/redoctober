package passvault

import "testing"

func TestRevocationGeneration(t *testing.T) {
	records, err := InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}

	if _, err = records.AddNewRecord("alice", "weakpassword", true, DefaultRecordType); err != nil {
		t.Fatalf("%v", err)
	}

	if gen := records.RevokeGeneration("alice"); gen != 0 {
		t.Fatalf("fresh record should be generation 0, have %d", gen)
	}

	if err = records.RevokeRecord("alice"); err != nil {
		t.Fatalf("%v", err)
	}
	if gen := records.RevokeGeneration("alice"); gen != 1 {
		t.Fatalf("revoked record should be generation 1, have %d", gen)
	}

	if err = records.RevokeRecord("alice"); err != nil {
		t.Fatalf("%v", err)
	}
	if gen := records.RevokeGeneration("alice"); gen != 2 {
		t.Fatalf("twice revoked record should be generation 2, have %d", gen)
	}

	// A deleted record is treated as revoked: any persisted
	// delegation (generation 0+) must be considered stale.
	if err = records.DeleteRecord("alice"); err != nil {
		t.Fatalf("%v", err)
	}
	if gen := records.RevokeGeneration("alice"); gen == 0 {
		t.Fatal("deleted record should report a revoking generation")
	}
}
