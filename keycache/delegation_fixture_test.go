// delegation_fixture_test.go: fixed fixtures for label/owner admission
// and slot-pinning behaviour of delegated keys.
//
// Copyright (c) 2013 CloudFlare, Inc.
package keycache

import (
	"bytes"
	"testing"

	"github.com/cloudflare/redoctober/passvault"
)

// delegationFixture bundles a cache, the delegator record and the
// wrapped-key material a caller would hand to DecryptKey*. Each fixture
// reports both the decryption verdict and the slot that actually
// performed it, so tests can assert on the chosen delegation identity
// rather than only on success/failure.
type delegationFixture struct {
	t       *testing.T
	cache   Cache
	record  passvault.PasswordRecord
	block   []byte
	wrapped []byte
}

func newDelegationFixture(t *testing.T) *delegationFixture {
	t.Helper()

	records, err := passvault.InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}

	pr, err := records.AddNewRecord("user", "weakpassword", true, passvault.DefaultRecordType)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// A 16-byte all-zero block encrypted with a random AES key; the AES
	// key is then wrapped to the delegator's public key.
	block := make([]byte, 16)
	wrapped, err := pr.EncryptKey(block)
	if err != nil {
		t.Fatalf("%v", err)
	}

	return &delegationFixture{
		t:       t,
		cache:   NewCache(),
		record:  pr,
		block:   block,
		wrapped: wrapped,
	}
}

func (f *delegationFixture) delegate(users, labels []string, uses int, slot string) {
	f.t.Helper()
	if err := f.cache.AddKeyFromRecord(f.record, "user", "weakpassword", users, labels, uses, slot, "1h"); err != nil {
		f.t.Fatalf("%v", err)
	}
}

// decrypt runs the slot-pinned decryption and returns the verdict plus
// the slot evidence.
func (f *delegationFixture) decrypt(user, slot string, labels []string) (ok bool, usedSlot string) {
	f.t.Helper()
	out, usedSlot, err := f.cache.DecryptKeySlot(f.block, "user", user, slot, labels, f.wrapped)
	if err != nil {
		return false, usedSlot
	}
	// The block is all zeroes and the wrapping key is the block itself;
	// a correct round trip must reproduce those zeroes.
	if !bytes.Equal(out, f.block) {
		f.t.Fatalf("decrypted block did not round-trip")
	}
	return true, usedSlot
}

func (f *delegationFixture) liveSlots() map[string]ActiveUser {
	f.t.Helper()
	return f.cache.UserKeys
}

// TestRestrictedDelegationRejectsUnlabelledCiphertext guards the core
// admission rule: a label-restricted delegation must not be treated as a
// match for ciphertext that carries no labels, and the rejected attempt
// must not consume a use.
func TestRestrictedDelegationRejectsUnlabelledCiphertext(t *testing.T) {
	f := newDelegationFixture(t)
	f.delegate(nil, []string{"red"}, 1, "")

	if ok, _ := f.decrypt("anybody", "", nil); ok {
		t.Fatal("label-restricted delegation matched unlabelled ciphertext")
	}

	if len(f.liveSlots()) != 1 {
		t.Fatalf("rejected decryption consumed a use, live=%d", len(f.liveSlots()))
	}

	// The same delegation still works once the ciphertext carries the
	// matching label, proving the restriction (not the delegation) was
	// the blocker.
	if ok, _ := f.decrypt("anybody", "", []string{"red"}); !ok {
		t.Fatal("matching label was rejected")
	}
	if len(f.liveSlots()) != 0 {
		t.Fatalf("successful decryption should exhaust the single use, live=%d", len(f.liveSlots()))
	}
}

// TestRestrictedDelegationRejectsWrongLabel ensures a non-matching label
// is rejected at admission without burning a use.
func TestRestrictedDelegationRejectsWrongLabel(t *testing.T) {
	f := newDelegationFixture(t)
	f.delegate(nil, []string{"red"}, 1, "")

	if ok, _ := f.decrypt("anybody", "", []string{"blue"}); ok {
		t.Fatal("label-restricted delegation matched a differently labelled ciphertext")
	}
	if len(f.liveSlots()) != 1 {
		t.Fatalf("wrong-label attempt consumed a use, live=%d", len(f.liveSlots()))
	}
}

// TestUnrestrictedDelegationStillMatches makes sure a delegation without
// labels continues to decrypt both labelled and unlabelled ciphertext.
func TestUnrestrictedDelegationStillMatches(t *testing.T) {
	f := newDelegationFixture(t)
	f.delegate(nil, nil, 3, "")

	if ok, _ := f.decrypt("anybody", "", nil); !ok {
		t.Fatal("unrestricted delegation rejected unlabelled ciphertext")
	}
	if ok, _ := f.decrypt("anybody", "", []string{"red"}); !ok {
		t.Fatal("unrestricted delegation rejected labelled ciphertext")
	}
	if len(f.liveSlots()) != 1 || f.liveSlots()[DelegateIndex{Name: "user"}].Usage.Uses != 1 {
		t.Fatalf("unrestricted delegation use accounting wrong: %+v", f.liveSlots())
	}
}

// TestSlotPinningPicksTheSameIdentity registers two delegations for the
// same delegator in distinct slots and proves that a slot-pinned
// decryption always consumes the named slot rather than whichever slot
// the backing map happens to surface first.
func TestSlotPinningPicksTheSameIdentity(t *testing.T) {
	f := newDelegationFixture(t)
	// Two slots, each with a single use; only slot "b" is label-scoped.
	f.delegate(nil, nil, 1, "a")
	f.delegate(nil, []string{"red"}, 1, "b")

	if len(f.liveSlots()) != 2 {
		t.Fatalf("expected two live slots, got %d", len(f.liveSlots()))
	}

	// Pinning slot "a" for an unlabelled ciphertext must use "a" and
	// leave the restricted slot "b" untouched.
	ok, used := f.decrypt("anybody", "a", nil)
	if !ok {
		t.Fatal("slot a decryption failed")
	}
	if used != "a" {
		t.Fatalf("expected slot a, decryption was served by slot %q", used)
	}
	if _, present := f.liveSlots()[DelegateIndex{Name: "user", Slot: "a"}]; present {
		t.Fatal("pinned slot a was not consumed")
	}
	if _, present := f.liveSlots()[DelegateIndex{Name: "user", Slot: "b"}]; !present {
		t.Fatal("restricted slot b was incorrectly consumed by slot a decryption")
	}

	// The restricted slot must still reject unlabelled ciphertext and
	// preserve its use.
	if ok, _ := f.decrypt("anybody", "b", nil); ok {
		t.Fatal("restricted slot b matched unlabelled ciphertext")
	}
	if _, present := f.liveSlots()[DelegateIndex{Name: "user", Slot: "b"}]; !present {
		t.Fatal("rejected slot b decryption consumed its use")
	}

	// With the right label, slot b is the identity that performs the
	// final decryption.
	ok, used = f.decrypt("anybody", "b", []string{"red"})
	if !ok {
		t.Fatal("slot b decryption with matching label failed")
	}
	if used != "b" {
		t.Fatalf("expected slot b, decryption was served by slot %q", used)
	}
	if len(f.liveSlots()) != 0 {
		t.Fatalf("expected all slots exhausted, live=%d", len(f.liveSlots()))
	}
}

// TestRetryConsumesTheSameSlot exercises a repeated pinned decryption:
// the first call uses one of two uses and a retry lands on the very same
// slot rather than drifting to a sibling.
func TestRetryConsumesTheSameSlot(t *testing.T) {
	f := newDelegationFixture(t)
	f.delegate(nil, nil, 2, "a")
	f.delegate(nil, nil, 2, "b")

	for i := 0; i < 2; i++ {
		ok, used := f.decrypt("anybody", "a", nil)
		if !ok {
			t.Fatalf("retry %d on slot a failed", i)
		}
		if used != "a" {
			t.Fatalf("retry %d drifted to slot %q", i, used)
		}
	}

	a := f.liveSlots()[DelegateIndex{Name: "user", Slot: "a"}]
	b := f.liveSlots()[DelegateIndex{Name: "user", Slot: "b"}]
	if a.Usage.Uses != 0 {
		t.Fatalf("slot a should be exhausted, uses=%d", a.Usage.Uses)
	}
	if b.Usage.Uses != 2 {
		t.Fatalf("slot b should be untouched, uses=%d", b.Usage.Uses)
	}
}

// TestOwnerUserRestrictionAdmission covers the owner-side Users list: a
// delegation limited to a set of users only admits those users, and a
// rejected user does not spend a use.
func TestOwnerUserRestrictionAdmission(t *testing.T) {
	f := newDelegationFixture(t)
	f.delegate([]string{"alice"}, []string{"red"}, 1, "")

	if ok, _ := f.decrypt("mallory", "", []string{"red"}); ok {
		t.Fatal("delegation admitted a user outside its Users list")
	}
	if len(f.liveSlots()) != 1 {
		t.Fatalf("unauthorised user consumed a use, live=%d", len(f.liveSlots()))
	}

	if ok, _ := f.decrypt("alice", "", []string{"red"}); !ok {
		t.Fatal("authorised user was rejected")
	}
	if len(f.liveSlots()) != 0 {
		t.Fatalf("authorised decryption did not consume the use, live=%d", len(f.liveSlots()))
	}
}
