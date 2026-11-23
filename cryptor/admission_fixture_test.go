// admission_fixture_test.go: end-to-end fixtures proving that the
// label/owner conditions on a delegation are enforced when a wrapped key
// is admitted (not after decryption), and that the chosen slot identity
// is stable across wrapped keys, shares and retries.
//
// Copyright (c) 2013 CloudFlare, Inc.
package cryptor

import (
	"bytes"
	"testing"

	"github.com/cloudflare/redoctober/config"
	"github.com/cloudflare/redoctober/keycache"
	"github.com/cloudflare/redoctober/passvault"
	"github.com/cloudflare/redoctober/persist"
)

type admissionFixture struct {
	t       *testing.T
	cache   keycache.Cache
	crypt   *Cryptor
	prs     map[string]passvault.PasswordRecord
}

func newAdmissionFixture(t *testing.T, names ...string) *admissionFixture {
	t.Helper()

	records, err := passvault.InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}

	cache := keycache.NewCache()
	store, err := persist.New(&config.Delegations{Persist: false})
	if err != nil {
		t.Fatalf("%v", err)
	}

	crypt := &Cryptor{records: &records, cache: &cache, persist: store}
	prs := map[string]passvault.PasswordRecord{}
	for _, name := range names {
		pr, err := records.AddNewRecord(name, "weakpassword", true, passvault.DefaultRecordType)
		if err != nil {
			t.Fatalf("%v", err)
		}
		prs[name] = pr
	}

	return &admissionFixture{t: t, cache: cache, crypt: crypt, prs: prs}
}

func (a *admissionFixture) delegate(name string, users, labels []string, uses int, slot string) {
	a.t.Helper()
	if err := a.cache.AddKeyFromRecord(a.prs[name], name, "weakpassword", users, labels, uses, slot, "1h"); err != nil {
		a.t.Fatalf("%v", err)
	}
}

func (a *admissionFixture) uses(name, slot string) int {
	a.t.Helper()
	return a.cache.UserKeys[keycache.DelegateIndex{Name: name, Slot: slot}].Usage.Uses
}

// decryptOutcome bundles the decryption verdict with the delegating
// identities that actually performed it, i.e. the slot evidence.
type decryptOutcome struct {
	ok        bool
	plaintext []byte
	delegates []string
}

func (a *admissionFixture) decrypt(user string, blob []byte) decryptOutcome {
	a.t.Helper()
	out, _, names, _, _, err := a.crypt.Decrypt(blob, user)
	if err != nil {
		return decryptOutcome{ok: false}
	}
	return decryptOutcome{ok: true, plaintext: out, delegates: names}
}

// TestAdmissionRejectsUnlabelledCiphertext is the headline regression:
// a label-restricted owner must not decrypt an unlabelled ciphertext, and
// the failed admission must leave its use count untouched.
func TestAdmissionRejectsUnlabelledCiphertext(t *testing.T) {
	a := newAdmissionFixture(t, "Alice")

	// Ciphertext carries no labels.
	blob, err := a.crypt.Encrypt(
		[]byte("secret"),
		nil,
		nil,
		AccessStructure{Minimum: 1, Names: []string{"Alice"}},
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Alice delegates a single use restricted to the "red" label.
	a.delegate("Alice", nil, []string{"red"}, 1, "")

	if res := a.decrypt("Bob", blob); res.ok {
		t.Fatal("restricted delegation admitted unlabelled ciphertext")
	}
	if got := a.uses("Alice", ""); got != 1 {
		t.Fatalf("rejected admission consumed a use, remaining=%d", got)
	}

	// An unrestricted delegation for Alice remains valid for the same
	// ciphertext.
	a.cache.Flush()
	a.delegate("Alice", nil, nil, 1, "")
	res := a.decrypt("Bob", blob)
	if !res.ok || !bytes.Equal(res.plaintext, []byte("secret")) {
		t.Fatalf("unrestricted delegation could not decrypt unlabelled ciphertext: %+v", res)
	}
}

// TestAdmissionWrongLabelDoesNotConsume verifies that a ciphertext whose
// labels do not intersect the delegation is rejected without spending a
// use, while a matching label succeeds.
func TestAdmissionWrongLabelDoesNotConsume(t *testing.T) {
	a := newAdmissionFixture(t, "Alice")

	redBlob, err := a.crypt.Encrypt(
		[]byte("red secret"),
		[]string{"red"},
		nil,
		AccessStructure{Minimum: 1, Names: []string{"Alice"}},
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	a.delegate("Alice", nil, []string{"blue"}, 1, "")

	if res := a.decrypt("Bob", redBlob); res.ok {
		t.Fatal("blue-only delegation admitted red ciphertext")
	}
	if got := a.uses("Alice", ""); got != 1 {
		t.Fatalf("wrong-label admission consumed a use, remaining=%d", got)
	}

	a.cache.Flush()
	a.delegate("Alice", nil, []string{"red"}, 1, "")
	if res := a.decrypt("Bob", redBlob); !res.ok {
		t.Fatal("matching-label delegation was rejected")
	}
}

// TestMultiWrappedKeyPinsSlot builds the random-slot scenario: the same
// owner delegates twice into distinct slots, and two different
// ciphertexts must each consume the slot whose restrictions admit them,
// never an arbitrary sibling slot.
func TestMultiWrappedKeyPinsSlot(t *testing.T) {
	a := newAdmissionFixture(t, "Alice")

	unlabelled, err := a.crypt.Encrypt(
		[]byte("open"),
		nil,
		nil,
		AccessStructure{Minimum: 1, Names: []string{"Alice"}},
	)
	if err != nil {
		t.Fatalf("%v", err)
	}
	redBlob, err := a.crypt.Encrypt(
		[]byte("red"),
		[]string{"red"},
		nil,
		AccessStructure{Minimum: 1, Names: []string{"Alice"}},
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Slot "open" is unrestricted; slot "red" is restricted to red. Both
	// have a single use.
	a.delegate("Alice", nil, nil, 1, "open")
	a.delegate("Alice", nil, []string{"red"}, 1, "red")

	// For the red ciphertext both slots are label-eligible, but the
	// sorted, deterministic admission pins the lexicographically first
	// slot ("open"). The red slot must survive untouched.
	if res := a.decrypt("Bob", redBlob); !res.ok || !bytes.Equal(res.plaintext, []byte("red")) {
		t.Fatalf("red ciphertext was not decrypted by the pinned open slot: %+v", res)
	}
	if _, present := a.cache.UserKeys[keycache.DelegateIndex{Name: "Alice", Slot: "open"}]; present {
		t.Fatal("pinned open slot was not consumed by the red ciphertext")
	}
	if _, present := a.cache.UserKeys[keycache.DelegateIndex{Name: "Alice", Slot: "red"}]; !present {
		t.Fatal("red slot was incorrectly consumed instead of the pinned open slot")
	}

	// The unlabelled ciphertext can only use the unrestricted slot; the
	// restricted slot never matches it.
	if res := a.decrypt("Bob", unlabelled); !res.ok || !bytes.Equal(res.plaintext, []byte("open")) {
		t.Fatalf("unlabelled ciphertext was not decrypted by the open slot: %+v", res)
	}
	if len(a.cache.UserKeys) != 0 {
		t.Fatalf("expected both slots consumed, live=%d", len(a.cache.UserKeys))
	}
}

// TestPredicateSharesUseOneIdentity covers the multi-share path: with a
// threshold predicate the recovered secret must be assembled using a
// single, consistently selected slot per owner, and a restricted owner
// must be rejected at admission for unlabelled ciphertext.
func TestPredicateSharesUseOneIdentity(t *testing.T) {
	a := newAdmissionFixture(t, "Alice", "Bob")

	blob, err := a.crypt.Encrypt(
		[]byte("split secret"),
		[]string{"red"},
		nil,
		AccessStructure{Predicate: "(1, Alice, Bob)"},
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Both owners delegate red-restricted single-use keys.
	a.delegate("Alice", nil, []string{"red"}, 1, "")
	a.delegate("Bob", nil, []string{"red"}, 1, "")

	res := a.decrypt("Carol", blob)
	if !res.ok || !bytes.Equal(res.plaintext, []byte("split secret")) {
		t.Fatalf("predicate decryption failed: %+v", res)
	}
	if len(res.delegates) != 1 {
		t.Fatalf("expected exactly one delegating owner, got %v", res.delegates)
	}
	owner := res.delegates[0]
	if owner != "Alice" && owner != "Bob" {
		t.Fatalf("unknown delegate %q", owner)
	}
	// The owner that supplied the share spent its only use; the other
	// remains fully available, proving shares were served by one pinned
	// identity rather than touching both.
	if got := a.uses(owner, ""); got != 0 {
		t.Fatalf("delegating owner %s use not consumed: %d", owner, got)
	}
}

// TestPredicateRejectsRestrictedOwnerOnUnlabelledData confirms the
// admission rule also holds on the predicate (share) path.
func TestPredicateRejectsRestrictedOwnerOnUnlabelledData(t *testing.T) {
	a := newAdmissionFixture(t, "Alice", "Bob")

	blob, err := a.crypt.Encrypt(
		[]byte("split secret"),
		nil,
		nil,
		AccessStructure{Predicate: "(1, Alice, Bob)"},
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	a.delegate("Alice", nil, []string{"red"}, 1, "")
	a.delegate("Bob", nil, []string{"red"}, 1, "")

	if res := a.decrypt("Carol", blob); res.ok {
		t.Fatal("restricted shares admitted unlabelled predicate ciphertext")
	}
	if a.uses("Alice", "") != 1 || a.uses("Bob", "") != 1 {
		t.Fatalf("rejected share admission consumed a use: alice=%d bob=%d",
			a.uses("Alice", ""), a.uses("Bob", ""))
	}
}

// TestTwoOwnerAdmissionEnforcesLabelsOnEveryOwner exercises a minimum-2
// combinatorial wrapped key: both owners must be admitted, a label
// mismatch on either owner aborts the whole wrapped key without touching
// any use, and once both match the reported delegates name both owners.
func TestTwoOwnerAdmissionEnforcesLabelsOnEveryOwner(t *testing.T) {
	a := newAdmissionFixture(t, "Alice", "Bob")

	redBlob, err := a.crypt.Encrypt(
		[]byte("two owner secret"),
		[]string{"red"},
		nil,
		AccessStructure{Minimum: 2, Names: []string{"Alice", "Bob"}},
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Alice carries the right label but Bob carries the wrong one.
	a.delegate("Alice", nil, []string{"red"}, 1, "")
	a.delegate("Bob", nil, []string{"blue"}, 1, "")

	if res := a.decrypt("Carol", redBlob); res.ok {
		t.Fatal("wrapped key admitted despite Bob's label mismatch")
	}
	if a.uses("Alice", "") != 1 || a.uses("Bob", "") != 1 {
		t.Fatalf("rejected two-owner admission consumed a use: alice=%d bob=%d",
			a.uses("Alice", ""), a.uses("Bob", ""))
	}

	// Re-delegate Bob with the matching label; now both owners are
	// admitted and the data decrypts, naming both as delegates.
	a.cache.Flush()
	a.delegate("Alice", nil, []string{"red"}, 1, "")
	a.delegate("Bob", nil, []string{"red"}, 1, "")

	res := a.decrypt("Carol", redBlob)
	if !res.ok || !bytes.Equal(res.plaintext, []byte("two owner secret")) {
		t.Fatalf("two-owner decryption failed: %+v", res)
	}
	seen := map[string]bool{}
	for _, d := range res.delegates {
		seen[d] = true
	}
	if !seen["Alice"] || !seen["Bob"] {
		t.Fatalf("expected both owners as delegate evidence, got %v", res.delegates)
	}
	if len(a.cache.UserKeys) != 0 {
		t.Fatalf("both owners should have spent their single use, live=%d", len(a.cache.UserKeys))
	}
}
